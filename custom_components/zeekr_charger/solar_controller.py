"""Solar-surplus (PV diversion) charging controller.

Periodically reads a user-selected "grid power" sensor (signed watts) and,
optionally, a home battery state-of-charge sensor, and steps the charger's
current limit to track available solar surplus — the same reactive approach
used by dedicated PV-diversion chargers (Zappi, Ohme, myenergi eddi).

Deliberately reactive, not forecast-based: if the grid is importing,
something already needs more power than solar provides (including whatever
the EV is drawing), so back off; if exporting, take more. Self-correcting
without any consumption model.

Sign convention: by default negative grid power = exporting (surplus).
Installations whose sensor reports export as positive can flip
settings.grid_power_inverted.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass

from homeassistant.core import HomeAssistant

from .const import (
    MIN_CHARGE_RATE,
    SOLAR_ASSUMED_VOLTAGE,
    SOLAR_DEFAULT_BATTERY_PRIORITY_SOC,
    SOLAR_DEFAULT_POLL_INTERVAL,
    SOLAR_DEFAULT_STEP_A,
    SOLAR_PAUSE_DEBOUNCE_SECONDS,
    SOLAR_RESUME_DEBOUNCE_SECONDS,
)

_LOGGER = logging.getLogger(__name__)


@dataclass
class SolarControllerSettings:
    """Live-tunable settings, backed by restorable HA entities/options."""

    enabled: bool = False
    grid_power_entity_id: str | None = None
    battery_soc_entity_id: str | None = None
    grid_power_inverted: bool = False  # True when positive = exporting
    battery_priority_soc: float = SOLAR_DEFAULT_BATTERY_PRIORITY_SOC
    min_current_a: int = MIN_CHARGE_RATE
    max_current_a: int = 32
    poll_interval_s: int = SOLAR_DEFAULT_POLL_INTERVAL
    step_a: int = SOLAR_DEFAULT_STEP_A


@dataclass
class SolarControllerStatus:
    """Live computed status, read by the diagnostic sensors."""

    available_surplus_w: float | None = None
    target_current_a: int | None = None
    paused_for_insufficient_solar: bool = False
    withheld_for_battery_priority: bool = False


class ZeekrSolarController:
    """Runs the periodic solar-surplus control loop for one charger."""

    def __init__(self, hass: HomeAssistant, coordinator) -> None:
        self.hass = hass
        self.coordinator = coordinator
        self.settings = SolarControllerSettings()
        self.status = SolarControllerStatus()
        self._task: asyncio.Task | None = None
        self._insufficient_since: float | None = None
        self._sufficient_since: float | None = None
        self._paused_by_solar = False

    @property
    def client(self):
        return self.coordinator.client

    def start(self) -> None:
        if self._task and not self._task.done():
            return
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self._task = None

    async def _loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(self.settings.poll_interval_s)
                # Always tick: _tick computes and publishes surplus/target
                # (read-only) regardless, and only actuates when enabled.
                await self._tick()
            except asyncio.CancelledError:
                break
            except Exception:  # noqa: BLE001
                _LOGGER.exception("Solar controller tick failed")

    def _read_float_state(self, entity_id: str | None) -> float | None:
        if not entity_id:
            return None
        state = self.hass.states.get(entity_id)
        if state is None or state.state in ("unknown", "unavailable"):
            return None
        try:
            return float(state.state)
        except ValueError:
            return None

    def _current_limit_a(self) -> int | None:
        """The charger's active limit, same precedence as the Charge Rate entities."""
        power_status = (self.coordinator.data or {}).get("power_status", {})
        limit = power_status.get("configured_limit_amps")
        if limit is None:
            limit = power_status.get("limit_amps")
        return int(limit) if limit is not None else None

    async def _tick(self) -> None:
        if not self.client or not self.client.is_connected:
            return

        grid_power_w = self._read_float_state(self.settings.grid_power_entity_id)
        if grid_power_w is None:
            _LOGGER.debug("Solar controller: grid power entity unavailable, skipping tick")
            self.status.available_surplus_w = None
            self.status.target_current_a = None
            return

        # Default convention: negative = exporting -> surplus available.
        surplus_w = grid_power_w if self.settings.grid_power_inverted else -grid_power_w

        withheld_for_battery = False
        battery_soc = self._read_float_state(self.settings.battery_soc_entity_id)
        if (
            self.settings.battery_soc_entity_id
            and battery_soc is not None
            and battery_soc < self.settings.battery_priority_soc
        ):
            # Home battery hasn't cleared its priority SOC — it eats the surplus first.
            surplus_w = 0.0
            withheld_for_battery = True

        self.status.available_surplus_w = surplus_w
        self.status.withheld_for_battery_priority = withheld_for_battery

        target_a = int(surplus_w // SOLAR_ASSUMED_VOLTAGE)
        self.status.target_current_a = target_a

        # Surplus/target above are read-only and always published, so the
        # sensors are useful for dashboarding and can be sanity-checked before
        # a car is ever plugged in. Everything below actuates the charger, so
        # it needs both the feature switched on and a car actually present.
        if not self.settings.enabled:
            return
        heartbeat_state = (self.coordinator.data or {}).get("heartbeat_state", {})
        if not heartbeat_state.get("car_connected"):
            return

        now = time.monotonic()
        if target_a < self.settings.min_current_a:
            await self._handle_insufficient_surplus(now)
        else:
            await self._handle_sufficient_surplus(now, target_a)

    async def _handle_insufficient_surplus(self, now: float) -> None:
        self._sufficient_since = None
        if self._insufficient_since is None:
            self._insufficient_since = now

        if (
            not self._paused_by_solar
            and now - self._insufficient_since >= SOLAR_PAUSE_DEBOUNCE_SECONDS
        ):
            _LOGGER.info(
                "Solar controller: insufficient surplus for over %ds, pausing charge",
                SOLAR_PAUSE_DEBOUNCE_SECONDS,
            )
            if await self.client.stop_charge():
                self._paused_by_solar = True
                self.status.paused_for_insufficient_solar = True

    async def _handle_sufficient_surplus(self, now: float, target_a: int) -> None:
        self._insufficient_since = None
        if self._sufficient_since is None:
            self._sufficient_since = now

        if self._paused_by_solar:
            if now - self._sufficient_since < SOLAR_RESUME_DEBOUNCE_SECONDS:
                return  # still debouncing resume
            _LOGGER.info("Solar controller: surplus recovered, resuming charge")
            if not await self.client.authorize_charge():
                return
            self._paused_by_solar = False
            self.status.paused_for_insufficient_solar = False

        target_a = max(self.settings.min_current_a, min(target_a, self.settings.max_current_a))
        current_a = self._current_limit_a()

        if current_a is None:
            new_a = target_a
        elif target_a > current_a:
            new_a = min(target_a, current_a + self.settings.step_a)
        elif target_a < current_a:
            new_a = max(target_a, current_a - self.settings.step_a)
        else:
            new_a = current_a

        if current_a is None or new_a != current_a:
            _LOGGER.debug(
                "Solar controller: current limit %sA -> %dA (target %dA, surplus %.0fW)",
                current_a if current_a is not None else "?",
                new_a,
                target_a,
                self.status.available_surplus_w or 0.0,
            )
            await self.client.set_current_limit(None, new_a)
            await self.coordinator.async_request_refresh()
