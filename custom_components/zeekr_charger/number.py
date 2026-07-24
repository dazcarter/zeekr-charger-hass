"""Number platform for the Zeekr charger integration."""

from __future__ import annotations

from typing import Any

from homeassistant.components.number import (
    NumberEntity,
    NumberEntityDescription,
    NumberMode,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import PERCENTAGE, UnitOfElectricCurrent
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.restore_state import RestoreEntity

from .const import DEFAULT_MAX_CHARGE_RATE, DOMAIN, MIN_CHARGE_RATE
from .entity import ZeekrChargerEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Zeekr charger numbers."""
    runtime = hass.data[DOMAIN][entry.entry_id]
    coordinator = runtime.coordinator
    solar = runtime.solar_controller
    async_add_entities(
        [
            ZeekrChargeRateNumber(coordinator),
            ZeekrSolarSettingNumber(
                coordinator,
                solar,
                NumberEntityDescription(
                    key="solar_min_current",
                    name="Solar Min Charge Current",
                    native_unit_of_measurement=UnitOfElectricCurrent.AMPERE,
                    icon="mdi:current-ac",
                ),
                attr="min_current_a",
                min_value=MIN_CHARGE_RATE,
                max_value=DEFAULT_MAX_CHARGE_RATE,
            ),
            ZeekrSolarSettingNumber(
                coordinator,
                solar,
                NumberEntityDescription(
                    key="solar_max_current",
                    name="Solar Max Charge Current",
                    native_unit_of_measurement=UnitOfElectricCurrent.AMPERE,
                    icon="mdi:current-ac",
                ),
                attr="max_current_a",
                min_value=MIN_CHARGE_RATE,
                max_value=DEFAULT_MAX_CHARGE_RATE,
            ),
            ZeekrSolarSettingNumber(
                coordinator,
                solar,
                NumberEntityDescription(
                    key="solar_battery_priority_soc",
                    name="Solar Battery Priority SOC",
                    native_unit_of_measurement=PERCENTAGE,
                    icon="mdi:battery-charging-80",
                ),
                attr="battery_priority_soc",
                min_value=0,
                max_value=100,
            ),
        ]
    )


class ZeekrChargeRateNumber(ZeekrChargerEntity, NumberEntity):
    """Set the charger's current limit (0xC0), min 6A, max = live grid capacity."""

    _attr_native_step = 1
    _attr_mode = NumberMode.SLIDER
    _attr_native_unit_of_measurement = UnitOfElectricCurrent.AMPERE

    def __init__(self, coordinator) -> None:
        super().__init__(
            coordinator,
            NumberEntityDescription(
                key="charge_rate",
                name="Charge Rate",
                icon="mdi:lightning-bolt",
            ),
        )

    @property
    def native_min_value(self) -> float:
        return MIN_CHARGE_RATE

    @property
    def native_max_value(self) -> float:
        # Live grid capacity when available, sensible fallback otherwise.
        grid = (self.coordinator.data or {}).get("current_config", {}).get("grid_capacity_a")
        if grid and grid >= MIN_CHARGE_RATE:
            return float(grid)
        return float(DEFAULT_MAX_CHARGE_RATE)

    @property
    def native_value(self) -> float | None:
        power_status = (self.coordinator.data or {}).get("power_status", {})
        configured = power_status.get("configured_limit_amps")
        if configured is not None and configured > 0:
            return float(configured)
        limit = power_status.get("limit_amps")
        return float(limit) if limit is not None else None

    async def async_set_native_value(self, value: float) -> None:
        # 0xC0 acks are unreliable by design — send and refresh; the next
        # 0xE0/heartbeat confirms whether the setting took.
        await self.coordinator.client.set_current_limit(None, int(value))
        await self.coordinator.async_request_refresh()


class ZeekrSolarSettingNumber(ZeekrChargerEntity, NumberEntity, RestoreEntity):
    """A live-adjustable, restorable solar controller setting."""

    _attr_native_step = 1
    _attr_mode = NumberMode.BOX

    def __init__(
        self,
        coordinator,
        solar_controller,
        description: NumberEntityDescription,
        attr: str,
        min_value: float,
        max_value: float,
    ) -> None:
        super().__init__(coordinator, description)
        self._solar_controller = solar_controller
        self._settings_attr = attr
        self._attr_native_min_value = min_value
        self._attr_native_max_value = max_value

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        last_state = await self.async_get_last_state()
        if last_state is not None and last_state.state not in ("unknown", "unavailable"):
            try:
                setattr(
                    self._solar_controller.settings,
                    self._settings_attr,
                    type(getattr(self._solar_controller.settings, self._settings_attr))(
                        float(last_state.state)
                    ),
                )
            except (ValueError, TypeError):
                pass

    @property
    def native_value(self) -> float:
        return float(getattr(self._solar_controller.settings, self._settings_attr))

    async def async_set_native_value(self, value: float) -> None:
        current = getattr(self._solar_controller.settings, self._settings_attr)
        setattr(self._solar_controller.settings, self._settings_attr, type(current)(value))
        self.async_write_ha_state()
