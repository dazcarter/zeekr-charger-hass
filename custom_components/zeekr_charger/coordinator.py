"""Data update coordinator for the Zeekr charger integration.

Static data (basic/employ/protection/WiFi/BLE info) is fetched once per
connection and cached; dynamic data (power status, current config, charge
mode, heartbeat state) refreshes every cycle. A transient BLE disconnect
never raises UpdateFailed — we return last-known data and let the client's
own reconnection logic recover, so entities don't flicker unavailable on
every proxy hiccup.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .ble_client import ZeekrBleClient
from .const import DEFAULT_SCAN_INTERVAL, DOMAIN
from .protocol import charge_mode_name

_LOGGER = logging.getLogger(__name__)

_EMPTY_DATA: dict[str, Any] = {
    "connected": False,
    "heartbeat_state": {},
    "heartbeat_stats": {"total_heartbeats": 0, "seconds_since_last_heartbeat": None},
    "connection_status": {},
    "telemetry": {},
    "current_config": {},
    "power_status": {},
    "basic_info": {},
    "employ_info": {},
    "protection_info": {},
    "wifi_config": {},
    "wifi_status": {},
    "ble_info": {},
    "charge_mode": None,
    "charge_mode_name": None,
}


class ZeekrChargerCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Coordinates polling for one Zeekr charger."""

    def __init__(
        self,
        hass: HomeAssistant,
        client: ZeekrBleClient,
        update_interval: timedelta = timedelta(seconds=DEFAULT_SCAN_INTERVAL),
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=update_interval,
        )
        self.client = client
        self._static_data_fetched = False
        self._last_connection_state = False

    async def force_refresh_static_data(self) -> None:
        """Re-fetch all once-per-connection data on the next refresh."""
        self._static_data_fetched = False
        await self.async_request_refresh()

    async def _async_update_data(self) -> dict[str, Any]:
        if not self.client.is_connected:
            # Reconnection is the client's job; keep serving last-known data.
            return self.data or dict(_EMPTY_DATA)

        try:
            return await self._poll()
        except Exception as exc:  # noqa: BLE001
            # Transient BLE errors mid-poll: same policy as disconnects.
            _LOGGER.warning("Poll cycle failed, serving last-known data: %s", exc)
            return self.data or dict(_EMPTY_DATA)

    async def _poll(self) -> dict[str, Any]:
        prev = self.data or {}

        # Refetch static data after every (re)connection.
        connected = self.client.is_connected
        if connected and not self._last_connection_state:
            self._static_data_fetched = False
        self._last_connection_state = connected

        static_keys = (
            "basic_info",
            "employ_info",
            "protection_info",
            "wifi_config",
            "wifi_status",
            "ble_info",
        )
        if not self._static_data_fetched:
            fetched = await self._fetch_static_data()
            # Never let a failed refetch wipe data we already have. The
            # charger answers these queries reliably only on the first
            # session after a reconnect, so an empty result means "ask again
            # later", not "this charger has no model number".
            static = {key: (fetched.get(key) or prev.get(key) or {}) for key in static_keys}
            # Only stop refetching once the charger actually told us
            # something; otherwise retry next cycle (bounded by the client's
            # unsupported-opcode retirement, so this can't spin forever).
            self._static_data_fetched = bool(static.get("basic_info"))
        else:
            static = {key: prev.get(key, {}) for key in static_keys}

        # Dynamic data, every cycle. Telemetry first: it carries charger
        # state, car-connected and the live session figures, and the charger
        # almost never volunteers a heartbeat on its own.
        await self.client.request_telemetry()
        current_config = await self.client.query_home_current_config()
        power_status = await self.client.query_power_status()
        charge_mode = await self.client.query_charge_mode()

        heartbeat_state = self.client.get_heartbeat_state()
        heartbeat_stats = self.client.get_heartbeat_stats()
        connection_status = self.client.get_connection_status()
        telemetry = self.client.get_last_telemetry()

        telemetry_dict: dict[str, Any] = {}
        if telemetry:
            # The charger's energy counter starts at 0 each session, so it is
            # reported as-is (an offset taken on first sight undercounts when HA
            # connects mid-session).
            session_energy = telemetry.session_energy_kwh
            telemetry_dict = {
                **telemetry.__dict__,
                "voltage_v": round(telemetry.voltage_v, 1),
                "current_a": round(telemetry.current_a, 1),
                "session_energy_kwh": round(session_energy, 4),
                "session_energy_kwh_raw": round(telemetry.session_energy_kwh, 4),
                "session_runtime_seconds": telemetry.runtime_seconds,
            }
            if not self.client.telemetry_is_live:
                # Session has ended: the charger only reports these while
                # charging, so holding the final reading makes a stopped
                # charger look like it is still drawing current. Session
                # totals are kept — they are the completed session's result.
                telemetry_dict["voltage_v"] = None
                telemetry_dict["current_a"] = None
                telemetry_dict["temperature_c"] = None
            # Prefer the session tracker's runtime if the frame's counter is 0.
            if (
                telemetry.runtime_seconds == 0
                and heartbeat_stats.get("charging_session_active")
                and heartbeat_stats.get("charging_session_duration")
            ):
                telemetry_dict["session_runtime_seconds"] = int(
                    heartbeat_stats["charging_session_duration"]
                )

        hb_dict = dict(heartbeat_state.__dict__)
        hb_dict.pop("telemetry", None)  # dataclass instance, not JSON-friendly

        return {
            **static,
            "current_config": current_config.__dict__ if current_config else prev.get("current_config", {}),
            "power_status": power_status.__dict__ if power_status else prev.get("power_status", {}),
            "charge_mode": charge_mode if charge_mode is not None else prev.get("charge_mode"),
            "charge_mode_name": charge_mode_name(
                charge_mode if charge_mode is not None else prev.get("charge_mode")
            ),
            "heartbeat_state": hb_dict,
            "heartbeat_stats": heartbeat_stats,
            "connection_status": connection_status,
            "telemetry": telemetry_dict,
            "connected": self.client.is_connected,
        }

    async def _fetch_static_data(self) -> dict[str, Any]:
        """Fetch all once-per-connection data, tolerating individual failures."""
        static: dict[str, Any] = {}
        for key, query in (
            ("basic_info", self.client.query_basic_info),
            ("employ_info", self.client.query_employ_info),
            ("protection_info", self.client.query_protection_info),
            ("wifi_config", self.client.query_wifi_config),
            ("ble_info", self.client.query_ble_info),
            ("wifi_status", self.client.query_wifi_status),
        ):
            try:
                static[key] = await query() or {}
            except Exception as exc:  # noqa: BLE001
                _LOGGER.warning("Static fetch of %s failed: %s", key, exc)
                static[key] = {}

        # Network status merges into wifi_status (error codes surface there).
        try:
            network_status = await self.client.query_network_status()
            if network_status:
                static["wifi_status"].update(network_status)
        except Exception as exc:  # noqa: BLE001
            _LOGGER.debug("Network status fetch failed: %s", exc)

        return static

    async def async_shutdown(self) -> None:
        await super().async_shutdown()
        if self.client:
            await self.client.async_disconnect()

    async def force_reconnect(self) -> bool:
        """User-triggered reconnect; refetches static data on success."""
        success = await self.client.force_reconnect()
        if success:
            self._static_data_fetched = False
            await self.async_request_refresh()
        return success
