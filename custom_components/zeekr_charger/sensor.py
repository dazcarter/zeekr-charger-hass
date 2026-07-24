"""Sensor platform for the Zeekr charger integration."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from homeassistant.components.sensor import (
    RestoreSensor,
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    EntityCategory,
    UnitOfElectricCurrent,
    UnitOfElectricPotential,
    UnitOfEnergy,
    UnitOfPower,
    UnitOfTemperature,
    UnitOfTime,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import protocol
from .const import DOMAIN
from .coordinator import ZeekrChargerCoordinator
from .entity import ZeekrChargerEntity


@dataclass(frozen=True, kw_only=True)
class ZeekrSensorDescription(SensorEntityDescription):
    """Sensor description with value/attribute extractors."""

    value_fn: Callable[[ZeekrChargerCoordinator], Any]
    attrs_fn: Callable[[ZeekrChargerCoordinator], dict[str, Any]] | None = None


def _data(coordinator: ZeekrChargerCoordinator) -> dict[str, Any]:
    return coordinator.data or {}


def _charge_rate(coordinator: ZeekrChargerCoordinator) -> float | None:
    power_status = _data(coordinator).get("power_status", {})
    configured = power_status.get("configured_limit_amps")
    if configured is not None and configured > 0:
        return float(configured)
    limit = power_status.get("limit_amps")
    return float(limit) if limit is not None else None


def _rated_capacity(coordinator: ZeekrChargerCoordinator) -> float | None:
    # Prefer 0xE0 (more reliable), fall back to 0xA9.
    max_cap = _data(coordinator).get("power_status", {}).get("max_current_capacity")
    if max_cap is not None and max_cap > 0:
        return float(max_cap)
    max_cap = _data(coordinator).get("current_config", {}).get("max_current_capacity_a")
    if max_cap is not None and max_cap > 0:
        return float(max_cap)
    return None


def _protection_flag(key: str) -> Callable[[ZeekrChargerCoordinator], str | None]:
    def getter(coordinator: ZeekrChargerCoordinator) -> str | None:
        value = _data(coordinator).get("protection_info", {}).get(key)
        if value is None:
            return None
        return "Enabled" if value == 1 else "Disabled"

    return getter


def _phase_status(coordinator: ZeekrChargerCoordinator) -> str | None:
    phase_flags = _data(coordinator).get("telemetry", {}).get("phase_flags")
    if phase_flags is None:
        return None
    # Lower bits are per-phase flags; higher-order bits are status noise.
    active_bits = phase_flags & 0x07
    if active_bits == 0 or (active_bits & (active_bits - 1)) == 0:
        return "Single Phase"
    return f"Multi Phase (flags: 0x{phase_flags:02X})"


def _wifi_status_text(coordinator: ZeekrChargerCoordinator) -> str | None:
    wifi_status = _data(coordinator).get("wifi_status", {})
    return wifi_status.get("result_detail_desc") or wifi_status.get("wifi_status")


def _network_mode(coordinator: ZeekrChargerCoordinator) -> str | None:
    # Raw value only — the WiFi/LAN/4G index mapping is unconfirmed, so no
    # fabricated labels.
    mode = _data(coordinator).get("wifi_status", {}).get("networking_mode")
    return f"Mode {mode}" if mode is not None else None


def _heartbeat_age(coordinator: ZeekrChargerCoordinator) -> float | None:
    # None when no heartbeat has EVER arrived — never a healthy-looking 0.
    seconds = _data(coordinator).get("heartbeat_stats", {}).get(
        "seconds_since_last_heartbeat"
    )
    return round(float(seconds), 1) if seconds is not None else None


def _solar_status(coordinator: ZeekrChargerCoordinator):
    controller = getattr(coordinator, "solar_controller", None)
    return controller.status if controller else None


SENSORS: tuple[ZeekrSensorDescription, ...] = (
    ZeekrSensorDescription(
        key="charge_rate",
        name="Charge Rate",
        native_unit_of_measurement=UnitOfElectricCurrent.AMPERE,
        icon="mdi:lightning-bolt",
        value_fn=_charge_rate,
    ),
    ZeekrSensorDescription(
        key="rated_current_capacity",
        name="Rated Current Capacity",
        native_unit_of_measurement=UnitOfElectricCurrent.AMPERE,
        icon="mdi:lightning-bolt-outline",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=_rated_capacity,
    ),
    ZeekrSensorDescription(
        key="serial_number",
        name="Serial Number",
        icon="mdi:identifier",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda c: _data(c).get("basic_info", {}).get("charge_point_number")
        or c.client.serial,
    ),
    ZeekrSensorDescription(
        key="firmware_version",
        name="Firmware Version",
        icon="mdi:chip",
        entity_category=EntityCategory.DIAGNOSTIC,
        # This charger reports "hardware_version" (V1.0); firmware_version is
        # not a key it emits. Confirmed by decoding a live 0xC1 payload.
        value_fn=lambda c: _data(c).get("basic_info", {}).get("firmware_version")
        or _data(c).get("basic_info", {}).get("hardware_version"),
    ),
    ZeekrSensorDescription(
        key="software_version",
        name="Software Version",
        icon="mdi:application-cog",
        entity_category=EntityCategory.DIAGNOSTIC,
        # Emitted as p_board_software_version / c_board_software_version
        # (both V1.1.0 on the test unit); expose the power board as the
        # headline value and the control board alongside it.
        value_fn=lambda c: _data(c).get("basic_info", {}).get("software_version")
        or _data(c).get("basic_info", {}).get("p_board_software_version"),
        attrs_fn=lambda c: {
            "p_board_software_version": _data(c)
            .get("basic_info", {})
            .get("p_board_software_version"),
            "c_board_software_version": _data(c)
            .get("basic_info", {})
            .get("c_board_software_version"),
            "hardware_version": _data(c).get("basic_info", {}).get("hardware_version"),
        },
    ),
    ZeekrSensorDescription(
        key="production_date",
        name="Production Date",
        icon="mdi:calendar",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda c: _data(c).get("basic_info", {}).get("production_date"),
    ),
    ZeekrSensorDescription(
        key="rated_power",
        name="Rated Power",
        native_unit_of_measurement=UnitOfPower.WATT,
        device_class=SensorDeviceClass.POWER,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda c: _data(c).get("basic_info", {}).get("rated_power_w"),
    ),
    ZeekrSensorDescription(
        key="model",
        name="Model",
        icon="mdi:ev-station",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda c: _data(c).get("basic_info", {}).get("model_number"),
    ),
    ZeekrSensorDescription(
        key="manufacturer",
        name="Manufacturer",
        icon="mdi:factory",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda c: _data(c).get("basic_info", {}).get("manufacturer") or "Zeekr",
    ),
    ZeekrSensorDescription(
        key="charger_state",
        name="Charger State",
        icon="mdi:state-machine",
        value_fn=lambda c: _data(c).get("heartbeat_state", {}).get("state"),
        attrs_fn=lambda c: {
            "port": _data(c).get("heartbeat_state", {}).get("port"),
            "last_update": _data(c).get("heartbeat_state", {}).get("timestamp"),
        },
    ),
    ZeekrSensorDescription(
        key="session_energy",
        name="Session Energy",
        native_unit_of_measurement=UnitOfEnergy.KILO_WATT_HOUR,
        device_class=SensorDeviceClass.ENERGY,
        state_class=SensorStateClass.TOTAL_INCREASING,
        value_fn=lambda c: _data(c).get("telemetry", {}).get("session_energy_kwh"),
    ),
    ZeekrSensorDescription(
        key="voltage",
        name="Voltage",
        native_unit_of_measurement=UnitOfElectricPotential.VOLT,
        device_class=SensorDeviceClass.VOLTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda c: _data(c).get("telemetry", {}).get("voltage_v"),
    ),
    ZeekrSensorDescription(
        key="in_use_current",
        name="In-use Current",
        native_unit_of_measurement=UnitOfElectricCurrent.AMPERE,
        device_class=SensorDeviceClass.CURRENT,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda c: _data(c).get("telemetry", {}).get("current_a"),
    ),
    ZeekrSensorDescription(
        key="charger_temperature",
        name="Charger Temperature",
        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
        device_class=SensorDeviceClass.TEMPERATURE,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda c: _data(c).get("heartbeat_state", {}).get("temperature_c")
        or _data(c).get("telemetry", {}).get("temperature_c"),
    ),
    ZeekrSensorDescription(
        key="session_runtime",
        name="Session Runtime",
        native_unit_of_measurement=UnitOfTime.SECONDS,
        state_class=SensorStateClass.TOTAL_INCREASING,
        icon="mdi:timer-outline",
        value_fn=lambda c: _data(c).get("telemetry", {}).get("session_runtime_seconds"),
    ),
    ZeekrSensorDescription(
        key="phase_status",
        name="Phase Status",
        icon="mdi:sine-wave",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=_phase_status,
    ),
    ZeekrSensorDescription(
        key="grid_capacity",
        name="Grid Capacity",
        native_unit_of_measurement=UnitOfElectricCurrent.AMPERE,
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:transmission-tower",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda c: _data(c).get("current_config", {}).get("grid_capacity_a"),
    ),
    ZeekrSensorDescription(
        key="wifi_ssid",
        name="WiFi SSID",
        icon="mdi:wifi",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda c: _data(c).get("wifi_status", {}).get("ssid"),
    ),
    ZeekrSensorDescription(
        key="wifi_status",
        name="WiFi Status",
        icon="mdi:wifi-check",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=_wifi_status_text,
        attrs_fn=lambda c: {
            "network_result": _data(c).get("wifi_status", {}).get("network_result"),
            "result_detail": _data(c).get("wifi_status", {}).get("result_detail"),
            "data_format": _data(c).get("wifi_status", {}).get("wifi_data_format"),
        },
    ),
    ZeekrSensorDescription(
        key="wifi_mac_address",
        name="WiFi MAC Address",
        icon="mdi:network-pos",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda c: _data(c).get("wifi_config", {}).get("wifi_mac_address"),
    ),
    ZeekrSensorDescription(
        key="wifi_module_firmware",
        name="WiFi Module Firmware",
        icon="mdi:chip",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda c: _data(c).get("wifi_config", {}).get(
            "wifi_module_firmware_version"
        ),
    ),
    ZeekrSensorDescription(
        key="network_mode",
        name="Network Mode",
        icon="mdi:network",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=_network_mode,
        attrs_fn=lambda c: {
            "raw_networking_mode": _data(c).get("wifi_status", {}).get("networking_mode"),
            "network_result": _data(c).get("wifi_status", {}).get("network_result"),
        },
    ),
    ZeekrSensorDescription(
        key="connection_status",
        name="Connection Status",
        icon="mdi:bluetooth-connect",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda c: "Connected" if _data(c).get("connected") else "Disconnected",
        attrs_fn=lambda c: _data(c).get("connection_status", {}),
    ),
    ZeekrSensorDescription(
        key="reconnect_attempts",
        name="Reconnect Attempts",
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:restart",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda c: _data(c).get("connection_status", {}).get("reconnect_attempts"),
    ),
    ZeekrSensorDescription(
        key="charge_mode",
        name="Charge Mode",
        icon="mdi:ev-plug-type2",
        value_fn=lambda c: _data(c).get("charge_mode_name"),
        attrs_fn=lambda c: {"raw_mode": _data(c).get("charge_mode")},
    ),
    ZeekrSensorDescription(
        key="grounding_detection",
        name="Grounding Detection",
        icon="mdi:earth",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=_protection_flag("grounding_detection"),
    ),
    ZeekrSensorDescription(
        key="relay_adhesion_detection",
        name="Relay Adhesion Detection",
        icon="mdi:connection",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=_protection_flag("relay_adhesion_detection"),
    ),
    ZeekrSensorDescription(
        key="improper_cable_detection",
        name="Improper Cable Detection",
        icon="mdi:alert-circle",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=_protection_flag("detection_of_improper_gun_line"),
    ),
    ZeekrSensorDescription(
        key="rcd_detection",
        name="RCD Detection",
        icon="mdi:shield-check",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=_protection_flag("rcd_detection"),
    ),
    ZeekrSensorDescription(
        key="time_since_heartbeat",
        name="Time Since Last Heartbeat",
        native_unit_of_measurement=UnitOfTime.SECONDS,
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:heart-pulse",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=_heartbeat_age,
        attrs_fn=lambda c: {
            "total_heartbeats": _data(c).get("heartbeat_stats", {}).get("total_heartbeats", 0),
            "charging_session_active": _data(c)
            .get("heartbeat_stats", {})
            .get("charging_session_active", False),
            "charging_session_duration_s": _data(c)
            .get("heartbeat_stats", {})
            .get("charging_session_duration"),
            "heartbeat_send_variant": _data(c)
            .get("heartbeat_stats", {})
            .get("heartbeat_send_variant"),
        },
    ),
    ZeekrSensorDescription(
        key="heartbeat_count",
        name="Heartbeat Count",
        state_class=SensorStateClass.TOTAL_INCREASING,
        icon="mdi:counter",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda c: _data(c).get("heartbeat_stats", {}).get("total_heartbeats"),
    ),
    ZeekrSensorDescription(
        key="connector_type",
        name="Connector Type",
        icon="mdi:power-plug",
        entity_category=EntityCategory.DIAGNOSTIC,
        # connector_type reads "NULL" on the test unit, so fall back to the
        # socket count, which is populated. Full 0xC2 payload in attributes.
        value_fn=lambda c: _data(c).get("employ_info", {}).get("connector_type")
        or (
            f"{sockets} socket"
            if (sockets := _data(c).get("employ_info", {}).get("num_socket_outlets"))
            else None
        ),
        attrs_fn=lambda c: _data(c).get("employ_info", {}),
    ),
    ZeekrSensorDescription(
        key="rated_charging_current",
        name="Rated Charging Current",
        native_unit_of_measurement=UnitOfElectricCurrent.AMPERE,
        icon="mdi:current-ac",
        entity_category=EntityCategory.DIAGNOSTIC,
        # From 0xC2 — the charger's own rating, distinct from the grid
        # capacity (0xA9) and the currently configured limit (0xE0).
        value_fn=lambda c: _data(c).get("employ_info", {}).get(
            "rated_charging_current_a"
        ),
    ),
    ZeekrSensorDescription(
        key="phase_of_charge_point",
        name="Charge Point Phase",
        icon="mdi:sine-wave",
        entity_category=EntityCategory.DIAGNOSTIC,
        # Raw value from 0xC2. Reads 3 on a single-phase 7kW unit, so this is
        # evidently a code rather than a phase count — surfaced unlabelled
        # rather than guessing at a meaning.
        value_fn=lambda c: _data(c).get("employ_info", {}).get("phase_of_charge_point"),
    ),
    ZeekrSensorDescription(
        key="ble_module_info",
        name="BLE Module",
        icon="mdi:bluetooth-settings",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda c: _data(c).get("ble_info", {}).get("firmware_version")
        or ("present" if _data(c).get("ble_info") else None),
        attrs_fn=lambda c: _data(c).get("ble_info", {}),
    ),
    ZeekrSensorDescription(
        key="solar_surplus",
        name="Available Solar Surplus",
        native_unit_of_measurement=UnitOfPower.WATT,
        device_class=SensorDeviceClass.POWER,
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:solar-power",
        value_fn=lambda c: (
            status.available_surplus_w if (status := _solar_status(c)) else None
        ),
        attrs_fn=lambda c: (
            {
                "paused_for_insufficient_solar": status.paused_for_insufficient_solar,
                "withheld_for_battery_priority": status.withheld_for_battery_priority,
            }
            if (status := _solar_status(c))
            else {}
        ),
    ),
    ZeekrSensorDescription(
        key="solar_target_current",
        name="Solar Target Current",
        native_unit_of_measurement=UnitOfElectricCurrent.AMPERE,
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:solar-power-variant",
        value_fn=lambda c: (
            status.target_current_a if (status := _solar_status(c)) else None
        ),
    ),
    ZeekrSensorDescription(
        key="charging_power",
        name="Charging Power",
        native_unit_of_measurement=UnitOfPower.WATT,
        device_class=SensorDeviceClass.POWER,
        state_class=SensorStateClass.MEASUREMENT,
        # V x I from telemetry. Both are None when idle (session ended), so
        # power reads 0 rather than a stale figure.
        value_fn=lambda c: (
            round(v * i)
            if (v := _data(c).get("telemetry", {}).get("voltage_v")) is not None
            and (i := _data(c).get("telemetry", {}).get("current_a")) is not None
            else 0
        ),
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Zeekr charger sensors."""
    coordinator: ZeekrChargerCoordinator = hass.data[DOMAIN][entry.entry_id].coordinator
    entities: list[SensorEntity] = [
        ZeekrSensor(coordinator, description) for description in SENSORS
    ]
    entities.append(ZeekrTotalEnergySensor(coordinator))
    async_add_entities(entities)


class ZeekrSensor(ZeekrChargerEntity, SensorEntity):
    """A Zeekr charger sensor driven by its entity description."""

    entity_description: ZeekrSensorDescription

    @property
    def native_value(self) -> Any:
        return self.entity_description.value_fn(self.coordinator)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        if self.entity_description.attrs_fn is None:
            return None
        return self.entity_description.attrs_fn(self.coordinator)


class ZeekrTotalEnergySensor(ZeekrChargerEntity, RestoreSensor):
    """Monotonic lifetime charging energy, folded from the resetting session
    counter and persisted across restarts. This is the sensor to add to the HA
    Energy Dashboard — it never resets, so it can't confuse the statistics."""

    _attr_device_class = SensorDeviceClass.ENERGY
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_native_unit_of_measurement = UnitOfEnergy.KILO_WATT_HOUR
    _attr_icon = "mdi:counter"

    def __init__(self, coordinator: ZeekrChargerCoordinator) -> None:
        super().__init__(
            coordinator,
            SensorEntityDescription(key="total_energy", name="Total Energy"),
        )
        self._total: float = 0.0
        self._last_session: float | None = None

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        last = await self.async_get_last_sensor_data()
        if last is not None and last.native_value is not None:
            self._total = float(last.native_value)
        # _last_session stays None so the first reading only seeds (no double count).

    @property
    def native_value(self) -> float:
        session = (self.coordinator.data or {}).get("telemetry", {}).get(
            "session_energy_kwh"
        )
        self._total, self._last_session = protocol.accumulate_lifetime_energy(
            self._total, self._last_session, session
        )
        return round(self._total, 3)
