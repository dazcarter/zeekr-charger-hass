"""Home Assistant integration entry-point for Zeekr BLE chargers."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from logging.handlers import RotatingFileHandler

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers import entity_registry as er

from .ble_client import ZeekrBleClient
from .const import (
    CONF_DEVICE_ADDRESS,
    CONF_GRID_POWER_INVERTED,
    CONF_HEARTBEAT_STALE_THRESHOLD,
    CONF_RECONNECT_INITIAL_DELAY,
    CONF_RECONNECT_MAX_ATTEMPTS,
    CONF_RECONNECT_MAX_DELAY,
    CONF_RESPONSE_TIMEOUT,
    CONF_SERIAL,
    CONF_SOLAR_BATTERY_SOC_ENTITY,
    CONF_SOLAR_GRID_POWER_ENTITY,
    DEFAULT_MAX_CHARGE_RATE,
    DOMAIN,
)
from .coordinator import ZeekrChargerCoordinator
from .solar_controller import ZeekrSolarController

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [
    Platform.SENSOR,
    Platform.BINARY_SENSOR,
    Platform.SWITCH,
    Platform.NUMBER,
    Platform.BUTTON,
]

# Map of pre-1.0 class-name-based unique_id suffixes to the new key-based
# scheme, so existing entity registry entries (entity_ids, history, dashboard
# references) survive the rebuild.
_LEGACY_UNIQUE_ID_MAP = {
    "zeekrchargercurrentlimitsensor": "charge_rate",
    "zeekrchargermaxcurrentcapacitysensor": "rated_current_capacity",
    "zeekrchargerserialsensor": "serial_number",
    "zeekrchargerversionsensor": "firmware_version",
    "zeekrchargerstatesensor": "charger_state",
    "zeekrchargersoftwareversionsensor": "software_version",
    "zeekrchargerproductiondatesensor": "production_date",
    "zeekrchargerratedpowersensor": "rated_power",
    "zeekrchargermodelsensor": "model",
    "zeekrchargermanufacturersensor": "manufacturer",
    "zeekrchargergroundingdetectionsensor": "grounding_detection",
    "zeekrchargerrelayadhesionsensor": "relay_adhesion_detection",
    "zeekrchargerimpropergunlinesensor": "improper_cable_detection",
    "zeekrchargerrcddetectionsensor": "rcd_detection",
    "zeekrchargerwifissidsensor": "wifi_ssid",
    "zeekrchargerwifistatussensor": "wifi_status",
    "zeekrchargersessionenergysensor": "session_energy",
    "zeekrchargervoltagesensor": "voltage",
    "zeekrchargercurrentsensor": "in_use_current",
    "zeekrchargertemperaturesensor": "charger_temperature",
    "zeekrchargersessionruntimesensor": "session_runtime",
    "zeekrchargerphasestatussensor": "phase_status",
    "zeekrchargergridcapacitysensor": "grid_capacity",
    "zeekrchargerconnectionstatussensor": "connection_status",
    "zeekrchargerreconnectattemptssensor": "reconnect_attempts",
    "zeekrchargerchargemodesensor": "charge_mode",
    "zeekrchargerwifimacaddresssensor": "wifi_mac_address",
    "zeekrchargerwifimodulefirmwaresensor": "wifi_module_firmware",
    "zeekrchargernetworkmodesensor": "network_mode",
    "zeekrchargerlastheartbeatsensor": "time_since_heartbeat",
    "zeekrchargersolarsurplussensor": "solar_surplus",
    "zeekrchargersolartargetcurrentsensor": "solar_target_current",
    "zeekrchargerchargingbinarysensor": "charging",
    "zeekrchargercarconnectedbinarysensor": "car_connected",
    "zeekrchargerheartbeatbinarysensor": "heartbeat_active",
    "zeekrchargerautochargeswitch": "plug_and_charge",
    "zeekrchargersolarchargingswitch": "solar_charging",
    "zeekrchargercurrentlimitnumber": "charge_rate",
    "zeekrchargersolarmincurrentnumber": "solar_min_current",
    "zeekrchargersolarmaxcurrentnumber": "solar_max_current",
    "zeekrchargersolarbatteryprioritysocnumber": "solar_battery_priority_soc",
    "zeekrchargerauthorizechargebutton": "start_charging",
    "zeekrchargerstopchargebutton": "stop_charging",
    "zeekrchargerforcereconnectbutton": "force_reconnect",
}


DEBUG_LOG_FILENAME = "zeekr_charger.log"


def _attach_debug_file_handler(path: str) -> None:
    """Mirror this integration's DEBUG output to its own log file.

    Home Assistant OS 2026.7 does not write config/home-assistant.log and the
    /api/error_log endpoint is gone, so the unconditional raw BLE trace this
    integration emits had nowhere to surface — which made every timing bug
    here a guessing game. Only attached when our logger is actually at DEBUG,
    so normal installs pay nothing.

    Runs in an executor: opening the file is blocking I/O.
    """
    logger = logging.getLogger(__package__)
    if any(getattr(h, "_zeekr_debug_handler", False) for h in logger.handlers):
        return
    handler = RotatingFileHandler(path, maxBytes=2_000_000, backupCount=2)
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    handler.setLevel(logging.DEBUG)
    handler._zeekr_debug_handler = True  # marker so we only attach once
    logger.addHandler(handler)
    logger.info("Zeekr debug log started at %s", path)


@dataclass
class ZeekrRuntimeData:
    """Runtime objects stored in hass.data for a config entry."""

    client: ZeekrBleClient
    coordinator: ZeekrChargerCoordinator
    solar_controller: ZeekrSolarController


async def _async_migrate_legacy_unique_ids(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Rename pre-1.0 class-name-based unique_ids to the key-based scheme."""
    serial = entry.data[CONF_SERIAL]
    registry = er.async_get(hass)
    for reg_entry in er.async_entries_for_config_entry(registry, entry.entry_id):
        prefix = f"{serial}_"
        if not reg_entry.unique_id.startswith(prefix):
            continue
        suffix = reg_entry.unique_id[len(prefix) :]
        new_key = _LEGACY_UNIQUE_ID_MAP.get(suffix)
        if new_key is None:
            continue
        new_unique_id = f"{serial}_{new_key}"
        if reg_entry.unique_id == new_unique_id:
            continue
        _LOGGER.info(
            "Migrating unique_id %s -> %s (%s)",
            reg_entry.unique_id,
            new_unique_id,
            reg_entry.entity_id,
        )
        try:
            registry.async_update_entity(reg_entry.entity_id, new_unique_id=new_unique_id)
        except ValueError as err:
            # A new-style entity already claimed the id (shouldn't happen on a
            # clean upgrade) — keep the old orphan rather than crash setup.
            _LOGGER.warning("Could not migrate %s: %s", reg_entry.entity_id, err)


def _apply_options(entry: ConfigEntry, runtime: ZeekrRuntimeData) -> None:
    """Push live-applicable options into the client and solar controller."""
    options = entry.options
    runtime.solar_controller.settings.grid_power_entity_id = options.get(
        CONF_SOLAR_GRID_POWER_ENTITY
    )
    runtime.solar_controller.settings.battery_soc_entity_id = options.get(
        CONF_SOLAR_BATTERY_SOC_ENTITY
    )
    runtime.solar_controller.settings.grid_power_inverted = bool(
        options.get(CONF_GRID_POWER_INVERTED, False)
    )
    if options.get(CONF_RESPONSE_TIMEOUT):
        runtime.client.set_response_timeout(float(options[CONF_RESPONSE_TIMEOUT]))
    runtime.client.set_reconnection_config(
        max_attempts=(
            int(options[CONF_RECONNECT_MAX_ATTEMPTS])
            if options.get(CONF_RECONNECT_MAX_ATTEMPTS)
            else None
        ),
        initial_delay=(
            float(options[CONF_RECONNECT_INITIAL_DELAY])
            if options.get(CONF_RECONNECT_INITIAL_DELAY)
            else None
        ),
        max_delay=(
            float(options[CONF_RECONNECT_MAX_DELAY])
            if options.get(CONF_RECONNECT_MAX_DELAY)
            else None
        ),
        stale_threshold=(
            float(options[CONF_HEARTBEAT_STALE_THRESHOLD])
            if options.get(CONF_HEARTBEAT_STALE_THRESHOLD)
            else None
        ),
    )


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up a Zeekr charger from a config entry."""
    hass.data.setdefault(DOMAIN, {})

    if _LOGGER.isEnabledFor(logging.DEBUG):
        await hass.async_add_executor_job(
            _attach_debug_file_handler, hass.config.path(DEBUG_LOG_FILENAME)
        )

    await _async_migrate_legacy_unique_ids(hass, entry)

    serial = entry.data[CONF_SERIAL]
    address = (
        entry.options.get(CONF_DEVICE_ADDRESS)
        or entry.data.get(CONF_DEVICE_ADDRESS)
        or serial  # fall back to name-based discovery
    )

    client = ZeekrBleClient(hass=hass, address=address, serial=serial)
    if not await client.async_connect():
        await client.async_disconnect()
        raise ConfigEntryNotReady(f"Failed to connect to charger {serial}")

    coordinator = ZeekrChargerCoordinator(hass, client)
    await coordinator.async_config_entry_first_refresh()

    solar_controller = ZeekrSolarController(hass, coordinator)
    solar_controller.settings.max_current_a = (
        coordinator.data.get("current_config", {}).get("grid_capacity_a")
        or DEFAULT_MAX_CHARGE_RATE
    )
    # Sensors read the controller's live status through the coordinator.
    coordinator.solar_controller = solar_controller

    runtime = ZeekrRuntimeData(
        client=client, coordinator=coordinator, solar_controller=solar_controller
    )
    _apply_options(entry, runtime)
    solar_controller.start()

    hass.data[DOMAIN][entry.entry_id] = runtime

    entry.async_on_unload(entry.add_update_listener(_async_options_updated))
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def _async_options_updated(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Apply updated options live — no BLE teardown needed for any of them."""
    runtime: ZeekrRuntimeData | None = hass.data.get(DOMAIN, {}).get(entry.entry_id)
    if runtime:
        _apply_options(entry, runtime)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a Zeekr charger config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    runtime: ZeekrRuntimeData | None = hass.data[DOMAIN].pop(entry.entry_id, None)
    if runtime:
        await runtime.solar_controller.stop()
        await runtime.coordinator.async_shutdown()
    return unload_ok
