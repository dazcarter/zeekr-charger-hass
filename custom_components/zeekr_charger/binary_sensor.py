"""Binary sensor platform for the Zeekr charger integration."""

from __future__ import annotations

from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import ZeekrChargerCoordinator
from .entity import ZeekrChargerEntity

BINARY_SENSORS: tuple[BinarySensorEntityDescription, ...] = (
    BinarySensorEntityDescription(
        key="charging",
        name="Charging",
        device_class=BinarySensorDeviceClass.RUNNING,
        icon="mdi:battery-charging",
    ),
    BinarySensorEntityDescription(
        key="car_connected",
        name="Car Connected",
        device_class=BinarySensorDeviceClass.CONNECTIVITY,
        icon="mdi:car-electric",
    ),
    BinarySensorEntityDescription(
        key="heartbeat_active",
        name="Heartbeat Active",
        device_class=BinarySensorDeviceClass.CONNECTIVITY,
        icon="mdi:heart-pulse",
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Zeekr charger binary sensors."""
    coordinator: ZeekrChargerCoordinator = hass.data[DOMAIN][entry.entry_id].coordinator
    async_add_entities(
        ZeekrBinarySensor(coordinator, description) for description in BINARY_SENSORS
    )


class ZeekrBinarySensor(ZeekrChargerEntity, BinarySensorEntity):
    """A Zeekr charger binary sensor."""

    @property
    def is_on(self) -> bool | None:
        data = self.coordinator.data or {}
        key = self.entity_description.key
        if key == "charging":
            return data.get("heartbeat_state", {}).get("charging", False)
        if key == "car_connected":
            return data.get("heartbeat_state", {}).get("car_connected", False)
        if key == "heartbeat_active":
            # None when a heartbeat has never been received — an honest
            # "unknown", not a healthy-looking False/0s (see build notes §3.3).
            seconds = data.get("heartbeat_stats", {}).get("seconds_since_last_heartbeat")
            if seconds is None:
                return None
            return seconds < 60
        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        if self.entity_description.key != "heartbeat_active":
            return None
        stats = (self.coordinator.data or {}).get("heartbeat_stats", {})
        return {
            "total_heartbeats": stats.get("total_heartbeats", 0),
            "seconds_since_last_heartbeat": stats.get("seconds_since_last_heartbeat"),
        }
