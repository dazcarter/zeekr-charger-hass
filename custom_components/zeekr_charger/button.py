"""Button platform for the Zeekr charger integration."""

from __future__ import annotations

import logging

from homeassistant.components.button import ButtonEntity, ButtonEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import ZeekrChargerCoordinator
from .entity import ZeekrChargerEntity

_LOGGER = logging.getLogger(__name__)

BUTTONS: tuple[ButtonEntityDescription, ...] = (
    ButtonEntityDescription(
        key="start_charging",
        name="Start Charging",
        icon="mdi:play",
    ),
    ButtonEntityDescription(
        key="stop_charging",
        name="Stop Charging",
        icon="mdi:stop",
    ),
    ButtonEntityDescription(
        key="force_reconnect",
        name="Force Reconnect",
        icon="mdi:bluetooth-connect",
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    ButtonEntityDescription(
        key="sync_time",
        name="Sync Time",
        icon="mdi:clock-check",
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Zeekr charger buttons."""
    coordinator: ZeekrChargerCoordinator = hass.data[DOMAIN][entry.entry_id].coordinator
    async_add_entities(ZeekrButton(coordinator, description) for description in BUTTONS)


class ZeekrButton(ZeekrChargerEntity, ButtonEntity):
    """A Zeekr charger action button."""

    async def async_press(self) -> None:
        key = self.entity_description.key
        client = self.coordinator.client
        if key == "start_charging":
            if not await client.authorize_charge():
                _LOGGER.warning("Start charging command got no acknowledgement")
        elif key == "stop_charging":
            if not await client.stop_charge():
                _LOGGER.warning("Stop charging command got no acknowledgement")
        elif key == "force_reconnect":
            await self.coordinator.force_reconnect()
        elif key == "sync_time":
            if not await client.sync_time():
                _LOGGER.warning("Time sync got no acknowledgement")
        await self.coordinator.async_request_refresh()
