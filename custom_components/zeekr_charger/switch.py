"""Switch platform for the Zeekr charger integration."""

from __future__ import annotations

from typing import Any

from homeassistant.components.switch import SwitchEntity, SwitchEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.restore_state import RestoreEntity

from .const import DOMAIN
from .entity import ZeekrChargerEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Zeekr charger switches."""
    runtime = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(
        [
            ZeekrPlugAndChargeSwitch(runtime.coordinator),
            ZeekrSolarChargingSwitch(runtime.coordinator, runtime.solar_controller),
        ]
    )


class ZeekrPlugAndChargeSwitch(ZeekrChargerEntity, SwitchEntity):
    """Toggle between plug & charge (0x00) and authorized mode (0x01) via 0xB3."""

    def __init__(self, coordinator) -> None:
        super().__init__(
            coordinator,
            SwitchEntityDescription(
                key="plug_and_charge",
                name="Plug & Charge",
                icon="mdi:ev-plug-type2",
            ),
        )

    @property
    def is_on(self) -> bool | None:
        mode = (self.coordinator.data or {}).get("charge_mode")
        if mode is None:
            return None
        return mode == 0x00

    async def async_turn_on(self, **kwargs: Any) -> None:
        if await self.coordinator.client.set_charge_mode(0x00):
            await self.coordinator.async_request_refresh()

    async def async_turn_off(self, **kwargs: Any) -> None:
        if await self.coordinator.client.set_charge_mode(0x01):
            await self.coordinator.async_request_refresh()


class ZeekrSolarChargingSwitch(ZeekrChargerEntity, SwitchEntity, RestoreEntity):
    """Master switch for the solar-surplus controller. Survives HA restarts."""

    def __init__(self, coordinator, solar_controller) -> None:
        super().__init__(
            coordinator,
            SwitchEntityDescription(
                key="solar_charging",
                name="Solar Surplus Charging",
                icon="mdi:solar-power",
            ),
        )
        self._solar_controller = solar_controller

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        last_state = await self.async_get_last_state()
        if last_state is not None:
            self._solar_controller.settings.enabled = last_state.state == "on"

    @property
    def is_on(self) -> bool:
        return self._solar_controller.settings.enabled

    async def async_turn_on(self, **kwargs: Any) -> None:
        self._solar_controller.settings.enabled = True
        self.async_write_ha_state()

    async def async_turn_off(self, **kwargs: Any) -> None:
        self._solar_controller.settings.enabled = False
        self.async_write_ha_state()
