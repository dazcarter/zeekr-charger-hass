"""Shared entity base for all Zeekr charger platforms."""

from __future__ import annotations

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity import EntityDescription
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import ZeekrChargerCoordinator


class ZeekrChargerEntity(CoordinatorEntity[ZeekrChargerCoordinator]):
    """Common device_info/unique_id wiring for every Zeekr charger entity."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: ZeekrChargerCoordinator,
        description: EntityDescription,
    ) -> None:
        super().__init__(coordinator)
        self.entity_description = description
        serial = coordinator.client.serial
        self._attr_unique_id = f"{serial}_{description.key}"
        basic_info = (coordinator.data or {}).get("basic_info", {})
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, serial)},
            name=f"Zeekr Charger {serial}",
            manufacturer="Zeekr",
            model=basic_info.get("model_number") or "Wallbox Charger",
            serial_number=basic_info.get("charge_point_number") or serial,
            sw_version=basic_info.get("software_version"),
        )

    @property
    def available(self) -> bool:
        # Entities stay available while the client auto-reconnects; last-known
        # data continues to be served (see coordinator docstring).
        return True
