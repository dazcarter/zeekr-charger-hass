"""Config flow for the Zeekr charger integration."""

from __future__ import annotations

from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.helpers import selector

from .ble_client import is_valid_mac_address
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
    CONFIG_FLOW_VERSION,
    DEFAULT_HEARTBEAT_STALE_THRESHOLD,
    DEFAULT_RECONNECT_INITIAL_DELAY,
    DEFAULT_RECONNECT_MAX_ATTEMPTS,
    DEFAULT_RECONNECT_MAX_DELAY,
    DEFAULT_RESPONSE_TIMEOUT,
    DOMAIN,
)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_SERIAL): str,
        vol.Optional(CONF_DEVICE_ADDRESS): str,
    }
)


class ZeekrChargerConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle the initial setup of a Zeekr charger."""

    VERSION = CONFIG_FLOW_VERSION

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            serial = user_input[CONF_SERIAL].strip().upper()
            device_address = (user_input.get(CONF_DEVICE_ADDRESS) or "").strip()

            if len(serial) < 8:
                errors[CONF_SERIAL] = "serial_too_short"
            elif device_address and not is_valid_mac_address(device_address):
                errors[CONF_DEVICE_ADDRESS] = "invalid_mac"
            else:
                await self.async_set_unique_id(serial)
                self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title=serial,
                    data={
                        CONF_SERIAL: serial,
                        CONF_DEVICE_ADDRESS: device_address or None,
                    },
                )

        return self.async_show_form(
            step_id="user", data_schema=STEP_USER_DATA_SCHEMA, errors=errors
        )

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> ZeekrChargerOptionsFlow:
        return ZeekrChargerOptionsFlow()


class ZeekrChargerOptionsFlow(config_entries.OptionsFlow):
    """Options: BLE MAC, solar entity pickers, timeouts, reconnection tuning."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            device_address = (user_input.get(CONF_DEVICE_ADDRESS) or "").strip()
            if device_address and not is_valid_mac_address(device_address):
                errors[CONF_DEVICE_ADDRESS] = "invalid_mac"
            else:
                return self.async_create_entry(title="", data=user_input)

        options = self.config_entry.options

        schema = vol.Schema(
            {
                vol.Optional(
                    CONF_DEVICE_ADDRESS,
                    description={
                        "suggested_value": options.get(CONF_DEVICE_ADDRESS)
                        or self.config_entry.data.get(CONF_DEVICE_ADDRESS)
                    },
                ): str,
                vol.Optional(
                    CONF_SOLAR_GRID_POWER_ENTITY,
                    description={
                        "suggested_value": options.get(CONF_SOLAR_GRID_POWER_ENTITY)
                    },
                ): selector.EntitySelector(
                    selector.EntitySelectorConfig(domain="sensor")
                ),
                vol.Optional(
                    CONF_GRID_POWER_INVERTED,
                    default=options.get(CONF_GRID_POWER_INVERTED, False),
                ): selector.BooleanSelector(),
                vol.Optional(
                    CONF_SOLAR_BATTERY_SOC_ENTITY,
                    description={
                        "suggested_value": options.get(CONF_SOLAR_BATTERY_SOC_ENTITY)
                    },
                ): selector.EntitySelector(
                    selector.EntitySelectorConfig(domain="sensor")
                ),
                vol.Optional(
                    CONF_RESPONSE_TIMEOUT,
                    default=options.get(CONF_RESPONSE_TIMEOUT, DEFAULT_RESPONSE_TIMEOUT),
                ): selector.NumberSelector(
                    selector.NumberSelectorConfig(min=5, max=60, step=1, unit_of_measurement="s")
                ),
                vol.Optional(
                    CONF_RECONNECT_MAX_ATTEMPTS,
                    default=options.get(
                        CONF_RECONNECT_MAX_ATTEMPTS, DEFAULT_RECONNECT_MAX_ATTEMPTS
                    ),
                ): selector.NumberSelector(
                    selector.NumberSelectorConfig(min=1, max=50, step=1)
                ),
                vol.Optional(
                    CONF_RECONNECT_INITIAL_DELAY,
                    default=options.get(
                        CONF_RECONNECT_INITIAL_DELAY, DEFAULT_RECONNECT_INITIAL_DELAY
                    ),
                ): selector.NumberSelector(
                    selector.NumberSelectorConfig(min=1, max=60, step=1, unit_of_measurement="s")
                ),
                vol.Optional(
                    CONF_RECONNECT_MAX_DELAY,
                    default=options.get(
                        CONF_RECONNECT_MAX_DELAY, DEFAULT_RECONNECT_MAX_DELAY
                    ),
                ): selector.NumberSelector(
                    selector.NumberSelectorConfig(
                        min=30, max=3600, step=10, unit_of_measurement="s"
                    )
                ),
                vol.Optional(
                    CONF_HEARTBEAT_STALE_THRESHOLD,
                    default=options.get(
                        CONF_HEARTBEAT_STALE_THRESHOLD, DEFAULT_HEARTBEAT_STALE_THRESHOLD
                    ),
                ): selector.NumberSelector(
                    selector.NumberSelectorConfig(
                        min=30, max=600, step=10, unit_of_measurement="s"
                    )
                ),
            }
        )

        return self.async_show_form(step_id="init", data_schema=schema, errors=errors)
