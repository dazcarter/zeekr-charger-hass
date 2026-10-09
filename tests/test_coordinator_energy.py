"""Coordinator reports the charger's session energy as-is.

The charger's energy counter starts at 0 each session, so a figure taken when
Home Assistant first sees a charging frame must not be subtracted from it
(that undercounts whenever HA connects mid-session).

Home Assistant and the BLE client are stubbed so this runs anywhere:
    python tests/test_coordinator_energy.py
"""

from __future__ import annotations

import asyncio
import importlib.util
import os
import sys
import types
import unittest

_PKG_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "custom_components", "zeekr_charger")
)
_PKG = "zc_coord"


def _load_coordinator():
    def stub(name: str, **attrs) -> types.ModuleType:
        module = types.ModuleType(name)
        module.__dict__.update(attrs)
        sys.modules[name] = module
        return module

    class _Generic:
        def __class_getitem__(cls, item):
            return cls

    class DataUpdateCoordinator(_Generic):
        def __init__(self, hass, logger, name=None, update_interval=None):
            self.data = None

    stub("homeassistant")
    stub("homeassistant.core", HomeAssistant=object)
    stub("homeassistant.helpers")
    stub(
        "homeassistant.helpers.update_coordinator",
        DataUpdateCoordinator=DataUpdateCoordinator,
    )

    pkg = types.ModuleType(_PKG)
    pkg.__path__ = [_PKG_DIR]
    sys.modules[_PKG] = pkg
    stub(f"{_PKG}.ble_client", ZeekrBleClient=object)

    for name in ("const", "protocol", "coordinator"):
        spec = importlib.util.spec_from_file_location(
            f"{_PKG}.{name}", os.path.join(_PKG_DIR, f"{name}.py")
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[f"{_PKG}.{name}"] = module
        spec.loader.exec_module(module)
    return sys.modules[f"{_PKG}.coordinator"], sys.modules[f"{_PKG}.protocol"]


coordinator, protocol = _load_coordinator()

# Real 21-byte frame: 0.13 kWh into a 142 s session.
MID_SESSION = bytes.fromhex("06009d0ca7590d007c5b0000ad058e0000000f011e")


class FakeClient:
    is_connected = True

    def __init__(self, telemetry):
        self._telemetry = telemetry
        self.live = True

    async def request_telemetry(self):
        return True

    async def query_home_current_config(self):
        return None

    async def query_power_status(self):
        return None

    async def query_charge_mode(self):
        return None

    def get_heartbeat_state(self):
        return protocol.HeartbeatState()

    def get_heartbeat_stats(self):
        return {}

    def get_connection_status(self):
        return {}

    def get_last_telemetry(self):
        return self._telemetry

    @property
    def telemetry_is_live(self):
        return self.live


def _poll(client):
    coord = coordinator.ZeekrChargerCoordinator(None, client)
    coord._static_data_fetched = True
    coord._last_connection_state = True  # no reconnect, so no static refetch
    return asyncio.run(coord._poll())


class TestSessionEnergy(unittest.TestCase):
    def test_mid_session_energy_is_not_offset(self):
        telemetry = protocol.parse_b5_telemetry(MID_SESSION)
        data = _poll(FakeClient(telemetry))["telemetry"]
        self.assertAlmostEqual(data["session_energy_kwh"], 0.13)
        self.assertAlmostEqual(data["session_energy_kwh_raw"], 0.13)
        self.assertEqual(data["session_runtime_seconds"], 142)

    def test_live_values_cleared_once_session_ends(self):
        client = FakeClient(protocol.parse_b5_telemetry(MID_SESSION))
        client.live = False
        data = _poll(client)["telemetry"]
        self.assertIsNone(data["voltage_v"])
        self.assertIsNone(data["current_a"])
        self.assertAlmostEqual(data["session_energy_kwh"], 0.13)  # total kept


if __name__ == "__main__":
    unittest.main(verbosity=2)
