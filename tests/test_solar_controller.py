"""Unit tests for the solar-surplus control loop.

The controller decides when to change a real EV charger's current and when to
stop/start a charging session, so its arithmetic and debounce logic deserve
coverage independent of live hardware.

Home Assistant is stubbed so this runs anywhere:
    python tests/test_solar_controller.py
"""

from __future__ import annotations

import asyncio
import importlib.util
import os
import sys
import types
import unittest

_PKG_DIR = os.path.join(
    os.path.dirname(__file__), "..", "custom_components", "zeekr_charger"
)


def _load_module_under_stubbed_ha():
    """Load solar_controller without importing Home Assistant or the package __init__."""
    ha = types.ModuleType("homeassistant")
    core = types.ModuleType("homeassistant.core")

    class HomeAssistant:  # minimal stand-in
        pass

    core.HomeAssistant = HomeAssistant
    ha.core = core
    sys.modules.setdefault("homeassistant", ha)
    sys.modules.setdefault("homeassistant.core", core)

    pkg = types.ModuleType("zc")
    pkg.__path__ = [os.path.abspath(_PKG_DIR)]
    sys.modules["zc"] = pkg

    for name in ("const", "solar_controller"):
        spec = importlib.util.spec_from_file_location(
            f"zc.{name}", os.path.join(_PKG_DIR, f"{name}.py")
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[f"zc.{name}"] = module
        spec.loader.exec_module(module)

    return sys.modules["zc.solar_controller"], sys.modules["zc.const"]


solar_controller, const = _load_module_under_stubbed_ha()


class FakeState:
    def __init__(self, state):
        self.state = state


class FakeStates:
    def __init__(self, values):
        self._values = values

    def get(self, entity_id):
        value = self._values.get(entity_id)
        return FakeState(value) if value is not None else None


class FakeHass:
    def __init__(self, values=None):
        self.states = FakeStates(values or {})


class FakeClient:
    def __init__(self, connected=True):
        self.is_connected = connected
        self.current_limits = []
        self.stop_calls = 0
        self.start_calls = 0
        self.stop_result = True
        self.start_result = True

    async def set_current_limit(self, port, amps):
        # port None means "client picks the active port" (see active_port)
        self.current_limits.append((port, amps))
        return True

    async def stop_charge(self):
        self.stop_calls += 1
        return self.stop_result

    async def authorize_charge(self):
        self.start_calls += 1
        return self.start_result


class FakeCoordinator:
    def __init__(self, client, data):
        self.client = client
        self.data = data
        self.refreshes = 0

    async def async_request_refresh(self):
        self.refreshes += 1


def build(grid_w=None, soc=None, car_connected=True, limit=None, **settings):
    values = {}
    if grid_w is not None:
        values["sensor.grid"] = str(grid_w)
    if soc is not None:
        values["sensor.soc"] = str(soc)
    hass = FakeHass(values)
    client = FakeClient()
    data = {
        "heartbeat_state": {"car_connected": car_connected},
        "power_status": {"configured_limit_amps": limit} if limit is not None else {},
    }
    coordinator = FakeCoordinator(client, data)
    ctrl = solar_controller.ZeekrSolarController(hass, coordinator)
    ctrl.settings.enabled = True
    ctrl.settings.grid_power_entity_id = "sensor.grid" if grid_w is not None else None
    if soc is not None:
        ctrl.settings.battery_soc_entity_id = "sensor.soc"
    for key, value in settings.items():
        setattr(ctrl.settings, key, value)
    return ctrl, client, coordinator


def run(coro):
    return asyncio.run(coro)


class TestSurplusMath(unittest.TestCase):
    def test_export_yields_surplus(self):
        # -4600W on the grid = exporting 4600W = 20A at 230V
        ctrl, _client, _c = build(grid_w=-4600, limit=6)
        run(ctrl._tick())
        self.assertEqual(ctrl.status.available_surplus_w, 4600)
        self.assertEqual(ctrl.status.target_current_a, 20)

    def test_import_yields_negative_surplus(self):
        ctrl, _client, _c = build(grid_w=822, limit=16)
        run(ctrl._tick())
        self.assertEqual(ctrl.status.available_surplus_w, -822)
        self.assertLess(ctrl.status.target_current_a, 0)

    def test_inverted_sign_convention(self):
        ctrl, _client, _c = build(grid_w=4600, limit=6, grid_power_inverted=True)
        run(ctrl._tick())
        self.assertEqual(ctrl.status.available_surplus_w, 4600)
        self.assertEqual(ctrl.status.target_current_a, 20)

    def test_unavailable_grid_sensor_clears_status(self):
        ctrl, client, _c = build(grid_w=None, limit=16)
        ctrl.settings.grid_power_entity_id = "sensor.missing"
        run(ctrl._tick())
        self.assertIsNone(ctrl.status.available_surplus_w)
        self.assertIsNone(ctrl.status.target_current_a)
        self.assertEqual(client.current_limits, [])


class TestBatteryPriority(unittest.TestCase):
    def test_surplus_withheld_below_threshold(self):
        ctrl, client, _c = build(
            grid_w=-4600, soc=48, limit=6, battery_priority_soc=80
        )
        run(ctrl._tick())
        self.assertEqual(ctrl.status.available_surplus_w, 0.0)
        self.assertTrue(ctrl.status.withheld_for_battery_priority)
        self.assertEqual(client.current_limits, [])

    def test_surplus_released_at_threshold(self):
        ctrl, _client, _c = build(
            grid_w=-4600, soc=85, limit=6, battery_priority_soc=80
        )
        run(ctrl._tick())
        self.assertEqual(ctrl.status.available_surplus_w, 4600)
        self.assertFalse(ctrl.status.withheld_for_battery_priority)


class TestStepLimiting(unittest.TestCase):
    def test_ramps_up_by_step_only(self):
        # target 20A from 6A must move one 2A step, not jump
        ctrl, client, _c = build(grid_w=-4600, limit=6)
        run(ctrl._tick())
        self.assertEqual(client.current_limits, [(None, 8)])

    def test_ramps_down_by_step_only(self):
        ctrl, client, _c = build(grid_w=-1610, limit=16)  # target 7A
        run(ctrl._tick())
        self.assertEqual(client.current_limits, [(None, 14)])

    def test_clamped_to_max(self):
        ctrl, client, _c = build(grid_w=-20000, limit=31, max_current_a=32)
        run(ctrl._tick())
        self.assertEqual(client.current_limits, [(None, 32)])

    def test_no_write_when_already_at_target(self):
        ctrl, client, _c = build(grid_w=-3680, limit=16)  # target exactly 16A
        run(ctrl._tick())
        self.assertEqual(client.current_limits, [])


class TestDebounce(unittest.TestCase):
    def test_insufficient_surplus_does_not_stop_immediately(self):
        ctrl, client, _c = build(grid_w=500, limit=16)
        run(ctrl._tick())
        self.assertEqual(client.stop_calls, 0, "must not stop on first low reading")

    def test_stops_after_sustained_insufficient_surplus(self):
        ctrl, client, _c = build(grid_w=500, limit=16)
        run(ctrl._tick())
        # Backdate the debounce start past the pause window
        ctrl._insufficient_since -= const.SOLAR_PAUSE_DEBOUNCE_SECONDS + 1
        run(ctrl._tick())
        self.assertEqual(client.stop_calls, 1)
        self.assertTrue(ctrl.status.paused_for_insufficient_solar)

    def test_does_not_resume_immediately_after_pause(self):
        ctrl, client, _c = build(grid_w=500, limit=16)
        run(ctrl._tick())
        ctrl._insufficient_since -= const.SOLAR_PAUSE_DEBOUNCE_SECONDS + 1
        run(ctrl._tick())
        # Sun returns
        ctrl.hass.states._values["sensor.grid"] = "-4600"
        run(ctrl._tick())
        self.assertEqual(client.start_calls, 0, "must debounce before resuming")

    def test_resumes_after_sustained_surplus(self):
        ctrl, client, _c = build(grid_w=500, limit=16)
        run(ctrl._tick())
        ctrl._insufficient_since -= const.SOLAR_PAUSE_DEBOUNCE_SECONDS + 1
        run(ctrl._tick())
        ctrl.hass.states._values["sensor.grid"] = "-4600"
        run(ctrl._tick())
        ctrl._sufficient_since -= const.SOLAR_RESUME_DEBOUNCE_SECONDS + 1
        run(ctrl._tick())
        self.assertEqual(client.start_calls, 1)
        self.assertFalse(ctrl.status.paused_for_insufficient_solar)


class TestActuationGating(unittest.TestCase):
    def test_status_published_but_no_actuation_without_car(self):
        """Surplus/target are dashboard values and must populate with no car,
        but nothing may be commanded."""
        ctrl, client, _c = build(grid_w=-4600, limit=6, car_connected=False)
        run(ctrl._tick())
        self.assertEqual(ctrl.status.available_surplus_w, 4600)
        self.assertEqual(ctrl.status.target_current_a, 20)
        self.assertEqual(client.current_limits, [])
        self.assertEqual(client.stop_calls, 0)

    def test_status_published_but_no_actuation_when_disabled(self):
        ctrl, client, _c = build(grid_w=-4600, limit=6)
        ctrl.settings.enabled = False
        run(ctrl._tick())
        self.assertEqual(ctrl.status.target_current_a, 20)
        self.assertEqual(client.current_limits, [])

    def test_nothing_happens_while_disconnected(self):
        ctrl, client, _c = build(grid_w=-4600, limit=6)
        client.is_connected = False
        run(ctrl._tick())
        self.assertEqual(client.current_limits, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
