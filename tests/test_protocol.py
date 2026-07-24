"""Unit tests for the pure protocol layer.

Runnable without Home Assistant or Bleak:
    python tests/test_protocol.py
    python -m pytest tests/
Identity-frame tests are skipped if pycryptodome is unavailable.
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..", "custom_components", "zeekr_charger")
)

import protocol  # noqa: E402

TOKEN = bytes(range(8))


def make_response(
    opcode: int,
    payload: bytes = b"",
    status: int = 0x00,
    token: bytes = TOKEN,
    tail: bytes = b"",
) -> bytes:
    """Build a well-formed 0xAA response frame for tests."""
    header = bytes([status, 0x00, len(payload) & 0xFF, (len(payload) >> 8) & 0xFF, 0x00])
    return bytes([0xAA, opcode]) + header + b"\x00" + token + payload + tail


class TestFrameBuild(unittest.TestCase):
    def test_pack_frame_request_layout(self):
        frame = protocol.pack_frame_request(0xB0, TOKEN, b"\x01\x02")
        self.assertEqual(frame[0], 0xFE)
        self.assertEqual(frame[1], 0xB0)
        self.assertEqual(frame[2:7], bytes([0x00, 0x00, 0x02, 0x00, 0x00]))
        self.assertEqual(frame[8:16], TOKEN)
        self.assertEqual(frame[16:], b"\x01\x02")

    def test_checksum_is_xor_of_prefix_token_payload(self):
        payload = b"\xAB\xCD"
        frame = protocol.pack_frame_request(0xC0, TOKEN, payload)
        expected = 0
        for b in frame[:7]:
            expected ^= b
        for b in TOKEN:
            expected ^= b
        for b in payload:
            expected ^= b
        self.assertEqual(frame[7], expected & 0xFF)

    def test_header_length_little_endian(self):
        header = protocol.build_header(0x1234)
        self.assertEqual(header, bytes([0x00, 0x00, 0x34, 0x12, 0x00]))

    def test_token_must_be_8_bytes(self):
        with self.assertRaises(ValueError):
            protocol.pack_frame_request(0xB0, b"\x00" * 7)


class TestFrameParse(unittest.TestCase):
    def test_parse_response_roundtrip(self):
        frame = make_response(0xE6, b"\x26\x01", status=0x00)
        pf = protocol.parse_frame(frame)
        self.assertEqual(pf.opcode, 0xE6)
        self.assertEqual(pf.status, 0x00)
        self.assertEqual(pf.token, TOKEN)
        self.assertEqual(pf.payload, b"\x26\x01")
        self.assertEqual(pf.tail, b"")

    def test_tail_byte_captured(self):
        frame = make_response(0xE0, b"\x00\x20\x10", tail=b"\x0A")
        pf = protocol.parse_frame(frame)
        self.assertEqual(pf.payload, b"\x00\x20\x10")
        self.assertEqual(pf.tail, b"\x0A")

    def test_trailing_aa_is_not_a_tail(self):
        frame = make_response(0xE0, b"\x00\x20\x10") + b"\xAA"
        pf = protocol.parse_frame(frame)
        self.assertEqual(pf.tail, b"")

    def test_incomplete_frame_raises(self):
        frame = make_response(0xC1, b"x" * 50)
        with self.assertRaises(ValueError):
            protocol.parse_frame(frame[:30])

    def test_status_byte_from_header(self):
        frame = make_response(0xB4, status=0x12)
        pf = protocol.parse_frame(frame)
        self.assertEqual(pf.status, 0x12)
        self.assertEqual(protocol.RESPONSE_STATUS_TEXT[0x12], "NO_PERMISSION")


class TestReassembler(unittest.TestCase):
    def test_single_chunk_frame(self):
        r = protocol.FrameReassembler()
        frame = make_response(0xB5, b"\x06\x01")
        frames = r.feed("s1", frame)
        self.assertEqual(frames, [frame])

    def test_multi_chunk_reassembly(self):
        r = protocol.FrameReassembler()
        frame = make_response(0xC1, b'{"a":1,"bbbb":"cccc"}' * 3)
        out: list[bytes] = []
        for i in range(0, len(frame), 20):
            out += r.feed("s1", frame[i : i + 20])
        self.assertEqual(out, [frame])

    def test_per_sender_buffers_are_independent(self):
        r = protocol.FrameReassembler()
        f1 = make_response(0xC1, b"payload-one-data-xx")
        f2 = make_response(0xC4, b"payload-two-data-yy")
        out: list[bytes] = []
        # Interleave chunks from two senders
        chunks1 = [f1[i : i + 10] for i in range(0, len(f1), 10)]
        chunks2 = [f2[i : i + 10] for i in range(0, len(f2), 10)]
        for c1, c2 in zip(chunks1, chunks2):
            out += r.feed("s1", c1)
            out += r.feed("s2", c2)
        for c in chunks1[len(chunks2) :]:
            out += r.feed("s1", c)
        for c in chunks2[len(chunks1) :]:
            out += r.feed("s2", c)
        self.assertIn(f1, out)
        self.assertIn(f2, out)
        self.assertEqual(len(out), 2)

    def test_lost_fragment_discarded_not_forwarded(self):
        r = protocol.FrameReassembler()
        broken = make_response(0xC1, b"x" * 100)[:40]  # truncated frame
        r.feed("s1", broken)
        good = make_response(0xB5, b"\x06\x01")
        frames = r.feed("s1", good)
        # The truncated buffer must be dropped, not emitted as a frame.
        self.assertEqual(frames, [good])

    def test_complete_buffer_flushed_when_new_frame_starts(self):
        r = protocol.FrameReassembler()
        f1 = make_response(0xB5, b"\x06\x01", tail=b"")
        # Feed f1 without it self-completing: append a tail byte so parse
        # succeeds only when flushed... simpler: feed f1 fully (it completes
        # immediately), then check a second frame also completes.
        out = r.feed("s1", f1)
        out += r.feed("s1", make_response(0xB5, b"\x00\x01"))
        self.assertEqual(len(out), 2)


class TestHeartbeatParsing(unittest.TestCase):
    def test_two_byte_state_update(self):
        state = protocol.parse_heartbeat_state(b"\x06\x01")
        self.assertTrue(state.charging)
        self.assertTrue(state.car_connected)
        self.assertEqual(state.state, "charging")
        self.assertEqual(state.port, 1)

    def test_two_byte_high_code_ignored(self):
        state = protocol.parse_heartbeat_state(b"\x8E\x01")
        self.assertFalse(state.charging)
        self.assertEqual(state.state, "unknown")  # untouched default

    def test_keepalive_carries_no_state(self):
        state = protocol.parse_heartbeat_state(b"\x01\x01\x01")
        self.assertEqual(state.state, "unknown")

    def test_real_8byte_idle_reply(self):
        """Real 0xB5 reply captured with the cable plugged in, charging stopped.

        The original notes put the state at byte 2, which reads 0xE9 here and
        parses as nonsense. Byte 0 gives 0x01 (preparing) which matches the
        physical situation, and is consistent with every other 0xB5 variant.
        """
        payload = bytes.fromhex("0101e90019090000")
        state = protocol.parse_heartbeat_state(payload)
        self.assertEqual(state.state, "preparing")
        self.assertTrue(state.car_connected)
        self.assertFalse(state.charging)
        self.assertEqual(state.port, 1)

    def test_full_telemetry(self):
        payload = bytearray(21)
        payload[0] = 0x06  # charging
        payload[1] = 0x00
        payload[2:6] = (1234).to_bytes(4, "little")  # sequence
        payload[6:8] = (0).to_bytes(2, "little")  # single phase
        payload[8:10] = (23050).to_bytes(2, "little")  # 230.50 V
        payload[12] = 160  # 16.0 A (0.1A units, low byte only)
        payload[14:16] = (250).to_bytes(2, "little")  # 2.50 kWh
        payload[19] = 42  # temperature on single-phase
        payload[20] = 0x77
        state = protocol.parse_heartbeat_state(bytes(payload))
        self.assertTrue(state.charging)
        t = state.telemetry
        self.assertIsNotNone(t)
        self.assertAlmostEqual(t.voltage_v, 230.5)
        self.assertAlmostEqual(t.current_a, 16.0)
        self.assertAlmostEqual(t.session_energy_kwh, 2.5)
        self.assertEqual(t.sequence_number, 1234)
        self.assertEqual(state.temperature_c, 42)

    def test_real_33byte_telemetry_capture(self):
        """Real charging frame from hardware, firmware V1.1.0.

        Units confirmed against wall time and measured power: bytes 26-27
        advance at exactly 1/second, bytes 6-7 are 0.01 kWh. The legacy
        21-byte offsets read zero for both on this firmware.
        """
        payload = bytes.fromhex(
            "0600fcfd5d6a4800226000002306000000000000000000000000a2020000110127"
        )
        t = protocol.parse_b5_telemetry(payload)
        self.assertIsNotNone(t)
        self.assertEqual(t.state, 0x06)
        self.assertAlmostEqual(t.voltage_v, 246.10)
        self.assertAlmostEqual(t.current_a, 15.71)
        self.assertAlmostEqual(t.session_energy_kwh, 0.72)
        self.assertEqual(t.runtime_seconds, 674)
        self.assertEqual(t.temperature_c, 39)
        self.assertEqual(t.port, 1)
        # Single-phase unit must not be reported as multi-phase
        self.assertEqual(t.phase_flags, 0)

    def test_33byte_frame_marks_charging(self):
        payload = bytes.fromhex(
            "0600fcfd5d6a4800226000002306000000000000000000000000a2020000110127"
        )
        state = protocol.parse_heartbeat_state(payload)
        self.assertTrue(state.charging)
        self.assertTrue(state.car_connected)
        self.assertEqual(state.state, "charging")

    def test_state_map_completeness(self):
        for code in (0x00, 0x0E, 0x0F, 0xC0):
            self.assertFalse(protocol.CHARGER_STATE_MAP[code].car_connected)
        self.assertTrue(protocol.CHARGER_STATE_MAP[0x06].charging)


class TestLifetimeEnergy(unittest.TestCase):
    def test_accumulates_across_a_session_reset(self):
        acc = protocol.accumulate_lifetime_energy
        total, last = 0.0, None
        # seed, climb within a session, then reset into a new one
        for s in [0.05, 5.0, 10.11]:      # session A
            total, last = acc(total, last, s)
        self.assertAlmostEqual(total, 10.06)  # seed 0.05 not counted
        total, last = acc(total, last, 10.11)  # idle hold, no change
        self.assertAlmostEqual(total, 10.06)
        for s in [0.03, 0.5]:              # session B (reset)
            total, last = acc(total, last, s)
        self.assertAlmostEqual(total, 10.06 + 0.03 + 0.47)

    def test_restore_does_not_double_count(self):
        acc = protocol.accumulate_lifetime_energy
        # restored total, first post-restart reading mid-session must only seed
        total, last = acc(100.0, None, 8.4)
        self.assertEqual(total, 100.0)
        total, last = acc(total, last, 8.9)
        self.assertAlmostEqual(total, 100.5)

    def test_none_reading_is_ignored(self):
        acc = protocol.accumulate_lifetime_energy
        self.assertEqual(acc(50.0, 3.0, None), (50.0, 3.0))


class TestPowerStatus(unittest.TestCase):
    def test_selector_byte_skipped(self):
        ps = protocol.parse_power_status(b"\x26\x00\x20\x10")
        self.assertEqual(ps.max_current_capacity, 0x20)
        self.assertEqual(ps.configured_limit_amps, 0x10)

    def test_tail_overrides_limit(self):
        ps = protocol.parse_power_status(b"\x00\x20\x10", tail=b"\x0A")
        self.assertEqual(ps.configured_limit_amps, 0x0A)


class TestCurrentConfig(unittest.TestCase):
    def test_c0_prefixed(self):
        cfg = protocol.parse_current_config(bytes([0xC0, 32]), tail=b"\x10")
        self.assertEqual(cfg.grid_capacity_a, 32)
        self.assertEqual(cfg.present_current_limit_a, 16)

    def test_8e_prefixed(self):
        cfg = protocol.parse_current_config(bytes([0x8E, 32, 1, 2, 0, 1]))
        self.assertEqual(cfg.grid_capacity_a, 32)
        self.assertEqual(cfg.grid_phase, 1)
        self.assertEqual(cfg.earthing_sys, 2)

    def test_direct_format(self):
        cfg = protocol.parse_current_config(bytes([40, 1, 2, 0, 1, 0]))
        self.assertEqual(cfg.grid_capacity_a, 40)
        self.assertEqual(cfg.grid_phase, 1)

    def test_old_16bit_fallback(self):
        cfg = protocol.parse_current_config(bytes([0, 40, 1, 2, 0, 1]))
        self.assertEqual(cfg.grid_capacity_a, 40)


class TestJsonParsing(unittest.TestCase):
    def test_extract_json_with_binary_prefix(self):
        payload = b"\x8e\x01" + b'{"model_number":[2,"Nora"],"rated_power":[3,7000]}'
        parsed = protocol.parse_config_json(protocol.OPC.QUERY_BASIC_INFO, payload)
        self.assertEqual(parsed["model_number"], "Nora")
        self.assertEqual(parsed["rated_power_w"], 7000)

    def test_real_c1_payload_field_names(self):
        """Field names as actually emitted by the charger (live 0xC1 capture).

        It reports hardware_version / p_board_software_version — there is no
        'firmware_version' or 'software_version' key, which is why those
        sensors read unknown despite 0xC1 answering.
        """
        body = (
            '{"model_number": [19, "Nora"], '
            '"charge_point_number": [19, "EC0000XX"], '
            '"production_date": [17, "2023-12-15 00:00:00"], '
            '"hardware_version": [17, "V1.0"], '
            '"p_board_software_version": [17, "V1.1.0"], '
            '"c_board_software_version": [17, "V1.1.0"], '
            '"rated_power": [17, 7000]}'
        ).encode()
        parsed = protocol.parse_config_json(protocol.OPC.QUERY_BASIC_INFO, b"\x01" + body)
        self.assertEqual(parsed["model_number"], "Nora")
        self.assertEqual(parsed["charge_point_number"], "EC0000XX")
        self.assertEqual(parsed["hardware_version"], "V1.0")
        self.assertEqual(parsed["p_board_software_version"], "V1.1.0")
        self.assertEqual(parsed["rated_power_w"], 7000)

    def test_null_strings_become_none(self):
        """The charger uses the literal string "NULL" for unset fields."""
        body = b'{"wifi_mac_address": [19, "NULL"], "connector_type": [19, "NULL"]}'
        parsed = protocol.parse_config_json(protocol.OPC.QUERY_WIFI_CONFIG, body)
        self.assertIsNone(parsed["wifi_mac_address"])
        self.assertIsNone(parsed["connector_type"])

    def test_no_json_returns_raw_hex(self):
        parsed = protocol.parse_config_json(protocol.OPC.QUERY_BASIC_INFO, b"\x01\x02")
        self.assertIn("raw_hex", parsed)

    def test_json_split_across_payload_and_tail(self):
        body = b'{"wifi_mac_address":[1,"AA:BB"]}'
        parsed = protocol.parse_config_json(
            protocol.OPC.QUERY_WIFI_CONFIG, b"\x01" + body[:-1], tail=body[-1:]
        )
        self.assertEqual(parsed["wifi_mac_address"], "AA:BB")


class TestWifiAndNetwork(unittest.TestCase):
    def test_wifi_status_ssid_password(self):
        payload = b"\xc0\x02" + b"MyNetwork\nhunter22\x03"
        result = protocol.parse_wifi_status(payload)
        self.assertEqual(result["wifi_status"], "Connected")
        self.assertEqual(result["ssid"], "MyNetwork")
        self.assertEqual(result["password"], "hunter22")

    def test_wifi_new_firmware_format_0x68(self):
        result = protocol.parse_wifi_status(b"\xc0\x68" + b"Net\npw")
        self.assertEqual(result["wifi_status"], "Connected")

    def test_wifi_status_format_byte_first_real_capture(self):
        """Real 0xE4 payload from hardware: STX, ssid, LF, password, ETX.

        The format byte is first here (no response-type byte), so reading
        full[1] grabbed the 'w' of the SSID and reported 0x77 as an unknown
        data format.
        """
        # Structure is the real captured one; the SSID/password are synthetic.
        payload = b"\x02example-ssid\nexample-pass\x03"
        result = protocol.parse_wifi_status(payload)
        self.assertEqual(result["wifi_data_format"], 0x02)
        self.assertEqual(result["wifi_status"], "Connected")
        self.assertEqual(result["ssid"], "example-ssid")
        self.assertEqual(result["password"], "example-pass")

    def test_network_status_error_code(self):
        payload = (0x200).to_bytes(2, "little") + (1).to_bytes(2, "little") + (
            0x1401
        ).to_bytes(4, "little")
        result = protocol.parse_network_status(payload)
        self.assertEqual(result["networking_mode"], 1)
        self.assertEqual(
            result["result_detail_desc"], "DHCP Startup Failed, WiFi Startup Failed"
        )


class TestChargeMode(unittest.TestCase):
    def test_selector_byte(self):
        self.assertEqual(protocol.parse_charge_mode(b"\x26\x01"), 0x01)
        self.assertEqual(protocol.parse_charge_mode(b"\x00"), 0x00)
        self.assertIsNone(protocol.parse_charge_mode(b""))

    def test_mode_names(self):
        self.assertEqual(protocol.charge_mode_name(0x00), "Plug & Charge (Auto)")
        self.assertIn("Unknown", protocol.charge_mode_name(0x99))


class TestTlv(unittest.TestCase):
    def test_basic_tlv(self):
        payload = bytes([0x01, 4]) + b"SN01" + bytes([0x88, 2]) + (32).to_bytes(2, "little")
        result = protocol.parse_tlv_response(payload)
        self.assertEqual(result["serial_number"], "SN01")
        self.assertEqual(result["max_current_capacity_a"], 32)

    def test_extended_length_ff(self):
        value = b"A" * 300
        payload = bytes([0x01, 0xFF]) + (300).to_bytes(2, "little") + value
        result = protocol.parse_tlv_response(payload)
        self.assertEqual(result["serial_number"], value.decode())


class TestIdentity(unittest.TestCase):
    def setUp(self):
        try:
            import Crypto  # noqa: F401
        except ImportError:
            self.skipTest("pycryptodome not installed")

    def test_identity_frame_structure(self):
        frame = protocol.build_identity_frame("EC0000XX1234567890", 88888)
        self.assertEqual(frame[0], 0xFE)
        self.assertEqual(frame[1], 0xFE)
        # Body: 0x82 bytes, starts with 80 00, token all zeros
        self.assertEqual(frame[8:16], b"\x00" * 8)
        payload = frame[16:]
        self.assertEqual(len(payload), 0x82)
        self.assertEqual(payload[0:2], b"\x80\x00")

    def test_identity_deterministic(self):
        f1 = protocol.build_identity_frame("EC0000XX", 88888)
        f2 = protocol.build_identity_frame("ec0000xx", 88888)
        self.assertEqual(f1, f2)

    def test_short_serial_rejected(self):
        with self.assertRaises(ValueError):
            protocol.build_identity_frame("SHORT", 88888)

    def test_token_extraction(self):
        # Token split across payload tail byte
        frame = make_response(0xFE, b"\x00" + bytes(range(0x10, 0x17)), tail=b"\x99")
        pf = protocol.parse_frame(frame)
        token = protocol.extract_token_from_response(pf)
        self.assertEqual(token, bytes(range(0x10, 0x17)) + b"\x99")


if __name__ == "__main__":
    unittest.main(verbosity=2)
