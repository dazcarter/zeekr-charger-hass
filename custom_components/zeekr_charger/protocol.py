"""Pure protocol layer for Zeekr/Raedian BLE EVSE chargers.

Frame building/parsing, identity encryption, chunk reassembly, and response
parsers. No Home Assistant or Bleak imports — independently unit-testable.

Everything here was reverse-engineered against real hardware (model "Nora",
EC0000XX, firmware V1.0/V1.1.0). Where parsing looks redundant (e.g. the four
0xA9 fallback branches) that reflects genuine observed variance across
firmware/response paths in the field — do not "simplify" it away.

Frame formats
=============
Request  (client -> charger):
    [0xFE SOF][opcode 1B][header 5B][checksum 1B][token 8B][payload N]
Response (charger -> client):
    [0xAA SOF][opcode 1B][header 5B][checksum 1B][token 8B][payload N][tail 0-1B]

Header: [status, 0x00, len_lo, len_hi, 0x00] — bytes 2-3 are the little-endian
payload length; header[0] is the status byte on responses.
Checksum: XOR of frame[:7] ^ token ^ payload, masked to one byte.
Tail: present only when exactly one byte follows the payload AND it is not
0xAA (which would be the start of the next frame). 0xE0/0xA9 carry the active
current limit there — never discard it.
"""

from __future__ import annotations

import json
import logging
import struct
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Optional

_LOGGER = logging.getLogger(__name__)

# ============== BLE GATT characteristics ==============
GATT_CHAR_WRITE = "0000abf1-0000-1000-8000-00805f9b34fb"  # write-without-response
GATT_CHAR_NOTIFY = "0000ff02-0000-1000-8000-00805f9b34fb"
GATT_CHAR_NOTIFY2 = "0000abf2-0000-1000-8000-00805f9b34fb"

SOF_REQUEST = 0xFE
SOF_RESPONSE = 0xAA

# Writes are chunked with a small inter-chunk delay; notification chunks are
# similarly ~20 bytes, so logical frames need reassembly.
WRITE_CHUNK_SIZE = 20
WRITE_CHUNK_DELAY = 0.01
MAX_FRAME_BUFFER = 1024


# ============== Opcodes ==============
class OPC(IntEnum):
    """Known opcodes. See protocol.md (appendices A and B) for details."""

    IDENTITY_AUTH = 0xFE
    HEARTBEAT = 0xB5
    SYNC_TIME = 0xB0
    SET_CHARGE_MODE = 0xB3
    AUTH_CHARGE = 0xB4
    STOP_CHARGE = 0xB6
    SET_CURRENT_LIMIT = 0xC0
    QUERY_POWER_STATUS = 0xE0
    QUERY_HOME_CURRENT = 0xA9
    QUERY_CHARGE_MODE = 0xE6
    QUERY_BASIC_INFO = 0xC1
    QUERY_EMPLOY_INFO = 0xC2
    QUERY_PROTECTION_INFO = 0xC4
    QUERY_WIFI_CONFIG = 0xC7
    QUERY_BLE_INFO = 0xC8
    QUERY_WIFI_STATUS = 0xE4
    QUERY_NETWORK_STATUS = 0xD3
    # Documented but never validated against hardware — not wired up:
    CONFIGURE_WIFI = 0xD2
    CHANGE_NETWORK_MODE = 0xD4
    ACTIVE_ADD_CARD = 0xD0
    CONFIGURE_METER = 0xF1
    QUERY_METER = 0xF2


RESPONSE_STATUS_TEXT = {
    0x00: "SUCCESS",
    0x11: "PARSE_ERROR",
    0x12: "NO_PERMISSION",  # stale token, or charger busy/not idle
    0x13: "REJECTED",
    0x14: "CMD_NOT_EXIST",
    0x15: "CMD_NOT_SUPPORTED",
    0x16: "TOKEN_TIMEOUT",
    0x50: "DEVICE_ERROR",
    0x51: "CMD_EXECUTE_FAILURE",
}

CHARGE_MODE_NAMES = {
    0x00: "Plug & Charge (Auto)",
    0x01: "Authorized (Requires Start)",
    0x02: "Scheduled",
    0x03: "Keyboard/Button",
    0x04: "Cost Effective",
    0x05: "Solar Only",
    0x10: "ECO Mode",
    0x12: "Solar Plus",
    0x26: "Selector/Config Mode",
    0x8E: "Unknown/Error State",
    0xC0: "Configuration Mode",
}

# 0xD3 result_detail codes (also appear via 0xE4)
NETWORK_ERROR_CODES = {
    0x200: "Success",
    0x400: "Client Problem",
    0x500: "Server Problem",
    0x1001: "WiFi Module Not Found",
    0x1002: "WiFi Module Not Supported, WiFi Startup Failed",
    0x1003: "WiFi Hardware Switch Not On, Startup Failed",
    0x1005: "SSID Invalid, Startup Failed",
    0x1006: "Password Invalid, Startup Failed",
    0x1401: "DHCP Startup Failed, WiFi Startup Failed",
    0x1502: "IP Setup Failed",
    0x5023: "Unknown WiFi Error, Startup Failed",
}


# ============== Charger state codes ==============
@dataclass(frozen=True)
class StateMapping:
    """Meaning of a charger state code (heartbeat byte 0 and elsewhere)."""

    car_connected: bool
    charging: bool
    state: str


CHARGER_STATE_MAP = {
    0x00: StateMapping(False, False, "available"),
    0x01: StateMapping(True, False, "preparing"),
    0x02: StateMapping(True, False, "suspended_ev"),
    0x03: StateMapping(True, False, "reserved"),
    0x04: StateMapping(True, False, "suspended_evse"),
    0x05: StateMapping(True, False, "charging_break_off"),
    0x06: StateMapping(True, True, "charging"),
    0x07: StateMapping(True, False, "pausing"),
    0x08: StateMapping(True, False, "finishing"),
    0x0E: StateMapping(False, False, "unavailable"),
    0x0F: StateMapping(False, False, "faulted"),
    0xC0: StateMapping(False, False, "available"),  # alternative encoding
}


# ============== Data models ==============
@dataclass
class ParsedFrame:
    """A fully reassembled and structurally parsed frame."""

    sof: int
    opcode: int
    header: bytes
    status: Optional[int]  # header[0] on responses, None on requests
    checksum: Optional[int]
    token: bytes
    payload: bytes
    tail: bytes = b""


@dataclass
class B5Telemetry:
    """Full 0xB5 telemetry while a session is active.

    Two layouts exist, told apart by payload length (see parse_b5_telemetry).
    Both are little-endian, and bytes 2-9 and 12-13 sit in the same place:

    21-byte "zeekr21" (verified against the vendor app on a single-phase 7 kW
    Neo over a 281 s charge: 14.5 A, 233.6 V, 0.261 kWh):
    - byte 0: state code (0x06 = charging)
    - byte 1: port
    - bytes 2-5: session sequence number (constant within a session)
    - bytes 6-7: session energy, 0.01 kWh, counting up from 0 each session
    - bytes 8-9: line voltage, 0.01 V
    - bytes 10-11: reserved (0)
    - bytes 12-13: current, 0.01 A
    - bytes 14-17: session runtime, seconds
    - bytes 18-19: constants (15, 1)
    - byte 20: internal temperature, degC (inferred: constant 30, no other
      plausible byte)

    33-byte "v33" (firmware V1.1.0): see _parse_b5_telemetry_v33.

    Reading the 21-byte frame the older way (energy at 14-15, runtime at
    15-16, "phase flags" at 6-7) reported the runtime as energy and the
    energy as phase flags.
    """

    state: int
    port: int
    sequence_number: int
    energy_centikwh: int
    voltage_centi_v: int
    current_centi_a: int
    runtime_seconds: int
    phase_flags: int = 0
    port_hint: int = 0
    checksum: int = 0
    temperature_c: Optional[int] = None
    layout: str = "zeekr21"

    @property
    def voltage_v(self) -> float:
        return self.voltage_centi_v / 100.0

    @property
    def current_a(self) -> float:
        return self.current_centi_a / 100.0

    @property
    def session_energy_kwh(self) -> float:
        return self.energy_centikwh / 100.0


@dataclass
class HeartbeatState:
    """Parsed heartbeat (0xB5) state."""

    car_connected: bool = False
    charging: bool = False
    state: str = "unknown"
    port: int = 0
    timestamp: float = 0.0
    telemetry: Optional[B5Telemetry] = None
    temperature_c: Optional[int] = None


@dataclass
class PowerStatus:
    """Power status from a 0xE0 response."""

    limit_amps: int = 0
    max_current_capacity: int = 0
    configured_limit_amps: int = 0


@dataclass
class CurrentConfig:
    """Home/grid current configuration from a 0xA9 response."""

    max_current_capacity_a: Optional[int] = None
    present_current_limit_a: Optional[int] = None
    grid_capacity_a: Optional[int] = None
    home_cfg_hex: Optional[str] = None
    grid_phase: Optional[int] = None
    earthing_sys: Optional[int] = None
    solar_pv: Optional[int] = None
    solar_phase: Optional[int] = None


# ============== Frame building ==============
def build_header(payload_len: int) -> bytes:
    """Build the 5-byte request header for the given payload length."""
    payload_len = max(payload_len, 0)
    return bytes([0x00, 0x00, payload_len & 0xFF, (payload_len >> 8) & 0xFF, 0x00])


def _compute_checksum(prefix: bytes, token: bytes, payload: bytes) -> int:
    checksum = 0
    for b in prefix:
        checksum ^= b
    for b in token:
        checksum ^= b
    for b in payload:
        checksum ^= b
    return checksum & 0xFF


def pack_frame_request(op: int, token: bytes, payload: bytes = b"", header: Optional[bytes] = None) -> bytes:
    """Pack a request frame."""
    if len(token) != 8:
        raise ValueError("token must be 8 bytes")
    h = header if header is not None else build_header(len(payload))
    if len(h) != 5:
        raise ValueError("header must be 5 bytes")

    frame = bytearray([SOF_REQUEST, op & 0xFF])
    frame.extend(h)
    frame.append(0x00)  # checksum placeholder
    frame.extend(token)
    frame.extend(payload)
    frame[7] = _compute_checksum(frame[:7], token, payload)
    return bytes(frame)


# ============== Frame parsing ==============
def parse_frame(data: bytes) -> ParsedFrame:
    """Parse a complete 0xAA response or 0xFE request frame.

    Raises ValueError if the data is not (yet) a complete frame — the
    reassembler relies on that to know when to keep buffering.
    """
    if not data or len(data) < 2:
        raise ValueError("frame too short")

    sof = data[0]
    op = data[1]

    if sof == SOF_RESPONSE:
        # AA | OPC | H0..H4 | CHK | T0..T7 | PAYLOAD | [TAIL]
        if len(data) < 1 + 1 + 5 + 1 + 8:
            raise ValueError("AA frame too short")
        header = data[2:7]
        payload_len = header[2] | (header[3] << 8)
        payload_start = 16
        payload_end = payload_start + payload_len
        if payload_end > len(data):
            raise ValueError("AA frame payload incomplete")
        payload = data[payload_start:payload_end]

        # A single trailing byte is a tail only if it isn't the start of the
        # next frame. 0xE0/0xA9 carry the active current limit here.
        tail = b""
        if payload_end < len(data) and data[payload_end] != SOF_RESPONSE:
            tail = data[payload_end : payload_end + 1]

        return ParsedFrame(
            sof=sof,
            opcode=op,
            header=header,
            status=header[0],
            checksum=data[7],
            token=data[8:16],
            payload=payload,
            tail=tail,
        )

    if sof == SOF_REQUEST:
        if len(data) < 10:
            raise ValueError("FE frame too short")
        return ParsedFrame(
            sof=sof,
            opcode=op,
            header=data[2:8],
            status=None,
            checksum=None,
            token=data[-8:],
            payload=data[8:-8] if len(data) > 16 else b"",
        )

    raise ValueError(f"unknown SOF 0x{sof:02X}")


class FrameReassembler:
    """Reassembles ~20-byte notification chunks into complete frames.

    Buffers are kept per GATT characteristic (keyed by sender handle) — the
    two notify characteristics are independent streams.
    """

    def __init__(self) -> None:
        self._buffers: dict[Any, bytearray] = {}

    def feed(self, sender: Any, chunk: bytes) -> list[bytes]:
        """Feed one notification chunk; return any complete frames."""
        buf = self._buffers.setdefault(sender, bytearray())
        frames: list[bytes] = []

        # A new frame starting while the buffer holds data means the old
        # buffer is either a complete frame we haven't flushed, or leftover
        # garbage from a frame whose fragment was lost in transit. Validate
        # before forwarding — never assume "new frame started" implies "old
        # buffer was complete", or corrupt bytes get parsed downstream with
        # zero indication anything went wrong.
        if chunk.startswith(bytes([SOF_RESPONSE])) and buf:
            try:
                parse_frame(bytes(buf))
                frames.append(bytes(buf))
            except ValueError:
                _LOGGER.warning(
                    "Discarding incomplete frame buffer (%d bytes) — a fragment "
                    "was likely lost in transit: %s",
                    len(buf),
                    bytes(buf).hex().upper(),
                )
            buf.clear()

        buf.extend(chunk)

        try:
            parse_frame(bytes(buf))
        except ValueError:
            # Not complete yet — keep accumulating, but never indefinitely.
            if len(buf) > MAX_FRAME_BUFFER:
                _LOGGER.warning("Frame buffer overflow (%d bytes), clearing", len(buf))
                buf.clear()
        else:
            frames.append(bytes(buf))
            buf.clear()

        return frames


# ============== Identity / authentication ==============
def _pkcs5_pad(data: bytes, block_size: int = 8) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def build_identity_frame(serial: str, station_id: int) -> bytes:
    """Build the 0xFE identity/auth frame.

    DES/ECB with fixed key "ucserver", arrived at empirically against real
    captured traffic — do not re-derive. station_id=88888 is what the known
    working client uses; its real meaning is unclear.
    """
    from Crypto.Cipher import DES  # lazy: keeps this module importable without pycryptodome

    block = bytearray(0x30)
    serial_clean = serial.replace("-", "").upper()
    if len(serial_clean) < 8:
        raise ValueError("Serial must be at least 8 characters")
    block[0:8] = serial_clean.encode("ascii")[:8]
    block[0x14] = 0x02  # auth level
    block[0x15] = 0x01  # client type
    station_ascii = str(station_id).encode("ascii")
    if len(station_ascii) > 0x0F:
        raise ValueError("Station ID too long")
    block[0x16 : 0x16 + len(station_ascii)] = station_ascii

    ciphertext = DES.new(b"ucserver", DES.MODE_ECB).encrypt(_pkcs5_pad(bytes(block), 8))

    body = bytearray(0x82)
    body[0:2] = b"\x80\x00"
    body[2 : 2 + len(ciphertext)] = ciphertext

    return pack_frame_request(
        OPC.IDENTITY_AUTH, b"\x00" * 8, bytes(body), header=build_header(len(body))
    )


def extract_token_from_response(pf: ParsedFrame) -> Optional[bytes]:
    """Extract the 8-byte session token from a 0xFE auth response."""
    if pf.payload:
        extra = pf.tail or b""
        if len(extra) == 1 and len(pf.payload) >= 7:
            return pf.payload[-7:] + extra
        if len(pf.payload) >= 8:
            return pf.payload[-8:]
    return pf.token


# ============== Command builders ==============
def cmd_sync_time(token: bytes, tz_minutes: int = 0, epoch: Optional[int] = None) -> bytes:
    """0xB0: payload is <IH little-endian epoch + tz-offset-minutes."""
    if epoch is None:
        epoch = int(time.time())
    payload = struct.pack("<IH", epoch & 0xFFFFFFFF, tz_minutes & 0xFFFF)
    return pack_frame_request(OPC.SYNC_TIME, token, payload)


def cmd_heartbeat(token: bytes, payload: bytes = b"") -> bytes:
    """0xB5 keep-alive. Payload variants are an open experiment — see client."""
    return pack_frame_request(OPC.HEARTBEAT, token, payload)


def cmd_set_charge_mode(token: bytes, mode: int) -> bytes:
    """0xB3: 0x00 = plug & charge (auto), 0x01 = authorized (requires start)."""
    return pack_frame_request(OPC.SET_CHARGE_MODE, token, bytes([mode & 0xFF]))


# Gun/connector index. The vendor app hardcodes "00" (BluetootchConstant$Gun
# .NORMAL) in every command body. An 0x01 also works on the single-gun test
# unit, but 00 is what the reference implementation sends.
GUN_NORMAL = 0x00


def cmd_auth_charge(token: bytes, gun: int = GUN_NORMAL) -> bytes:
    """0xB4 start/authorize charging.

    Body is TWO bytes, not one — the vendor app builds `startCharger` as
    cmd "B4" with body "0000", while every other command uses a single gun
    byte. Sending one byte gets an ack but does not start a session, which is
    almost certainly why Start appeared inert.
    """
    return pack_frame_request(OPC.AUTH_CHARGE, token, bytes([gun & 0xFF, 0x00]))


def cmd_stop_charge(token: bytes, gun: int = GUN_NORMAL) -> bytes:
    """0xB6 stop charging. Vendor body: "00" (single gun byte)."""
    return pack_frame_request(OPC.STOP_CHARGE, token, bytes([gun & 0xFF]))


def cmd_query_status(token: bytes, gun: int = GUN_NORMAL) -> bytes:
    """0xB5 GET_CHARGER_STATE. Vendor body: "00".

    Despite the name "heartbeat" in the original notes, this is a plain
    request/response query (vendor: `queryStatus(token)`); the charger never
    volunteers it.
    """
    return pack_frame_request(OPC.HEARTBEAT, token, bytes([gun & 0xFF]))


def cmd_set_current_limit(token: bytes, port: Optional[int], amps: int) -> bytes:
    """0xC0 SET_POWER. Vendor body: "00" + power (gun byte then amps)."""
    gun = GUN_NORMAL if port is None else port
    return pack_frame_request(OPC.SET_CURRENT_LIMIT, token, bytes([gun & 0xFF, amps & 0xFF]))


def cmd_query(opcode: int, token: bytes, payload: bytes = b"") -> bytes:
    """Generic query frame builder."""
    return pack_frame_request(opcode, token, payload)


# ============== Response parsers ==============
def _parse_b5_telemetry_v33(payload: bytes) -> Optional[B5Telemetry]:
    """Parse the 33-byte 0xB5 telemetry payload (firmware V1.1.0).

    Layout derived empirically from live frames and confirmed against wall
    time and measured power — the 21-byte layout in the original notes does
    NOT apply to this firmware (its energy/runtime offsets are always zero
    here, and bytes 6-7 are energy, not phase flags):

      byte  0     state (0x06 = charging)
      byte  1     port hint
      bytes 2-5   session start, unix epoch (LE u32)
      bytes 6-7   session energy, 0.01 kWh (LE)
      bytes 8-9   line voltage, 0.01 V (LE)
      bytes 12-13 current, 0.01 A (LE)
      bytes 26-27 session runtime, seconds (LE)
      byte  30    configured current limit, A
      byte  31    port
      byte  32    internal temperature, degC

    Verified 2026-07-20: bytes 26-27 advanced at exactly 1.000/second over a
    210s window, and epoch + runtime matched the capture time to the second;
    bytes 6-7 gained 0.22 kWh against 0.226 kWh expected at a measured 3.87 kW.
    """
    try:
        return B5Telemetry(
            state=payload[0],
            port=payload[31] or payload[1],
            sequence_number=int.from_bytes(payload[2:6], "little"),
            energy_centikwh=int.from_bytes(payload[6:8], "little"),
            voltage_centi_v=int.from_bytes(payload[8:10], "little"),
            current_centi_a=int.from_bytes(payload[12:14], "little"),
            runtime_seconds=int.from_bytes(payload[26:28], "little"),
            phase_flags=0,
            port_hint=payload[1],
            checksum=payload[30],  # configured current limit mirror
            temperature_c=payload[32],
            layout="v33",
        )
    except Exception:  # noqa: BLE001
        _LOGGER.warning("Failed to parse 33-byte B5 telemetry: %s", payload.hex().upper())
        return None


def _parse_b5_telemetry_zeekr21(payload: bytes) -> Optional[B5Telemetry]:
    """Parse the 21-byte 0xB5 telemetry payload (layout in B5Telemetry)."""
    try:
        return B5Telemetry(
            state=payload[0],
            port=payload[1],
            sequence_number=int.from_bytes(payload[2:6], "little"),
            energy_centikwh=int.from_bytes(payload[6:8], "little"),
            voltage_centi_v=int.from_bytes(payload[8:10], "little"),
            current_centi_a=int.from_bytes(payload[12:14], "little"),
            runtime_seconds=int.from_bytes(payload[14:18], "little"),
            phase_flags=0,
            port_hint=payload[1],
            temperature_c=payload[20],
            layout="zeekr21",
        )
    except Exception:  # noqa: BLE001 - malformed telemetry must never crash RX path
        _LOGGER.warning("Failed to parse 21-byte B5 telemetry: %s", payload.hex().upper())
        return None


def parse_b5_telemetry(payload: bytes) -> Optional[B5Telemetry]:
    """Parse a 0xB5 telemetry payload: 33 bytes or more is v33, else 21-byte."""
    if len(payload) >= 33:
        return _parse_b5_telemetry_v33(payload)
    if len(payload) < 21:
        return None
    return _parse_b5_telemetry_zeekr21(payload)


def parse_heartbeat_state(payload: bytes) -> HeartbeatState:
    """Parse any of the known 0xB5 payload shapes, distinguished by length.

    Shorter variants still update car-connected/charging from the state byte
    even without full telemetry.
    """
    info = HeartbeatState(timestamp=time.time())

    def apply_state(code: int) -> None:
        mapping = CHARGER_STATE_MAP.get(code)
        if mapping:
            info.car_connected = mapping.car_connected
            info.charging = mapping.charging
            info.state = mapping.state
        else:
            info.state = f"unknown_{code:02X}"

    if len(payload) == 2:
        # [state, port] short state update. Codes >= 0x80 are non-standard
        # format indicators the vendor app ignores — do the same.
        info.port = payload[1]
        if payload[0] < 0x80:
            apply_state(payload[0])
    elif payload == b"\x01\x01\x01":
        pass  # simple keep-alive/ack, carries no state
    elif len(payload) == 8:
        # Short reply to a 0xB5 GET_CHARGER_STATE query when no session is
        # running. The original notes describe this as a "limit snapshot" with
        # the state at byte 2, which yields nonsense (0xE9). Every other 0xB5
        # variant puts the state first, and reading byte 0 gives 0x01
        # (preparing) for a captured frame taken with the cable plugged in and
        # charging stopped — which matches reality, so byte 0 it is.
        #   observed idle: 01 01 E9 00 19 09 00 00
        info.port = payload[1]
        apply_state(payload[0])
    elif len(payload) >= 21:
        telemetry = parse_b5_telemetry(payload)
        if telemetry:
            info.port = telemetry.port
            info.telemetry = telemetry
            info.temperature_c = telemetry.temperature_c
            apply_state(telemetry.state)
        else:
            apply_state(payload[0])
            info.port = payload[1]
    elif len(payload) == 1:
        info.state = f"single_byte_{payload[0]:02X}"
    else:
        info.state = f"unknown_len_{len(payload)}"
        if payload:
            apply_state(payload[0])
        if len(payload) >= 2:
            info.port = payload[1]

    return info


def parse_power_status(payload: bytes, tail: bytes = b"") -> PowerStatus:
    """Parse a 0xE0 power status response (payload + tail combined)."""
    full = payload + (tail or b"")
    if full and full[0] == 0x26:  # optional selector byte
        full = full[1:]
    if not full:
        return PowerStatus()

    max_current_a = 0
    set_current_a = 0
    if len(full) >= 3:
        max_current_a = full[1]
        set_current_a = full[-1] if len(full) > 3 else full[2]
    elif len(full) == 2:
        set_current_a = full[1]

    return PowerStatus(
        limit_amps=set_current_a,
        max_current_capacity=max_current_a,
        configured_limit_amps=set_current_a,
    )


def parse_current_config(payload: bytes, tail: bytes = b"") -> CurrentConfig:
    """Parse a 0xA9 home/grid current config response.

    The response format is genuinely inconsistent across firmware/response
    paths — all four observed variants are handled:
    1. 0xC0-prefixed: [0xC0, grid_capacity, ...]
    2. direct: [grid_capacity, grid_phase, earthing, solar_pv, solar_phase, ...]
    3. 0x8E-prefixed: [0x8E, grid_capacity, grid_phase, earthing, solar_pv, solar_phase]
    4. old fallback: grid_capacity as 16-bit BE over the first two bytes
    The tail byte, when present, is the currently configured limit in amps.
    """
    configured_limit = tail[0] if tail else None
    hex_repr = payload.hex()

    if len(payload) >= 2 and payload[0] == 0xC0:
        return CurrentConfig(
            max_current_capacity_a=payload[1],
            present_current_limit_a=configured_limit,
            grid_capacity_a=payload[1],
            home_cfg_hex=hex_repr,
        )

    if len(payload) >= 2 and payload[0] == 0x8E:
        if len(payload) >= 6:
            return CurrentConfig(
                max_current_capacity_a=payload[1],
                present_current_limit_a=configured_limit,
                grid_capacity_a=payload[1],
                home_cfg_hex=hex_repr,
                grid_phase=payload[2],
                earthing_sys=payload[3],
                solar_pv=payload[4],
                solar_phase=payload[5],
            )
        return CurrentConfig(
            max_current_capacity_a=payload[1],
            present_current_limit_a=configured_limit,
            grid_capacity_a=payload[1],
            home_cfg_hex=hex_repr,
        )

    if len(payload) >= 6:
        # Direct format, but keep the old 16-bit-BE fallback semantics when the
        # first byte alone would be implausibly small and the pair plausible.
        grid_capacity = payload[0]
        if grid_capacity == 0 and payload[1] != 0:
            grid_capacity = (payload[0] << 8) | payload[1]  # old fallback
        return CurrentConfig(
            max_current_capacity_a=grid_capacity,
            present_current_limit_a=configured_limit,
            grid_capacity_a=grid_capacity,
            home_cfg_hex=hex_repr,
            grid_phase=payload[1],
            earthing_sys=payload[2],
            solar_pv=payload[3],
            solar_phase=payload[4],
        )

    _LOGGER.warning("0xA9 payload too short to parse: %s", hex_repr)
    return CurrentConfig(present_current_limit_a=configured_limit, home_cfg_hex=hex_repr)


def extract_json_from_payload(payload: bytes) -> Optional[str]:
    """Extract a balanced-brace JSON substring from a mixed binary payload."""
    s = payload.decode("utf-8", errors="ignore")
    start = s.find("{")
    if start == -1 or "}" not in s:
        return None

    depth = 0
    for i in range(start, len(s)):
        if s[i] == "{":
            depth += 1
        elif s[i] == "}":
            depth -= 1
            if depth == 0:
                return s[start : i + 1].strip()

    # Unbalanced (truncated) — fall back to slicing to the last brace so the
    # caller can at least log/inspect partials.
    last = s.rfind("}")
    return s[start : last + 1].strip() if last > start else None


# Field-name normalization for the JSON config queries (C1/C2/C7)
_JSON_FIELD_MAPPINGS: dict[int, dict[str, str]] = {
    OPC.QUERY_BASIC_INFO: {
        "rated_power": "rated_power_w",
        "rate_charging_current": "rated_charging_current_a",
        "number_of_socket_outlets": "num_socket_outlets",
    },
    OPC.QUERY_EMPLOY_INFO: {
        "rate_charging_current": "rated_charging_current_a",
        "number_of_socket_outlets": "num_socket_outlets",
    },
}


def parse_config_json(opcode: int, payload: bytes, tail: bytes = b"") -> Optional[dict[str, Any]]:
    """Parse a JSON-bearing config response (0xC1/C2/C4/C7/C8).

    JSON values often arrive as [type_code, value] two-element arrays —
    normalize by extracting the value. Returns {"raw_hex": ...} when no JSON
    is found so callers still get visibility into what arrived.
    """
    full = payload + (tail or b"")
    json_str = extract_json_from_payload(full)
    if not json_str:
        _LOGGER.warning("No JSON found in 0x%02X response: %s", opcode, full.hex())
        return {"raw_hex": full.hex()}
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as err:
        _LOGGER.warning("Failed to parse 0x%02X response JSON: %s", opcode, err)
        return {"raw_hex": full.hex()}

    def _clean(value: Any) -> Any:
        # Values arrive as [type_code, value] pairs. The charger also uses the
        # literal string "NULL" for unset fields (wifi_mac_address,
        # connector_type) — surface those as absent rather than as text.
        if isinstance(value, list) and len(value) == 2:
            value = value[1]
        if isinstance(value, str) and value.strip().upper() in ("NULL", ""):
            return None
        return value

    normalized = {key: _clean(val) for key, val in data.items()}
    mappings = _JSON_FIELD_MAPPINGS.get(opcode, {})
    return {mappings.get(key, key): value for key, value in normalized.items()}


def parse_wifi_status(payload: bytes, tail: bytes = b"") -> dict[str, Any]:
    """Parse a 0xE4 WiFi status response.

    SSID and password arrive as "ssid\\npassword" framed with 0x02/0x03
    control bytes. The data-format byte has been observed as 0x01, 0x02, and
    0x68 (newer firmware) — all mean connected/valid.
    """
    full = payload + (tail or b"")
    result: dict[str, Any] = {}
    if len(full) < 2:
        return result

    result["wifi_flag_hex"] = full[:2].hex()

    # Two layouts occur in the field. Some firmware sends
    # [response_type][format][ssid...] (e.g. C0 02 ...), this unit sends the
    # format/STX byte first: 02 <ssid> 0a <password> 03. Detect which,
    # rather than blindly reading full[1] — that read the 'w' of the SSID
    # (0x77) and reported it as an unknown data format.
    valid_formats = (0x01, 0x02, 0x68)
    if full[0] in valid_formats:
        data_format = full[0]
        body_start = 1
        result["wifi_response_type"] = None
    else:
        data_format = full[1]
        body_start = 2
        result["wifi_response_type"] = f"0x{full[0]:02X}"
    result["wifi_data_format"] = data_format

    if data_format in valid_formats:
        result["wifi_status"] = "Connected"
        result["wifi_status_code"] = 0
    else:
        result["wifi_status"] = f"Unknown data format: 0x{data_format:02X}"
        result["wifi_status_code"] = data_format
        _LOGGER.warning(
            "0xE4 unknown data-format byte 0x%02X (response: %s)", data_format, full.hex()
        )

    body = full[body_start:].decode("utf-8", errors="ignore")
    if "\n" in body:
        ssid, pwd = body.split("\n", 1)
        # Strip framing control bytes (0x02 STX / 0x03 ETX and friends)
        ssid = ssid.strip("".join(chr(c) for c in range(0x20)))
        pwd = pwd.strip("".join(chr(c) for c in range(0x20)))
        if ssid:
            result["ssid"] = ssid
        if pwd:
            result["password"] = pwd
    elif body:
        result["ssid_or_value"] = body

    return result


def parse_network_status(payload: bytes, tail: bytes = b"") -> dict[str, Any]:
    """Parse a 0xD3 network status response (error-code map in NETWORK_ERROR_CODES)."""
    full = payload + (tail or b"")
    result: dict[str, Any] = {}
    if len(full) >= 2:
        result["network_result"] = int.from_bytes(full[0:2], "little")
    if len(full) >= 4:
        # Raw index — the WiFi/LAN/4G mapping is unconfirmed, so no labels.
        result["networking_mode"] = int.from_bytes(full[2:4], "little")
    if len(full) >= 8:
        detail = int.from_bytes(full[4:8], "little")
        result["result_detail"] = detail
        result["result_detail_desc"] = NETWORK_ERROR_CODES.get(
            detail, f"Unknown Error (0x{detail:04X})"
        )
    return result


def accumulate_lifetime_energy(
    total: float, last_session: Optional[float], current_session: Optional[float]
) -> tuple[float, Optional[float]]:
    """Fold the charger's per-session energy counter into a monotonic lifetime total.

    The 0xB5 session-energy field resets to ~0 at the start of every charge and
    holds its final value between charges. Returns (new_total, new_last).
    A drop means a new session started, so the current reading is fresh energy;
    the first reading after start/restore just seeds `last` without adding, so
    a restored total is never double-counted.
    """
    if current_session is None:
        return total, last_session
    if last_session is None:
        return total, current_session  # seed only
    if current_session >= last_session:
        return total + (current_session - last_session), current_session
    return total + current_session, current_session  # reset -> new session


def parse_charge_mode(payload: bytes) -> Optional[int]:
    """Parse a 0xE6 charge-mode response (optional leading 0x26 selector)."""
    if not payload:
        return None
    if payload[0] == 0x26 and len(payload) >= 2:
        return payload[1]
    return payload[0]


def charge_mode_name(mode: Optional[int]) -> Optional[str]:
    if mode is None:
        return None
    return CHARGE_MODE_NAMES.get(mode, f"Unknown Mode (0x{mode:02X})")


def parse_tlv_response(payload: bytes) -> dict[str, Any]:
    """Parse a TLV response ([Type 1B][Length 1B][Value...]; length 0xFF means
    the next two LE bytes carry the real length). Falls back from JSON."""
    result: dict[str, Any] = {}
    if len(payload) == 1:
        return {"status_byte": payload[0]}

    if payload.startswith(b"{") or b'"' in payload:
        json_str = extract_json_from_payload(payload)
        if json_str:
            try:
                result.update(json.loads(json_str))
                return result
            except json.JSONDecodeError:
                pass

    tag_names = {
        0x01: "serial_number",
        0x02: "model",
        0x03: "manufacturer",
        0x04: "firmware_version",
        0x05: "hardware_version",
        0x06: "production_date",
        0x07: "rated_charging_current_a",
        0x08: "rated_power_w",
        0x09: "c_board_software_version",
        0x0A: "device_type",
        0x0B: "mac_address",
        0x0C: "ip_address",
    }

    i = 0
    while i + 2 <= len(payload):
        tag = payload[i]
        length = payload[i + 1]
        i += 2
        if length == 0xFF:
            if i + 2 > len(payload):
                break
            length = int.from_bytes(payload[i : i + 2], "little")
            i += 2
        if i + length > len(payload):
            break
        value = payload[i : i + length]
        i += length

        if value and all(32 <= b <= 126 for b in value):
            result[tag_names.get(tag, f"field_{tag:02X}")] = value.decode("ascii")
        elif tag == 0x88 and len(value) <= 4:
            result["max_current_capacity_a"] = int.from_bytes(value, "little")
        elif tag == 0xDD and len(value) <= 4:
            result["present_current_limit_a"] = int.from_bytes(value, "little")
        else:
            result[f"field_{tag:02X}_hex"] = value.hex()

    return result
