"""BLE transport and session layer for Zeekr chargers.

Bleak-specific connection/notification handling, session token lifecycle,
request/response correlation, and the reconnection state machine. Protocol
knowledge (frame formats, parsers) lives in protocol.py.

Raw RX visibility is unconditional at DEBUG level — every notification chunk
and every reassembled frame. Enable with:

    logger:
      logs:
        custom_components.zeekr_charger: debug
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any, Optional

from bleak import BleakClient, BleakScanner
from bleak.backends.device import BLEDevice
from bleak_retry_connector import establish_connection
from homeassistant.components import bluetooth
from homeassistant.core import HomeAssistant

from . import protocol
from .const import (
    AUTH_RESPONSE_TIMEOUT,
    DEFAULT_HEARTBEAT_STALE_THRESHOLD,
    DEFAULT_RECONNECT_INITIAL_DELAY,
    DEFAULT_RECONNECT_MAX_ATTEMPTS,
    DEFAULT_RECONNECT_MAX_DELAY,
    DEFAULT_RESPONSE_TIMEOUT,
    HEARTBEAT_SEND_INTERVAL,
    LATE_RESPONSE_MAX_AGE,
    RESPONSE_NUDGE_INTERVAL,
    TELEMETRY_RESPONSE_TIMEOUT,
)
from .protocol import (
    GATT_CHAR_NOTIFY,
    GATT_CHAR_NOTIFY2,
    GATT_CHAR_WRITE,
    OPC,
    B5Telemetry,
    CurrentConfig,
    FrameReassembler,
    HeartbeatState,
    PowerStatus,
)

_LOGGER = logging.getLogger(__name__)

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$|^[0-9A-Fa-f]{12}$")

# Payload for the keep-alive/nudge write. This is only used to poke the
# charger into flushing a queued reply, so the body is irrelevant and an
# empty one is cheapest. (0xB5 is really GET_CHARGER_STATE, not a heartbeat —
# see TELEMETRY_PAYLOAD_VARIANTS and protocol.md Appendix B.)
HEARTBEAT_PAYLOAD_VARIANTS: tuple[bytes, ...] = (b"",)

# Payloads to try when requesting charger state (0xB5). The vendor app sends
# the gun byte "00" (queryStatus -> cmd B5, body "00"), so that is tried
# first; 0x01 is kept as a fallback because it is what was proven to work on
# the test unit before the app was available. Rotate until one answers, then
# lock. An empty body never answers.
TELEMETRY_PAYLOAD_VARIANTS: tuple[bytes, ...] = (b"\x00", b"\x01", b"\x01\x01\x01", b"")

# Consecutive timeouts before an opcode is treated as unsupported by this
# charger and skipped (see ZeekrBleClient._note_opcode_timeout).
UNSUPPORTED_TIMEOUT_THRESHOLD = 3

# How long a never-answered opcode stays retired before we try it once more.
# State changes (a car being plugged in) can make an opcode start answering.
UNSUPPORTED_RETRY_INTERVAL = 600.0


def is_valid_mac_address(address: str) -> bool:
    """Check whether the string looks like a BLE MAC address."""
    return bool(_MAC_RE.match(address))


class ZeekrBleClient:
    """BLE client for one Zeekr charger."""

    def __init__(
        self,
        hass: HomeAssistant,
        address: str,
        serial: str,
        station_id: int = 88888,
    ) -> None:
        self.hass = hass
        self.address = address
        self.serial = serial
        self.station_id = station_id

        self._client: Optional[BleakClient] = None
        self._token: Optional[bytes] = None
        self._connected = False
        self._connected_since: float = 0.0
        self._discovered_address: Optional[str] = None

        self._reassembler = FrameReassembler()
        self._pending_responses: dict[int, asyncio.Future] = {}
        self._response_timeout: float = DEFAULT_RESPONSE_TIMEOUT

        # This protocol has no request pipelining: the charger answers one
        # command at a time and gets confused by overlapping writes. Serialize
        # every exchange (coordinator polls, solar controller, button presses).
        self._request_lock = asyncio.Lock()
        self._request_in_flight_since: Optional[float] = None

        # Opcodes this charger never answers. Each dead query costs a full
        # response timeout every poll cycle, which is what starved the poll
        # loop and tripped the staleness watchdog. Stop asking after
        # UNSUPPORTED_TIMEOUT_THRESHOLD consecutive timeouts; a user-initiated
        # Force Reconnect clears the list to re-probe.
        self._opcode_timeout_counts: dict[int, int] = {}
        self._unsupported_opcodes: set[int] = set()
        self._unsupported_since: dict[int, float] = {}
        # Opcodes that have answered at least once this session. An opcode
        # that has ever replied is supported by definition, so later timeouts
        # are transient (this charger drops replies under load) and must never
        # retire it — retired opcodes are never sent, so they could otherwise
        # never prove themselves again. Observed live: 0xE0 answered twice,
        # timed out three times, and was wrongly retired for good.
        self._opcodes_ever_answered: set[int] = set()

        # Responses that arrived after their request gave up, keyed by opcode.
        # This charger regularly answers config queries slower than the
        # request timeout over a proxy; without this the data was discarded.
        self._late_responses: dict[int, tuple[float, bytes, bytes]] = {}

        # Heartbeat / telemetry state. last_heartbeat_time is None (never
        # numeric zero) until the first 0xB5 response ever arrives — 0.0 would
        # be indistinguishable from "received just now" downstream.
        self._last_heartbeat_time: Optional[float] = None
        self._heartbeat_count: int = 0
        self._last_heartbeat_state = HeartbeatState()
        self._last_telemetry: Optional[B5Telemetry] = None
        # Whether the most recent 0xB5 reply actually carried telemetry. False
        # once the charger goes idle, so stale live readings can be dropped.
        self._telemetry_live: bool = False
        self._last_power_status: Optional[PowerStatus] = None
        self._charging_session_start: Optional[float] = None

        # Heartbeat-payload experiment state
        self._heartbeat_variant_index = 0
        self._heartbeat_variant_locked = False
        self._telemetry_variant_index = 0
        self._telemetry_variant_locked = False
        self._heartbeat_task: Optional[asyncio.Task] = None

        # RX diagnostics: opcode -> count of received frames, always on.
        self._rx_opcode_counts: dict[int, int] = {}
        self._last_rx_time: Optional[float] = None

        # Reconnection state machine
        self._should_reconnect = True
        self._reconnect_task: Optional[asyncio.Task] = None
        self._connection_monitor_task: Optional[asyncio.Task] = None
        self._reconnect_attempts = 0
        self._max_reconnect_attempts = DEFAULT_RECONNECT_MAX_ATTEMPTS
        self._reconnect_delay = DEFAULT_RECONNECT_INITIAL_DELAY
        self._max_reconnect_delay = DEFAULT_RECONNECT_MAX_DELAY
        self._heartbeat_stale_threshold = DEFAULT_HEARTBEAT_STALE_THRESHOLD

    # ============== Tuning ==============

    def set_response_timeout(self, timeout: float) -> None:
        self._response_timeout = max(5.0, timeout)

    def set_reconnection_config(
        self,
        max_attempts: Optional[int] = None,
        initial_delay: Optional[float] = None,
        max_delay: Optional[float] = None,
        stale_threshold: Optional[float] = None,
    ) -> None:
        if max_attempts is not None:
            self._max_reconnect_attempts = max_attempts
        if initial_delay is not None:
            self._reconnect_delay = initial_delay
        if max_delay is not None:
            self._max_reconnect_delay = max_delay
        if stale_threshold is not None:
            self._heartbeat_stale_threshold = stale_threshold
        _LOGGER.info(
            "Reconnection config: max_attempts=%d initial_delay=%.1fs "
            "max_delay=%.1fs stale_threshold=%.1fs",
            self._max_reconnect_attempts,
            self._reconnect_delay,
            self._max_reconnect_delay,
            self._heartbeat_stale_threshold,
        )

    # ============== Discovery / connection ==============

    async def _discover_device(self) -> Optional[str]:
        """Resolve the charger's BLE address, by MAC or by advertised name."""
        if is_valid_mac_address(self.address):
            return self.address.upper()

        _LOGGER.info("Discovering Zeekr charger by name: %s", self.address)
        discovered = bluetooth.async_discovered_service_info(self.hass)
        for info in discovered:
            name = info.name or ""
            if (
                name in (self.address, self.serial)
                or self.address.lower() in name.lower()
                or self.serial.lower() in name.lower()
            ):
                _LOGGER.info("Found Zeekr charger: %s (%s)", name, info.address)
                return info.address

        _LOGGER.error(
            "Could not find Zeekr charger named '%s'. Discovered: %s. "
            "Provide the BLE MAC address directly in the options if discovery keeps failing.",
            self.address,
            [f"{d.name or 'Unknown'} ({d.address})" for d in discovered],
        )
        return None

    async def _resolve_ble_device(self, device_address: str) -> Optional[BLEDevice]:
        """Resolve a real BLEDevice for the address before connecting.

        bleak_retry_connector.establish_connection() reads device.details on
        Linux — handing it a bare address string raises AttributeError and
        kills the connection attempt. Prefer HA's own Bluetooth cache, fall
        back to an active scan.
        """
        try:
            candidate = bluetooth.async_ble_device_from_address(self.hass, device_address)
        except Exception as exc:  # noqa: BLE001
            _LOGGER.debug("HA BLE cache lookup failed for %s: %s", device_address, exc)
            candidate = None

        if isinstance(candidate, BLEDevice):
            return candidate
        device_attr = getattr(candidate, "device", None)
        if isinstance(device_attr, BLEDevice):
            return device_attr

        _LOGGER.debug("HA BLE cache miss for %s; active BleakScanner lookup", device_address)
        try:
            return await BleakScanner.find_device_by_address(device_address, timeout=10.0)
        except Exception as exc:  # noqa: BLE001
            _LOGGER.debug("Active scan lookup failed for %s: %s", device_address, exc)
            return None

    async def async_connect(self) -> bool:
        """Discover, connect, authenticate, and start the session tasks."""
        self._should_reconnect = True
        if not await self._establish_session():
            return False
        await self._start_connection_monitor()
        return True

    async def _establish_session(self) -> bool:
        """One full connect + auth cycle. Shared by connect and reconnect."""
        try:
            device_address = self._discovered_address or await self._discover_device()
            if not device_address:
                return False
            self._discovered_address = device_address

            ble_device = await self._resolve_ble_device(device_address)
            if ble_device is None:
                _LOGGER.error(
                    "Charger %s discovered but no usable BLEDevice object is "
                    "available yet (proxy may not have seen an advertisement recently)",
                    device_address,
                )
                return False

            _LOGGER.info("Connecting to charger BLE device %s", device_address)
            client = await establish_connection(
                BleakClient,
                ble_device,
                f"zeekr_charger_{self.serial}",
                max_attempts=3,
            )
            if not client or not client.is_connected:
                _LOGGER.error("Failed to establish BLE connection")
                return False
            self._client = client

            # MTU exchange is commonly unsupported through a BLE proxy — fine.
            try:
                if hasattr(client, "exchange_mtu"):
                    mtu = await client.exchange_mtu(517)
                    _LOGGER.debug("Negotiated MTU: %d", mtu)
            except Exception as exc:  # noqa: BLE001
                _LOGGER.debug("MTU exchange failed (normal via proxy): %s", exc)

            for char_uuid in (GATT_CHAR_NOTIFY, GATT_CHAR_NOTIFY2):
                try:
                    await client.start_notify(char_uuid, self._notification_handler)
                    _LOGGER.debug("Enabled notifications on %s", char_uuid)
                except Exception as exc:  # noqa: BLE001
                    _LOGGER.warning("Could not enable notify on %s: %s", char_uuid, exc)

            # Reset per-session freshness state BEFORE authenticating. The auth
            # exchange and initial setup legitimately receive frames (0xFE,
            # 0xB0, sometimes a 0xB5); clearing the timestamps afterwards threw
            # that evidence away and left last_rx_time None on a live link, so
            # the staleness watchdog measured from connect time and tore down
            # healthy sessions in a loop.
            self._connected_since = time.time()
            self._last_heartbeat_time = None
            self._last_rx_time = None

            if not await self._authenticate():
                await self._teardown_client()
                return False

            self._connected = True
            self._start_heartbeat_task()
            _LOGGER.info("Connected and authenticated to charger at %s", device_address)
            return True

        except Exception as exc:  # noqa: BLE001
            _LOGGER.error("Connection failed: %s (%s)", exc, type(exc).__name__, exc_info=True)
            return False

    async def _teardown_client(self) -> None:
        if self._client:
            try:
                if self._client.is_connected:
                    await self._client.disconnect()
            except Exception as exc:  # noqa: BLE001
                _LOGGER.debug("Error during BLE disconnect: %s", exc)
        self._client = None
        self._connected = False
        self._token = None
        self._stop_heartbeat_task()

    async def async_disconnect(self) -> None:
        """Disconnect and stop all session tasks permanently."""
        _LOGGER.info("Disconnecting from charger")
        self._should_reconnect = False
        for task in (self._reconnect_task, self._connection_monitor_task):
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        self._reconnect_task = None
        self._connection_monitor_task = None
        await self._teardown_client()
        self._reconnect_attempts = 0

    # ============== Connection monitor / reconnection ==============

    async def _start_connection_monitor(self) -> None:
        if self._connection_monitor_task and not self._connection_monitor_task.done():
            return
        self._connection_monitor_task = asyncio.create_task(self._connection_monitor_loop())

    async def _connection_monitor_loop(self) -> None:
        while self._should_reconnect:
            try:
                if not self.is_connected:
                    _LOGGER.info("Connection lost, triggering reconnection")
                    self._trigger_reconnection()
                elif self._request_in_flight_since is not None and (
                    time.time() - self._request_in_flight_since
                    <= self._response_timeout + 5
                ):
                    # A request is legitimately outstanding and hasn't hit its
                    # own timeout yet. That is expected quiet, not a dead link —
                    # tearing down here would kill sessions mid-poll.
                    pass
                else:
                    # The GATT link can stay nominally connected while the
                    # charger goes silent (writes succeed, zero notifications).
                    # Track staleness against the last *received* frame, with
                    # connect time as the baseline before anything arrives.
                    reference = self._last_rx_time or self._connected_since
                    if reference:
                        stale_for = time.time() - reference
                        if stale_for > self._heartbeat_stale_threshold:
                            # Silence is NOT proof of death. With no car
                            # plugged in the charger pushes nothing at all,
                            # and 0xB5 heartbeats often go unanswered even
                            # when charging. Tearing down on quiet alone put
                            # us in a reconnect loop, and repeated reconnects
                            # appear to degrade the charger's BLE stack until
                            # only auth/time-sync still answer. Probe first.
                            if await self._liveness_probe():
                                _LOGGER.debug(
                                    "Quiet for %.0fs but liveness probe answered — "
                                    "link healthy, charger just idle",
                                    stale_for,
                                )
                            else:
                                _LOGGER.warning(
                                    "Quiet for %.0fs and liveness probe got no "
                                    "response — treating session as dead, reconnecting",
                                    stale_for,
                                )
                                self._connected = False
                                self._trigger_reconnection()
                await asyncio.sleep(10)
            except asyncio.CancelledError:
                break
            except Exception as exc:  # noqa: BLE001
                _LOGGER.warning("Connection monitor error: %s", exc)
                await asyncio.sleep(5)

    async def _liveness_probe(self) -> bool:
        """Prove the link is alive using an opcode the charger reliably answers.

        0xB0 (time sync) has answered on every observed session, including
        ones where every data query timed out, which makes it the dependable
        choice. 0xB5 is useless here — it is the opcode that never answers.
        """
        _LOGGER.debug("Running liveness probe (0xB0)")
        return await self.sync_time()

    def _trigger_reconnection(self) -> None:
        if self._reconnect_task and not self._reconnect_task.done():
            return
        self._reconnect_task = asyncio.create_task(self._reconnection_loop())

    async def _reconnection_loop(self) -> None:
        while self._should_reconnect:
            try:
                self._reconnect_attempts += 1
                delay = min(
                    self._reconnect_delay * (2 ** (self._reconnect_attempts - 1)),
                    self._max_reconnect_delay,
                )
                if self._reconnect_attempts > self._max_reconnect_attempts:
                    delay = max(delay, 300)
                    _LOGGER.info(
                        "Max reconnect attempts reached; retrying every %.0fs", delay
                    )
                else:
                    _LOGGER.info(
                        "Reconnect attempt %d/%d in %.1fs",
                        self._reconnect_attempts,
                        self._max_reconnect_attempts,
                        delay,
                    )
                await asyncio.sleep(delay)
                if not self._should_reconnect:
                    return

                await self._teardown_client()
                if await self._establish_session():
                    _LOGGER.info(
                        "Reconnected after %d attempt(s)", self._reconnect_attempts
                    )
                    self._reconnect_attempts = 0
                    return
            except asyncio.CancelledError:
                return
            except Exception as exc:  # noqa: BLE001
                _LOGGER.error("Reconnection error: %s", exc)

    async def force_reconnect(self) -> bool:
        """User-triggered immediate reconnect, bypassing the backoff curve."""
        _LOGGER.info("Force reconnect requested")
        self._reconnect_attempts = 0
        # A manual reconnect is the explicit "try everything again" signal, so
        # re-probe opcodes previously retired as unsupported.
        self._unsupported_opcodes.clear()
        self._opcode_timeout_counts.clear()
        self._unsupported_since.clear()
        await self._teardown_client()
        return await self._establish_session()

    # ============== RX path ==============

    def _notification_handler(self, sender: Any, data: bytearray) -> None:
        chunk = bytes(data)
        _LOGGER.debug("RX chunk sender=%s: %s", sender, chunk.hex().upper())
        for frame in self._reassembler.feed(sender, chunk):
            _LOGGER.debug("RX frame: %s", frame.hex().upper())
            self._process_frame(frame)

    def _process_frame(self, frame_data: bytes) -> None:
        try:
            pf = protocol.parse_frame(frame_data)
        except ValueError as exc:
            _LOGGER.warning("Unparseable frame %s: %s", frame_data.hex().upper(), exc)
            return

        self._last_rx_time = time.time()
        self._rx_opcode_counts[pf.opcode] = self._rx_opcode_counts.get(pf.opcode, 0) + 1
        self._opcodes_ever_answered.add(pf.opcode)

        if pf.status not in (None, 0x00):
            _LOGGER.warning(
                "Opcode 0x%02X response status 0x%02X (%s), payload=%s",
                pf.opcode,
                pf.status,
                protocol.RESPONSE_STATUS_TEXT.get(pf.status, "UNKNOWN"),
                pf.payload.hex(),
            )

        try:
            if pf.opcode == OPC.IDENTITY_AUTH and pf.status == 0 and not self._token:
                self._token = protocol.extract_token_from_response(pf)
                if self._token:
                    future = self._pending_responses.get(OPC.IDENTITY_AUTH)
                    if future and not future.done():
                        future.set_result(self._token)

            elif pf.opcode == OPC.HEARTBEAT:
                self._handle_heartbeat(pf)

            elif pf.opcode == OPC.QUERY_POWER_STATUS:
                # 0xE0 is fire-and-forget by design: store the latest value.
                self._last_power_status = protocol.parse_power_status(pf.payload, pf.tail)
                _LOGGER.debug("Power status: %s", self._last_power_status)

            elif pf.opcode in self._pending_responses:
                future = self._pending_responses.pop(pf.opcode)
                if not future.done():
                    future.set_result((pf.payload, pf.tail))

            else:
                # No future waiting: either a genuine unsolicited push, or —
                # far more commonly with this charger over a BLE proxy — a
                # reply that arrived after its request gave up. Either way the
                # data is good, so cache it for the next request instead of
                # discarding it, and don't hold the lateness against the
                # opcode (it answers, just slowly).
                self._late_responses[pf.opcode] = (time.time(), pf.payload, pf.tail)
                self._opcode_timeout_counts.pop(pf.opcode, None)
                self._unsupported_opcodes.discard(pf.opcode)
                _LOGGER.info(
                    "RX late/unsolicited opcode 0x%02X (cached for next request): "
                    "status=0x%02X payload=%s tail=%s",
                    pf.opcode,
                    pf.status if pf.status is not None else 0,
                    pf.payload.hex(),
                    pf.tail.hex() if pf.tail else "-",
                )
        except Exception as exc:  # noqa: BLE001
            _LOGGER.warning("Frame processing error for opcode 0x%02X: %s", pf.opcode, exc)

    def _handle_heartbeat(self, pf: protocol.ParsedFrame) -> None:
        """Handle a 0xB5 frame — the first one ever is a headline event."""
        # 0xB5 is also pollable as a normal request (see request_telemetry).
        # Resolve any waiter first so the coordinator can refresh charger
        # state every cycle instead of relying on the charger volunteering.
        future = self._pending_responses.pop(OPC.HEARTBEAT, None)
        if future is not None and not future.done():
            future.set_result((pf.payload, pf.tail))

        self._heartbeat_count += 1
        if self._heartbeat_count == 1:
            _LOGGER.warning(
                "FIRST 0xB5 HEARTBEAT RESPONSE EVER RECEIVED (payload=%s, tail=%s, "
                "active send variant=%s) — the §2.6 mystery may be cracked; "
                "locking heartbeat payload variant",
                pf.payload.hex(),
                pf.tail.hex() if pf.tail else "-",
                HEARTBEAT_PAYLOAD_VARIANTS[self._heartbeat_variant_index].hex() or "empty",
            )
            self._heartbeat_variant_locked = True

        state = protocol.parse_heartbeat_state(pf.payload)
        self._last_heartbeat_state = state
        self._last_heartbeat_time = state.timestamp

        # Independent charging-session tracking
        if state.charging and self._charging_session_start is None:
            self._charging_session_start = state.timestamp
            _LOGGER.info("Charging session started")
        elif not state.charging and self._charging_session_start is not None:
            _LOGGER.info(
                "Charging session ended after %.0fs",
                state.timestamp - self._charging_session_start,
            )
            self._charging_session_start = None

        # A short (non-telemetry) reply means the charger is idle and is no
        # longer reporting live measurements. Remember that, so instantaneous
        # values (current/voltage/temperature) can be cleared rather than
        # left showing the last figures from a finished session.
        self._telemetry_live = state.telemetry is not None

        if state.telemetry:
            self._last_telemetry = state.telemetry
            _LOGGER.debug(
                "Telemetry: %.2f kWh, %.1f V, %.1f A, %ds",
                state.telemetry.session_energy_kwh,
                state.telemetry.voltage_v,
                state.telemetry.current_a,
                state.telemetry.runtime_seconds,
            )

    # ============== TX path ==============

    async def _send_frame(self, frame: bytes) -> None:
        if not self._client or not self._client.is_connected:
            raise RuntimeError("Not connected to charger")
        _LOGGER.debug("TX frame: %s", frame.hex().upper())
        try:
            for i in range(0, len(frame), protocol.WRITE_CHUNK_SIZE):
                chunk = frame[i : i + protocol.WRITE_CHUNK_SIZE]
                await self._client.write_gatt_char(GATT_CHAR_WRITE, chunk, response=False)
                await asyncio.sleep(protocol.WRITE_CHUNK_DELAY)
        except Exception as exc:
            _LOGGER.error("Failed to send frame: %s", exc)
            self._connected = False
            if self._should_reconnect:
                self._trigger_reconnection()
            raise

    async def _request(
        self,
        opcode: int,
        payload: bytes = b"",
        timeout: Optional[float] = None,
    ) -> Optional[tuple[bytes, bytes]]:
        """Send a request and await the (payload, tail) of the matching response.

        Serialized against every other exchange. Returns None on timeout —
        generous timeouts are essential through a BLE proxy, and some opcodes
        legitimately drop acks.
        """
        if not self._token:
            _LOGGER.warning("Cannot send opcode 0x%02X — no session token", opcode)
            return None

        # Use a reply that landed after its request timed out, rather than
        # paying the full wait again. Consumed on read, so the following cycle
        # issues a fresh request and the data keeps refreshing.
        cached = self._late_responses.pop(opcode, None)
        if cached is not None:
            received_at, payload_out, tail_out = cached
            if time.time() - received_at <= LATE_RESPONSE_MAX_AGE:
                _LOGGER.debug(
                    "Using late response for opcode 0x%02X (%.0fs old)",
                    opcode,
                    time.time() - received_at,
                )
                return (payload_out, tail_out)

        if opcode in self._unsupported_opcodes:
            retired_at = self._unsupported_since.get(opcode, 0.0)
            if time.time() - retired_at < UNSUPPORTED_RETRY_INTERVAL:
                _LOGGER.debug("Skipping opcode 0x%02X — marked unsupported", opcode)
                return None
            # Periodically re-probe: an opcode can start answering once the
            # charger changes state (e.g. a car is plugged in).
            _LOGGER.info("Re-probing opcode 0x%02X after back-off", opcode)
            self._unsupported_opcodes.discard(opcode)
            self._opcode_timeout_counts.pop(opcode, None)

        effective_timeout = timeout or self._response_timeout

        async with self._request_lock:
            future: asyncio.Future = asyncio.get_running_loop().create_future()
            self._pending_responses[opcode] = future
            self._request_in_flight_since = time.time()
            try:
                await self._send_frame(protocol.cmd_query(opcode, self._token, payload))
                result = await self._await_response_with_nudge(future, effective_timeout)
            except asyncio.TimeoutError:
                self._note_opcode_timeout(opcode, effective_timeout)
                return None
            except RuntimeError:
                return None
            finally:
                self._pending_responses.pop(opcode, None)
                self._request_in_flight_since = None

            self._opcode_timeout_counts.pop(opcode, None)
            return result

    async def _await_response_with_nudge(
        self, future: asyncio.Future, timeout: float
    ) -> tuple[bytes, bytes]:
        """Wait for a response, poking the charger to flush it.

        This charger holds a completed reply in its notify queue until another
        write arrives. Measured on real hardware: a 0xB0 reply sat undelivered
        for 31s, then landed 0.2s after the next heartbeat was sent. Waiting
        passively therefore reads as "slow" or even "unsupported" when the
        answer was ready almost immediately.

        So we wait in short slices and send a cheap heartbeat between them to
        flush the pending notification. The heartbeat is fire-and-forget and
        already the session keep-alive, which makes it a harmless poke. We
        hold the request lock here, so this writes directly rather than going
        through send_heartbeat() (which would deadlock on that same lock).

        Raises asyncio.TimeoutError if the overall budget expires.
        """
        deadline = time.monotonic() + timeout
        nudges = 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise asyncio.TimeoutError
            try:
                # shield: the slice timing out must not cancel the real future.
                return await asyncio.wait_for(
                    asyncio.shield(future), min(RESPONSE_NUDGE_INTERVAL, remaining)
                )
            except asyncio.TimeoutError:
                if time.monotonic() >= deadline:
                    raise
                nudges += 1
                _LOGGER.debug("Nudging charger to flush pending reply (#%d)", nudges)
                await self._send_frame(protocol.cmd_heartbeat(self._token))

    def _note_opcode_timeout(self, opcode: int, timeout: float) -> None:
        """Count a timeout and retire the opcode once it looks unsupported."""
        count = self._opcode_timeout_counts.get(opcode, 0) + 1
        self._opcode_timeout_counts[opcode] = count
        _LOGGER.warning(
            "Timeout (%.0fs) waiting for opcode 0x%02X response (%d consecutive)",
            timeout,
            opcode,
            count,
        )
        if opcode in self._opcodes_ever_answered:
            # Proven supported — this is a dropped reply, not an unsupported
            # command. Keep asking.
            return
        if count >= UNSUPPORTED_TIMEOUT_THRESHOLD:
            self._unsupported_opcodes.add(opcode)
            self._unsupported_since[opcode] = time.time()
            _LOGGER.warning(
                "Opcode 0x%02X has timed out %d times and has never answered — "
                "skipping it so it stops starving the poll cycle. It will be "
                "re-probed in %.0f min, or immediately via Force Reconnect.",
                opcode,
                count,
                UNSUPPORTED_RETRY_INTERVAL / 60,
            )

    # ============== Authentication ==============

    async def _authenticate(self) -> bool:
        try:
            future: asyncio.Future = asyncio.get_running_loop().create_future()
            self._pending_responses[OPC.IDENTITY_AUTH] = future
            await self._send_frame(
                protocol.build_identity_frame(self.serial, self.station_id)
            )
            try:
                await asyncio.wait_for(future, AUTH_RESPONSE_TIMEOUT)
            finally:
                self._pending_responses.pop(OPC.IDENTITY_AUTH, None)

            if not self._token:
                _LOGGER.error("Authentication completed without a session token")
                return False

            _LOGGER.info("Authentication successful")
            await self._initial_setup()
            return True
        except asyncio.TimeoutError:
            _LOGGER.error("Authentication timeout (%.0fs)", AUTH_RESPONSE_TIMEOUT)
            return False
        except Exception as exc:  # noqa: BLE001
            _LOGGER.error("Authentication failed: %s", exc)
            return False

    async def _initial_setup(self) -> None:
        """Post-auth sequence mirroring the known-working client: time sync,
        settle, then a first heartbeat."""
        try:
            await self.sync_time()
            await asyncio.sleep(1.0)
            await self.send_heartbeat()
            await asyncio.sleep(0.5)
        except Exception as exc:  # noqa: BLE001
            _LOGGER.warning("Initial setup failed: %s", exc)

    # ============== Heartbeat ==============

    def _start_heartbeat_task(self) -> None:
        if self._heartbeat_task and not self._heartbeat_task.done():
            return
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())

    def _stop_heartbeat_task(self) -> None:
        if self._heartbeat_task and not self._heartbeat_task.done():
            self._heartbeat_task.cancel()
        self._heartbeat_task = None

    async def _heartbeat_loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(HEARTBEAT_SEND_INTERVAL)
                if self.is_connected:
                    await self.send_heartbeat()
            except asyncio.CancelledError:
                return
            except Exception as exc:  # noqa: BLE001
                _LOGGER.debug("Heartbeat send failed: %s", exc)

    async def send_heartbeat(self) -> None:
        """Send a 0xB5 keep-alive (fire-and-forget).

        Payload-variant experiment: rotate through the documented shapes until
        the charger ever answers, then lock (see HEARTBEAT_PAYLOAD_VARIANTS).
        """
        if not self._token:
            return
        variant = HEARTBEAT_PAYLOAD_VARIANTS[self._heartbeat_variant_index]
        async with self._request_lock:
            await self._send_frame(protocol.cmd_heartbeat(self._token, variant))
        _LOGGER.debug(
            "Heartbeat sent (variant=%s%s)",
            variant.hex() or "empty",
            ", locked" if self._heartbeat_variant_locked else "",
        )
        if not self._heartbeat_variant_locked:
            self._heartbeat_variant_index = (self._heartbeat_variant_index + 1) % len(
                HEARTBEAT_PAYLOAD_VARIANTS
            )

    # ============== Commands ==============

    async def sync_time(self) -> bool:
        """0xB0 time sync using the host's local timezone offset."""
        if not self._token:
            return False
        tz_minutes = -time.timezone // 60
        async with self._request_lock:
            future: asyncio.Future = asyncio.get_running_loop().create_future()
            self._pending_responses[OPC.SYNC_TIME] = future
            self._request_in_flight_since = time.time()
            try:
                await self._send_frame(protocol.cmd_sync_time(self._token, tz_minutes))
                await self._await_response_with_nudge(future, self._response_timeout)
                _LOGGER.info("Time sync acknowledged")
                return True
            except asyncio.TimeoutError:
                _LOGGER.warning("No time sync acknowledgement")
                return False
            except Exception as exc:  # noqa: BLE001
                _LOGGER.warning("Time sync failed: %s", exc)
                return False
            finally:
                self._pending_responses.pop(OPC.SYNC_TIME, None)
                self._request_in_flight_since = None

    @property
    def active_port(self) -> int:
        """Gun/connector index used in command bodies.

        The vendor app hardcodes 0x00 for every command; confirmed by
        disassembling SendCmdClient. 0x01 also works on this single-gun unit,
        but 0x00 is the reference behaviour.
        """
        return protocol.GUN_NORMAL

    async def authorize_charge(self) -> bool:
        """0xB4 start/authorize charging (two-byte body, per the vendor app)."""
        result = await self._request(
            OPC.AUTH_CHARGE, bytes([self.active_port, 0x00])
        )
        return result is not None

    async def stop_charge(self) -> bool:
        """0xB6 stop charging."""
        result = await self._request(OPC.STOP_CHARGE, bytes([self.active_port]))
        return result is not None

    async def set_charge_mode(self, mode: int) -> bool:
        """0xB3: 0x00 = plug & charge, 0x01 = authorized."""
        result = await self._request(OPC.SET_CHARGE_MODE, bytes([mode & 0xFF]))
        return result is not None

    async def set_current_limit(self, port: Optional[int], amps: int) -> bool:
        """0xC0 set current limit. Fire-and-forget: the charger frequently
        drops this ack, so a missing response is not failure — the next
        heartbeat/0xE0 query confirms whether it took."""
        if not self._token:
            return False
        if port is None:
            port = self.active_port
        try:
            async with self._request_lock:
                await self._send_frame(
                    protocol.cmd_set_current_limit(self._token, port, amps)
                )
            return True
        except Exception as exc:  # noqa: BLE001
            _LOGGER.warning("Set current limit failed: %s", exc)
            return False

    # ============== Queries ==============

    # 0xA9/0xE0/0xE6 were the only queries sent with an empty payload, and the
    # only three this charger never answered — even with nudges flushing its
    # notify queue. Every query that does work (0xC1/0xC2/0xC4/0xC7/0xC8/0xD3/
    # 0xE4) sends a 0x01 "read" selector, so send it here too.
    QUERY_SELECTOR = b"\x01"

    async def request_telemetry(self) -> bool:
        """Actively poll 0xB5 for charger state and telemetry.

        The charger volunteers heartbeats only rarely — one in three hours was
        observed even while charging — so charger state, car-connected and all
        session telemetry would otherwise sit frozen at whatever the last
        spontaneous frame said. Requesting it like any other opcode (with
        nudging to flush the reply) refreshes it every poll cycle.
        """
        variant = TELEMETRY_PAYLOAD_VARIANTS[self._telemetry_variant_index]
        result = await self._request(
            OPC.HEARTBEAT, variant, timeout=TELEMETRY_RESPONSE_TIMEOUT
        )
        if result is not None:
            if not self._telemetry_variant_locked:
                _LOGGER.warning(
                    "Telemetry request answered with payload %s — locking onto it",
                    variant.hex() or "empty",
                )
                self._telemetry_variant_locked = True
            return True

        if not self._telemetry_variant_locked:
            self._telemetry_variant_index = (self._telemetry_variant_index + 1) % len(
                TELEMETRY_PAYLOAD_VARIANTS
            )
            _LOGGER.debug(
                "Telemetry request unanswered; next payload variant %s",
                TELEMETRY_PAYLOAD_VARIANTS[self._telemetry_variant_index].hex() or "empty",
            )
        return False

    async def query_power_status(self) -> Optional[PowerStatus]:
        """0xE0 power status (limit + capacity)."""
        result = await self._request(OPC.QUERY_POWER_STATUS, self.QUERY_SELECTOR)
        if result is None:
            return self._last_power_status
        payload, tail = result
        self._last_power_status = protocol.parse_power_status(payload, tail)
        return self._last_power_status

    async def query_home_current_config(self) -> Optional[CurrentConfig]:
        """0xA9 home/grid current configuration."""
        result = await self._request(OPC.QUERY_HOME_CURRENT, self.QUERY_SELECTOR)
        if result is None:
            return None
        payload, tail = result
        return protocol.parse_current_config(payload, tail)

    async def query_charge_mode(self) -> Optional[int]:
        """0xE6 current charge mode."""
        result = await self._request(OPC.QUERY_CHARGE_MODE, self.QUERY_SELECTOR)
        if result is None:
            return None
        payload, _tail = result
        return protocol.parse_charge_mode(payload)

    async def _query_config_json(self, opcode: int, description: str) -> Optional[dict[str, Any]]:
        """Generic JSON config query (0xC1/C2/C4/C7/C8), 0x01 payload."""
        result = await self._request(opcode, b"\x01")
        if result is None:
            _LOGGER.warning("No %s response received", description)
            return None
        payload, tail = result
        return protocol.parse_config_json(opcode, payload, tail)

    async def query_basic_info(self) -> Optional[dict[str, Any]]:
        return await self._query_config_json(OPC.QUERY_BASIC_INFO, "basic info")

    async def query_employ_info(self) -> Optional[dict[str, Any]]:
        return await self._query_config_json(OPC.QUERY_EMPLOY_INFO, "employ info")

    async def query_protection_info(self) -> Optional[dict[str, Any]]:
        return await self._query_config_json(OPC.QUERY_PROTECTION_INFO, "protection info")

    async def query_wifi_config(self) -> Optional[dict[str, Any]]:
        return await self._query_config_json(OPC.QUERY_WIFI_CONFIG, "WiFi config")

    async def query_ble_info(self) -> Optional[dict[str, Any]]:
        return await self._query_config_json(OPC.QUERY_BLE_INFO, "BLE device info")

    async def query_wifi_status(self) -> Optional[dict[str, Any]]:
        """0xE4 WiFi status (binary format: SSID/password, data-format byte)."""
        result = await self._request(OPC.QUERY_WIFI_STATUS, b"\x01")
        if result is None:
            return None
        payload, tail = result
        return protocol.parse_wifi_status(payload, tail)

    async def query_network_status(self) -> Optional[dict[str, Any]]:
        """0xD3 network status with mapped error codes."""
        result = await self._request(OPC.QUERY_NETWORK_STATUS, b"\x01")
        if result is None:
            return None
        payload, tail = result
        return protocol.parse_network_status(payload, tail)

    # ============== State accessors ==============

    @property
    def is_connected(self) -> bool:
        return bool(self._connected and self._client and self._client.is_connected)

    @property
    def session_token(self) -> Optional[bytes]:
        return self._token

    def get_heartbeat_state(self) -> HeartbeatState:
        return self._last_heartbeat_state

    def get_last_telemetry(self) -> Optional[B5Telemetry]:
        return self._last_telemetry

    @property
    def telemetry_is_live(self) -> bool:
        """True when the last 0xB5 reply carried live telemetry."""
        return self._telemetry_live

    def get_last_power_status(self) -> Optional[PowerStatus]:
        return self._last_power_status

    def get_heartbeat_stats(self) -> dict[str, Any]:
        """Heartbeat/session statistics. seconds_since_last_heartbeat is None
        (not 0) when no heartbeat has ever been received."""
        now = time.time()
        return {
            "total_heartbeats": self._heartbeat_count,
            "last_heartbeat_time": self._last_heartbeat_time,
            "seconds_since_last_heartbeat": (
                now - self._last_heartbeat_time
                if self._last_heartbeat_time is not None
                else None
            ),
            "charging_session_active": self._charging_session_start is not None,
            "charging_session_start": self._charging_session_start,
            "charging_session_duration": (
                now - self._charging_session_start if self._charging_session_start else 0
            ),
            "heartbeat_send_variant": (
                HEARTBEAT_PAYLOAD_VARIANTS[self._heartbeat_variant_index].hex() or "empty"
            ),
            "heartbeat_variant_locked": self._heartbeat_variant_locked,
        }

    def get_connection_status(self) -> dict[str, Any]:
        return {
            "connected": self.is_connected,
            "should_reconnect": self._should_reconnect,
            "reconnect_attempts": self._reconnect_attempts,
            "max_reconnect_attempts": self._max_reconnect_attempts,
            "discovered_address": self._discovered_address,
            "has_token": self._token is not None,
            "heartbeat_count": self._heartbeat_count,
            "last_rx_time": self._last_rx_time,
            "seconds_since_last_rx": (
                time.time() - self._last_rx_time if self._last_rx_time else None
            ),
            "rx_opcode_counts": {
                f"0x{op:02X}": count for op, count in sorted(self._rx_opcode_counts.items())
            },
            "unsupported_opcodes": sorted(
                f"0x{op:02X}" for op in self._unsupported_opcodes
            ),
            "opcodes_ever_answered": sorted(
                f"0x{op:02X}" for op in self._opcodes_ever_answered
            ),
        }
