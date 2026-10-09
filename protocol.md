# Zeekr / Brioess Charger BLE Protocol

This document summarizes the application-layer BLE protocol used by the Zeekr wallbox, based on traffic captures

## 1. BLE Transport Basics
- **Services & Characteristics**
  - Primary service `0000FFFF-0000-1000-8000-00805F9B34FB`
    - `FF01-...` Write (some firmwares accept Write With Response; most use WNR)
    - `FF02-...` Notify / Read (primary notification path)
  - Secondary service `0000ABF0-0000-1000-8000-00805F9B34FB`
    - `ABF1-...` Write Without Response (commonly used for requests)
    - `ABF2-...` Notify (secondary notification path)
- **Connection routine**
  1. Connect and request high MTU (firmware accepts 517 bytes).
  2. Enable notifications on `FF02` and `ABF2` (use `ABF4` too if exposed).
  3. Send requests via `ABF1` (fallback to `FF01` if required).
  4. Charger accepts only one central connection at a time.

## 2. Framing & Checksums
Every packet is a framed message containing a single opcode.

```
Request:  FE | OPC | H0 H1 H2 H3 H4 | CHK | TOKEN[8] | PAYLOAD...
Response: AA | OPC | H0 H1 H2 H3 H4 | CHK | TOKEN[8] | PAYLOAD... | [TAIL]
```

- **SOF**: `0xFE` for requests, `0xAA` for responses.
- **Opcode**: 1 byte.
- **Header**: 5 bytes. `H2|H3` (little endian) is the payload length. `H0` doubles as status for replies.
- **Checksum** (`CHK`): XOR of header (SOF excluded), token, and payload: `CHK = xor(H0..H4, TOKEN[0..7], PAYLOAD)`.
- **Token**: 8-byte session token provided by the authentication step. All commands must echo it.
- **Payload**: Command-specific data; empty for many requests.
- **Tail**: Optional single byte on responses (examples: `0x7D` closing brace, current limit mirror). Always inspect trailing bytes past the declared payload length.

Notifications may split frames across BLE packets. Reassemble chunks until the next `0xAA` start byte is seen.

## 3. Authentication & Session Bootstrap
1. **Identity request (`0xFE` opcode, `IDENTITY_AUTH`)**
   - Build a 0x30-byte block:
     - Bytes 0x00–0x07: Charger serial (ASCII, uppercase, hyphen removed).
     - Bytes 0x08–0x13: `0x00` padding.
     - Byte 0x14: `0x02` (auth level).
     - Byte 0x15: `0x01` (client type).
     - Bytes 0x16–0x24: Station/account identifier as ASCII digits, padded with zeros.
     - Remaining bytes: zero.
   - Apply PKCS#5 padding to 56 bytes and encrypt with DES/ECB using key `"ucserver"`.
   - Wrap ciphertext in an 0x82-byte payload: `80 00 || ciphertext || zero padding`.
   - Send frame with `token = 00...00`.
2. **Identity response**
   - Reply is `AA FE ...` carrying status, hardware/software strings, and an 8-byte session token (last bytes of payload/tail). Extract and persist this token.
3. **Immediate follow-ups**
   - `0xB0 SYNC_TIME_CMD`: payload `<epoch (uint32 LE)><timezone_minutes (uint16 LE)>`.
   - Optional info pulls (e.g., `0xC1` basic info) to confirm the token.
4. **Token Lifetime**
   - Token persists until idle timeout or charger reset. A `TOKEN_TIMEOUT` status requires re-auth.

## 4. Response Status Codes
These map header byte `H0` in responses:

| Code | Meaning             |
|------|---------------------|
| 0x00 | SUCCESS             |
| 0x11 | PARSE_ERROR         |
| 0x12 | NO_PERMISSION       |
| 0x13 | REJECTED            |
| 0x14 | CMD_NOT_EXIST       |
| 0x15 | CMD_NOT_SUPPORTED   |
| 0x16 | TOKEN_TIMEOUT       |
| 0x50 | DEVICE_ERROR        |
| 0x51 | CMD_EXECUTE_FAILURE |

## 5. Command Reference
Only opcodes observed on production firmware are listed. All requests echo the session token and typically carry empty payloads unless specified.

### 5.1 Session & Control
| Opcode | Request Payload                      | Response Highlights |
|--------|--------------------------------------|---------------------|
| 0xFE (`IDENTITY_AUTH`) | DES-encrypted block (see §3) | Returns auth level, firmware strings, session token |
| 0xB0 (`SYNC_TIME_CMD`) | `<epoch><tz_minutes>`        | Echoes the time values |
| 0xB3 (`SET_CHARGE_MODEL`) | `00` = auto-start, `01` = authorised-start | Ack only |
| 0xB4 (`AUTH_CHARGE_CMD`) | none | Ack (`AA B4`) with success status |
| 0xB5 (`HEARTBEAT`) | none | Heartbeat payload (see §6) |
| 0xB6 (`STOP_CHARGE_CMD`) | none | Ack; includes cumulative energy counter |

### 5.2 Power & Current
| Opcode | Request Payload             | Response Highlights |
|--------|-----------------------------|---------------------|
| 0xC0 (`POWER_CONTROL`) | `[port, amps]` | Optional ack; charger adopts requested limit if within installation caps |
| 0xE0 (`QUERY_POWER_PERCENT`) | none | Payload: status byte, device max current, set current; tail mirrors configured limit |
| 0xA9 (`QUERY_HOME_CURRENT`) | none | Returns installation configuration (grid capacity, earthing, solar flags) with tail repeating current limit |

### 5.3 Information Queries
| Opcode | Description |
|--------|-------------|
| 0xC1 (`CHARGE_POINT_BASIC_INFORMATION`) | Static device metadata (serial, power, firmware revisions). Payload may include JSON or TLV strings. |
| 0xC2 (`CHARGE_POINT_EMPLOY_INFORMATION`) | Site/installation info (connector type, rated current, number of outlets). |
| 0xC8 (`BLUETOOTH_DEVICE_INFORMATION`) | BLE board firmware and MAC address. |
| 0xC4 (`PROTECTION_CONFIGURATION`) | Residual current, relay checks, RFID flags. |

### 5.4 Networking & Services
| Opcode | Description |
|--------|-------------|
| 0xD2 (`CONFIGURATION_WIFI_NETWORK`) | TLV payload configuring SSID, credentials, DHCP/static IP, DNS. |
| 0xD3 (`CHECK_NETWORK_STATUS`) | Bitfields for link status, IP acquisition, backend reachability. |
| 0xD4 (`CHANGE_NET_MODE`) | Switches between Wi-Fi/LAN/4G priority modes. |
| 0xC6 / 0xBF / 0xCF | LAN, grid-network, and 4G module configuration (TLV encoded). |
| 0x86 / 0xD6–0xDA | OCPP server profile management (host, port, scheme, path, heartbeat). |

### 5.5 RFID & Metering
| Opcode | Description |
|--------|-------------|
| 0xD0 (`ACTIVE_ADD_CARD`) | Arms RFID reader to learn a new token; async notification informs success. |
| 0xF1 / 0xF2 (`CONFIGURE_ELECTRIC_METER`, `QUERY_ELECTRIC_METER_CONFIGURATION`) | Meter binding, Modbus parameters, CT/phase setup. |

## 6. Heartbeat Payloads (`0xB5` Responses)
Heartbeats appear multiple times per minute and vary by length:

- **Keep-alive**: `01 01 01` — simple acknowledgement.
- **State packets**: `[state, port]` — map state codes via table below.
- **Limit snapshot**: `08-byte` structure `[type, port, state, reserved, amps_le, 0x00, 0x00, 0x00]` announcing configured current.
- **Telemetry block (21 bytes)**
  - Byte 0: state (`0x06` = charging)
  - Byte 1: port
  - Bytes 2–5: session sequence number (little endian)
  - Bytes 6–7: status/flags (phase bitfield, etc.)
  - Bytes 8–9: line voltage (0.01 V units)
  - Byte 12: current (0.1 A units)
  - Bytes 13–14: session energy (0.01 kWh)
  - Bytes 16–19: session runtime (seconds)
  - Byte 20: checksum / rolling counter

### State Code Map
| Value | Description        | Car Connected | Charging |
|-------|--------------------|---------------|----------|
| 0x00  | available          | No            | No       |
| 0x01  | preparing          | Yes           | No       |
| 0x02  | suspended (EV)     | Yes           | No       |
| 0x03  | reserved           | Yes           | No       |
| 0x04  | suspended (EVSE)   | Yes           | No       |
| 0x05  | charging break-off | Yes           | No       |
| 0x06  | charging           | Yes           | Yes      |
| 0x07  | pausing            | Yes           | No       |
| 0x08  | finishing          | Yes           | No       |
| 0x0E  | unavailable        | No            | No       |
| 0x0F  | faulted            | No            | No       |
| 0xC0  | available (alt)    | No            | No       |

## 7. TLV and JSON Handling
Many responses blend TLV data with embedded JSON:
- If payload starts with `{` or contains printable braces, extract the JSON substring (balanced braces) before parsing TLVs.
- TLV convention: `[Type (1B)] [Length (1B)] [Value ...]`, with `0xFF` length meaning the next two bytes encode the actual length (little endian).
- Known tag hints:
  - `0x01`: serial number
  - `0x02`: model name
  - `0x04`: firmware version
  - `0x07`: rated charging current (A)
  - `0x08`: rated power (W)
  - `0x88`: maximum current capacity (little endian integer)
  - `0xDD`: present current limit (little endian integer)

## 8. Implementation Notes & Tips
- Always check the trailing byte after the declared payload length—`0xE0` and `0xA9` rely on it for the active current limit.
- Charger may drop acknowledgements for `0xC0`; trust subsequent heartbeat or query responses to confirm the new setting.
- If `NO_PERMISSION` (`0x12`) appears, ensure the session token is valid and that the charger is in an idle state for the requested operation.
- For automation, a safe cycle is: `HEARTBEAT` → `QUERY_POWER_PERCENT` → `POWER_CONTROL` → monitor `HEARTBEAT` telemetry until stable.
- BLE connection loss resets the session; repeat the identity handshake to recover.

---

# Appendix A — Findings from live hardware, 2026-07-20

Verified against a single-phase 7 kW "Nora" (`EC0000XX`, hardware V1.0,
software V1.1.0, built 2023-12-15) over an ESPHome BLE proxy. Captured with
the integration's own debug log (`config/zeekr_charger.log`). These findings
correct or supersede several assumptions in the body of this document.

## A.1 The charger does not flush a reply until the next write (critical)

**This is the single most important behaviour of this protocol.** A completed
response sits in the charger's notify queue and is not delivered until the
central writes something else. Captured verbatim:

```
14:48:08,757  TX  FEB0...   sync time request
14:48:38,779  WARNING: No time sync acknowledgement      <- gave up after 30s
14:48:39,780  TX  FEB5...   heartbeat
14:48:39,976  RX  AAB0...   the sync reply — 0.2s after that write
```

The reply was ready almost immediately; it waited 31 seconds for a packet to
push it out. Consequences:

- **There is no such thing as a slow opcode here.** Any "latency" measurement
  taken by waiting passively is really measuring *time until the next write*.
  Timeouts of 5s, 12s, 15s and 30s all produce different, equally meaningless
  numbers.
- **Opcodes look unsupported when they are not.** Retiring an opcode after N
  passive timeouts will retire perfectly good commands.
- **Back-to-back queries appear to work** because each request flushes the
  previous one's reply. A lone query in isolation appears dead.
- **Fire-and-forget cannot work.** Sending `0xE0` and reading a cached value
  0.3s later never observes that request's own reply.
- **It very likely explains the `0xB5` heartbeat mystery.** Nothing is ever
  written after a heartbeat, so its reply is never flushed. With nudging in
  place, `0xB5` replies do arrive.

**Implementation:** while awaiting any response, write a cheap frame (a
heartbeat works well and doubles as keep-alive) every ~2s until the reply
lands. See `_await_response_with_nudge` in `ble_client.py`.

### Evidence, and why this is the charger rather than the transport

Measured over 583 consecutive RX events on a live session:

```
delay from most recent TX -> RX:  min 0.089s  median 0.136s  max 0.315s
RX within 1s of a TX:             583 / 583  (100.0%)
RX more than 4s after last TX:    0
```

Every reply landed within ~0.3s of a write; none ever arrived unprompted.

It is tempting to blame the ESPHome BLE proxy or a long connection interval,
but that cannot explain the observation. The Bluetooth LE specification caps
`connInterval` at **4.0 s** (0x0C80 x 1.25 ms), and peripheral latency lets a
peripheral skip connection events only when it has *nothing* to send. A
peripheral holding a ready reply therefore transmits at the next connection
event — within 4 s, worst case. The captured `0xB0` reply was held for **31 s**
across a window containing no writes, i.e. through roughly eight guaranteed
opportunities to transmit. The charger chose not to send.

This also reconciles with the upstream project's README, which reports
charge-rate changes taking effect "within a second or so". That describes
*physical actuation* from a write, which requires no reply at all; and a
continuously polling client flushes each queued reply with its next request,
so the queuing is invisible unless you deliberately send one command and wait.

## A.2 Query opcodes need a `0x01` read selector

`0xA9`, `0xE0` and `0xE6` never answered with an empty payload — not even
with nudging. Sending the same single `0x01` selector byte that the config
queries use made all three respond immediately:

| Opcode | Empty payload | With `0x01` |
|---|---|---|
| `0xA9` query home/grid current | no reply | grid capacity 50 A |
| `0xE0` query power status | no reply | limit 16 A, capacity 32 A |
| `0xE6` query charge mode | no reply | `0x00` plug & charge |

Treat `0x01` as the default payload for all read queries.

## A.3 Corrected field names (`0xC1` basic info)

The charger emits neither `firmware_version` nor `software_version`:

```json
{"model_number": [19, "Nora"], "charge_point_number": [19, "EC0000XX"],
 "production_date": [17, "2023-12-15 00:00:00"], "hardware_version": [17, "V1.0"],
 "p_board_software_version": [17, "V1.1.0"], "c_board_software_version": [17, "V1.1.0"],
 "charge_point_type": [19, "Nora"], "rated_power": [17, 7000],
 "time_settings": [51, "2023-12-15T12:30:25.000Z"]}
```

Unset fields are the **literal string `"NULL"`**, not JSON null — seen in
`connector_type` (`0xC2`) and `wifi_mac_address` /
`wifi_module_firmware_version` (`0xC7`, where `wifi_function_enable` is 0).

## A.4 `0xE4` WiFi status has two layouts

This unit puts the format byte **first**, with no response-type byte:

```
02 <ssid> 0A <password> 03             -> format 0x02, STX/LF/ETX framed
```

Other firmware sends `[response_type][format][ssid...]` (e.g. `C0 02 ...`).
Detect which by testing whether byte 0 is a known format (`0x01`, `0x02`,
`0x68`); reading byte 1 blindly returns the first character of the SSID.

## A.5 `0xC2` employ info is populated and worth reading

```json
{"connector_type": [19, "NULL"], "rate_charging_current": [19, 32],
 "phase_of_charge_point": [19, 3], "number_of_socket_outlets": [17, 1]}
```

`phase_of_charge_point` reads **3 on a single-phase unit**, so it is a code of
some kind, not a phase count. Do not label it as phases.

## A.6 Connection notes

- `bleak_retry_connector.establish_connection()` must be given a resolved
  `BLEDevice`, never an address string (confirmed again here).
- Auth (`0xFE`) sometimes times out on the first attempt right after a
  reconnect and succeeds on the retry; budget for a retry rather than
  treating the first failure as fatal.
- Silence is **not** evidence of a dead link. With no car connected the
  charger pushes nothing at all. Probe with `0xB0` before concluding the
  session is dead — it answered on every observed session.

## A.7 Control commands need a port byte (verified on hardware)

`0xB4` and `0xB6` were documented as taking no payload. Sent empty they get
**no response at all**. Live heartbeats report the port in payload byte 1
(`00 01` = state, port), i.e. port **1** on the test unit — but the reference
implementation sent `0xC0` with port **0**, which the charger silently ignored.

Verified 2026-07-20 with a car connected:

| Command | Empty / port 0 | With port 1 |
|---|---|---|
| `0xB6` stop | no reply | `AAB6...` status 0x00, **car stopped charging** |
| `0xB4` start | no reply | `AAB4...00` status 0x00 (see caveat) |
| `0xB3` set mode | n/a (already had payload) | works both directions, reads back |
| `0xC0` set current | silently ignored | **applied**: 16A -> 10A, confirmed via 0xE0 |

The `0xC0` case is the clearest proof: with port 0 the frame was accepted by
the link and did nothing; with port 1 the limit actually changed and read back
on the next `0xE0` query.

**Caveat on `0xB4`:** it is acknowledged but does **not** resume a session that
was ended by `0xB6`, in either Plug & Charge or Authorized mode. The cable
appears to need re-plugging for the EV to re-initiate. Do not present Start as
an undo for Stop.

## A.8 Telemetry is conditional on an active session (resolves §2.6)

`0xB5` returns a 21/33-byte telemetry payload **only while charging**:

```
06 00 64F05D6A E000 D25F 0000 C805 ...
^state 0x06    ^seq       ^245.30V  ^14.80A
```

When idle it returns an 8-byte short form (`01 01 E9 00 19 09 00 00`) whose
byte 2 (`0xE9`) is not a known state code — meaning is unconfirmed, so it is
surfaced as `unknown_E9` rather than guessed at.

The charger also almost never volunteers a heartbeat (one in three hours, even
mid-charge), so `0xB5` must be **polled like any other opcode** or charger
state sits frozen at the last spontaneous frame. This — not any payload
variant — is why the original investigation saw no telemetry: it was waiting
for pushes that do not come, mostly with no car connected.

## A.9 21-byte `0xB5` telemetry layout (from upstream, 2026-10-09)

Captured by upstream (geoffwatts/zeekr_evse_hass `5ac26ba`) from a
single-phase 7 kW Neo over a 281 s charge, checked against the vendor app
(14.5 A, 233.6 V, 0.261 kWh). Replaces the §6 21-byte layout:

| Bytes | Field |
|---|---|
| 2-5 | session sequence (constant per session) |
| 6-7 | session energy, 0.01 kWh, **starts at 0 each session** |
| 8-9 | voltage, 0.01 V |
| 12-13 | current, 0.01 A |
| 14-17 | session runtime, seconds (LE) |
| 20 | temperature, degC (inferred: constant 30) |

Because the counter starts at 0, session energy is reported as-is. A baseline
taken when HA first sees a charging frame undercounts after a mid-session
connect (the 33-byte capture in `tests/test_protocol.py` already shows
0.72 kWh at 674 s and 3.87 kW, i.e. a counter that began with the session).

---

---

# Appendix B — Confirmed against the vendor Android app (2026-07-20)

Extracted by static analysis of the Zeekr app APK (`com.haohan.chargehomeclient`,
`classes11.dex`) — DEX string/field tables parsed directly, no decompiler.
This confirms or corrects several things Appendix A had to infer.

## B.1 The real opcode table (`BluetootchConstant$Cmd`)

| Const | Op | Notes |
|---|---|---|
| `ATCH` | `FE` | auth |
| `ATCH2` | `FD` | **second auth variant, not previously known** |
| `SYNC_DATE` | `B0` | |
| `GET_DEVICE_INFO` | `B1` | **not previously known** |
| `SET_CHARGER_MODE` | `B3` | |
| `START_CHARGER` | `B4` | |
| `GET_CHARGER_STATE` | `B5` | **see B.2 — this is a query, not a heartbeat** |
| `STOP_CHARGER` | `B6` | |
| `QUERY_CHARGER_RECORD` | `B7` | **not previously known** — charging history |
| `START_UPDATE` / `GET_UPDATE_CHUNK` / `OTA_FINISH` | `B9`/`BA`/`BB` | OTA. Do not touch. |
| `SET_POWER` | `C0` | |
| `WIFI` | `D2` | |
| `PILE_NETWORK` | `D3` | |
| `QUERY_POWER` | `E0` | |
| `GET_CHARGER_MODE` | `E6` | |

Also: `Cipher.KEY_3DES = "ucserver"` (confirms the DES key),
`Protocol$StartCode.REQUEST_CODE = FE` / `RESPOND_CODE = AA`,
`ErrorCode.TOKEN_ERR = "16"`, `Gun.NORMAL = "00"`,
`Permission.SINGLE/ALONG = 00/01`.

**`Mode.AT_ONCE = 00`, `Mode.AUTH = 01`, `Mode.TIMER = 02`** — there is a third
scheduled/timer charge mode the integration does not expose.

## B.2 `0xB5` is `GET_CHARGER_STATE`, not a heartbeat

This is the answer to the long-standing "§2.6 heartbeat mystery". The opcode
is named `GET_CHARGER_STATE` and the app calls it via `queryStatus(token)`.
It is a **request/response query**, not something the charger broadcasts. The
original notes' expectation that the charger pushes it "multiple times per
minute" is simply wrong — it pushes nothing, which is why an entire debugging
session saw zero heartbeats.

Poll it like any other opcode. Independently discovered here by experiment
before the APK confirmed it.

## B.3 Frame structure (`BleProtocolBean`)

The app models a frame as exactly the fields we reverse-engineered:

```
startCode, cmd, flag, sequenceNumber, bodyLength,
statusCode, checkSum, authData (token), cipherBody, plainBody
```

Note `cipherBody` vs `plainBody`: bodies may be encrypted on some paths. This
integration only ever uses the plaintext path, which the charger accepts.

## B.4 Command surface (`ICmd`)

```
auth(...)  auth2(...)          syncDate(token)
queryStatus(token)             queryPower(token)
queryDeviceInfo(token)         queryChargerMode(token)
queryChargerRecord(token, ?)   getPileNetWork(token)
startCharger(token)            stopCharger(token)
setPower(token, power)         setChargerMode(token, mode)
setWifiInfo(token, ssid, pwd)
```

## B.5 Still unresolved

- The gun/port byte. `Gun.NORMAL = "00"`, yet empirically `0xB4`/`0xB6`/`0xB5`
  only answer when sent with a `01` payload and are silent when sent empty.
  Whether `00` would work equally well is untested — the payload's *presence*
  is what demonstrably matters.
- Whether `START_CHARGER` can resume a session ended by `STOP_CHARGER`.
  Observed: it is acknowledged but does not restart; a cable re-plug did.
- `ChargerStateEnum` (CHARGING / ERROR / IDLING / PAUSED / WAITING) is built in
  `<clinit>`, so its numeric mapping is not recoverable from the DEX metadata
  alone and would need real bytecode disassembly.
