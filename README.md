# Zeekr Charger — Home Assistant Integration

Control and monitor a Zeekr-branded (Raedian-built) EV wallbox directly over
**Bluetooth Low Energy**. No cloud, no OCPP — the charger's OCPP path does not
support current control, so BLE is the only way to set the charge rate.

> ⚠️ High-voltage equipment can be dangerous. Use at your own risk. Have limits
> validated by a licensed electrician, and never exceed your circuit rating.

## Status

Verified end-to-end against a single-phase 7 kW **"Nora"** (`EC0000XX`,
hardware V1.0, software V1.1.0) over an ESPHome Bluetooth proxy: connection,
all controls, and live telemetry during a real charging session.

This version fixes several problems that made earlier versions unreliable —
see [What changed](#what-changed). If BLE never connected for you, or the
charge-rate slider appeared to do nothing, those are fixed here.

## Features

- **Local BLE control** — works with Home Assistant's Bluetooth stack,
  including [ESPHome Bluetooth proxies](https://esphome.io/projects/), which
  is the normal setup since few HA servers sit within BLE range of a garage.
- **Controls** — start/stop charging, set current limit (6 A to grid
  capacity), plug-and-charge vs. authorised mode, time sync, force reconnect.
- **Monitoring** — charger state, car connected, live voltage/current,
  session energy/runtime, temperature, charge mode, grid capacity, protection
  flags (grounding, relay adhesion, RCD, cable), WiFi and network status,
  connection diagnostics.
- **Solar-surplus (PV diversion) charging** — tracks a grid-power sensor of
  your choosing and steps the charge current to soak up excess solar, with
  optional home-battery priority and debounced pause/resume. Reactive, like
  Zappi/myenergi, rather than forecast-based.

## Installation

**HACS** → Integrations → ⋮ → Custom repositories → add this repo as type
*Integration* → install **Zeekr Charger** → restart Home Assistant.

**Manual** — copy `custom_components/zeekr_charger/` into your HA
`config/custom_components/` and restart.

## Setup

Settings → Devices & Services → Add Integration → **Zeekr Charger**.

- **Serial number** (required) — on the charger label, e.g. `EC0000XX…`. Also
  used for discovery if you don't supply a MAC.
- **BLE MAC address** (optional) — provide it if name discovery fails.
  Accepts `AA:BB:CC:DD:EE:FF`, `AA-BB-CC-DD-EE-FF` or `AABBCCDDEEFF`.

### Options

Settings → Devices & Services → Zeekr Charger → **Configure**:

| Option | Notes |
|---|---|
| BLE MAC address | Overrides the setup value |
| Grid power sensor | Signed watts, for solar-surplus charging |
| Grid power inverted | Tick if your sensor reports export as **positive** |
| Battery SOC sensor | Optional; the EV waits until the battery clears its threshold |
| BLE response timeout | Default 12 s. Raise if you see timeouts through a slow proxy |
| Reconnection tuning | Max attempts, initial/max delay, silence window |

### Solar-surplus charging

1. Pick your **grid power** sensor in options. Default convention is
   *negative = exporting*; tick the inversion box if yours is the other way.
2. Optionally pick a **battery SOC** sensor — the EV only gets surplus once
   the battery passes the *Solar Battery Priority SOC* number entity.
3. Turn on the **Solar Surplus Charging** switch.

The loop runs every 60 s, moves the limit by at most 2 A per tick, pauses only
after ~5 minutes of insufficient surplus and resumes after ~1 minute of
sufficient surplus, so passing clouds don't flap the session. The surplus and
target-current sensors populate even with the feature off, so you can sanity
check it before arming it.

## What changed

Findings from a full day of live debugging plus static analysis of the vendor
Android app. Full detail in [protocol.md](protocol.md) appendices A and B.

**The charger does not deliver a reply until the next write arrives.** A
response sits in its notify queue, ready, until something else is sent — a
`0xB0` reply was observed sitting undelivered for 31 seconds, then arriving
0.2 s after the next write. Measured across 583 replies: every single one
landed within 0.089–0.315 s of a write, and none ever arrived unprompted.
The integration now *nudges* — while awaiting any reply it sends a cheap
frame every 2 s to flush it. Without this, opcodes look slow, intermittent,
or entirely unsupported.

**Every command has a specific body, and several were wrong.**

| Command | Body |
|---|---|
| `B5` query state | `00` |
| `B6` stop | `00` |
| `B4` **start** | `0000` — two bytes, unlike everything else |
| `C0` set power | `00` + amps |
| `B1` device info | *(empty)* |
| Read queries (`A9`, `E0`, `E6`, `C1`…) | `01` selector |

Sending `B4` a single byte gets an acknowledgement and does nothing, which is
why Start appeared inert. Read queries sent with an empty body never answer
at all.

**`0xB5` is `GET_CHARGER_STATE`, not a heartbeat.** Earlier notes described it
as something the charger broadcasts "multiple times per minute". It broadcasts
nothing — it is a plain request/response query, and it only returns full
telemetry while a session is active. It must be polled.

**Corrected telemetry layout** for firmware V1.1.0 (33-byte payload): session
energy is at bytes 6–7 (0.01 kWh) and runtime at bytes 26–27 (seconds), not
where the older notes placed them; temperature is byte 32. The old offsets sit
at zero permanently, which is why energy, runtime and temperature never
populated.

**Reliability fixes** — resolve a real `BLEDevice` before connecting (a bare
address string raises `AttributeError: 'str' object has no attribute
'details'` on Linux, matching upstream issue #5); don't treat an idle charger's
silence as a dead link (it pushes nothing when no car is connected); serialise
all BLE exchanges, since the protocol has no pipelining.

## Troubleshooting

**Enable the debug log.** Home Assistant OS no longer writes
`config/home-assistant.log`, so this integration mirrors its own DEBUG output
to **`config/zeekr_charger.log`** (2 MB, 2 rotations):

```yaml
logger:
  logs:
    custom_components.zeekr_charger: debug
```

**A sensor is blank.** Check *Connection Status* → `rx_opcode_counts`. If the
opcode count is climbing but the sensor is empty, it's a parsing bug worth
reporting. If the opcode never appears, the charger isn't answering it.

**Some values are legitimately empty.** Voltage, current, session energy,
runtime and temperature only populate while a car is charging — the charger
doesn't report them otherwise. If WiFi is disabled on the charger
(`wifi_function_enable: 0`), the WiFi MAC and module firmware report `NULL`.

**Start doesn't resume after Stop.** Fixed in this version (the two-byte body
above). If it still happens, check the log for an `AAB4` reply.

**Connection problems.** *Connection Status* attributes show the discovered
address, reconnect count and per-opcode RX counts. Press *Force Reconnect* to
retry immediately and re-probe any opcode previously marked unsupported.

## Supported hardware

- **Tested:** single-phase 7 kW Zeekr "Nora" (`EC0000XX`), firmware V1.0 /
  software V1.1.0, via ESPHome BLE proxy.
- **Likely compatible:** other Raedian-built variants using the same protocol.
- **Untested:** 11 kW / 3-phase models. The solar controller assumes
  single-phase 230 V when converting watts to amps.

Not implemented: WiFi credential writing (`D2`), network mode (`D4`), RFID
(`D0`), meter config (`F1`/`F2`), OTA (`B9`/`BA`/`BB`). The OTA opcodes are
known but deliberately left alone — a botched firmware write bricks the unit.

## Development

Layered so the protocol is testable without hardware: `protocol.py` (pure
frame building/parsing, no HA or Bleak imports) → `ble_client.py` (transport,
session, reconnection) → coordinator and entities.

```bash
python tests/test_protocol.py          # 45 tests — framing, parsers, reassembly
python tests/test_solar_controller.py  # 17 tests — PV-diversion control logic
```

Both suites stub Home Assistant, so they run on a bare Python install. Parser
tests use payloads captured from real hardware: if you change a parser and a
test fails, the charger disagrees with you.

## Credits

Originally created by [@geoffwatts](https://github.com/geoffwatts/zeekr_evse_hass)
(MIT). Protocol corrections and reliability work contributed back from live
hardware debugging.
