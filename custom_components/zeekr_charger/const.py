"""Constants for the Zeekr Charger integration."""

from __future__ import annotations

DOMAIN = "zeekr_charger"

CONFIG_FLOW_VERSION = 1

# Config entry data
CONF_SERIAL = "serial"
CONF_DEVICE_ADDRESS = "device_address"

# Options
CONF_SOLAR_GRID_POWER_ENTITY = "solar_grid_power_entity"
CONF_SOLAR_BATTERY_SOC_ENTITY = "solar_battery_soc_entity"
CONF_GRID_POWER_INVERTED = "grid_power_inverted"
CONF_RESPONSE_TIMEOUT = "response_timeout"
CONF_RECONNECT_MAX_ATTEMPTS = "reconnect_max_attempts"
CONF_RECONNECT_INITIAL_DELAY = "reconnect_initial_delay"
CONF_RECONNECT_MAX_DELAY = "reconnect_max_delay"
CONF_HEARTBEAT_STALE_THRESHOLD = "heartbeat_stale_threshold"

# Polling
DEFAULT_SCAN_INTERVAL = 15  # seconds between coordinator refresh cycles
HEARTBEAT_SEND_INTERVAL = 20  # seconds between client-sent 0xB5 keep-alives

# BLE request/response timeout. This was raised to 30s when replies appeared
# to take that long, but that was the notify-flush behaviour, not latency:
# every measured reply arrives 0.089-0.315s after a write. With nudging every
# 2s a reply lands within ~2.5s of the request, so 12s allows several nudge
# attempts while failing fast instead of stalling the whole poll cycle.
# User-tunable.
DEFAULT_RESPONSE_TIMEOUT = 12.0
AUTH_RESPONSE_TIMEOUT = 20.0

# Telemetry (0xB5) is only answered while a charging session is active. When
# idle it never replies, so a long timeout just stalls every poll cycle for
# nothing. Replies land ~0.2s after a nudge, so a few nudge attempts is ample.
TELEMETRY_RESPONSE_TIMEOUT = 6.0

# A response that misses its window is still good data — cache it this long so
# the next request for that opcode can use it instead of re-paying the wait.
LATE_RESPONSE_MAX_AGE = 180.0

# This charger does not deliver a queued notification until another write
# arrives — measured on real hardware, a 0xB0 reply sat undelivered for 31s
# and landed 0.2s after the next heartbeat went out. So while waiting for a
# response we poke it at this interval to flush the reply out.
RESPONSE_NUDGE_INTERVAL = 2.0

# Reconnection defaults (user-tunable via options)
DEFAULT_RECONNECT_MAX_ATTEMPTS = 10
DEFAULT_RECONNECT_INITIAL_DELAY = 5.0
DEFAULT_RECONNECT_MAX_DELAY = 300.0

# The GATT link can stay nominally "connected" while the charger goes silent.
# If nothing (heartbeat or any notification) arrives within this window we
# force a full disconnect+reconnect cycle. Heartbeats are sent every
# HEARTBEAT_SEND_INTERVAL, so 90s tolerates a few missed cycles.
DEFAULT_HEARTBEAT_STALE_THRESHOLD = 120.0

# Charge rate limits
MIN_CHARGE_RATE = 6  # Amps — minimum viable EVSE current per IEC 61851
DEFAULT_MAX_CHARGE_RATE = 32  # fallback when live grid capacity is unavailable

# Solar-surplus (PV diversion) charging
# Assumed single-phase AU mains voltage, used to convert surplus watts to amps.
# Only validated against single-phase chargers; 3-phase installs would need
# this divided across phases.
SOLAR_ASSUMED_VOLTAGE = 230
SOLAR_DEFAULT_POLL_INTERVAL = 60  # seconds between control-loop ticks ("gentle")
SOLAR_DEFAULT_STEP_A = 2  # max amps the loop moves the limit per tick
SOLAR_DEFAULT_BATTERY_PRIORITY_SOC = 80  # % home battery SOC before EV gets surplus

# Debounce windows before pausing/resuming charging on insufficient surplus,
# so passing clouds don't flap the session.
SOLAR_PAUSE_DEBOUNCE_SECONDS = 300
SOLAR_RESUME_DEBOUNCE_SECONDS = 60
