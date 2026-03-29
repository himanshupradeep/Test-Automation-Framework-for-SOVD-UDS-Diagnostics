"""
CAN Bus Utilities — python-can wrapper
=======================================
In this UDS project, diagnostics run over TCP (simulating DoIP).
This module shows how you would set up python-can for CAN-based UDS
using python-can + isotp + udsoncan on real hardware.

Real project flow:
    bus    = can.Bus(interface='vector', channel=0, bitrate=500_000)
    conn   = PythonIsoTpConnection(bus, rxid=0x7E8, txid=0x7DF)
    client = udsoncan.Client(conn, config={...})
    client.change_session(DiagnosticSessionControl.Session.extendedDiagnosticSession)
"""

import logging
import struct

log = logging.getLogger("CANUtils")

try:
    import can
    CAN_AVAILABLE = True
except ImportError:
    CAN_AVAILABLE = False
    can = None


# ── Standard UDS addressing ────────────────────────────────────────────────────
class CANAddr:
    UDS_FUNCTIONAL  = 0x7DF   # Functional (broadcast) — used for discovery
    UDS_PHYSICAL    = 0x7E0   # Physical (target ECU)  — used for diagnostics
    UDS_RESPONSE    = 0x7E8   # ECU → tester response


def create_virtual_bus(channel: str = "vcan0") -> "can.Bus | None":
    """Open a virtual CAN bus (no hardware required)."""
    if not CAN_AVAILABLE:
        log.warning("python-can not installed — CAN features disabled")
        return None
    bus = can.Bus(channel=channel, interface="virtual")
    log.info("Virtual CAN bus on channel '%s'", channel)
    return bus


def create_vector_bus(channel: int = 0, bitrate: int = 500_000) -> "can.Bus | None":
    """
    Open a Vector CANalyzer / CANcase hardware interface.
    Requires Vector XL driver installed on Windows.
    """
    if not CAN_AVAILABLE:
        return None
    try:
        bus = can.Bus(interface="vector", channel=channel, bitrate=bitrate)
        log.info("Vector CAN bus on channel %d @ %d bps", channel, bitrate)
        return bus
    except Exception as exc:
        log.error("Vector bus failed: %s", exc)
        return None


# ── udsoncan usage example ─────────────────────────────────────────────────────
UDSONCAN_EXAMPLE = """
# How to use udsoncan with python-can on real hardware:

import can
import udsoncan
from udsoncan.connections import PythonIsoTpConnection
from udsoncan.client import Client

# 1. Open CAN bus
bus = can.Bus(interface='vector', channel=0, bitrate=500_000)

# 2. Create ISO-TP transport connection
conn = PythonIsoTpConnection(
    bus,
    rxid=0x7E8,    # ECU response CAN ID
    txid=0x7DF,    # Tester request CAN ID
)

# 3. Configure UDS client
config = {
    'exception_on_negative_response': True,
    'exception_on_invalid_response':  True,
    'security_algo': my_seed_key_function,  # OEM-specific
    'p2_timeout': 1,
    'p2_star_timeout': 5,
}

# 4. Run diagnostic tests
with Client(conn, config=config) as client:
    # Session
    client.change_session(udsoncan.services.DiagnosticSessionControl.Session.extendedDiagnosticSession)

    # Security
    client.unlock_security_access(level=1)

    # Read VIN
    result = client.read_data_by_identifier(0xF190)
    vin = result.service_data.values[0xF190].raw_value.decode()

    # Write coding value
    client.write_data_by_identifier(0x0101, bytes([80]))

    # Read DTCs
    dtcs = client.get_dtc_by_status_mask(0xFF)
    for dtc in dtcs.dtcs:
        print(f"DTC: {dtc.id:#08x} status={dtc.status.byte:#04x}")

    # Clear DTCs
    client.clear_dtc(group_of_dtc=0xFFFFFF)
"""
