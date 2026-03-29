"""
conftest.py — shared pytest fixtures
=====================================
ECU starts once per session (session scope).
Client reconnects fresh per test (function scope).
ECU state resets to defaults before every test.
"""

import logging
import time
import pytest

from services.mock_ecu import MockECU
from services.uds_client import UDSClient
from services.uds_constants import DiagSession, DTCStatus

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s  %(levelname)-7s  %(name)s  %(message)s",
    datefmt="%H:%M:%S",
)


@pytest.fixture(scope="session")
def ecu():
    """Start the mock ECU once for the entire test session."""
    server = MockECU()
    server.start()
    time.sleep(0.1)
    yield server
    server.stop()


@pytest.fixture
def client(ecu):
    """
    Fresh UDS client + clean ECU state for every single test.
    The ECU is reset to known defaults so tests never depend on each other.
    """
    # Reset ECU to known defaults
    from services.uds_constants import DiagSession
    ecu.state.session           = DiagSession.DEFAULT
    ecu.state.security_unlocked = False
    ecu.state.pending_seed      = 0
    ecu.state.failed_attempts   = 0
    ecu.state.lockout_until     = 0.0
    ecu.state.audio_volume_max  = 80
    ecu.state.display_brightness = 70
    ecu.state.language_code     = 0x01
    ecu.state.speed_limit_kmh   = 130
    ecu.state.dtcs              = {}
    ecu.state.last_tester_present = __import__("time").monotonic()

    with UDSClient() as c:
        yield c


@pytest.fixture
def extended_client(client, ecu):
    """
    Client pre-configured in extended session with security unlocked.
    Convenience fixture for tests that only care about coding / DID write.
    """
    client.set_session(DiagSession.EXTENDED)
    client.unlock_security()
    yield client
