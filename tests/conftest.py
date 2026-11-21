import pytest

from a2aguard.servers import HardenedServer, VulnerableServer


@pytest.fixture
def labs():
    hardened = HardenedServer()
    vulnerable = VulnerableServer()
    hardened.start()
    vulnerable.start()
    try:
        yield hardened, vulnerable
    finally:
        hardened.stop()
        vulnerable.stop()
