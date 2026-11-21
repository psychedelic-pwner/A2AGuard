"""Local security checks for A2A-shaped agent HTTP servers."""

__version__ = "0.1.0"

from a2aguard.checks import ALL_CHECKS, Check, Result, run_suite
from a2aguard.servers import HardenedServer, VulnerableServer

__all__ = [
    "ALL_CHECKS",
    "Check",
    "HardenedServer",
    "Result",
    "VulnerableServer",
    "run_suite",
    "__version__",
]
