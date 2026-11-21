import socket

from a2aguard.checks import ALL_CHECKS, run_suite

REQUIRED = [
    "card_hygiene",
    "auth_required",
    "auth_rejects_unknown_token",
    "task_isolation",
    "input_bounds",
    "callback_allowlist",
    "capability_honesty",
    "artifact_is_data",
]


def test_required_checks_are_present():
    names = [check.name for check in ALL_CHECKS]
    for name in REQUIRED:
        assert name in names


def test_every_check_discriminates(labs):
    hardened, vulnerable = labs
    hard = {item.name: item for item in run_suite(hardened.base_url)}
    weak = {item.name: item for item in run_suite(vulnerable.base_url)}
    for check in ALL_CHECKS:
        assert hard[check.name].passed is True, f"{check.name} hardened: {hard[check.name].evidence}"
        assert weak[check.name].passed is False, f"{check.name} vulnerable passed: {weak[check.name].evidence}"
        assert hard[check.name].severity
        assert hard[check.name].remediation
        assert weak[check.name].evidence


def test_probes_stay_on_localhost(labs, monkeypatch):
    hardened, vulnerable = labs
    seen: list[tuple] = []
    real = socket.create_connection

    def spy(address, *args, **kwargs):
        seen.append(address if isinstance(address, tuple) else (address,))
        return real(address, *args, **kwargs)

    # Python 3.14 copies socket.create_connection onto each HTTPConnection.
    monkeypatch.setattr(socket, "create_connection", spy)
    run_suite(hardened.base_url)
    run_suite(vulnerable.base_url)
    assert seen, "checks opened no sockets"
    for address in seen:
        assert address[0] in {"127.0.0.1", "localhost", "::1"}, address
