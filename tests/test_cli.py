import json

from a2aguard.checks import Result
from a2aguard.cli import classify_exit, main

REQUIRED = (
    "card_hygiene",
    "auth_required",
    "auth_rejects_unknown_token",
    "task_isolation",
    "input_bounds",
    "callback_allowlist",
    "capability_honesty",
    "artifact_is_data",
)


def test_checks_lists_every_name(capsys):
    assert main(["checks"]) == 0
    out = capsys.readouterr().out
    for name in REQUIRED:
        assert name in out


def test_selftest_matrix(capsys):
    assert main(["selftest"]) == 0
    out = capsys.readouterr().out
    assert "hardened" in out and "vulnerable" in out
    assert "discrimination: ok" in out
    for name in REQUIRED:
        assert name in out
    for line in out.splitlines():
        if not line or line.startswith("check") or line.startswith("discrimination"):
            continue
        parts = line.split()
        assert parts[1] == "PASS", line
        assert parts[2] == "FAIL", line


def test_run_json_and_fail_on(labs, capsys):
    hardened, vulnerable = labs
    assert main(["run", hardened.base_url, "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["target"] == hardened.base_url
    assert all(item["passed"] is True for item in payload["results"])
    names = {item["name"] for item in payload["results"]}
    assert set(REQUIRED) <= names

    assert main(["run", vulnerable.base_url, "--fail-on", "high"]) == 1
    text = capsys.readouterr().out
    assert "auth_required" in text
    assert "FAIL" in text


def test_fail_on_threshold():
    results = [
        Result("low-one", False, "low", "evidence", "fix"),
        Result("high-one", True, "high", "evidence", "fix"),
    ]
    assert classify_exit(results, "info") == 1
    assert classify_exit(results, "low") == 1
    assert classify_exit(results, "medium") == 0
    assert classify_exit(results, "critical") == 0
    assert classify_exit([Result("ok", True, "high", "e", "r")], "info") == 0


def test_refuses_remote_target_without_connecting(monkeypatch, capsys):
    def blocked(*_args, **_kwargs):
        raise AssertionError("run must not connect to a non-local host")

    monkeypatch.setattr("a2aguard.cli.request", blocked)
    code = main(["run", "http://example.com/agent"])
    err = capsys.readouterr().err
    assert code == 2
    assert "warning:" in err
    assert "non-local" in err
    assert "example.com" in err


def test_allow_remote_prints_responsible_use_notice(monkeypatch, capsys):
    from a2aguard.transport import TransportError

    def blocked(*_args, **_kwargs):
        raise TransportError("stopped before the network")

    monkeypatch.setattr("a2aguard.cli.request", blocked)
    code = main(["run", "http://203.0.113.5/agent", "--allow-remote", "--timeout", "0.2"])
    err = capsys.readouterr().err
    assert code == 2
    assert "responsible-use notice" in err
    assert "203.0.113.5" in err
    assert "allowed to test" in err


def test_lab_requires_a_mode():
    import pytest

    with pytest.raises(SystemExit) as caught:
        main(["lab"])
    assert caught.value.code != 0
