"""Command line for a2aguard."""

from __future__ import annotations

import argparse
import json
import sys
from urllib.parse import urlparse

from a2aguard import __version__
from a2aguard.checks import ALL_CHECKS, Result, all_transport_failures, run_suite
from a2aguard.servers import ALICE, BOB, BOUNDS, HardenedServer, VulnerableServer, serve
from a2aguard.transport import RemoteRefused, TransportError, is_loopback_url, request

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.cmd == "checks":
        return _cmd_checks()
    if args.cmd == "run":
        return _cmd_run(args)
    if args.cmd == "lab":
        mode = "hardened" if args.hardened else "vulnerable"
        serve(mode, args.port)
        return 0
    if args.cmd == "selftest":
        return _cmd_selftest()
    parser.error(f"unknown command {args.cmd}")
    return 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="a2aguard", description="A2A protocol hygiene checks")
    parser.add_argument("--version", action="version", version=f"a2aguard {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("checks", help="list checks")

    run = sub.add_parser("run", help="run every check against one server")
    run.add_argument("url")
    run.add_argument("--json", action="store_true", help="print a JSON report")
    run.add_argument("--sarif", action="store_true", help="print a SARIF 2.1.0 report")
    run.add_argument(
        "--fail-on",
        default="info",
        dest="fail_on",
        choices=list(SEVERITY_RANK),
        help="lowest severity that causes exit 1 (default: info, any failure)",
    )
    run.add_argument(
        "--allow-remote",
        action="store_true",
        help="allow a non-loopback target and print a responsible-use notice",
    )
    run.add_argument("--token", default=ALICE, help="bearer token for the primary identity")
    run.add_argument("--peer-token", default=BOB, help="bearer token for the second identity")
    run.add_argument("--bounds-token", default=BOUNDS, help="bearer token used by the task-cap probe")
    run.add_argument("--timeout", type=float, default=2.0)

    lab = sub.add_parser("lab", help="serve a reference agent on 127.0.0.1")
    mode = lab.add_mutually_exclusive_group(required=True)
    mode.add_argument("--hardened", action="store_true")
    mode.add_argument("--vulnerable", action="store_true")
    lab.add_argument("--port", type=int, default=8080)

    sub.add_parser("selftest", help="prove hardened passes and vulnerable fails")
    return parser


def _cmd_checks() -> int:
    width = max(len(check.name) for check in ALL_CHECKS)
    for check in ALL_CHECKS:
        print(f"{check.name:<{width}}  {check.severity:<8}  {check.description}")
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    if args.json and args.sarif:
        print("error: choose only one of --json or --sarif", file=sys.stderr)
        return 2
    if not is_loopback_url(args.url):
        if not args.allow_remote:
            _warn_refused(args.url)
            return 2
        _warn_allow_remote(args.url)
    try:
        request("GET", _join(args.url, "/.well-known/agent-card.json"), timeout=args.timeout, retries=0)
    except TransportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    try:
        results = run_suite(
            args.url,
            timeout=args.timeout,
            allow_remote=args.allow_remote,
            token=args.token,
            peer_token=args.peer_token,
            bounds_token=args.bounds_token,
        )
    except RemoteRefused:
        _warn_refused(args.url)
        return 2
    if all_transport_failures(results):
        print("error: target did not answer the checks", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(_json_report(args.url, results), indent=2))
    elif args.sarif:
        print(json.dumps(_sarif_report(args.url, results), indent=2))
    else:
        print(_table(results))
    return classify_exit(results, args.fail_on)


def _cmd_selftest() -> int:
    hardened = HardenedServer()
    vulnerable = VulnerableServer()
    try:
        hardened.start()
        vulnerable.start()
        hardened_results = run_suite(hardened.base_url)
        vulnerable_results = run_suite(vulnerable.base_url)
    except (TransportError, OSError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        hardened.stop()
        vulnerable.stop()
    print(_matrix(hardened_results, vulnerable_results))
    ok = all(item.passed for item in hardened_results) and all(not item.passed for item in vulnerable_results)
    if ok:
        print("discrimination: ok")
        return 0
    print("discrimination: failed", file=sys.stderr)
    _print_failures("hardened", hardened_results)
    _print_failures("vulnerable", vulnerable_results)
    return 1


def classify_exit(results: list[Result], fail_on: str) -> int:
    threshold = SEVERITY_RANK[fail_on]
    for item in results:
        if item.passed:
            continue
        if SEVERITY_RANK.get(item.severity, 0) >= threshold:
            return 1
    return 0


def _print_failures(label: str, results: list[Result]) -> None:
    for item in results:
        unexpected = (label == "hardened" and not item.passed) or (label == "vulnerable" and item.passed)
        if unexpected:
            print(f"{label} {item.name}: {item.evidence}", file=sys.stderr)


def _warn_refused(url: str) -> None:
    print(
        f"warning: refusing non-local target {url}. "
        "Pass --allow-remote only for a host you are authorized to test.",
        file=sys.stderr,
    )


def _warn_allow_remote(url: str) -> None:
    host = urlparse(url).hostname or url
    print(
        "warning: responsible-use notice: --allow-remote set; "
        f"hygiene probes will be sent to {host}. "
        "Use this only on a server you operate or are allowed to test. "
        "Checks create and read tasks and submit callback URLs. They do not request those URLs.",
        file=sys.stderr,
    )


def _join(base_url: str, path: str) -> str:
    return base_url.rstrip("/") + path


def _table(results: list[Result]) -> str:
    name_w = max(len("check"), *(len(item.name) for item in results))
    lines = [f"{'check':<{name_w}}  result  severity  evidence"]
    for item in results:
        status = "PASS" if item.passed else "FAIL"
        evidence = item.evidence.replace("\n", " ")
        lines.append(f"{item.name:<{name_w}}  {status:<6}  {item.severity:<8}  {evidence}")
    return "\n".join(lines)


def _matrix(hardened: list[Result], vulnerable: list[Result]) -> str:
    vuln = {item.name: item.passed for item in vulnerable}
    name_w = max(len("check"), *(len(item.name) for item in hardened))
    lines = [f"{'check':<{name_w}}  hardened  vulnerable"]
    for item in hardened:
        other = vuln.get(item.name, False)
        lines.append(
            f"{item.name:<{name_w}}  {'PASS' if item.passed else 'FAIL':<8}  {'PASS' if other else 'FAIL'}"
        )
    return "\n".join(lines)


def _json_report(target: str, results: list[Result]) -> dict:
    return {
        "target": target,
        "results": [
            {
                "name": item.name,
                "passed": item.passed,
                "severity": item.severity,
                "evidence": item.evidence,
                "remediation": item.remediation,
            }
            for item in results
        ],
    }


def _sarif_report(target: str, results: list[Result]) -> dict:
    rules = [
        {
            "id": check.name,
            "shortDescription": {"text": check.description},
            "help": {"text": check.remediation},
            "defaultConfiguration": {"level": _sarif_level(check.severity)},
        }
        for check in ALL_CHECKS
    ]
    sarif_results = []
    for item in results:
        sarif_results.append(
            {
                "ruleId": item.name,
                "level": "none" if item.passed else _sarif_level(item.severity),
                "kind": "pass" if item.passed else "fail",
                "message": {"text": item.evidence if item.passed else f"{item.evidence} Fix: {item.remediation}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": target}}}],
            }
        )
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "a2aguard",
                        "version": __version__,
                        "informationUri": "https://a2a-protocol.org",
                        "rules": rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }


def _sarif_level(severity: str) -> str:
    if severity in {"high", "critical"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"
