"""Protocol-hygiene checks. Each check is one assertion, with evidence and a fix."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from a2aguard.servers import ALICE, BOB, BOUNDS, UNKNOWN
from a2aguard.transport import RemoteRefused, Response, TransportError, assert_local, request

BODY_LIMIT = 64 * 1024
TASK_PROBE_CEILING = 12
MARKER = "status note 42"
TIMEOUT = 2.0

_URL_RE = re.compile(r"https?://[^\s\"'\\<>]+")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SENSITIVE_PORTS = frozenset(
    {22, 23, 25, 2375, 2376, 2379, 2380, 3306, 5432, 5672, 6379, 9200, 9300, 11211, 27017, 6443, 10250, 10255}
)
_INTERNAL_SUFFIXES = (".internal", ".local", ".corp", ".lan", ".home", ".localhost")
_INTERNAL_NAMES = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    "metadata.internal",
    "host.docker.internal",
}
_INSTRUCTION_KEYS = {
    "system",
    "systeminstruction",
    "systemprompt",
    "instruction",
    "instructions",
}
_DEV_ENVIRONMENTS = {"dev", "development", "local"}
_PRIVATE_CALLBACKS = (
    "http://127.0.0.1:9/hook",
    "http://10.0.0.5/hook",
    "http://192.168.1.5/hook",
    "http://172.16.0.5/hook",
    "http://169.254.169.254/latest",
    "http://[::1]/hook",
)


@dataclass(frozen=True)
class Result:
    name: str
    passed: bool
    severity: str
    evidence: str
    remediation: str


class Check:
    """One hygiene check. Call it with a base URL."""

    name: str
    description: str
    severity: str
    remediation: str

    def __call__(
        self,
        base_url: str,
        *,
        timeout: float = TIMEOUT,
        allow_remote: bool = False,
        token: str = ALICE,
        peer_token: str = BOB,
        bounds_token: str = BOUNDS,
    ) -> Result:
        assert_local(base_url, allow_remote=allow_remote)
        return self.run(
            base_url,
            timeout=timeout,
            allow_remote=allow_remote,
            token=token,
            peer_token=peer_token,
            bounds_token=bounds_token,
        )

    def run(self, base_url: str, **kwargs: object) -> Result:
        raise NotImplementedError

    def _ok(self, evidence: str) -> Result:
        return Result(self.name, True, self.severity, evidence, self.remediation)

    def _bad(self, evidence: str) -> Result:
        return Result(self.name, False, self.severity, evidence, self.remediation)


def _join(base_url: str, path: str) -> str:
    return base_url.rstrip("/") + path


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _call(
    method: str,
    url: str,
    *,
    timeout: float,
    headers: dict[str, str] | None = None,
    body: object = None,
) -> Response:
    return request(method, url, headers=headers, body=body, timeout=timeout, retries=1)


def _host_is_leak(host: str, allowed_host: str) -> bool:
    host = host.lower().rstrip(".")
    allowed = allowed_host.lower().rstrip(".")
    if host == allowed:
        return False
    if host in _INTERNAL_NAMES or any(host.endswith(suffix) for suffix in _INTERNAL_SUFFIXES):
        return True
    if "metadata" in host:
        return True
    try:
        import ipaddress

        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or not ip.is_global
    )


def find_internal_leaks(document: str, *, allowed_host: str, allowed_port: int | None) -> list[str]:
    leaks: list[str] = []
    seen: set[str] = set()

    def add(item: str) -> None:
        if item not in seen:
            seen.add(item)
            leaks.append(item)

    for match in _URL_RE.findall(document):
        parsed = urlparse(match)
        host = parsed.hostname
        if host is None:
            continue
        if _host_is_leak(host, allowed_host):
            add(match)
            continue
        if (
            parsed.port
            and allowed_port
            and parsed.port != allowed_port
            and parsed.port in _SENSITIVE_PORTS
        ):
            add(match)
    for match in _IP_RE.findall(document):
        if _host_is_leak(match, allowed_host):
            add(match)
    return leaks


def _instruction_leak(obj: object, marker: str) -> bool:
    if isinstance(obj, dict):
        for key, value in obj.items():
            normalized = str(key).lower().replace("-", "").replace("_", "")
            if normalized in _INSTRUCTION_KEYS and marker in json.dumps(value):
                return True
            if normalized == "executed" and value is True:
                return True
            if _instruction_leak(value, marker):
                return True
    elif isinstance(obj, list):
        return any(_instruction_leak(item, marker) for item in obj)
    return False


def _explicitly_protected(card: dict, base_url: str) -> bool:
    if urlparse(base_url).scheme == "https":
        return True
    card_url = card.get("url")
    if isinstance(card_url, str) and card_url.startswith("https://"):
        return True
    if str(card.get("environment", "")).lower() in _DEV_ENVIRONMENTS:
        return True
    return card.get("dev") is True


class CardHygiene(Check):
    name = "card_hygiene"
    severity = "high"
    description = "Agent card is reachable, declares auth, and does not leak internal hosts or wildcard CORS."
    remediation = (
        "Serve /.well-known/agent-card.json over HTTPS or mark the card environment as development. "
        "Declare securitySchemes and security. Remove internal hostnames, private addresses, and "
        "service ports. Do not send Access-Control-Allow-Origin: * together with credentials."
    )

    def run(self, base_url: str, **kwargs: object) -> Result:
        timeout = float(kwargs.get("timeout", TIMEOUT))
        failures: list[str] = []
        response = _call(
            "GET",
            _join(base_url, "/.well-known/agent-card.json"),
            timeout=timeout,
            headers={"Origin": "https://evil.example"},
        )
        card: dict | None = None
        if response.status != 200:
            failures.append(f"card status {response.status}")
        else:
            try:
                parsed = response.json()
            except json.JSONDecodeError:
                parsed = None
                failures.append("card is not json")
            if not isinstance(parsed, dict):
                failures.append("card is not a json object")
            else:
                card = parsed
        if card is not None:
            if not _explicitly_protected(card, base_url):
                failures.append("neither HTTPS nor an explicit development marker")
            schemes = card.get("securitySchemes")
            security = card.get("security")
            if not isinstance(schemes, dict) or not schemes or not isinstance(security, list) or not security:
                failures.append("auth schemes are missing")
            parsed_url = urlparse(base_url)
            leaks = find_internal_leaks(
                response.text,
                allowed_host=parsed_url.hostname or "",
                allowed_port=parsed_url.port,
            )
            if leaks:
                failures.append("internal host or port leaked: " + ", ".join(leaks[:4]))
        origin = response.headers.get("access-control-allow-origin", "")
        credentials = response.headers.get("access-control-allow-credentials", "")
        if origin.strip() == "*" and credentials.strip().lower() == "true":
            failures.append("CORS allows any origin with credentials")
        if failures:
            return self._bad("; ".join(failures))
        return self._ok(
            "agent card is reachable and declares auth without internal leaks or credentialed wildcard CORS"
        )


class AuthRequired(Check):
    name = "auth_required"
    severity = "high"
    description = "Task creation rejects a request that has no Authorization header."
    remediation = "Require Authorization: Bearer before creating a task. Respond 401 or 403 and do not store the task."

    def run(self, base_url: str, **kwargs: object) -> Result:
        timeout = float(kwargs.get("timeout", TIMEOUT))
        response = _call("POST", _join(base_url, "/tasks"), timeout=timeout, body={"message": "ping"})
        if response.status in {401, 403}:
            return self._ok(f"POST /tasks without credentials returned {response.status}")
        return self._bad(f"POST /tasks without credentials returned {response.status}")


class AuthRejectsUnknownToken(Check):
    name = "auth_rejects_unknown_token"
    severity = "high"
    description = "Task creation rejects a bearer token the server did not issue."
    remediation = "Keep an allowlist of issued tokens. Unknown bearer values must get 401 or 403, not a new task."

    def run(self, base_url: str, **kwargs: object) -> Result:
        timeout = float(kwargs.get("timeout", TIMEOUT))
        response = _call(
            "POST",
            _join(base_url, "/tasks"),
            timeout=timeout,
            headers=_bearer(UNKNOWN),
            body={"message": "ping"},
        )
        if response.status in {401, 403}:
            return self._ok(f"unknown bearer returned {response.status}")
        return self._bad(f"unknown bearer returned {response.status}")


class TaskIsolation(Check):
    name = "task_isolation"
    severity = "high"
    description = "One identity cannot read a task that belongs to another identity."
    remediation = "Bind each task to the authenticated identity. Return 403 or 404 when the caller is not the owner."

    def run(self, base_url: str, **kwargs: object) -> Result:
        timeout = float(kwargs.get("timeout", TIMEOUT))
        token = str(kwargs.get("token", ALICE))
        peer = str(kwargs.get("peer_token", BOB))
        created = _call(
            "POST",
            _join(base_url, "/tasks"),
            timeout=timeout,
            headers=_bearer(token),
            body={"message": "isolation probe"},
        )
        if created.status not in {200, 201}:
            return self._bad(f"owner could not create a task: {created.status}")
        try:
            task_id = str(created.json()["id"])  # type: ignore[index]
        except (json.JSONDecodeError, KeyError, TypeError):
            return self._bad("create response did not include a task id")
        owner_view = _call(
            "GET",
            _join(base_url, f"/tasks/{task_id}"),
            timeout=timeout,
            headers=_bearer(token),
        )
        peer_view = _call(
            "GET",
            _join(base_url, f"/tasks/{task_id}"),
            timeout=timeout,
            headers=_bearer(peer),
        )
        if owner_view.status != 200:
            return self._bad(f"owner read returned {owner_view.status}; peer read returned {peer_view.status}")
        if peer_view.status in {401, 403, 404}:
            return self._ok(f"owner read 200; peer read {peer_view.status}")
        return self._bad(f"peer read returned {peer_view.status}")


class InputBounds(Check):
    name = "input_bounds"
    severity = "medium"
    description = "Oversized task payloads are rejected with 4xx and are not stored."
    remediation = (
        f"Reject task bodies larger than {BODY_LIMIT} bytes with 413 before parsing or storing them. "
        "Do not answer 5xx."
    )

    def run(self, base_url: str, **kwargs: object) -> Result:
        timeout = float(kwargs.get("timeout", TIMEOUT))
        token = str(kwargs.get("token", ALICE))
        payload = {"message": "A" * (BODY_LIMIT + 4096)}
        response = _call(
            "POST",
            _join(base_url, "/tasks"),
            timeout=timeout,
            headers=_bearer(token),
            body=payload,
        )
        if response.status in {401, 403}:
            return self._bad(f"size probe was blocked by auth ({response.status}); provide a valid --token")
        if 400 <= response.status < 500:
            return self._ok(f"oversized payload returned {response.status}")
        return self._bad(f"oversized payload returned {response.status}")


class TaskBounds(Check):
    name = "task_bounds"
    severity = "medium"
    description = "A per-identity task cap refuses further creates instead of growing without a limit."
    remediation = (
        f"Enforce a per-identity queue cap at or below {TASK_PROBE_CEILING} open tasks and respond 429. "
        "The suite sends at most that many creates on the bounds token."
    )

    def run(self, base_url: str, **kwargs: object) -> Result:
        timeout = float(kwargs.get("timeout", TIMEOUT))
        token = str(kwargs.get("bounds_token", BOUNDS))
        accepted = 0
        last = 0
        for index in range(TASK_PROBE_CEILING):
            response = _call(
                "POST",
                _join(base_url, "/tasks"),
                timeout=timeout,
                headers=_bearer(token),
                body={"message": f"bounds-{index}"},
            )
            last = response.status
            if response.status == 429:
                if accepted == 0:
                    return self._ok("task creation is already refused with 429")
                return self._ok(f"accepted {accepted} tasks then returned 429")
            if 200 <= response.status < 300:
                accepted += 1
                continue
            if response.status in {401, 403}:
                return self._bad(f"bounds token was rejected ({response.status})")
            return self._bad(f"unexpected status {response.status} while probing task limits")
        return self._bad(f"created {accepted} tasks with no 429 (last status {last})")


class CallbackAllowlist(Check):
    name = "callback_allowlist"
    severity = "high"
    description = "Callback registration refuses loopback, private, and link-local URLs."
    remediation = (
        "Allowlist callback URLs. Reject loopback, private, link-local, and metadata addresses with 400. "
        "Store the URL only. Do not fetch it from the request path."
    )

    def run(self, base_url: str, **kwargs: object) -> Result:
        timeout = float(kwargs.get("timeout", TIMEOUT))
        token = str(kwargs.get("token", ALICE))
        created = _call(
            "POST",
            _join(base_url, "/tasks"),
            timeout=timeout,
            headers=_bearer(token),
            body={"message": "callback probe"},
        )
        if created.status not in {200, 201}:
            return self._bad(f"could not create a task to attach a callback: {created.status}")
        try:
            task_id = str(created.json()["id"])  # type: ignore[index]
        except (json.JSONDecodeError, KeyError, TypeError):
            return self._bad("create response did not include a task id")
        accepted: list[str] = []
        for callback in _PRIVATE_CALLBACKS:
            response = _call(
                "POST",
                _join(base_url, f"/tasks/{task_id}/callback"),
                timeout=timeout,
                headers=_bearer(token),
                body={"url": callback},
            )
            if response.status < 400 or response.status >= 500:
                accepted.append(f"{callback} -> {response.status}")
        if accepted:
            return self._bad("private callback accepted: " + "; ".join(accepted))
        return self._ok(f"all {len(_PRIVATE_CALLBACKS)} private or loopback callbacks were rejected")


class CapabilityHonesty(Check):
    name = "capability_honesty"
    severity = "medium"
    description = "Every declared skill endpoint exists, and an undeclared capability is rejected."
    remediation = (
        "Publish only skills the server implements, and reject unknown skill ids with 4xx on both "
        "/skills/{id} and task creation."
    )

    def run(self, base_url: str, **kwargs: object) -> Result:
        timeout = float(kwargs.get("timeout", TIMEOUT))
        token = str(kwargs.get("token", ALICE))
        card_response = _call("GET", _join(base_url, "/.well-known/agent-card.json"), timeout=timeout)
        try:
            card = card_response.json()
        except json.JSONDecodeError:
            return self._bad(f"agent card status {card_response.status} is not json")
        if not isinstance(card, dict):
            return self._bad("agent card is not a json object")
        skills = card.get("skills")
        if not isinstance(skills, list) or not skills:
            return self._bad("agent card declares no skills")
        problems: list[str] = []
        for skill in skills:
            if not isinstance(skill, dict) or not skill.get("id"):
                problems.append("skill entry is missing an id")
                continue
            skill_id = str(skill["id"])
            endpoint = skill.get("endpoint") or f"/skills/{skill_id}"
            target = _same_host_endpoint(base_url, str(endpoint))
            if target is None:
                problems.append(f"skill {skill_id} endpoint is not on this host")
                continue
            response = _call(
                "POST",
                target,
                timeout=timeout,
                headers=_bearer(token),
                body={"input": "ping"},
            )
            if response.status >= 400:
                problems.append(f"declared skill {skill_id} returned {response.status}")
        undeclared_skill = _call(
            "POST",
            _join(base_url, "/skills/a2aguard-undeclared"),
            timeout=timeout,
            headers=_bearer(token),
            body={"input": "ping"},
        )
        undeclared_task = _call(
            "POST",
            _join(base_url, "/tasks"),
            timeout=timeout,
            headers=_bearer(token),
            body={"message": "ping", "skill": "a2aguard-undeclared"},
        )
        if undeclared_skill.status < 400 or undeclared_skill.status >= 500:
            problems.append(f"undeclared /skills route returned {undeclared_skill.status}")
        if undeclared_task.status < 400 or undeclared_task.status >= 500:
            problems.append(f"undeclared task skill returned {undeclared_task.status}")
        if problems:
            return self._bad("; ".join(problems))
        return self._ok("declared skills responded and undeclared capabilities were rejected")


class ArtifactIsData(Check):
    name = "artifact_is_data"
    severity = "high"
    description = "Text artifacts are type-checked and stored as data, not copied into an instruction path."
    remediation = (
        "Require a data mimeType, store the artifact with role=data, and reject missing or non-data types with 4xx. "
        "Do not copy artifact text into a system or instruction field and do not mark it executed."
    )

    def run(self, base_url: str, **kwargs: object) -> Result:
        timeout = float(kwargs.get("timeout", TIMEOUT))
        token = str(kwargs.get("token", ALICE))
        problems: list[str] = []
        created = _call(
            "POST",
            _join(base_url, "/tasks"),
            timeout=timeout,
            headers=_bearer(token),
            body={"message": "store", "artifacts": [{"mimeType": "text/plain", "text": MARKER}]},
        )
        if created.status not in {200, 201}:
            return self._bad(f"typed artifact was not accepted: {created.status}")
        try:
            created_body = created.json()
            task_id = str(created_body["id"])  # type: ignore[index]
        except (json.JSONDecodeError, KeyError, TypeError):
            return self._bad("typed artifact response did not include a task id")
        fetched = _call(
            "GET",
            _join(base_url, f"/tasks/{task_id}"),
            timeout=timeout,
            headers=_bearer(token),
        )
        try:
            fetched_body = fetched.json()
        except json.JSONDecodeError:
            fetched_body = {}
        if _instruction_leak(created_body, MARKER) or _instruction_leak(fetched_body, MARKER):
            problems.append("artifact text was copied into an instruction field or marked executed")
        artifacts = fetched_body.get("artifacts") if isinstance(fetched_body, dict) else None
        if not isinstance(artifacts, list) or not artifacts:
            problems.append("artifact was not stored")
        else:
            first = artifacts[0]
            if not isinstance(first, dict) or first.get("mimeType") != "text/plain" or first.get("role") != "data":
                problems.append("stored artifact is missing a data mimeType or role")
            elif first.get("text") != MARKER:
                problems.append("stored artifact text does not match what was submitted")
        missing = _call(
            "POST",
            _join(base_url, "/tasks"),
            timeout=timeout,
            headers=_bearer(token),
            body={"message": "store", "artifacts": [{"text": MARKER}]},
        )
        if missing.status < 400 or missing.status >= 500:
            problems.append(f"missing mimeType returned {missing.status}")
        rejected = _call(
            "POST",
            _join(base_url, "/tasks"),
            timeout=timeout,
            headers=_bearer(token),
            body={
                "message": "store",
                "artifacts": [{"mimeType": "application/x-executable", "text": MARKER}],
            },
        )
        if rejected.status < 400 or rejected.status >= 500:
            problems.append(f"non-data mimeType returned {rejected.status}")
        if problems:
            return self._bad("; ".join(problems))
        return self._ok("typed artifact stored as data; untyped and non-data artifacts rejected")


def _same_host_endpoint(base_url: str, endpoint: str) -> str | None:
    if endpoint.startswith("/") and not endpoint.startswith("//"):
        return _join(base_url, endpoint)
    parsed = urlparse(endpoint)
    base = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        return None
    if parsed.hostname.lower() != (base.hostname or "").lower():
        return None
    if parsed.port != base.port:
        return None
    return endpoint


card_hygiene = CardHygiene()
auth_required = AuthRequired()
auth_rejects_unknown_token = AuthRejectsUnknownToken()
task_isolation = TaskIsolation()
input_bounds = InputBounds()
task_bounds = TaskBounds()
callback_allowlist = CallbackAllowlist()
capability_honesty = CapabilityHonesty()
artifact_is_data = ArtifactIsData()

ALL_CHECKS: list[Check] = [
    card_hygiene,
    auth_required,
    auth_rejects_unknown_token,
    task_isolation,
    input_bounds,
    task_bounds,
    callback_allowlist,
    capability_honesty,
    artifact_is_data,
]


def run_checks(base_url: str, **kwargs: object) -> list[Result]:
    """Run every check. Transport failures become failed results. Remote refusal still raises."""
    assert_local(base_url, allow_remote=bool(kwargs.get("allow_remote", False)))
    results: list[Result] = []
    for check in ALL_CHECKS:
        try:
            results.append(check(base_url, **kwargs))  # type: ignore[arg-type]
        except RemoteRefused:
            raise
        except TransportError as exc:
            results.append(Result(check.name, False, check.severity, f"transport error: {exc}", check.remediation))
        except Exception as exc:  # noqa: BLE001 — one bad check must not hide the rest
            results.append(
                Result(
                    check.name,
                    False,
                    check.severity,
                    f"check error: {type(exc).__name__}: {exc}",
                    check.remediation,
                )
            )
    return results


run_suite = run_checks


def all_transport_failures(results: list[Result]) -> bool:
    return bool(results) and all(item.evidence.startswith("transport error:") for item in results)
