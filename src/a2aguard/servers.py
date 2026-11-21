"""In-process A2A reference servers. Loopback only. Callbacks are stored, never fetched."""

from __future__ import annotations

import argparse
import json
import re
import socket
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlparse

from a2aguard.constants import (
    ABSOLUTE_MAX_BODY_BYTES,
    LAB_TOKEN_A,
    LAB_TOKEN_B,
    MAX_BODY_BYTES,
    UNKNOWN_TOKEN,
)
from a2aguard.policy import is_forbidden_callback

ALICE = LAB_TOKEN_A
BOB = LAB_TOKEN_B
BOUNDS = "a2aguard-lab-bounds"
UNKNOWN = UNKNOWN_TOKEN
LAB_TOKENS = frozenset({ALICE, BOB, BOUNDS})

BODY_LIMIT = MAX_BODY_BYTES
TASK_LIMIT = 5
ABSOLUTE_READ_CAP = ABSOLUTE_MAX_BODY_BYTES
DATA_MIMES = frozenset({"text/plain", "application/json"})
DECLARED_SKILLS = frozenset({"echo"})

_TASK_PATH = re.compile(r"^/tasks/([0-9a-f]+)$")
_CALLBACK_PATH = re.compile(r"^/tasks/([0-9a-f]+)/callback$")
_SKILL_PATH = re.compile(r"^/skills/([A-Za-z0-9._-]{1,64})$")


def callback_target_forbidden(url: str) -> bool:
    """True when a callback URL must be refused. Classification is local; nothing is fetched."""
    return is_forbidden_callback(url)


class _State:
    def __init__(self, mode: str, port: int) -> None:
        self.mode = mode
        self.port = port
        self.tasks: dict[str, dict] = {}
        self.counts: dict[str, int] = {}
        self.lock = threading.Lock()
        self.outbound_requests: list[str] = []


class _LabHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address) -> None:
        return


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "a2aguard-lab/0.1.0"

    def log_message(self, fmt: str, *args) -> None:
        return

    def handle_one_request(self) -> None:
        self.close_connection = True
        super().handle_one_request()

    @property
    def state(self) -> _State:
        return self.server.state  # type: ignore[attr-defined]

    def do_GET(self) -> None:
        path = self._path()
        if path is None:
            return
        if path == "/":
            self._send(200, {"service": "a2aguard-lab", "mode": self.state.mode})
            return
        if path == "/.well-known/agent-card.json":
            self._send(200, self._card())
            return
        task = _TASK_PATH.fullmatch(path)
        if task:
            self._get_task(task.group(1))
            return
        skill = _SKILL_PATH.fullmatch(path)
        if skill:
            self._skill(skill.group(1))
            return
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        path = self._path()
        if path is None:
            return
        if path == "/tasks":
            self._create_task()
            return
        callback = _CALLBACK_PATH.fullmatch(path)
        if callback:
            self._register_callback(callback.group(1))
            return
        skill = _SKILL_PATH.fullmatch(path)
        if skill:
            self._skill(skill.group(1))
            return
        self._send(404, {"error": "not found"})

    def _path(self) -> str | None:
        path = unquote(urlparse(self.path).path)
        if ".." in path.split("/"):
            self._send(400, {"error": "bad path"})
            return None
        return path

    def _card(self) -> dict:
        base = f"http://127.0.0.1:{self.state.port}/"
        if self.state.mode == "hardened":
            return {
                "name": "a2aguard-hardened",
                "description": "Hardened reference A2A agent used by a2aguard selftest.",
                "url": base,
                "version": "0.1.0",
                "protocolVersion": "0.3.0",
                "environment": "development",
                "capabilities": {"streaming": False, "pushNotifications": True},
                "securitySchemes": {
                    "bearer": {
                        "type": "http",
                        "scheme": "bearer",
                        "description": "Bearer token issued to the calling identity.",
                    }
                },
                "security": [{"bearer": []}],
                "defaultInputModes": ["text/plain", "application/json"],
                "defaultOutputModes": ["application/json"],
                "skills": [
                    {
                        "id": "echo",
                        "name": "Echo",
                        "description": "Store a text message as a data artifact.",
                        "tags": ["echo"],
                        "endpoint": "/skills/echo",
                    }
                ],
            }
        return {
            "name": "a2aguard-vulnerable",
            "description": "Deliberately non-compliant reference A2A agent.",
            "url": "http://10.0.0.8:5432/internal",
            "version": "0.1.0",
            "protocolVersion": "0.3.0",
            "environment": "production",
            "capabilities": {"streaming": False, "pushNotifications": True, "exec": True},
            "defaultInputModes": ["text/plain"],
            "defaultOutputModes": ["text/plain"],
            "skills": [
                {
                    "id": "echo",
                    "name": "Echo",
                    "description": "Declared skill with no implementation.",
                    "tags": ["echo"],
                    "endpoint": "/skills/echo",
                }
            ],
            "internalHostname": "db.internal",
            "metadataEndpoint": "http://169.254.169.254/latest/meta-data/",
        }

    def _identity(self) -> str | None | bool:
        """Return the token, None when the header is missing, False when it is unknown."""
        header = self.headers.get("Authorization", "")
        if self.state.mode == "vulnerable":
            if header.lower().startswith("bearer "):
                return header[7:].strip() or "anon"
            return "anon"
        if not header:
            return None
        if not header.lower().startswith("bearer "):
            return False
        token = header[7:].strip()
        if token in LAB_TOKENS:
            return token
        return False

    def _require_auth(self) -> str | None:
        if self.state.mode == "vulnerable":
            ident = self._identity()
            return ident if isinstance(ident, str) else "anon"
        ident = self._identity()
        if ident is None:
            self._send(401, {"error": "authentication required"}, www_auth=True)
            return None
        if ident is False:
            self._send(401, {"error": "unknown token"}, www_auth=True)
            return None
        return ident

    def _read_body(self) -> bytes | None:
        raw = self.headers.get("Content-Length")
        try:
            declared = int(raw) if raw is not None else None
        except ValueError:
            self._send(400, {"error": "bad content-length"})
            return None
        if declared is not None and declared < 0:
            self._send(400, {"error": "bad content-length"})
            return None
        limit = BODY_LIMIT if self.state.mode == "hardened" else ABSOLUTE_READ_CAP
        if declared is not None and declared > limit:
            # Cap the drain so a huge Content-Length cannot pin the lab.
            self._discard(min(declared, ABSOLUTE_READ_CAP))
            if self.state.mode == "hardened":
                self._send(413, {"error": "payload too large", "limit": BODY_LIMIT})
            else:
                self._send(200, {"id": uuid.uuid4().hex, "accepted": declared, "stored": False})
            return None
        to_read = declared if declared is not None else limit + 1
        data = self._read_exact(to_read)
        if self.state.mode == "hardened" and len(data) > BODY_LIMIT:
            self._send(413, {"error": "payload too large", "limit": BODY_LIMIT})
            return None
        return data

    def _read_exact(self, n: int) -> bytes:
        buf = bytearray()
        remaining = n
        while remaining > 0:
            chunk = self.rfile.read(min(65536, remaining))
            if not chunk:
                break
            buf += chunk
            remaining -= len(chunk)
        return bytes(buf)

    def _discard(self, n: int) -> None:
        remaining = n
        while remaining > 0:
            chunk = self.rfile.read(min(65536, remaining))
            if not chunk:
                break
            remaining -= len(chunk)

    def _create_task(self) -> None:
        raw = self._read_body()
        if raw is None:
            return
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else {}
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send(400, {"error": "body must be json"})
            return
        if not isinstance(payload, dict):
            self._send(400, {"error": "body must be a json object"})
            return
        owner = self._require_auth()
        if owner is None:
            return
        skill = payload.get("skill")
        artifacts = payload.get("artifacts")
        if self.state.mode == "hardened":
            if skill is not None and skill not in DECLARED_SKILLS:
                self._send(400, {"error": "undeclared capability", "skill": skill})
                return
            problem = _artifact_problem(artifacts)
            if problem:
                self._send(400, {"error": problem})
                return
            with self.state.lock:
                limit = _task_limit(owner)
                if self.state.counts.get(owner, 0) >= limit:
                    self._send(429, {"error": "task limit exceeded", "limit": limit}, retry_after=60)
                    return
                task = _new_task(owner, payload, hardened=True)
                self.state.tasks[task["id"]] = task
                self.state.counts[owner] = self.state.counts.get(owner, 0) + 1
            self._send(200, _public_task(task))
            return
        with self.state.lock:
            task = _new_task(owner, payload, hardened=False)
            self.state.tasks[task["id"]] = task
            self.state.counts[owner] = self.state.counts.get(owner, 0) + 1
        self._send(200, _public_task(task))

    def _get_task(self, task_id: str) -> None:
        owner = self._require_auth()
        if owner is None:
            return
        with self.state.lock:
            task = self.state.tasks.get(task_id)
        if task is None:
            self._send(404, {"error": "not found"})
            return
        if self.state.mode == "hardened" and task["owner"] != owner:
            self._send(403, {"error": "forbidden"})
            return
        self._send(200, _public_task(task))

    def _register_callback(self, task_id: str) -> None:
        raw = self._read_body()
        if raw is None:
            return
        owner = self._require_auth()
        if owner is None:
            return
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else {}
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send(400, {"error": "body must be json"})
            return
        if not isinstance(payload, dict) or not isinstance(payload.get("url"), str):
            self._send(400, {"error": "callback url is required"})
            return
        url = payload["url"]
        with self.state.lock:
            task = self.state.tasks.get(task_id)
        if task is None:
            self._send(404, {"error": "not found"})
            return
        if self.state.mode == "hardened" and task["owner"] != owner:
            self._send(403, {"error": "forbidden"})
            return
        if self.state.mode == "hardened" and callback_target_forbidden(url):
            self._send(400, {"error": "callback url is not allowlisted"})
            return
        with self.state.lock:
            task["callbacks"].append(url)
        self._send(200, {"registered": True, "url": url})

    def _skill(self, skill_id: str) -> None:
        if self.command == "POST":
            raw = self._read_body()
            if raw is None:
                return
        owner = self._require_auth()
        if owner is None:
            return
        if self.state.mode == "hardened":
            if skill_id not in DECLARED_SKILLS:
                self._send(400, {"error": "undeclared capability", "skill": skill_id})
                return
            self._send(200, {"skill": skill_id, "role": "data", "accepted": True})
            return
        if skill_id in DECLARED_SKILLS:
            self._send(404, {"error": "not found"})
            return
        self._send(200, {"skill": skill_id, "accepted": True})

    def _send(
        self,
        status: int,
        obj: dict,
        *,
        www_auth: bool = False,
        retry_after: int | None = None,
    ) -> None:
        data = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        if www_auth:
            self.send_header("WWW-Authenticate", "Bearer")
        if retry_after is not None:
            self.send_header("Retry-After", str(retry_after))
        if self.state.mode == "vulnerable":
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()
        self.wfile.write(data)


def _task_limit(owner: str) -> int:
    # The bounds identity is the one the cap probe fills. Other lab identities
    # keep a higher ceiling so a second local run can still create tasks.
    if owner == BOUNDS:
        return TASK_LIMIT
    return 64


def _artifact_problem(artifacts: object) -> str | None:
    if artifacts is None:
        return None
    if not isinstance(artifacts, list):
        return "artifacts must be a list"
    for item in artifacts:
        if not isinstance(item, dict):
            return "artifact must be an object"
        if item.get("mimeType") not in DATA_MIMES:
            return "artifact mimeType is not a data type"
        if not isinstance(item.get("text"), str):
            return "artifact text must be a string"
    return None


def _stored_artifacts(payload: dict, *, hardened: bool) -> list[dict]:
    raw = payload.get("artifacts")
    if not isinstance(raw, list):
        return []
    if not hardened:
        return [item for item in raw if isinstance(item, dict)]
    return [
        {"mimeType": item["mimeType"], "role": "data", "text": item["text"]}
        for item in raw
        if isinstance(item, dict)
    ]


def _instruction_text(payload: dict) -> str:
    raw = payload.get("artifacts")
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                return item["text"]
    message = payload.get("message")
    return message if isinstance(message, str) else ""


def _new_task(owner: str, payload: dict, *, hardened: bool) -> dict:
    message = payload.get("message") if isinstance(payload.get("message"), str) else ""
    task = {
        "id": uuid.uuid4().hex,
        "owner": owner,
        "status": "completed",
        "message": message,
        "artifacts": _stored_artifacts(payload, hardened=hardened),
        "callbacks": [],
    }
    if not hardened:
        task["systemInstruction"] = _instruction_text(payload)
        task["executed"] = True
    return task


def _public_task(task: dict) -> dict:
    view = {
        "id": task["id"],
        "status": task["status"],
        "message": task["message"],
        "artifacts": task["artifacts"],
    }
    if "systemInstruction" in task:
        view["systemInstruction"] = task["systemInstruction"]
        view["executed"] = task["executed"]
    return view


class LabServer:
    """HTTP lab bound to loopback. `start` returns the bound port."""

    mode = "hardened"

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        if host not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("lab servers bind loopback only")
        self.host = host
        self._httpd: _LabHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.port = port

    def start(self) -> int:
        if self._httpd is not None:
            raise RuntimeError("server already started")
        httpd = _LabHTTPServer((self.host, self.port), _Handler)
        self.port = int(httpd.server_address[1])
        httpd.state = _State(self.mode, self.port)  # type: ignore[attr-defined]
        self._httpd = httpd
        thread = threading.Thread(target=httpd.serve_forever, name=f"a2aguard-{self.mode}", daemon=True)
        thread.start()
        self._thread = thread
        self._wait_until_listening()
        return self.port

    def _wait_until_listening(self) -> None:
        host = "127.0.0.1" if self.host == "localhost" else self.host
        if host == "::1":
            host = "::1"
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                with socket.create_connection((host, self.port), timeout=0.2):
                    return
            except OSError:
                time.sleep(0.01)
        raise RuntimeError("lab server did not accept connections")

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def state(self) -> _State:
        if self._httpd is None:
            raise RuntimeError("server is not started")
        return self._httpd.state  # type: ignore[attr-defined]

    def stop(self) -> None:
        httpd = self._httpd
        if httpd is None:
            return
        httpd.shutdown()
        httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=3)
        self._httpd = None

    def __enter__(self) -> LabServer:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()


class HardenedServer(LabServer):
    mode = "hardened"


class VulnerableServer(LabServer):
    mode = "vulnerable"


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="a2aguard.servers")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--hardened", action="store_true")
    mode.add_argument("--vulnerable", action="store_true")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args(argv)
    serve("hardened" if args.hardened else "vulnerable", args.port)


def serve(mode: str, port: int) -> None:
    cls = HardenedServer if mode == "hardened" else VulnerableServer
    server = cls(port=port)
    bound = server.start()
    print(f"a2aguard lab listening on http://127.0.0.1:{bound} ({mode})", flush=True)
    try:
        if server._thread is not None:
            server._thread.join()
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()


if __name__ == "__main__":
    main()
