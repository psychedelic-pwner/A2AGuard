import http.client

from a2aguard.checks import BODY_LIMIT
from a2aguard.servers import (
    ALICE,
    BOB,
    UNKNOWN,
    VulnerableServer,
    callback_target_forbidden,
)
from a2aguard.transport import request


def test_bind_is_loopback_only():
    import pytest

    with pytest.raises(ValueError, match="loopback"):
        VulnerableServer(host="0.0.0.0")


def test_hardened_enforces_the_lab_contract(labs):
    hardened, _vulnerable = labs
    base = hardened.base_url
    card = request("GET", f"{base}/.well-known/agent-card.json", retries=0)
    assert card.status == 200
    body = card.json()
    assert isinstance(body, dict)
    assert body["securitySchemes"]["bearer"]["scheme"] == "bearer"
    assert "access-control-allow-origin" not in card.headers
    assert "10.0.0.8" not in card.text
    assert "169.254.169.254" not in card.text

    open_post = request("POST", f"{base}/tasks", body={"message": "x"}, retries=0)
    assert open_post.status == 401
    unknown = request(
        "POST",
        f"{base}/tasks",
        headers={"Authorization": f"Bearer {UNKNOWN}"},
        body={"message": "x"},
        retries=0,
    )
    assert unknown.status == 401

    created = request(
        "POST",
        f"{base}/tasks",
        headers={"Authorization": f"Bearer {ALICE}"},
        body={"message": "secret-a"},
        retries=0,
    )
    assert created.status == 200
    task_id = created.json()["id"]
    peer = request(
        "GET",
        f"{base}/tasks/{task_id}",
        headers={"Authorization": f"Bearer {BOB}"},
        retries=0,
    )
    assert peer.status == 403
    owner = request(
        "GET",
        f"{base}/tasks/{task_id}",
        headers={"Authorization": f"Bearer {ALICE}"},
        retries=0,
    )
    assert owner.status == 200
    assert "secret-a" in owner.text

    big = {"message": "A" * (BODY_LIMIT + 100)}
    over = request(
        "POST",
        f"{base}/tasks",
        headers={"Authorization": f"Bearer {ALICE}"},
        body=big,
        retries=0,
    )
    assert over.status == 413

    for url in (
        "http://127.0.0.1:9/hook",
        "http://10.1.2.3/hook",
        "http://169.254.169.254/latest",
        "http://[::1]/hook",
    ):
        assert callback_target_forbidden(url), url
        resp = request(
            "POST",
            f"{base}/tasks/{task_id}/callback",
            headers={"Authorization": f"Bearer {ALICE}"},
            body={"url": url},
            retries=0,
        )
        assert resp.status == 400, url
    assert hardened.state.outbound_requests == []


def test_vulnerable_is_open(labs):
    _hardened, vulnerable = labs
    base = vulnerable.base_url
    card = request("GET", f"{base}/.well-known/agent-card.json", retries=0)
    parsed = card.json()
    assert "securitySchemes" not in parsed
    assert "10.0.0.8" in card.text
    assert "169.254.169.254" in card.text
    assert card.headers.get("access-control-allow-origin") == "*"
    assert card.headers.get("access-control-allow-credentials") == "true"

    created = request("POST", f"{base}/tasks", body={"message": "secret-v"}, retries=0)
    assert created.status == 200
    task_id = created.json()["id"]
    peer = request(
        "GET",
        f"{base}/tasks/{task_id}",
        headers={"Authorization": f"Bearer {BOB}"},
        retries=0,
    )
    assert peer.status == 200
    assert "secret-v" in peer.text

    over = request("POST", f"{base}/tasks", body={"message": "B" * (BODY_LIMIT + 100)}, retries=0)
    assert over.status == 200
    hooked = request(
        "POST",
        f"{base}/tasks/{task_id}/callback",
        body={"url": "http://169.254.169.254/latest"},
        retries=0,
    )
    assert hooked.status == 200
    assert vulnerable.state.outbound_requests == []


def test_lab_speaks_http_on_the_bound_port(labs):
    hardened, _vulnerable = labs
    conn = http.client.HTTPConnection("127.0.0.1", hardened.port, timeout=2)
    try:
        conn.request("GET", "/.well-known/agent-card.json")
        resp = conn.getresponse()
        raw = resp.read()
    finally:
        conn.close()
    assert resp.status == 200
    assert b"bearer" in raw
    assert b"10.0.0." not in raw
