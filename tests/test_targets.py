from a2aguard.checks import find_internal_leaks
from a2aguard.servers import callback_target_forbidden


def test_private_callbacks_are_forbidden_and_public_names_are_not():
    assert callback_target_forbidden("http://127.0.0.1/hook")
    assert callback_target_forbidden("http://localhost/hook")
    assert callback_target_forbidden("http://10.1.2.3/hook")
    assert callback_target_forbidden("http://192.168.0.5/hook")
    assert callback_target_forbidden("http://172.16.0.4/hook")
    assert callback_target_forbidden("http://169.254.169.254/latest")
    assert callback_target_forbidden("http://[::1]/hook")
    assert callback_target_forbidden("http://[fe80::1]/hook")
    assert callback_target_forbidden("file:///etc/passwd")
    assert callback_target_forbidden("https://callbacks.example.com/hook") is False
    assert callback_target_forbidden("http://8.8.8.8/hook") is False


def test_card_scan_ignores_the_probed_host():
    document = '{"url":"http://127.0.0.1:9/","internal":"http://10.0.0.8:5432/db"}'
    leaks = find_internal_leaks(document, allowed_host="127.0.0.1", allowed_port=9)
    assert any("10.0.0.8" in item for item in leaks)
    assert all("127.0.0.1:9" not in item for item in leaks)
