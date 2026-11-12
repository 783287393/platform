"""范围安全测试：白名单、协议、私网/公网目标、重定向越界。

最低要求 6 项，覆盖未授权目标在扫描前被拒绝。
"""
from core import gate


def test_localhost_allowed():
    result = gate.check_target("http://localhost:8000/")
    assert result["allowed"] is True
    assert result["host"] == "localhost"


def test_loopback_ip_allowed():
    result = gate.check_target("http://127.0.0.1:8000/login")
    assert result["allowed"] is True


def test_docker_internal_allowed():
    result = gate.check_target("http://host.docker.internal:3000")
    assert result["allowed"] is True


def test_public_domain_rejected():
    result = gate.check_target("https://example.com/login")
    assert result["allowed"] is False
    assert "不在白名单" in result["reason"]


def test_private_rfc1918_not_auto_authorized():
    # RFC1918 私网地址不会自动视为已授权，必须明确登记进白名单
    result = gate.check_target("http://192.168.1.20:8080/")
    assert result["allowed"] is False


def test_non_http_scheme_rejected():
    result = gate.check_target("file:///etc/passwd")
    assert result["allowed"] is False


def test_malformed_url_rejected():
    result = gate.check_target("not-a-url")
    assert result["allowed"] is False


def test_redirect_to_external_rejected():
    result = gate.check_redirect("http://127.0.0.1:8000/", "https://evil.example.com/")
    assert result["allowed"] is False
    assert "重定向到非授权目标" in result["reason"]
