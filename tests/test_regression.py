"""修复回归测试：安全头按模式出现/缺失，且页面功能不退化。

最低要求 3 项：问题关闭且原功能不退化。
"""
from web.target_app import PAGE_MARKER, build_headers, render_page


def test_security_headers_present_after_fix():
    headers = build_headers(add_headers=True)
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert "Content-Security-Policy" in headers


def test_security_headers_absent_before_fix():
    headers = build_headers(add_headers=False)
    assert "X-Frame-Options" not in headers
    assert "Content-Security-Policy" not in headers


def test_page_content_not_broken_by_fix():
    page = render_page()
    assert PAGE_MARKER in page
    assert "<h1>" in page
