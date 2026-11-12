"""本地被测示例页面（仅用于本机授权环境的 ZAP 被动检查演示）。

用法：
    python web/target_app.py --port 8000             # 修复前：不带安全响应头
    python web/target_app.py --port 8000 --headers   # 修复后：带 CSP / X-Frame-Options / X-Content-Type-Options

注意：这是本人可修改的本地演示页面，不是 Juice Shop 靶场；靶场内置漏洞不计入本人修复成果。
"""
from __future__ import annotations

import argparse
import http.server
import socketserver

PAGE_MARKER = "vuln-lab-target"

PAGE = f"""<!doctype html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>实验07 本地示例</title></head>
<body>
  <h1>本地演示页面</h1>
  <p>marker={PAGE_MARKER}</p>
  <p>本页面仅用于 ZAP 被动规则演示，不包含真实账号与个人数据。</p>
</body>
</html>"""

# 修复前基线：尚未配置 CSP / X-Frame-Options / X-Content-Type-Options 安全响应头。


def build_headers(add_headers: bool) -> dict[str, str]:
    """回归测试直接调用：返回响应头字典。"""
    return {"Content-Type": "text/html; charset=utf-8"}


def render_page() -> str:
    return PAGE


class DemoHandler(http.server.BaseHTTPRequestHandler):
    add_headers: bool = False

    def do_GET(self) -> None:
        body = PAGE.encode("utf-8")
        self.send_response(200)
        for key, value in build_headers(self.add_headers).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:  # 静默访问日志
        pass


def main() -> None:
    parser = argparse.ArgumentParser(description="实验07 本地被测示例")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--headers", action="store_true", help="携带安全响应头（修复后）")
    args = parser.parse_args()
    DemoHandler.add_headers = args.headers
    with socketserver.TCPServer(("127.0.0.1", args.port), DemoHandler) as httpd:
        print(f"target on http://127.0.0.1:{args.port}  headers={args.headers}")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
