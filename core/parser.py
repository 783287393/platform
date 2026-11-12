"""ZAP 2.17.0 Traditional JSON 报告解析。

实测结构：site[] -> alerts[] -> instances[]。
规则字段：pluginid / riskcode / alert(name) / desc / solution / cweid；
实例位置字段：uri / method / param / evidence。

注意：不能假设每条 alert 顶层有一个 url，多处实例必须逐实例取 uri；
API 的 alerts 视图与报告导出格式不完全相同，本解析器只对应 Traditional JSON。
"""
from __future__ import annotations

import html
import re
from html.parser import HTMLParser


class _TextExtractor(HTMLParser):
    """把描述/建议中的 HTML 标签剥离为纯文本，避免扫描证据被当作可信 HTML 执行。"""

    def __init__(self) -> None:
        super().__init__()
        self._parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self._parts.append(data)

    def get_text(self) -> str:
        return "".join(self._parts)


def clean_html(text: str | None) -> str:
    if not text:
        return ""
    extractor = _TextExtractor()
    try:
        extractor.feed(str(text))
    except (ValueError, TypeError):
        pass
    unescaped = html.unescape(extractor.get_text())
    return re.sub(r"\s+", " ", unescaped).strip()


def _as_int(value) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return 0


def parse_zap_report(data: dict) -> list[dict]:
    """把 Traditional JSON 解析为扁平的告警实例列表。"""
    alerts: list[dict] = []
    sites = data.get("site") or []

    for site in sites:
        site_name = site.get("@name") or ""
        for alert in site.get("alerts") or []:
            instances = alert.get("instances") or []
            # 兼容个别规则只挂站点级信息、没有实例数组的情况
            if not instances:
                instances = [
                    {"uri": site_name, "method": "GET", "param": "", "evidence": ""}
                ]

            for inst in instances:
                alerts.append(
                    {
                        "pluginid": str(alert.get("pluginid", "")).strip(),
                        "riskcode": _as_int(alert.get("riskcode", 0)),
                        "name": clean_html(alert.get("alert") or alert.get("name") or ""),
                        "desc": clean_html(alert.get("desc") or ""),
                        "solution": clean_html(alert.get("solution") or ""),
                        "cwe": str(alert.get("cweid") or alert.get("cwe") or "").strip(),
                        "uri": (inst.get("uri") or site_name or "").strip(),
                        "method": (inst.get("method") or "GET").upper(),
                        "param": (inst.get("param") or "").strip(),
                        "evidence": clean_html(inst.get("evidence") or ""),
                    }
                )
    return alerts
