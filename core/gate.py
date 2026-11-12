"""扫描前授权门禁：目标 URL 必须命中白名单，否则在发起任何请求前拒绝并记录。

注意：本模块只做初始目标校验。若后续发生重定向，跳转目标必须再次过同一门禁，
不能因为初始 URL 已授权就假定后续访问也获授权（见 docs/01-授权范围.md）。
"""
from __future__ import annotations

from urllib.parse import urlsplit

from . import config


def check_target(raw_url: str) -> dict:
    """校验目标是否在授权范围内。

    返回 dict: allowed / reason / normalized / host。
    """
    result: dict = {"allowed": False, "reason": "", "normalized": "", "host": ""}
    url = (raw_url or "").strip()
    if not url:
        result["reason"] = "地址为空"
        return result

    try:
        parts = urlsplit(url)
    except ValueError as exc:
        result["reason"] = f"URL 解析失败：{exc}"
        return result

    if not parts.scheme:
        result["reason"] = "缺少协议头（仅允许 http/https）"
        return result
    if parts.scheme.lower() not in config.ALLOWED_SCHEMES:
        result["reason"] = f"协议 {parts.scheme} 不在允许范围"
        return result

    host = (parts.hostname or "").lower()
    if not host:
        result["reason"] = "无法解析主机名"
        return result
    if parts.username or parts.password:
        result["reason"] = "地址中不允许携带用户名/密码信息"
        return result

    result["host"] = host
    if host not in config.WHITELIST_HOSTS:
        result["reason"] = (
            f"主机 {host} 不在白名单；仅允许 {sorted(config.WHITELIST_HOSTS)}，"
            "公网域名与未登记私网地址一律拒绝"
        )
        return result

    result["allowed"] = True
    result["normalized"] = parts._replace(fragment="").geturl()
    return result


def check_redirect(from_url: str, to_url: str) -> dict:
    """校验重定向目标：跳转地址必须同样命中白名单。"""
    dest = check_target(to_url)
    if not dest["allowed"]:
        dest["reason"] = f"重定向到非授权目标：{dest['reason']}"
    dest["from"] = from_url
    return dest
