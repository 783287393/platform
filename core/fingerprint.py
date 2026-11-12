"""稳定指纹：规则 ID + 规范化 origin + HTTP 方法 + 路径 + 排序后的参数名。

设计取舍（见 docs/03-指纹与自主设计.md）：
- 不使用告警描述文本做指纹：文案随规则版本变化，且同一规则多处实例描述相同；
- 剔除时间戳、nonce、会话标记等易变查询值，避免同一页面被重复归并出多条 Finding；
- 路径、方法、参数名不同则绝不合并，避免把不同资源错误归并。
"""
from __future__ import annotations

import hashlib
from urllib.parse import parse_qsl, urlsplit

from . import config


def normalize_uri(uri: str) -> tuple[str, str, tuple[str, ...]]:
    """返回 (origin, path, sorted_param_names)。"""
    uri = (uri or "").strip()
    parts = urlsplit(uri)
    scheme = (parts.scheme or "http").lower()
    host = (parts.hostname or "").lower()
    port = f":{parts.port}" if parts.port else ""

    path = parts.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")

    query = sorted(
        key
        for key, _ in parse_qsl(parts.query, keep_blank_values=True)
        if key.lower() not in config.VOLATILE_PARAMS
    )
    origin = f"{scheme}://{host}{port}"
    return origin, path, tuple(query)


def make_fingerprint(pluginid: str, uri: str, method: str) -> str:
    origin, path, params = normalize_uri(uri)
    raw = "|".join(
        [
            str(pluginid).strip(),
            origin,
            path,
            (method or "GET").upper(),
            ",".join(params),
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
