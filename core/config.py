"""全局配置：路径、白名单、状态机、风险等级与已知规则说明。"""
from __future__ import annotations

import os
from pathlib import Path

# ---------- 路径 ----------
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
SAMPLE_DIR = DATA_DIR / "samples"
DOCS_DIR = BASE_DIR / "docs"
EVIDENCE_DIR = DOCS_DIR / "evidence"

DB_PATH = Path(os.environ.get("APP_DB_PATH", str(DATA_DIR / "security.db")))

# ---------- 授权白名单 ----------
# 仅本机回环与课程组明确添加的 Compose 服务名；公网域名、RFC1918 私网地址
# 都不会自动进入白名单，必须在 scope.md 中由批准人明确登记。
WHITELIST_HOSTS = {"localhost", "127.0.0.1", "host.docker.internal"}
ALLOWED_SCHEMES = {"http", "https"}

# ---------- 风险等级（对齐 ZAP riskcode） ----------
RISK_LABEL = {0: "Info", 1: "Low", 2: "Medium", 3: "High"}
RISK_CODE = {v: k for k, v in RISK_LABEL.items()}

# ---------- 漏洞状态机 ----------
STATUSES = [
    "New",
    "Confirmed",
    "False Positive",
    "Accepted Risk",
    "In Progress",
    "Resolved",
    "Verified",
]
OPEN_STATUSES = {"New", "Confirmed", "In Progress", "Resolved"}
CLOSED_STATUSES = {"Verified", "False Positive", "Accepted Risk"}

# 只有满足证据条件才允许进入 Verified（见 db.transition_finding）
VERIFIED_REQUIRES = {"commit_sha", "rescan_batch_id"}

# ---------- 已知规则说明（名称以 ZAP 2.17.0 Traditional JSON 为准） ----------
RULE_INFO: dict[str, tuple[str, str]] = {
    "10020": (
        "Missing Anti-clickjacking Header",
        "缺少 X-Frame-Options 响应头，页面可能被嵌入 iframe 造成点击劫持",
    ),
    "10021": (
        "X-Content-Type-Options Header Missing",
        "缺少 X-Content-Type-Options 响应头，浏览器可能对响应内容做 MIME 嗅探",
    ),
    "10038": (
        "Content Security Policy Header Not Set",
        "未设置 Content Security Policy 响应头，缺少脚本与资源来源约束",
    ),
    "10035": (
        "Strict-Transport-Security Header Not Set",
        "未设置 HSTS；HSTS 仅适用于 HTTPS，本机 HTTP 演示不适用",
    ),
    "10096": (
        "Banner/Information Disclosure",
        "信息泄露类提示，需结合页面可达性与业务影响人工判断",
    ),
}

# 指纹规范化时剔除的易变查询参数（随机值、会话标记）
VOLATILE_PARAMS = {
    "timestamp", "ts", "t", "nonce", "sid", "sessionid", "token", "_", "rnd", "rand",
}
