"""脱敏导出：导出前对 Token、Cookie、口令、JWT 等敏感字段做正则脱敏。

注意：自动脱敏是辅助手段，提交前仍需人工复核报告中是否残留个人数据；
原始报告只保存在教师可访问位置，不随仓库公开。
"""
from __future__ import annotations

import csv
import io
import json
import re
from typing import Optional

from . import config, db

_SECRET_PATTERNS = [
    (re.compile(r"(?i)(authorization\s*[:=]\s*)\S+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(cookie\s*[:=]\s*)\S+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(set-cookie\s*[:=]\s*)\S+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(password\s*[:=]\s*)\S+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(token\s*[:=]\s*)\S+"), r"\1[REDACTED]"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
     "[REDACTED_JWT]"),
]


def redact(text: str | None) -> str:
    if not text:
        return ""
    out = str(text)
    for pattern, repl in _SECRET_PATTERNS:
        out = pattern.sub(repl, out)
    return out


def _rows(db_path: Optional[str] = None) -> list[dict]:
    findings = db.list_findings(db_path=db_path)
    rows = []
    for f in findings:
        alerts = db.list_alerts(finding_id=f["id"], db_path=db_path)
        uris = "; ".join(a["uri"] for a in alerts)
        evidence = " | ".join(a["evidence"] for a in alerts if a["evidence"])
        rows.append(
            {
                "finding_id": f["id"],
                "fingerprint": f["fingerprint"],
                "pluginid": f["pluginid"],
                "name": redact(f["name"]),
                "risk": config.RISK_LABEL.get(f["riskcode"], str(f["riskcode"])),
                "cwe": f["cwe"],
                "status": f["status"],
                "owner": f["owner"] or "",
                "branch": f["branch"] or "",
                "commit_sha": f["commit_sha"] or "",
                "review_reason": redact(f["review_reason"] or ""),
                "uris": redact(uris),
                "evidence": redact(evidence),
            }
        )
    return rows


def export_csv(db_path: Optional[str] = None) -> str:
    rows = _rows(db_path)
    buf = io.StringIO()
    if rows:
        writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    return buf.getvalue()


def export_json(db_path: Optional[str] = None) -> str:
    return json.dumps(_rows(db_path), ensure_ascii=False, indent=2)
