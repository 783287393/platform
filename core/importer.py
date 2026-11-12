"""报告导入：解析 -> 稳定指纹 -> 去重归并 -> 留存本次出现实例。

重复导入同一报告：已存在的 Finding 只追加出现历史，不重复创建；
本次是否再次出现由 alerts 表中的批次记录体现。
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Optional

from . import db, fingerprint, parser


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def import_report(data: dict, batch_label: str, kind: str,
                  source_file: str = "", target: str = "", ruleset: str = "",
                  note: str = "", db_path: Optional[Path | str] = None) -> dict:
    alerts = parser.parse_zap_report(data)

    sha256 = ""
    if source_file and Path(source_file).exists():
        sha256 = _sha256_file(Path(source_file))

    batch_id = db.add_batch(
        label=batch_label, kind=kind, source_file=source_file, target=target,
        ruleset=ruleset, note=note, sha256=sha256, db_path=db_path,
    )

    stats = {"alerts": len(alerts), "new_findings": 0, "repeat_findings": 0,
             "alerts_linked": 0}

    for alert in alerts:
        fp = fingerprint.make_fingerprint(alert["pluginid"], alert["uri"], alert["method"])
        finding = db.find_by_fingerprint(fp, db_path=db_path)
        if finding is None:
            finding_id = db.insert_finding(fp, alert, batch_id, db_path=db_path)
            stats["new_findings"] += 1
        else:
            db.touch_finding(finding["id"], batch_id, alert["riskcode"], db_path=db_path)
            finding_id = finding["id"]
            stats["repeat_findings"] += 1
        db.add_alert(finding_id, batch_id, alert, db_path=db_path)
        stats["alerts_linked"] += 1

    stats["batch_id"] = batch_id
    return stats


def import_json_file(file_path: str | Path, batch_label: str, kind: str,
                     target: str = "", ruleset: str = "", note: str = "",
                     db_path: Optional[Path | str] = None) -> dict:
    import json

    path = Path(file_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    return import_report(
        data, batch_label=batch_label, kind=kind, source_file=str(path),
        target=target, ruleset=ruleset, note=note, db_path=db_path,
    )
