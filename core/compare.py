"""before/after 批次按指纹对比：新增 / 未变 / 已关闭 / 风险变化。

关闭判定前提：after 批次覆盖了 before 的目标页面（见 docs/08-未做与限制.md）。
覆盖不足时不能仅凭“规则不再出现”判修复，状态应保持 Resolved 而非 Verified。
"""
from __future__ import annotations

from typing import Optional

from . import db


def diff_batches(before_id: int, after_id: int,
                 db_path: Optional[str] = None) -> dict:
    before = db.fingerprints_in_batch(before_id, db_path=db_path)
    after = db.fingerprints_in_batch(after_id, db_path=db_path)

    before_fps = set(before)
    after_fps = set(after)

    closed = sorted(before_fps - after_fps)
    new = sorted(after_fps - before_fps)
    unchanged = sorted(before_fps & after_fps)

    risk_changed = []
    for fp in unchanged:
        if before[fp]["riskcode"] != after[fp]["riskcode"]:
            risk_changed.append(
                {
                    "fingerprint": fp,
                    "name": after[fp]["name"],
                    "before_risk": before[fp]["riskcode"],
                    "after_risk": after[fp]["riskcode"],
                }
            )

    return {
        "before_batch": before_id,
        "after_batch": after_id,
        "new": [after[fp] for fp in new],
        "closed": [before[fp] for fp in closed],
        "unchanged": [after[fp] for fp in unchanged],
        "risk_changed": risk_changed,
        "summary": {
            "new": len(new),
            "closed": len(closed),
            "unchanged": len(unchanged),
            "risk_changed": len(risk_changed),
        },
    }
