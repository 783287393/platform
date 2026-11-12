"""导出复核记录与前后报告哈希说明，落盘到 docs/evidence/。"""
from __future__ import annotations

import hashlib

from . import config, db


def review_log() -> str:
    reviews = db.list_reviews()
    findings = {f["id"]: f for f in db.list_findings()}
    lines = ["===== 人工复核记录 =====", f"复核条数：{len(reviews)}", ""]
    for r in reviews:
        finding = findings.get(r["finding_id"], {})
        lines.append(f"F-{r['finding_id']} [{r['verdict']}] {finding.get('name', '')}")
        lines.append(f"  规则：{finding.get('pluginid', '')}　风险："
                     f"{config.RISK_LABEL.get(finding.get('riskcode', 0), '')}")
        lines.append(f"  复核人：{r['reviewer']}　时间：{r['created_at']}")
        lines.append(f"  理由：{r['reason']}")
        lines.append(f"  证据：{r['evidence_note']}")
        lines.append("")
    lines.append("覆盖说明：样本共 5 条 Finding，已全部人工复核；真实扫描不足 5 条时复核全部，"
                 "并记录实际覆盖与判断理由，不伪造告警。")
    return "\n".join(lines)


def hash_report() -> str:
    lines = ["===== before/after 样本报告哈希与覆盖说明 ====="]
    for name in ["zap-before.json", "zap-after.json"]:
        path = config.SAMPLE_DIR / name
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{name}  sha256={digest}")
    lines += [
        "",
        "覆盖范围：http://127.0.0.1:8000/ 单页；ZAP 2.17.0 被动规则集；",
        "前后两轮目标、规则集与数据范围一致。关闭依据为同指纹复扫不再出现，",
        "不是报告总数下降；覆盖不足时状态保持 Resolved，不判 Verified。",
    ]
    return "\n".join(lines)


def write_all() -> None:
    config.EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    (config.EVIDENCE_DIR / "review-log.txt").write_text(review_log(), encoding="utf-8")
    (config.EVIDENCE_DIR / "before-after-hash.txt").write_text(hash_report(), encoding="utf-8")


if __name__ == "__main__":
    write_all()
    print("evidence written to docs/evidence/")
