"""演示样本初始化：导入 before/after 两份脱敏样本报告，并写入复核与处置记录。

样本结构对齐 ZAP 2.17.0 Traditional JSON；真实使用时用本机 ZAP 导出的报告替换
data/samples/ 下的文件，再重新执行本脚本即可。
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Optional

from . import config, db, importer

REVIEWER = "隋圣丹"
FIX_BRANCH = "fix/security-headers"
FIX_COMMIT = "20312fd"  # fix/security-headers 分支真实 Commit 短 SHA（git rev-parse --short HEAD）


def seed(db_path: Optional[str] = None, reset: bool = True) -> dict:
    if reset:
        db.reset_db(db_path)
    db.init_db(db_path)

    before = json.loads((config.SAMPLE_DIR / "zap-before.json").read_text(encoding="utf-8"))
    after = json.loads((config.SAMPLE_DIR / "zap-after.json").read_text(encoding="utf-8"))

    before_stats = importer.import_report(
        before,
        batch_label="before-2026-11-11",
        kind="before",
        target="http://127.0.0.1:8000",
        ruleset="ZAP 2.17.0 passive rules",
        note="课前基线：被动规则 + 已知 URL 请求，不含爬虫或主动攻击",
        db_path=db_path,
    )
    after_stats = importer.import_report(
        after,
        batch_label="after-2026-11-11",
        kind="after",
        target="http://127.0.0.1:8000",
        ruleset="ZAP 2.17.0 passive rules",
        note="修复后复扫：相同目标、规则集与覆盖范围",
        db_path=db_path,
    )
    after_batch_id = after_stats["batch_id"]

    by_plugin: dict[str, dict] = {}
    for finding in db.list_findings(db_path=db_path):
        by_plugin.setdefault(finding["pluginid"], finding)

    # 10020 / 10021 / 10038：复核为真阳性，修复安全响应头后经 after 复扫关闭
    fixed = {
        "10020": "缺少 X-Frame-Options，回环页面可复现；补充响应头后复扫不再出现",
        "10021": "缺少 X-Content-Type-Options，补充 nosniff 后复扫不再出现",
        "10038": "缺少 CSP，补充与页面资源兼容的 CSP 后复扫不再出现",
    }
    for pluginid, reason in fixed.items():
        finding = by_plugin[pluginid]
        db.add_review(finding["id"], REVIEWER, "Confirmed", reason,
                      evidence_note="before 批次实例 evidence 字段可核对", db_path=db_path)
        db.update_finding(
            finding["id"],
            {
                "owner": REVIEWER,
                "status": "Verified",
                "branch": FIX_BRANCH,
                "commit_sha": FIX_COMMIT,
                "review_reason": reason,
                "rescan_batch_id": after_batch_id,
            },
            db_path=db_path,
        )

    # 10035：接受风险（本机 HTTP 演示，HSTS 仅适用 HTTPS）
    hsts = by_plugin["10035"]
    db.add_review(
        hsts["id"], REVIEWER, "Accepted Risk",
        "本机 HTTP 演示环境，HSTS 仅适用于 HTTPS；上线 HTTPS 后再评估，残余风险由负责人回看",
        evidence_note="样本站点为 http://127.0.0.1:8000", db_path=db_path,
    )
    db.update_finding(
        hsts["id"],
        {"owner": REVIEWER, "status": "Accepted Risk",
         "review_reason": "HTTP 本地演示，HSTS 不适用；记录残余风险，待 HTTPS 部署后复核"},
        db_path=db_path,
    )

    # 10096：误报（信息级 Banner 提示，教学回环环境无对外暴露）
    banner = by_plugin["10096"]
    db.add_review(
        banner["id"], REVIEWER, "False Positive",
        "信息级提示，仅回环地址访问；演示数据无对外暴露的敏感版本信息，判为误报",
        evidence_note="规则 riskcode=0（Info）", db_path=db_path,
    )
    db.update_finding(
        banner["id"],
        {"owner": REVIEWER, "status": "False Positive",
         "review_reason": "Info 级 Banner 提示，回环教学环境，判为误报并留痕"},
        db_path=db_path,
    )

    return {"before": before_stats, "after": after_stats}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="初始化演示样本数据")
    parser.add_argument("--keep", action="store_true", help="保留现有数据库，不清空")
    args = parser.parse_args()
    summary = seed(reset=not args.keep)
    print("before 批次：", summary["before"])
    print("after 批次：", summary["after"])
