"""工作流测试：状态、负责人、处置理由与 Verified 证据约束。

最低要求 6 项；只有有证据记录才可 Verified。
"""
import pytest

from core import db, importer


def _one_finding(db_path, pluginid="10020", uri="http://127.0.0.1:8000/"):
    data = {
        "site": [{
            "@name": uri,
            "alerts": [{
                "pluginid": pluginid, "riskcode": "2", "alert": "demo",
                "desc": "", "solution": "", "cweid": "103",
                "instances": [{"uri": uri, "method": "GET", "param": "", "evidence": "e"}],
            }],
        }]
    }
    importer.import_report(data, "before-1", "before", db_path=db_path)
    return db.list_findings(db_path=db_path)[0]


def test_new_finding_starts_as_new(db_path):
    finding = _one_finding(db_path)
    assert finding["status"] == "New"


def test_transition_to_confirmed_persists(db_path):
    finding = _one_finding(db_path)
    updated = db.update_finding(finding["id"], {"status": "Confirmed"}, db_path=db_path)
    assert updated["status"] == "Confirmed"


def test_owner_status_reason_persisted(db_path):
    finding = _one_finding(db_path)
    updated = db.update_finding(
        finding["id"],
        {"owner": "stu", "status": "In Progress", "review_reason": "回环页面可复现"},
        db_path=db_path,
    )
    assert updated["owner"] == "stu"
    assert updated["status"] == "In Progress"
    assert updated["review_reason"] == "回环页面可复现"


def test_verified_rejected_without_commit(db_path):
    finding = _one_finding(db_path)
    with pytest.raises(ValueError, match="Commit"):
        db.update_finding(
            finding["id"], {"status": "Verified", "rescan_batch_id": 1}, db_path=db_path,
        )


def test_verified_rejected_without_rescan_batch(db_path):
    finding = _one_finding(db_path)
    with pytest.raises(ValueError, match="复扫批次"):
        db.update_finding(
            finding["id"], {"status": "Verified", "commit_sha": "a1b2c3d"}, db_path=db_path,
        )


def test_verified_accepted_with_commit_and_rescan(db_path):
    finding = _one_finding(db_path)
    after_stats = importer.import_report(
        {"site": []}, "after-1", "after", db_path=db_path,
    )
    updated = db.update_finding(
        finding["id"],
        {"status": "Verified", "commit_sha": "a1b2c3d", "branch": "fix/h",
         "rescan_batch_id": after_stats["batch_id"]},
        db_path=db_path,
    )
    assert updated["status"] == "Verified"
    db.add_review(finding["id"], "stu", "Confirmed", "修复后复扫不再出现", db_path=db_path)
    reviews = db.list_reviews(finding["id"], db_path=db_path)
    assert reviews[0]["verdict"] == "Confirmed"
