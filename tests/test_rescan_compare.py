"""复扫对比测试：before/after 同协议下新增/未变/关闭分类可核对。

最低要求 2 项。
"""
import json

from core import compare, config, importer


def _report(pluginid, uri, riskcode):
    return {
        "site": [{
            "@name": uri,
            "alerts": [{
                "pluginid": pluginid, "riskcode": str(riskcode), "alert": f"rule-{pluginid}",
                "desc": "", "solution": "", "cweid": "",
                "instances": [{"uri": uri, "method": "GET", "param": "", "evidence": "e"}],
            }],
        }]
    }


def test_sample_before_after_diff(db_path):
    before = json.loads((config.SAMPLE_DIR / "zap-before.json").read_text(encoding="utf-8"))
    after = json.loads((config.SAMPLE_DIR / "zap-after.json").read_text(encoding="utf-8"))
    b1 = importer.import_report(before, "before-1", "before", db_path=db_path)
    b2 = importer.import_report(after, "after-1", "after", db_path=db_path)

    diff = compare.diff_batches(b1["batch_id"], b2["batch_id"], db_path=db_path)
    assert diff["summary"]["closed"] == 3      # 10020 / 10021 / 10038
    assert diff["summary"]["unchanged"] == 2   # 10035 / 10096
    assert diff["summary"]["new"] == 0


def test_risk_change_is_classified(db_path):
    uri = "http://127.0.0.1:8000/"
    b1 = importer.import_report(_report("10020", uri, 1), "before-1", "before", db_path=db_path)
    b2 = importer.import_report(_report("10020", uri, 2), "after-1", "after", db_path=db_path)

    diff = compare.diff_batches(b1["batch_id"], b2["batch_id"], db_path=db_path)
    assert diff["summary"]["unchanged"] == 1
    assert diff["summary"]["risk_changed"] == 1
    assert diff["risk_changed"][0]["before_risk"] == 1
    assert diff["risk_changed"][0]["after_risk"] == 2
