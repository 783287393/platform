"""解析 / 去重测试：缺字段、重复、路径参数、批次留存与误合并反例。

最低要求 8 项，覆盖导入稳定且不错误增殖。
"""
import json

from core import config, fingerprint, importer, parser

BEFORE = json.loads((config.SAMPLE_DIR / "zap-before.json").read_text(encoding="utf-8"))


def _report(pluginid, uri, method="GET", riskcode=1, desc="<p>hi <b>x</b></p>"):
    alert = {
        "pluginid": pluginid, "riskcode": str(riskcode), "alert": f"rule-{pluginid}",
        "desc": desc, "solution": "fix it", "cweid": "",
        "instances": [{"uri": uri, "method": method, "param": "", "evidence": "e"}],
    }
    return {"site": [{"@name": uri, "alerts": [alert]}]}


def test_parse_three_level_structure():
    alerts = parser.parse_zap_report(BEFORE)
    # 10020 有 2 个实例，其余 4 条规则各 1 个实例，共 6 条
    assert len(alerts) == 6
    assert {a["pluginid"] for a in alerts} == {"10020", "10021", "10038", "10035", "10096"}


def test_missing_fields_do_not_crash():
    data = {"site": [{"@name": "http://127.0.0.1:8000", "alerts": [{}]}]}
    alerts = parser.parse_zap_report(data)
    assert len(alerts) == 1
    assert alerts[0]["pluginid"] == ""
    assert alerts[0]["riskcode"] == 0


def test_instance_uri_fallback_without_top_level_url():
    data = {"site": [{"@name": "http://127.0.0.1:8000/", "alerts": [
        {"pluginid": "10020", "riskcode": "2", "instances": []}
    ]}]}
    alerts = parser.parse_zap_report(data)
    assert alerts[0]["uri"] == "http://127.0.0.1:8000/"


def test_html_desc_is_sanitized_to_plain_text():
    alerts = parser.parse_zap_report(
        _report("10020", "http://127.0.0.1:8000/", desc="<p>Use <code>X-Frame-Options</code> &amp; CSP</p>")
    )
    text = alerts[0]["desc"]
    assert "<" not in text and ">" not in text
    assert "X-Frame-Options" in text and "&" in text


def test_same_fingerprint_in_one_batch_is_one_finding(db_path):
    data = _report("10020", "http://127.0.0.1:8000/")
    data["site"][0]["alerts"][0]["instances"] = [
        {"uri": "http://127.0.0.1:8000/", "method": "GET", "param": "", "evidence": "e1"},
        {"uri": "http://127.0.0.1:8000/", "method": "GET", "param": "", "evidence": "e2"},
    ]
    stats = importer.import_report(data, "b1", "before", db_path=db_path)
    assert stats["new_findings"] == 1
    assert stats["alerts_linked"] == 2


def test_repeated_import_does_not_duplicate_finding(db_path):
    first = importer.import_report(BEFORE, "before-1", "before", db_path=db_path)
    second = importer.import_report(BEFORE, "before-2", "before", db_path=db_path)
    assert second["new_findings"] == 0
    assert second["repeat_findings"] == first["alerts"]
    # 出现历史保留在 alerts 表中
    from core import db
    assert len(db.list_alerts(db_path=db_path)) == first["alerts"] * 2


def test_volatile_query_params_are_normalized():
    fp1 = fingerprint.make_fingerprint("10020", "http://127.0.0.1:8000/login?ts=1&sid=a", "GET")
    fp2 = fingerprint.make_fingerprint("10020", "http://127.0.0.1:8000/login?ts=2&sid=b", "GET")
    assert fp1 == fp2


def test_different_path_or_method_is_not_merged():
    fp_root = fingerprint.make_fingerprint("10020", "http://127.0.0.1:8000/", "GET")
    fp_login = fingerprint.make_fingerprint("10020", "http://127.0.0.1:8000/login", "GET")
    fp_post = fingerprint.make_fingerprint("10020", "http://127.0.0.1:8000/", "POST")
    assert fp_root != fp_login
    assert fp_root != fp_post
