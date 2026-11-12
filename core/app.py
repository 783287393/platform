"""Streamlit 漏洞管理平台主界面。

页面：概览 / 授权范围 / 报告导入 / 漏洞复核 / 复扫对比 / 证据链 / 导出说明。
运行：streamlit run core/app.py（项目根目录下执行）。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import compare, config, db, exporter, gate, importer  # noqa: E402

st.set_page_config(page_title="实验07 · 漏洞管理平台", layout="wide", page_icon="🛡")

# ---------- 初始化 ----------
db.init_db()

if "gate_log" not in st.session_state:
    st.session_state.gate_log = []


def risk_label(code: int) -> str:
    return config.RISK_LABEL.get(code, str(code))


def findings_df() -> pd.DataFrame:
    rows = db.list_findings()
    if not rows:
        return pd.DataFrame()
    return pd.DataFrame(
        [
            {
                "ID": f["id"],
                "规则": f["pluginid"],
                "告警名称": f["name"],
                "风险": risk_label(f["riskcode"]),
                "CWE": f["cwe"],
                "状态": f["status"],
                "负责人": f["owner"] or "—",
                "Commit": f["commit_sha"] or "—",
                "首次批次": f["first_batch_id"],
                "最近批次": f["last_batch_id"],
            }
            for f in rows
        ]
    )


# ---------- 侧边栏导航 ----------
page = st.sidebar.radio(
    "功能导航",
    ["概览 Dashboard", "授权范围门禁", "报告导入", "漏洞复核与处置",
     "复扫对比", "证据链追踪", "导出与说明"],
)

st.sidebar.caption("实验 07 · 软件安全检测与漏洞管理平台\n仅本机回环环境使用，不扫描未授权目标")

# =====================================================================
# 1. 概览 Dashboard
# =====================================================================
if page == "概览 Dashboard":
    st.title("软件安全检测与漏洞管理平台")
    st.caption("ZAP 2.17.0 被动扫描 · Streamlit + SQLite · 授权门禁 / 指纹去重 / 修复复扫闭环")

    st.warning(
        "**法律与范围警告**：本平台仅用于本人本地、教师授权或专门靶场环境的被动检查。"
        "扫描前必须通过白名单门禁；未授权的公网资产一律不得扫描。扫描告警不等于安全结论，"
        "剩余风险如实展示，不宣称应用已无漏洞。"
    )

    findings = db.list_findings()
    batches = db.list_batches()

    col1, col2, col3, col4 = st.columns(4)
    open_count = sum(1 for f in findings if f["status"] in config.OPEN_STATUSES)
    closed_count = sum(1 for f in findings if f["status"] in config.CLOSED_STATUSES)
    reviewed = sum(1 for f in findings if f["status"] != "New")
    col1.metric("Finding 总数", len(findings))
    col2.metric("未关闭", open_count)
    col3.metric("已关闭 / 处置", closed_count)
    col4.metric("已人工复核", reviewed)

    st.subheader("风险分布")
    if findings:
        risk_counts = pd.Series(
            [risk_label(f["riskcode"]) for f in findings]
        ).value_counts().reindex(["High", "Medium", "Low", "Info"], fill_value=0)
        st.bar_chart(risk_counts)
    else:
        st.info("暂无数据，请先在「报告导入」页导入 before 样本报告。")

    st.subheader("状态分布")
    if findings:
        status_counts = pd.Series([f["status"] for f in findings]).value_counts()
        st.bar_chart(status_counts)

    if len(batches) >= 2:
        st.subheader("前后批次对比概览")
        before_b = next((b for b in batches if b["kind"] == "before"), batches[0])
        after_b = next((b for b in batches if b["kind"] == "after"), batches[-1])
        diff = compare.diff_batches(before_b["id"], after_b["id"])
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("新增", diff["summary"]["new"])
        c2.metric("已关闭", diff["summary"]["closed"])
        c3.metric("未变", diff["summary"]["unchanged"])
        c4.metric("风险变化", diff["summary"]["risk_changed"])

    st.subheader("Finding 列表")
    df = findings_df()
    if not df.empty:
        st.dataframe(df, use_container_width=True, hide_index=True)

# =====================================================================
# 2. 授权范围门禁
# =====================================================================
elif page == "授权范围门禁":
    st.title("授权范围与白名单门禁")
    st.caption("SCOPE GATE · 扫描前强制校验，越界目标在发起任何请求前拒绝并记录")

    scope_path = config.BASE_DIR / "scope.md"
    if scope_path.exists():
        with st.expander("scope.md 授权记录", expanded=True):
            st.markdown(scope_path.read_text(encoding="utf-8"))

    st.subheader("白名单主机")
    st.write(sorted(config.WHITELIST_HOSTS))
    st.caption("公网域名、RFC1918 私网地址不会自动视为已授权；教师明确添加的目标才可使用。")

    st.subheader("目标校验")
    target = st.text_input("输入待扫描目标 URL", value="http://127.0.0.1:8000/")
    if st.button("校验目标"):
        result = gate.check_target(target)
        st.session_state.gate_log.append(
            {"url": target, "allowed": result["allowed"], "reason": result["reason"],
             "normalized": result["normalized"]}
        )
        if result["allowed"]:
            st.success(f"允许：{result['normalized']}")
        else:
            st.error(f"拒绝：{result['reason']}")

    if st.session_state.gate_log:
        st.subheader("本次会话校验记录")
        st.dataframe(pd.DataFrame(st.session_state.gate_log), use_container_width=True, hide_index=True)

    st.subheader("禁止动作")
    st.markdown(
        """
- 不调用主动扫描（ascan）、不进行爆破、注入尝试或认证绕过；
- 不对公网域名、未登记私网地址发起任何请求；
- 重定向到非白名单主机时立即停止；
- 不使用真实账号与真实个人数据，演示数据全部虚构。
        """
    )

# =====================================================================
# 3. 报告导入
# =====================================================================
elif page == "报告导入":
    st.title("ZAP 报告导入")
    st.caption("PARSE · FINGERPRINT · DEDUP · KEEP OCCURRENCE HISTORY")

    col1, col2 = st.columns(2)
    with col1:
        sample = st.selectbox("选择内置脱敏样本", ["zap-before.json", "zap-after.json", "（上传文件）"])
    with col2:
        batch_label = st.text_input("批次标签", value="before-2026-11-11")
        kind = st.selectbox("批次类型", ["before", "after", "manual"])

    uploaded = st.file_uploader("或上传 ZAP Traditional JSON 报告", type=["json"])
    note = st.text_area("批次备注", value="被动规则 + 已知 URL 请求，不含爬虫或主动攻击")

    if st.button("导入报告"):
        if uploaded is not None:
            data = json.loads(uploaded.getvalue().decode("utf-8"))
            source = uploaded.name
        elif sample != "（上传文件）":
            data = json.loads((config.SAMPLE_DIR / sample).read_text(encoding="utf-8"))
            source = str(config.SAMPLE_DIR / sample)
        else:
            st.error("请选择内置样本或上传 JSON 文件")
            st.stop()

        stats = importer.import_report(
            data, batch_label=batch_label, kind=kind, source_file=source,
            target="http://127.0.0.1:8000", ruleset="ZAP 2.17.0 passive rules", note=note,
        )
        st.success(
            f"导入完成：告警实例 {stats['alerts']} 条，"
            f"新建 Finding {stats['new_findings']} 条，"
            f"重复归并 {stats['repeat_findings']} 条。"
        )
        st.caption("重复导入同一报告：已存在的 Finding 只追加出现历史，不重复创建。")

    st.subheader("已导入批次")
    batches = db.list_batches()
    if batches:
        st.dataframe(pd.DataFrame(batches), use_container_width=True, hide_index=True)
    else:
        st.info("尚未导入任何批次。")

# =====================================================================
# 4. 漏洞复核与处置
# =====================================================================
elif page == "漏洞复核与处置":
    st.title("漏洞复核与处置")
    st.caption("TRIAGE · OWNER · STATUS · EVIDENCE")

    f_all = db.list_findings()
    if not f_all:
        st.info("暂无 Finding，请先在「报告导入」页导入报告。")
        st.stop()

    c1, c2, c3 = st.columns(3)
    status_filter = c1.selectbox("状态筛选", ["全部"] + config.STATUSES)
    risk_filter = c2.selectbox("风险筛选", ["全部", "High", "Medium", "Low", "Info"])
    owner_filter = c3.selectbox("负责人筛选", ["全部"] + sorted({f["owner"] for f in f_all if f["owner"]}))

    filtered = f_all
    if status_filter != "全部":
        filtered = [f for f in filtered if f["status"] == status_filter]
    if risk_filter != "全部":
        filtered = [f for f in filtered if risk_label(f["riskcode"]) == risk_filter]
    if owner_filter != "全部":
        filtered = [f for f in filtered if f["owner"] == owner_filter]

    st.dataframe(findings_df()[findings_df()["ID"].isin([f["id"] for f in filtered])],
                 use_container_width=True, hide_index=True)

    st.subheader("处置明细")
    finding_id = st.selectbox("选择 Finding", [f["id"] for f in filtered],
                              format_func=lambda i: f"F-{i} · " + next(
                                  f["name"] for f in filtered if f["id"] == i))
    finding = db.get_finding(finding_id)

    alerts = db.list_alerts(finding_id=finding_id)
    reviews = db.list_reviews(finding_id=finding_id)

    st.markdown(f"**规则 {finding['pluginid']} · {finding['name']}**")
    st.caption(f"CWE: {finding['cwe'] or '—'}　风险: {risk_label(finding['riskcode'])}　指纹: {finding['fingerprint']}")

    with st.expander("告警实例与证据", expanded=True):
        for a in alerts:
            st.write(f"- `{a['method']} {a['uri']}`　参数: {a['param'] or '—'}")
            if a["evidence"]:
                st.caption(f"证据：{a['evidence']}")

    with st.expander("历史复核记录"):
        if reviews:
            for r in reviews:
                st.write(f"- **{r['verdict']}**（{r['reviewer']}，{r['created_at']}）：{r['reason']}")
        else:
            st.info("尚无复核记录")

    with st.form("edit_finding"):
        st.subheader("更新处置信息")
        owner = st.text_input("负责人", value=finding["owner"] or "")
        status = st.selectbox("状态", config.STATUSES, index=config.STATUSES.index(finding["status"]))
        branch = st.text_input("修复分支", value=finding["branch"] or "")
        commit = st.text_input("修复 Commit SHA", value=finding["commit_sha"] or "")
        rescan = st.selectbox(
            "复扫批次", ["（无）"] + [f"{b['id']} · {b['label']}" for b in db.list_batches()]
        )
        reason = st.text_area("处置理由 / 复核说明", value=finding["review_reason"] or "")
        reviewer = st.text_input("复核人", value="隋圣丹")
        verdict = st.selectbox("复核判定", ["Confirmed", "False Positive", "Accepted Risk"])
        submitted = st.form_submit_button("保存处置")

    if submitted:
        rescan_batch_id = None
        if rescan != "（无）":
            rescan_batch_id = int(rescan.split(" · ")[0])
        try:
            updated = db.update_finding(
                finding_id,
                {"owner": owner, "status": status, "branch": branch, "commit_sha": commit,
                 "review_reason": reason, "rescan_batch_id": rescan_batch_id},
            )
            db.add_review(finding_id, reviewer, verdict, reason)
            st.success(f"已保存：F-{finding_id} 当前状态 {updated['status']}")
        except ValueError as exc:
            st.error(f"保存被拒绝：{exc}")

# =====================================================================
# 5. 复扫对比
# =====================================================================
elif page == "复扫对比":
    st.title("before / after 复扫对比")
    st.caption("DIFF BY FINGERPRINT · NEW / UNCHANGED / CLOSED / RISK CHANGED")

    batches = db.list_batches()
    if len(batches) < 2:
        st.info("至少需要两个批次（before / after）才能对比。")
        st.stop()

    blabels = [f"{b['id']} · {b['label']}（{b['kind']}）" for b in batches]
    before_label = st.selectbox("before 批次", blabels, index=0)
    after_label = st.selectbox("after 批次", blabels, index=len(blabels) - 1)
    before_id = int(before_label.split(" · ")[0])
    after_id = int(after_label.split(" · ")[0])

    diff = compare.diff_batches(before_id, after_id)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("新增", diff["summary"]["new"])
    c2.metric("已关闭", diff["summary"]["closed"])
    c3.metric("未变", diff["summary"]["unchanged"])
    c4.metric("风险变化", diff["summary"]["risk_changed"])

    st.caption("关闭依据：同目标、同规则集、同覆盖范围下复扫不再出现；覆盖不足时保持 Resolved，不判 Verified。")

    def _mini(rows):
        if not rows:
            return pd.DataFrame()
        return pd.DataFrame(
            [{"规则": r["pluginid"], "名称": r["name"], "风险": risk_label(r["riskcode"]),
              "状态": r["status"]} for r in rows]
        )

    st.subheader("已关闭（before 出现，after 未出现）")
    st.dataframe(_mini(diff["closed"]), use_container_width=True, hide_index=True)
    st.subheader("未变（两批次均出现）")
    st.dataframe(_mini(diff["unchanged"]), use_container_width=True, hide_index=True)
    st.subheader("新增（after 首次出现）")
    st.dataframe(_mini(diff["new"]), use_container_width=True, hide_index=True)
    if diff["risk_changed"]:
        st.subheader("风险等级变化")
        st.dataframe(pd.DataFrame(diff["risk_changed"]), use_container_width=True, hide_index=True)

# =====================================================================
# 6. 证据链追踪
# =====================================================================
elif page == "证据链追踪":
    st.title("一条 Finding 的证据链")
    st.caption("BEFORE REPORT → REVIEW → FIX BRANCH / COMMIT → REGRESSION → AFTER RESCAN")

    findings = db.list_findings()
    if not findings:
        st.info("暂无 Finding。")
        st.stop()

    fid = st.selectbox("选择 Finding", [f["id"] for f in findings],
                       format_func=lambda i: f"F-{i} · " + next(f["name"] for f in findings if f["id"] == i))
    f = db.get_finding(fid)
    batches = {b["id"]: b for b in db.list_batches()}

    st.markdown(f"### F-{f['id']} · {f['name']}（{risk_label(f['riskcode'])} · {f['status']}）")

    timeline = []
    first_b = batches.get(f["first_batch_id"])
    last_b = batches.get(f["last_batch_id"])
    if first_b:
        timeline.append(f"① 首次发现：批次 {first_b['label']}（{first_b['kind']}），来源 {first_b['source_file']}")
    for r in db.list_reviews(finding_id=fid):
        timeline.append(f"② 人工复核：{r['verdict']} — {r['reason']}（{r['reviewer']}，{r['created_at']}）")
    if f["branch"] or f["commit_sha"]:
        timeline.append(f"③ 修复：分支 {f['branch'] or '—'} · Commit {f['commit_sha'] or '—'}")
    rescan_b = batches.get(f["rescan_batch_id"])
    if rescan_b:
        timeline.append(f"④ 复扫证据：批次 {rescan_b['label']}（{rescan_b['kind']}），指纹未再出现")
    if f["status"] == "Verified":
        timeline.append("⑤ 状态 Verified：复扫不再出现且证据链完整")
    elif f["status"] in config.CLOSED_STATUSES:
        timeline.append(f"⑤ 状态 {f['status']}：非复扫关闭，按复核结论处置")
    else:
        timeline.append("⑤ 仍在开放状态，等待修复或复核")

    for line in timeline:
        st.write(line)

    st.subheader("出现历史（按批次）")
    alerts = db.list_alerts(finding_id=fid)
    st.dataframe(
        pd.DataFrame([
            {"批次": batches[a["batch_id"]]["label"], "方法": a["method"], "URI": a["uri"],
             "证据": a["evidence"]} for a in alerts
        ]),
        use_container_width=True, hide_index=True,
    )

# =====================================================================
# 7. 导出与说明
# =====================================================================
elif page == "导出与说明":
    st.title("脱敏导出与交付说明")
    st.caption("DESENSITIZED EXPORT · NO CREDENTIALS IN SUBMISSION")

    st.markdown(
        """
### 导出原则
- 导出前自动脱敏 Token、Cookie、口令与 JWT；自动脱敏之外仍需人工复核；
- 原始 ZAP 报告只保存在本机 / 教师可访问位置，不随公开仓库提交；
- 演示结束后轮换临时 Token、清理测试账号；数据库文件不纳入 Git。
        """
    )

    col1, col2 = st.columns(2)
    col1.download_button("导出脱敏 CSV", exporter.export_csv(), file_name="findings-redacted.csv",
                         mime="text/csv")
    col2.download_button("导出脱敏 JSON", exporter.export_json(), file_name="findings-redacted.json",
                         mime="application/json")

    st.subheader("测试证据原件")
    st.markdown(
        """
- `docs/evidence/test-run.txt`：pytest 全部用例运行结果与退出码；
- `docs/evidence/review-log.txt`：人工复核记录与覆盖说明；
- `docs/evidence/before-after-hash.txt`：前后报告哈希与覆盖范围说明。
        """
    )
