# 05 Git 与开源规范

## 1. 分支与提交

- 远程仓库 `origin`：<https://github.com/783287393/platform.git>；上游 ZAP / Streamlit 等仅作参考基线；
- `main`：项目基线（授权门禁、ZAP 报告导入、指纹去重、工作流与页面、测试与文档）；
- `fix/security-headers`：安全响应头修复分支，Commit 短 SHA `20312fd`
  （完整 SHA `20312fd03823637422cb1bb07dd57ff1eedae29b`），补充 CSP / X-Frame-Options / X-Content-Type-Options；
- 演示库中 10020 / 10021 / 10038 三条 Verified Finding 关联该分支与 Commit；本地数据库 `data/security.db` 不入库，重新 seed 后仍记录上述分支与 SHA。

参考命令：

```powershell
git remote -v
git switch -c fix/security-headers
git status
git add web/target_app.py
git commit -m "fix(security): add CSP, X-Frame-Options and X-Content-Type-Options"
git push -u origin main
git push -u origin fix/security-headers
git log --oneline --graph --decorate --all
```

## 2. 自审清单（合并前逐条核对）

- [ ] 目标命中白名单，未扫描未授权资产；
- [ ] 重复导入不新建 Finding，出现历史保留在 alerts 表；
- [ ] Verified 状态均有 Commit 与复扫批次证据；
- [ ] 误报 / 接受风险留有理由与复核人；
- [ ] 导出报告已脱敏，无 Token / Cookie / 口令；
- [ ] 测试全部通过，证据已落盘 docs/evidence/。

## 3. 许可证与来源

- 本项目代码：Apache-2.0（与上游 ZAP 许可证对齐，便于二次开发）；
- 第三方组件许可证见 `NOTICE.md`；
- 复制上游代码、数据、图片时在 NOTICE.md / README 记录来源、作者、链接与许可证；
- 不替换项目名称、Logo 后冒充原创；本人实现范围在 README 第 9 节列明。
