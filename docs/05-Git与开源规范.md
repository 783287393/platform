# 05 Git 与开源规范

## 1. 分支与提交

- 个人仓库 `origin`，上游 ZAP / Streamlit 等作为参考基线保留 `upstream` 记录；
- 功能在特性分支 `feature/finding-lifecycle` 上开发，main 保持可运行；
- 至少 5 个可解释的非合并 Commit，覆盖：基线 → 门禁与解析 → 指纹去重 → 工作流与页面 → 测试与文档；
- PR 关联对应 Issue（授权范围、告警指纹、人工复核、修复复扫），合并前完成有文字记录的自审 Review。

参考命令：

```powershell
git remote -v
git switch -c feature/finding-lifecycle
git status
git add <本次实际修改的文件>
git commit -m "feat(findings): deduplicate ZAP alerts across scans"
git push -u origin feature/finding-lifecycle
git log --oneline --graph --decorate --all -n 30
git shortlog -sne HEAD
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
