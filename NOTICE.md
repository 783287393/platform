# NOTICE — 第三方组件与来源清单

本项目为课程实验二次开发，下列上游组件仅作为基线与依赖，版权归原作者所有。

| 组件 | 用途 | 许可证 | 来源 |
| --- | --- | --- | --- |
| OWASP ZAP 2.17.0 | Web 被动安全检测与报告生成（上游工具，未修改其源码） | Apache-2.0 | https://github.com/zaproxy/zaproxy |
| Streamlit 1.67.0 | Web 界面与 Dashboard 组件库 | Apache-2.0 | https://github.com/streamlit/streamlit |
| Python 3.13 | 运行时 | PSF License | https://www.python.org/ |
| SQLite 3.x | 嵌入式数据库（Python 标准库 sqlite3） | Public Domain | https://www.sqlite.org/ |
| pytest 9.2.0 | 测试框架 | MIT | https://github.com/pytest-dev/pytest |
| pandas 3.1.1 | 表格数据处理 | BSD-3-Clause | https://github.com/pandas-dev/pandas |

## 样本数据说明

`data/samples/zap-before.json`、`zap-after.json` 为对齐 ZAP 2.17.0 Traditional JSON
结构的脱敏演示样本，告警内容为本实验虚构的本地回环页面示例，不含真实账号、Cookie 或
个人数据。

## 二次开发边界

ZAP 的规则库、告警判定与报告导出属于上游既有能力；本人实现范围（解析、指纹、去重、
状态工作流、对比、图表、脱敏导出）见 README 第 9 节。
