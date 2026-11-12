"""实验 07 软件安全检测与漏洞管理平台。

模块划分：
- config:      白名单、状态、风险等级与路径配置
- gate:        扫描前目标白名单强制校验
- parser:      ZAP Traditional JSON 报告解析与 HTML 净化
- fingerprint: 稳定指纹（规则 ID + 规范化 origin/方法/路径/参数）
- db:          SQLite 表结构与访问层
- importer:    报告导入、指纹去重与出现历史留存
- compare:     before/after 批次按指纹对比（新增/未变/已关闭/风险变化）
- exporter:    脱敏导出
- seed:        演示样本数据初始化
- app:         Streamlit Web 界面
"""

__version__ = "0.1.0"
