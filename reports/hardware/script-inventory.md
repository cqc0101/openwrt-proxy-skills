# 文件与脚本清单

基线 97 个文件，新增 1 个行为测试文件，修订源共 98 个文件；Python 38，Shell 9。全量路径、行数、字节数和 SHA-256 见 inventory.json。后生成的报告与脱敏证据不重复计入源代码测试规模。

全部文件纳入清单和文本扫描，Python AST/JSON 语法、Shell 原生语法与回归覆盖并行使用。人工复核聚焦网络生命周期、配置生成、SSRF/SSH/事务核心与全部本轮 diff；不声称每一行都经过形式化证明。

设备侧 8 个技能 Shell 文件都执行了正常/诊断或接管路径，9 个 Shell 文件均通过设备 ash 语法检查。Docker entrypoint 为主机容器入口，仅语法检查，不把它当作 OpenWrt 本机入口。Python 入口由宿主和独立 Linux 执行；缺 Python 的 R2S 上未执行，明确 BLOCKED。

