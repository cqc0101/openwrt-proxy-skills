# 更新日志

版本号遵循语义化版本（`主版本.次版本.修订号`）。0.x 阶段接口与目录结构可能调整。

## [0.4.0] - 2026-11-09

### 协议规范对齐、dae 传输层完备支持与底层守护增强 (Protocol Alignment & System Hardening)

- **sing-box 规则规范化与私有域名消除**：
  - 彻底移除了 `dns.rules` 中的非标字段 `preferred_by`，使生成的 DNS 规则严格符合 sing-box Schema；
  - 移除了基准模板和 mixins 中硬编码的私有域名（如 `x1pro.lan`、`speed.lan`），替换为标准 RFC 局域网私网后缀（`.lan`、`.local`、`.home.arpa`），并新增门禁测试断言。
- **dae 传输层完备支持 (WebSocket / gRPC)**：
  - 升级 `sub_parser.py` 的 `to_dae_nodes` 导出器，在生成 dae 节点 URI 时精准注入 `&type=ws&path=...&host=...` 与 `&type=grpc&serviceName=...`，确保 VLESS 与 Trojan 在 dae 中能够建立 WebSocket 和 gRPC 握手。
- **dae 全量配置自动化合成器 (`sub_to_dae.py --full`)**：
  - `sub_to_dae.py` 新增 `--full`、`--lan-iface`、`--wan-iface` 与 `--out` 参数，支持一键将订阅节点注入 `openwrt.dae` 基准模板，并自动调用 `check_dae_syntax.py` 执行 5 条铁律静态门禁校验，直接产出合规生产级 `config.dae`。
- **OpenWrt SSH 守护进程 OOM 豁免保护 (`oom_score_adj`)**：
  - 在 `setup_openwrt_network.sh` 中对 `dropbear` / `sshd` 注入 `oom_score_adj -1000` 保护，杜绝路由器在极端高并发或低内存场景下被内核 OOM Killer 误杀 SSH 守护导致失联。
- **智能诊断工具全景体检升级 (`doctor.sh`)**：
  - 增加 `fw_tun_ok`（检查防火墙是否正确放行 tun0 转发）与 `outbound_ok`（实际探测 Cloudflare 204 境外连通性），在结构化 JSON 中实时暴露并输出对应自愈建议。
- **架构清理与测试套件扩充**：
  - 移除冗余的 `diagnose_openwrt.sh` 及已废弃的本地临时脚本，单元测试套件扩充至 **157 项**（全量 PASS）。

## [0.3.1] - 2026-11-09

### 网络治理修正与生产加固 (Network Governance & Production Hardening)

- **移除防火墙 53 端口 DNAT 劫持规则**：
  - 彻底移除了 `setup_openwrt_network.sh` 中的 Port 53 DNAT 规则，杜绝该规则在 PREROUTING 阶段将局域网 DNS 短路送往本机 Dnsmasq，确保 Layer 3 `tun0` 路由接管与 `hijack-dns` 防污染正常工作；
  - 增加 `--revert` 时对 LAN 区域 `masq` / `masquerade` 的干净清理逻辑。
- **修复 DoH (HTTPS) 上游 DNS URL 解析**：
  - 在 `auto_config.py` 中引入精确 URL 解析器，将 DoH URL 正确剥离并分发至 `server`（主机名/IP）、`server_port` 及 `path` 字段，严格符合 sing-box DNS 规范；
  - 增加对自定义 UDP 远端 DNS 的健壮支持。
- **探针参数与冲突检测增强**：
  - `probe.sh` 参数解析改为全参数循环遍历，避免 `-j` / `--json` 标志被位置参数截断；
  - 在 JSON 输出的 `conflicts` 块中补齐 `dnsmasq_upstream` 与 `dnsmasq_loop_risk` 事实字段。
- **部署指令与技能指南纠偏**：
  - 修正 `SKILL.md`：移除无 `sftp-server` 支持的 `scp` 上传指令，统一重构为原生 `ssh` + `stdin` 管道；纠正 v1.13 规则集 `download_detour` 描述与 dae 订阅转换脚本指令；
  - 规范 `modular-blocks.md`：入站 TUN 显式绑定 `tun0` 并设置 `auto_redirect: false`；DNS 拦截规则升级为 `protocol: dns` 或 `port: 53` 双条件逻辑判定。
- **测试基座与工程门禁升级**：
  - 重构 `docker/run_docker_tests.py`：实现真实的远程 SSH 沙盒校验与服务部署执行流，支持无依赖进程内 `OpenWrtState` 仿真；
  - 消除本地压力测试脚本中的绝对路径与特定私网 IP 硬编码；
  - 在 `test_docs.py` 中新增静态禁词门禁，严禁废弃脚本名称与个人本地路径引入代码库。

## [0.3.0] - 2026-11-08

### 架构精简与解耦 (Architecture Streamlining & Decoupled Tooling)

- **移除宿主机端胶水脚本**：
  - 彻底删除了宿主机端冗余的 `deploy_singbox.sh/ps1` 与 `deploy_dae.sh/ps1`，改为通过标准 SSH 管道执行沙盒语法预检 (`sing-box check` / `dae validate -c`) 与原子服务平滑重启；
  - 删除了冗余的宿主机远程 PowerShell 薄包装脚本 (`.ps1`)，消除跨平台运维的双倍维护负担与行为漂移；
  - 两个技能仅保留纯正 POSIX `/bin/sh` 与跨平台 Python 脚本，原生贴合软路由 Linux 物理执行环境。
- **文档深度精简与高密度重构**：
  - 将原本平铺冗余的 19 篇长篇手册提炼合并为 6 篇高密度的一级参考文档：
    - `singbox-openwrt`: `architecture-and-schema.md`、`dns-and-routing.md`、`openwrt-pitfalls-and-troubleshooting.md`、`modular-blocks.md`
    - `dae-openwrt`: `dae-rules-and-syntax.md`、`troubleshooting.md`
  - 显著降低多级文档检索开销与跨文档语义矛盾。
- **模块化积木片段与解耦 (Composable Modular Mixins)**：
  - 新增 `assets/mixins/` 目录，包含 `inbound_tun.json`、`experimental.json`、`dns_base.json`、`route_base.json`、`outbounds_base.json` 等独立原子片段，摆脱对固定大模板的死板依赖。
- **统一的最后一公里网络闭环 Hook (`setup_openwrt_network.sh`)**：
  - 将零散的防火墙脚本与网络调优整合为统一的 `setup_openwrt_network.sh`（直接运行在路由器上，兼顾 SSH 远程调度）：
  - 动态精准查询 LAN zone（杜绝 `@zone[0]` 盲猜）；
  - 注入 `tun0` 放行与 `forward=ACCEPT`；
  - 激活 MSS 钳制 (`mtu_fix='1'`) 解决 PPPoE MTU 1492 卡死；
  - 开启 DNAT 53 端口防泄漏重定向；
  - 开启 Dnsmasq `filter_aaaa='1'` 纯净 IPv4 模式；
  - 写入 `/etc/sysctl.d/99-singbox.conf` / `99-dae.conf`，激活 BBR 拥塞控制与 65536 连接池；
  - 支持 `--bypass` 自动配置 LAN 区域 masquerade 伪装，支持 `--revert` 一键无损还原基线。
- **智能诊断工具全面支持结构化 JSON (`doctor.sh --json` & `diagnose_dns.sh --json`)**：
  - 升级 `doctor.sh` 与 `diagnose_dns.sh`，支持 `-j` / `--json` 原生输出结构化 JSON，输出 `overall_code`、`status`、`issues` 与 `suggested_actions`；
  - 输出机器可读的标准诊断结构，便于脚本解析与自动化运维自愈。
- **测试矩阵与工程质量升级**：
  - 新增 `tests/test_mixins.py`；
  - 重构 `test_deploy_scripts.py`、`test_diagnose_dns.py`、`test_doc_consistency.py`；
  - 全量 154 项单元回归测试 100% 通过；
  - 本地 Docker 容器与边界压力测试矩阵全部通过；
  - 敏感凭据与网络资产脱敏扫描 100% 通过（严格遵守 RFC 5737 测试桩规范）。

---

## [0.2.0] - 2026-11-08

### 重大特性与架构升级

- **DNS 治理与防污染矩阵 (DNS Governance & Leak Prevention)**：
  - 在 sing-box（全部 4 款模板）与 dae 核心规则中全量注入 DoH / Apple 私密代理 Canary 域名阻断（`use-application-dns.net`, `mask.icloud.com`, `mask-h2.icloud.com`），强制 Firefox、Chrome 与 iOS/macOS 遵循网关防污染分流与 FakeIP，彻底根除私密代理绕过引发的国内 CDN 降速；
  - 最后一公里加固脚本自动注入并持久化 Dnsmasq AAAA 过滤（`filter_aaaa='1'`），双重锁定纯净 IPv4 解析，根除移动端国内 App 转圈假死；
  - 专项 DNS Doctor（`diagnose_dns.sh`）检测维度由 5 维扩充至 7 维全景审计（新增 Canary 阻断审计、Dnsmasq 本地回环死锁审计与 AAAA 纯净配置审计）；
  - `probe.sh` 深度探测 Dnsmasq 上游配置，自动告警本地回环死锁风险。
- **模块化规则积木架构 (Modular Blocks & Composable Rules)**：
  - 新增 `references/modular-blocks.md`（singbox 与 dae 双端），将规则沉淀为正交原子积木，支持根据主路由、旁路由或分流拓扑按需灵活拼装生产配置。
  - 重构 `SKILL.md` 与参考文档体系，建立涵盖环境拓扑感知、规则积木拼装、静态门禁审计、网络接管与结构化自愈诊断的全流程工程闭环。
- **最后一公里网络与网关接管闭环 (Last-Mile Transparent Proxy Network Hook)**：
  - 升级 `setup_openwrt_network.sh`；
  - 自动持久化内核转发 `net.ipv4.ip_forward=1`；
  - 动态定位真实 LAN 区域（坚决消除 `@zone[0]` 盲猜隐患）并信任注入 `tun0` (`forward='ACCEPT'`)；
  - 开启 MSS 钳制 (`mtu_fix='1'`)，彻底消除 PPPoE 大包 TLS 握手黑洞与卡死；
  - 配置局域网 Port 53 DNAT 劫持，防止内网终端直连本地 Dnsmasq 导致 DNS 污染与出海穿透失效；
  - 支持 `--bypass` 自动配置 LAN 区域动态伪装 (`masquerade='1'`)，彻底解决单臂旁路由非对称路由客户端 RST 丢包；
  - 支持 `--revert` 一键无损还原系统网络基线。
- **Bootstrap DNS 节点域名直连防死锁机制 (Anti-Deadlock Bootstrap DNS)**：
  - 在 `sub_parser.py` 新增 `extract_node_domains()` 原语与 `--format domains` CLI；
  - 在 `auto_config.py` 与 `modular-blocks.md` 中自动将代理节点使用的域名注入 `dns.rules`（直连 DNS 解析器）、`route.rules`（`outbound: direct`）及 `outbound.domain_resolver`，彻底根除“依赖代理节点解析域名，却因未解析域名无法连上节点”的致命启动死锁；
  - `check_config.py` 新增节点域名防死锁静态门禁检查。
- **旁路由 (Bypass Gateway) 首等支持**：
  - `auto_config.py` 新增 `--topology {main,bypass}` 与 `--main-router-ip`，自动在 `route.rules` 中保障主路由回环放行。
- **跨平台与工程稳固性提升**：
  - SSH 连接默认使用 `StrictHostKeyChecking=accept-new`，消除静默中间人攻击风险同时保障免密自动化；
  - 补充全量单元测试与回归套件，测试总数扩充至 141 项（100% 通过）。

---

## [0.1.0] - 2026-11-07

### 首个公开版本

#### 内容

- 两个技能：`singbox-openwrt`（sing-box 1.13 / 1.14+，TUN + FakeIP/RealIP）与 `dae-openwrt`（dae / daed eBPF）。
- 目录按标准规范组织：`skills/<技能名>/SKILL.md`；模板置于 `assets/templates/`；参考文档保持一级深度。
- 脚本：环境检测、订阅解析与节点转换、配置生成、网络闭环接管、诊断。
- 模板：4 个 sing-box 基准模板与 1 个 dae 基准模板。
- 参考文档：架构与门控、DNS防环、避坑排障、模块化积木。
- 测试：回归测试套件与 GitHub Actions CI。
