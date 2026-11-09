# 更新日志

版本号遵循语义化版本（`主版本.次版本.修订号`）。0.x 阶段接口与目录结构可能调整。

## [0.5.2] - 2026-11-09

### 进程与管道弹性、物理硬件自适应与全链路超时硬化 (Resilience & Hardware Adaptability)

- **[高危] `setup_openwrt_network.sh` 修复 SSH 管道下 `$0` 回滚崩溃与看门狗进程竞态**：
  - 彻底修复通过 `ssh "sh -s"` 管道执行时因 `$0="sh"` 导致子看门狗 `sh "$0" --revert` 执行失败的致命缺陷，改为直接在子进程内存中调用 `run_router_hardening "--revert"` / `run_dae_hardening "--revert"`；
  - 增加 `/tmp/proxy_watchdog.pid` 进程锁与 `kill_active_watchdog`，防止反复重试触发看门狗进程竞态踩踏。
- **[特性] 无损物理网络基线备份与内存自适应连接池 (`nf_conntrack_max`)**：
  - 首次运行前自动持久化快照至 `/etc/config/.network_baseline.bak`，精准保留 `ORIG_LAN_MASQ`、`ORIG_LAN_MTU_FIX` 与 `ORIG_FILTER_AAAA`，`--revert` 严格无损还原，消除盲目破坏原有网络选项的反模式；
  - 依据物理内存动态自适应连接池：128MB 弱内存路由器配置 `16384`（杜绝 OOM 崩溃），256MB 配置 `32768`，512MB+ 配置 `65536`。
- **[优化] `dae` 网络接管合并防火墙重载 (Single Firewall Reload)**：
  - 消除旧版连续 3 次触发 `/etc/init.d/firewall reload` 导致的瞬时连接抖动，合并全量变更后在正向流程末尾仅执行 1 次平滑重载。
- **[审计] `check_config.py` 静态门禁增强传输层与端口边界校验**：
  - 新增 `transport.type` 白名单审计，精准拦截手改配置中的 `xhttp`/`splithttp`/`kcp` 等未受 sing-box 标准支持的传输层；
  - 新增出站代理节点端口合法性检验（`1 <= server_port <= 65535`），杜绝越界端口下发启动崩溃。
- **[容错] 诊断与探测脚本超时硬化与二级路由风险识别**：
  - `diagnose_dns.sh` 与 `doctor.sh` 为 `dig` 注入 `+time=2 +tries=1`、为 `curl` 注入 `-m 5`、为 `nslookup` 包装 `timeout 3`，防止上游死循环阻塞诊断 120 秒；
  - `probe.sh` 新增 `PRIVATE_WAN_DNS_RISK` 检测，自动预警光猫二级路由下的私网 DNS 旁路隐患。
- **[特性] `sub_parser.py` 导出 dae 完整保留 TLS ALPN 与 HY2 端口跳跃 (`mport`)**：
  - 支持将 `alpn` 及 `server_ports` 转换为 dae 原生 `alpn=...` 与 `mport=...` 查询参数。
- **[测试] 单元测试矩阵扩充至 199 项**：
  - 扩充测试套件至 199 项，全量 100% 满分通过。

## [0.5.1] - 2026-11-09

### 拓扑增强、SSH 会话解耦与 Agent 规范合规 (Topology & Process Hardening)

- **[特性] `sub_to_dae.py` 原生支持旁路由拓扑与主路由直连放行**：
  - 新增 `--topology {main, bypass}` 与 `--main-router-ip` 命令行参数；
  - 旁路由模式下自动在 `must_direct` 后注入 `dip(<main-router-ip>) -> direct`，杜绝单臂旁路流量自环与非对称丢包。
- **[高危] `setup_openwrt_network.sh` 修复看门狗导致 SSH 会话悬挂假死 (SSH Stdin Leak)**：
  - 自动回滚看门狗后台子进程重定向补齐 `</dev/null`（`</dev/null >/dev/null 2>&1 &`）；
  - 彻底阻断因后台进程继承 SSH 标准输入导致的远端 SSH 会话无法正常退出、前端发布流程长期阻塞假死的问题。
- **[规范] AgentSkills 开放协议元数据合规 (Frontmatter Specification)**：
  - `dae-openwrt` 与 `singbox-openwrt` 的 `SKILL.md` 补齐 `license: MIT` 与 `compatibility` 声明，完全符合 AgentSkills 规范。
- **[语法] `check_dae_syntax.py` 补充未配对单引号语法检测**：
  - 完善单引号词法状态机，针对 `pa'ss` 等非闭合单引号异常提供精准行号定位与语法阻断。
- **[测试] 单元测试矩阵扩充至 192 项**：
  - 补齐 dae 旁路由规则注入单测、看门狗 stdin 隔离断言、AgentSkills frontmatter 合规校验及未平衡单引号拦截，100% 满分通过。

## [0.5.0] - 2026-11-09

### 新特性与现代协议扩展 (New Features & Protocol Expansions)

- **[特性] 新增 TUIC 与 AnyTLS 全链路协议支持**：
  - `parse_node.py`、`sub_parser.py` 与 `to_dae_nodes` 全面支持 TUIC (`tuic://`) 与 AnyTLS (`anytls://`) 协议解析；
  - 自动适配 TLS ALPN (`h3`/`h2`)、拥塞控制算法 (`congestion_control: bbr`) 与多路复用参数 (`multiplex`)；
  - 同步打通 Clash YAML 代理节点转换与 dae 节点导出语法。
- **[特性] 新增 Modern Transport 现代传输层支持 (HTTPUpgrade & H2)**：
  - 为 VLESS 与 Trojan 节点扩展 `httpupgrade` 与 `h2` 传输层解析，支持独立配置 `path`、`host` 及 TLS ALPN (`["h2", "http/1.1"]`)；
  - 精确映射 sing-box `transport: {"type": "httpupgrade", "path": "...", "host": "..."}` 块。
- **[安全] 不支持传输层快速失败防护 (Fail-fast Transport Gating)**：
  - 对尚未受目标核心稳定支持的传输层协议（如 `xhttp`、`splithttp`、`kcp`、`quic` 等）建立阻断门禁；
  - 在 URI 解析中显式抛出 `ValueError`，在 Clash YAML 转换中丢弃并返回空对象，**严禁静默降级为裸 TCP** 造成黑洞或握手超时故障。
- **[重构] 模块化正交积木动态组装 (`compose_from_mixins`)**：
  - `auto_config.py` 引入 `compose_from_mixins` 架构级拼装引擎，统一调度 `assets/mixins/` 内的模块化积木；
  - 彻底杜绝全量独立基准模板与正交积木之间的双数据源配置漂移。
- **[测试] 单元测试矩阵扩充至 189 项**：
  - 新增 TUIC/AnyTLS 语法校验、HTTPUpgrade 传输映射、不支持协议硬拦截阻断测试；
  - 全量 189 项单元测试与 Docker/Mock 仿真套件 100% 绿灯通过。

## [0.4.3] - 2026-11-09

### 全量安全审计与 26 项深度缺陷修复 (Full Security Audit & Deep Remediation)

- **[高危] `sub_parser.py` 修复 URLSafe Base64 静默删字符乱码漏洞 (F-01)**：
  - 修复 `safe_b64decode` 优先调用 `base64.b64decode` 导致将 `-`/`_` 静默删除、使含中文节点名的 URLSafe Base64 订阅解码成乱码并返回 0 节点的严重缺陷；统一使用 `urlsafe_b64decode` 并补充 `gb18030` 解码回退。
- **[高危] `auto_config.py` 修复 `--dns-cn` DoH 域名自锁崩溃 (F-02)**：
  - 当 `--dns-cn` 传入域名型 DoH URL（如 `https://dns.alidns.com/dns-query`）时，自动注入纯 IP 引导解析器 `bootstrap-dns (223.5.5.5)` 作为 `route.default_domain_resolver` 与 `alidns.domain_resolver`，消除与 v0.4.2 纯 IP 引导门禁的自相冲突。
- **[高危] `auto_config.py` 阻断失效订阅静默回退 `US-Node` 假节点 (F-03)**：
  - 当用户显式指定 `--sub` 或 `--node` 但有效节点数为 0 时，强制报错退出 (`exit 1`)，严禁静默输出含 `example.com:34589` 占位假节点的配置造成全屋断网。
- **[高危] `doctor.sh` 移除导致全网解析瘫痪的 `127.0.0.1#5335` 建议指令 (F-04)**：
  - 修正 `dns_lookup_timeout` 故障建议为清理本地回环上游 `uci delete dhcp.@dnsmasq[0].server`，杜绝将 Dnsmasq 指向未监听的 `5335` 端口或触发回环死锁。
- **[高危] 全局节点标签去重防碰撞与 `check_config.py` 重复 Tag 门禁 (F-05)**：
  - 修复 `filter_nodes`、`to_dae_nodes` 与 `auto_config.py` 中去重后缀与存量节点名二次碰撞（如 `HK`、`HK`、`HK 2` 产出两个 `HK-2`）的漏洞；在 `check_config.py` 中新增各模块重复 `tag` 阻断检测。
- **[高危] 节点 URI 协议解析与转 dae 百分号编码加固 (F-06, F-15)**：
  - 修复 SIP002 `ss://` 百分号编码（如 `%3D`）引发的 `binascii.Error` 崩溃；
  - 修复 Hysteria2 / Trojan `user:password` 复合鉴权丢失用户名的问题，并支持 Hysteria2 端口跳跃（`20000-50000` -> `server_ports`）；
  - 修复 `to_dae_nodes` 未对密码与查询参数执行 RFC 3986 百分号编码导致含 `#`/`@`/`?` 的密码截断 URI 的漏洞；
  - 修复 VMess 节点 `"ps": ""` 为空字符串时生成空 tag 引发悬空引用报错的问题。
- **[高危] `setup_openwrt_network.sh` 与 `auto_config.py` SSH 参数注入防护与 `shift` 保护 (F-07)**：
  - 消除未加引号的 `$SSH_CMD` 词法分裂，增加主机名/用户名/端口格式校验与 `--` 选项分隔符，并在 `-u/-p/-i` 缺失参数值时安全报错退出。
- **[高危] `SKILL.md` 部署指令加固：补齐 `dae` `0600` 权限锁与 `sing-box` `user='root'` / `uci commit` (F-08, F-09)**：
  - 在 `dae-openwrt/SKILL.md` 中补充 `chmod 600` 权限锁与原生 `dae` (`/etc/init.d/dae`) 热重载指令；
  - 在 `singbox-openwrt/SKILL.md` 中补齐配置快照备份、`uci set sing-box.main.user='root'`、`workdir='/tmp/sing-box'` 与 `uci commit sing-box`。
- **[中危] 订阅解压体积限制、静态审计补全与固件兼容提升 (F-10 ~ F-20)**：
  - `sub_parser.py` 增加 10MB 响应与流式解压上限防 Gzip 炸弹，并为 Clash YAML 增加单节点 `try-except` 异常隔离；
  - `check_config.py` 补齐 `route.final`、`selector.default`、空 `outbounds`、嵌套 `logical` 规则集引用及 `ipaddress` 严格纯 IP 校验；
  - `check_dae_syntax.py` 改为引号感知注释剥离，修复含 `#Tag` 的双引号违规节点漏检；`openwrt.dae` 补充 DNS `request` 层 Canary 阻断；
  - `probe.sh` 结合 `DISTRIB_DESCRIPTION` 与 `/etc/os-release` 精准识别真机 iStoreOS，并用精确进程/UCI 匹配替代 `pgrep -f`；
  - `diagnose_dns.sh` 修正 `[7/7]` 检测计数错乱（8/7）、`dig` 文本过滤与 IPv6/RFC1918 匹配范围；
  - `setup_openwrt_network.sh` 补齐 `--revert` 对 `flow_offloading` 与 `mtu_fix` 的还原，并将参考文档中的 `masquerade='1'` 统一更正为 OpenWrt 标准 `masq='1'`。

## [0.4.2] - 2026-11-09

### 深度漏洞修复与健壮性加固 (Deep Hardening & Bug Fixes)

- **[高危] `doctor.sh` 排除致命反向建议**：
  - 修复 `doctor.sh` 规则集下载超时特征中建议用户显式配置 `download_detour: direct` 的严重自相矛盾漏洞（该配置会导致 sing-box 启动期触发 `empty direct outbound` 致命崩溃）；修正为引导用户重新生成时指定 `--mirror jsdelivr` CDN 加速镜像。
- **[高危] `dae/setup_openwrt_network.sh` 补充旁路由 `--bypass` 支持**：
  - 修复 `dae-openwrt` 脚本中未处理 `--bypass` 参数导致误把参数作为目标 IP 执行 SSH 崩溃的缺陷；完整实现 LAN 区域 IP 伪装 (`masq='1'`) 及 `--revert` 回滚清理。
- **[高危] `check_config.py` 拦截引导 DNS 域名型自环死锁**：
  - 新增静态审计门禁：校验 `route.default_domain_resolver` 所指向的 DNS 服务器其自身地址必须为纯 IP，杜绝因配置域名型引导解析器引发的不可逆无限递归 DNS 死锁。
- **[中危] `auto_config.py` 动态规则补全 `"action": "route"` 规范**：
  - 节点域名防死锁直连注入时，为 `dns.rules` 和 `route.rules` 项显式补充 `"action": "route"`，消除现代严格 schema 检验下的潜在不兼容。
- **[中危] `sub_parser.py` 转 dae 词法单引号转义与明文 VLESS 支持**：
  - 在生成 dae 节点时，对 URI 内部的单引号 `'` 强制进行 RFC 3986 `%27` 安全转义，彻底杜绝包含单引号密码打断 dae 语法的事故；
  - 修复非 TLS / 明文 VLESS 节点被强制注入 `security=tls` 导致握手失败的问题，精确输出 `security=none`。
- **[低危] `diagnose_dns.sh` IPv6 AAAA 检测兼容 dig**：
  - 在无 `nslookup` 仅有 `dig` 的最小化环境中补充 AAAA 过滤探测分支，杜绝假阳性 PASS 误报。
- **[低危] 文档笔误校正**：
  - 修正 `troubleshooting.md` 中“节点缺少双引号”的自相矛盾笔误为“节点未用单引号包裹”。

## [0.4.1] - 2026-11-09

### 错误修复 (Bug Fixes)

- **[高危] `dae validate` 命令语法修正**：
  - `dae-openwrt/SKILL.md`、`check_dae_syntax.py` 中所有出现的 `dae validate -c <file>` 均修正为 `dae validate <file>`；dae 官方 CLI 不支持 `-c` 参数（该参数属于 sing-box），错误用法会导致 Agent 部署流程在验证步骤直接失败。
- **[高危] dae procd/非 procd 热重载场景区分**：
  - 在 `dae-openwrt/SKILL.md` 红线部分补充说明：ImmortalWrt 官方源的 `dae` 包由 procd 管理，热重载使用 `/etc/init.d/dae reload`；裸二进制模式使用 `dae reload`。
- **[中危] OpenWrt 包管理器信息更正**：
  - `architecture-and-schema.md` 中明确了包管理器说明：OpenWrt **24.10 及更早正式 Release** 仍使用 `opkg` 作为包管理器，`apk` 仅在 main / SNAPSHOT 开发分支实验性启用。
- **[中危] `dae-openwrt/SKILL.md` 步骤数量标注错误**：
  - 修正 "6步工程闭环" 为 "7步工程闭环"（实际含步骤 7：结构化自愈诊断）。
- **[低危] `v1.14 download_detour` 禁止说明歧义修正**：
  - `singbox-openwrt/SKILL.md` 中统一说明：`download_detour: "direct"` 在 v1.13 和 v1.14 中均**不能**显式声明，这是全版本禁用字段，不仅限于 v1.14。
- **[低危] `http_clients` 的 `detour` 字段避坑说明增强**：
  - `architecture-and-schema.md` 中明确指出 `direct-client` 对象**不设 `detour` 字段**即为直连，显式写 `"detour": "direct"` 会触发致命崩溃，防止误操作。

## [0.3.0] - 2026-11-08

### 架构精简与解耦 (Architecture Streamlining & Decoupled Tooling)

- **移除宿主机端胶水脚本**：
  - 彻底删除了宿主机端冗余的 `deploy_singbox.sh/ps1` 与 `deploy_dae.sh/ps1`，改为通过标准 SSH 管道执行沙盒语法预检 (`sing-box check` / `dae validate`) 与原子服务平滑重启；
  - 删除了冗余的宿主机远程 PowerShell 薄包装脚本 (`.ps1`)，消除跨平台运维的双倍维护负担与行为漂移；
  - 两个技能仅保留纯正 POSIX `/bin/sh` 与跨平台 Python 脚本，原生贴合软路由 Linux 物理执行环境。
- **文档深度精简与高密度重构**：
  - 将原本平铺冗余的 19 篇长篇手册提炼合并为 6 篇高密度的一级参考文档。
- **模块化积木片段与解耦 (Composable Modular Mixins)**：
  - 新增 `assets/mixins/` 目录，包含 `inbound_tun.json`、`experimental.json`、`dns_base.json`、`route_base.json`、`outbounds_base.json` 等独立原子片段。
- **统一的最后一公里网络闭环 Hook (`setup_openwrt_network.sh`)**：
  - 动态精准查询 LAN zone（杜绝 `@zone[0]` 盲猜）；注入 `tun0` 放行与 `forward=ACCEPT`；激活 MSS 钳制 (`mtu_fix='1'`)；开启 Dnsmasq `filter_aaaa='1'`；写入 `/etc/sysctl.d/99-singbox.conf` / `99-dae.conf`；支持 `--bypass` 与 `--revert`。
- **智能诊断工具全面支持结构化 JSON (`doctor.sh --json` & `diagnose_dns.sh --json`)**。

---

## [0.2.0] - 2026-11-08

### 重大特性与架构升级

- **DNS 治理与防污染矩阵 (DNS Governance & Leak Prevention)**
- **模块化规则积木架构 (Modular Blocks & Composable Rules)**
- **最后一公里网络与网关接管闭环 (Last-Mile Transparent Proxy Network Hook)**
- **Bootstrap DNS 节点域名直连防死锁机制 (Anti-Deadlock Bootstrap DNS)**
- **旁路由 (Bypass Gateway) 首等支持**

---

## [0.1.0] - 2026-11-07

### 首个公开版本

- 两个技能：`singbox-openwrt`（sing-box 1.13 / 1.14+，TUN + FakeIP/RealIP）与 `dae-openwrt`（dae eBPF）。
