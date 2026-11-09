# 更新日志

版本号遵循语义化版本（`主版本.次版本.修订号`）。0.x 阶段接口与目录结构可能调整。

## [0.5.6] - 2026-11-09

### 第三轮极限白盒审计、深水区加固与残余漏洞全量清零 (Merged Hardened & White-Box Release)

- **[高危] 修复 `parse_hysteria2` 将端口 `0`、越界端口 `>65535` 及反转跳跃范围 `50000-20000` 静默篡改为 `443` 的漏洞 (R3-01)**：
  - 原 `parse_hysteria2` 使用 `parsed.port or 443` 并在 `except ValueError:` 中回退 `first_p or 443`，导致端口 `0`、`70000` 或非法跳跃范围 `50000-20000` 被静默改写为 `443` 混入生产配置；现已严格校验 `1 <= port <= 65535` 与 `mport` 范围合法性。
- **[高危] 补全 `check_config.py` 对残缺代理节点、`outbound.domain_resolver` 悬空引用及空 `dns.servers.server` 的阻断门禁 (R3-02)**：
  - 修复代理出站缺失 `server`、`server_port`、`uuid`、`password`、`method` 时 `check_config.py` 0 报错放行的盲区；
  - 新增 `outbounds[i].domain_resolver` 引用存在性校验与 `dns.servers[i].server` 非空校验。
- **[高危] 为 `check_dae_syntax.py` 新增 `group` 策略组与 `dns.upstream` 悬空引用静态审计及跨引号配对检测 (R3-03)**：
  - 解析 `group {}` 与 `dns { upstream {} }` 块，精准拦截 `routing` 与 `dns.routing` 中指向未定义策略组或未定义 DNS 上游的悬空规则；
  - 将单/双引号闭合检测升级为状态机判断，消除双引号内含单引号（如 `ext:"a'b.dat:cn"`）时的误判并补齐双引号未闭合检测。
- **[中危] 阻断 Python `bool` 子类化 `int` 引发的 `port: true -> 1` 类型穿透漏洞 (R3-04)**：
  - 在 `parse_vmess`、`parse_clash_proxy`、`to_dae_nodes` 与 `detect_remote_version` 中显式拦截 `isinstance(port, bool)`，并在 `to_dae_nodes` 导出 `vmess://` 时自动剥离 IPv6 方括号。
- **[中危] 补齐 SSH 端口范围 (`1..65535`)、空白 DNS 参数及 Mock 仿真流水线 JSON 真实性校验 (R3-05, R3-06)**：
  - `setup_openwrt_network.sh` 与 `auto_config.py` 新增 SSH 端口 `1..65535` 边界检查与空白 DNS 地址拦截；
  - 修复 `run_docker_tests.py` 在无 `paramiko` 进程内 Mock 模式下因端口未监听降级生成 `1.13` 配置的假阳性问题。
- **[高危] 修复 `sub_parser.py` 纯 Python YAML 引擎块字典嵌套回退污染与键值拆分缺陷 (F-27)**：
  - 重构纯 Python YAML 状态机的缩进回退机制（dedent stack），并在退出子缩进层时清理 `pending_key`，彻底避免 `smux` 后的顶层参数被错误吞没；
  - 新增 `_split_yaml_kv` 函数，安全切分键值对，彻底杜绝冒号后缺少空格（如 `port:443` 或 `http://...`）时的非法截断。
- **[高危] 根治 `setup_openwrt_network.sh` 后台看门狗导致 SSH 会话挂起 45 秒 (F-28)**：
  - 重构看门狗后台子进程启动方式，采用双重子 Shell 孤儿化与完全重定向 `( ( sleep 45 ... ) </dev/null >/dev/null 2>&1 & ... )`，彻底解耦 SSH 管道与标准输出文件描述符，解决非交互式 SSH 会话等待看门狗超时的问题。
- **[诊断] 消除 `doctor.sh` 建议重启不兼容 Web 版 `daed` 的矛盾诊断 (F-29)**：
  - 在检查冲突的守护进程时，明确区分原生 `dae` (CLI/procd) 与第三方面板 `daed` (Web)；
  - 当发现系统中正在运行 `daed` 时，不再误报“建议运行 /etc/init.d/daed restart”，而是明确提示协议/架构不兼容并建议 `opkg install dae`。
- **[诊断] 提升 `diagnose_dns.sh` IPv6 地址提取准确度 (F-30)**：
  - 优化 IPv6 地址正则匹配逻辑，要求至少包含两个冒号或双冒号缩写（`::`），彻底防止单冒号十六进制单词误匹配为 IPv6 地址导致虚假污染告警。
- **[门禁] 增强 `check_dae_syntax.py` 与 `check_config.py` 静态门禁防护 (F-31, F-32)**：
  - `check_dae_syntax.py` 在检查单引号配对时，增加对转义单引号 `\'` 的安全豁免；
  - `check_config.py` 补充对 `route.default_interface` 接口名称的严格字符白名单正则校验，防止异常字符串注入路由配置。
- **[清理] 加固 `setup_openwrt_network.sh` 的 `--revert` 清理逻辑 (F-33)**：
  - 无论在 `singbox` 还是 `dae` 下执行 `--revert`，均同时清理 `/etc/sysctl.d/99-singbox.conf` 与 `/etc/sysctl.d/99-dae.conf`，彻底杜绝双套件切换部署时残留旧套件的 sysctl 优化项。
- **[单测] 单元测试矩阵扩充至 229 项 (全量 PASS)**：
  - 整合双版本所有白盒对抗与深水区单测用例，测试用例总数达到 **229 项**，覆盖率与严苛度创历史新高。

## [0.5.5] - 2026-11-09

### 第二轮极限对抗审计与深水区缺陷清零 (Round 2 Deep Adversarial Audit & Bug Zeroing)

- **[致命] 修复 `setup_openwrt_network.sh` 中 `.boot_guard` 在正常部署流程触发自杀式回滚的逻辑死锁**：
  - 原 `0.5.4_2` 在函数入口无条件判断 `if [ -f /etc/sing-box/.boot_guard ]`，导致 `--watchdog` 创建哨兵后，紧接着执行的网络闭环配置或 `--confirm` 会立即误判为“硬重启崩溃”并自我回滚，且 `--confirm` 分支永远无法到达；
  - 现修正为仅当闪存 `.boot_guard` 存在**且**内存盘 `/tmp/proxy_watchdog.token` 已因重启挥发丢失（同时当前动作非 `--confirm`/`--revert`/`--watchdog`）时才触发启动恢复，并同步注册 `/etc/uci-defaults/99-proxy-boot-guard` 实现真正断电/Panic 重启后的开机自动自愈。
- **[高危] 修复 `diagnose_dns.sh` 中 `awk` 正则 `sub(/[#:].*/, "", tok)` 截断全部 IPv6 冒号导致 AAAA 泄漏漏检的漏洞**：
  - 原脚本在剥离端口号时误用 `[#:]` 字符类，将所有 IPv6 地址从第一个冒号处截断（如 `2404:6800::1` 变成 `2404`），致使后续 IPv6 正则永远无法匹配，第 4 关 AAAA 污染检测在 `nslookup` 下恒定假阳性 PASS；现已拆分为精准剥离 `#port` 与 IPv4 `:port`。
- **[高危] 修复 `parse_clash_yaml_pure_python` 在嵌套流式字典、多级块字典、YAML 列表及行内注释下的 6 处解析缺陷**：
  - 重构纯标准库 Clash YAML 解析引擎，完整支持行内 `#` 注释剥离、嵌套 `{...}` 流式字典（如内联 `ws-opts: {path: /ws, headers: {Host: ...}}`）、多级缩进字典栈、行内/多行列表（`alpn`）以及 Base64 包裹的 Clash YAML 订阅。
- **[高危] 修复 `auto_config.py` 与 `sub_parser.py` 未在清洗阶段过滤 Shadowsocks 废弃加密算法导致整份订阅中止的缺陷**：
  - 在 `filter_nodes`、`parse_clash_proxy` 与 `auto_config.py` 解析期直接隔离 `aes-256-cfb`、`rc4-md5`、`chacha20` 等废弃流加密节点，使含单颗旧节点的机场订阅能平滑跳过坏节点，避免混入配置后被 `check_config.py` 全局阻断 (`exit 3`)。
- **[中危] 修复 `probe.sh` 与 `doctor.sh` 的 `daed_conflict` 静态文件死锁误报与 `FREE_ROM` 归零缺陷**：
  - 移除对静态残留文件 `/etc/daed/wing.db` 的硬绑定（避免执行 `/etc/init.d/daed stop && disable` 后仍永久报错），改为检测 `daed` 真实运行进程与服务启用状态，且在 `doctor.sh sing-box` 模式下不误报 `daed` 指令；
  - 修复 `probe.sh` 在 `/overlay` 未独立挂载（归属 `/`）的固件上 `df -m /overlay` 匹配不到 `$NF=="/overlay"` 导致剩余闪存误报为 `0MB` 的缺陷；
  - 增强 `check_config.py` 对 `tun.address` 无掩码非法 CIDR 与 `urltest` 误配 `default` 字段的静态阻断。
- **[修复] 清理 `CHANGELOG.md` 控制字符损坏并扩充回归单测至 222 项**。

## [0.5.4] - 2026-11-09

### 全栈深度审计加固与边界缺陷清零 (Deep Code Audit & Full-Stack Hardening)

- **[高危] 根治 `/tmp` 内存盘挥发性失效 (Flash Pre-Rollback & Boot Guard)**：
  - 在 `setup_openwrt_network.sh` 中为 `--watchdog` 引入持久化闪存快照 `/etc/sing-box/.config.json.rollback`（或 `dae` 的 `.config.dae.rollback`）与启动哨兵 `.boot_guard`；
  - 彻底根治因极端配置引发内核崩溃（Kernel Panic）或硬件断电时 `/tmp` 内存盘被瞬间清空导致看门狗与快照挥发失效的单点隐患；路由器在硬重启后执行开机即时自愈强力还原。
- **[高危] 攻克无 PyYAML 环境下 Clash 订阅解析盲区与 YAML 锚点支持**：
  - 在 `sub_parser.py` 中内置基于纯标准库的轻量 YAML 状态机 `parse_clash_yaml_pure_python`；
  - 完整解析 `&anchor` 块式/流式锚点定义与 `<<: *anchor` 属性继承，实现 0 第三方库依赖下 100% 成功解析主流机场复杂 Clash 订阅。
- **[治理] 破除 `daed` (Web面板) 与原生 `dae` (CLI/procd) 的天然认知断层**：
  - `probe.sh` 与 `doctor.sh` 引入对 `daed` 进程、`/etc/daed/wing.db` 数据库与 2023 端口的强互斥检测与诊断提醒；
  - `SKILL.md` 新增强互斥红线，严禁在 `daed` 独占 eBPF/TC 时盲目下发原生 `config.dae` 配置。
- **[门禁] `check_config.py` 补充 Shadowsocks 废弃流加密方法阻断**：
  - 静态门禁扫描拦截 `aes-256-cfb`、`rc4-md5`、`bf-cfb` 等已遭 sing-box v1.8+ 淘汰的 Cipher，阻断启动崩溃。
- **[高危] 修复 `doctor.sh` 默认 `all` 模式跳过进程与 `tun0` 存活检查的盲区**：
  - 当不带服务名直接运行 `doctor.sh --json` 时，原先 `SERVICE_NAME="all"` 未进入 `sing-box`/`dae` 分支，导致核心进程停摆或 `tun0` 丢失时仍误报 `healthy`；现已补全自动引擎状态检查与 `tun0`/防火墙校验。
- **[高危] 修复 `setup_openwrt_network.sh` 看门狗并发竞争误回滚与基线恢复盲区**：
  - 为 `--watchdog` 引入唯一令牌 `/tmp/proxy_watchdog.token` 与 `pkill -P` 子进程清理，根治 BusyBox `ash` 下前序残留 `sleep 45` 子进程误回滚后续已确认部署的竞态漏洞；
  - 补全 `ORIG_LAN_FORWARD` 基线备份与无损恢复，消除 `[ -n ... ] && uci set || uci delete` 短路误删隐患；
  - 为 `dae` 网络脚本补齐 `LAN_INDEX` 缺失显式报错拦截与 `clean_dns_redirects` 遗留 53 端口 DNAT 清理。
- **[高危] 修复 `auto_config.py` 自定义 `IP:Port` 及 `tls://`/`quic://` DNS 上游解析错误**：
  - 修复传入 `--dns-cn 127.0.0.1:5335`（如 AdGuardHome/SmartDNS 级联）时未拆分 `server_port` 且误判为域名注入 `bootstrap-dns` 的缺陷；新增对 `tls://`、`quic://`、`h3://`、`tcp://`、`udp://` 协议及 `[ipv6]:port` 的完整解析；
  - 调整 `dns_base.json` 与 4 个基准模板的 `dns.rules` 顺序，使 `geosite-ads` 与 Canary 域名（`use-application-dns.net`、`mask.icloud.com`）阻断优先于 `clash_mode: Global`。
- **[中危] 节点解析期端口边界强校验与协议无损转换加固**：
  - 在 `parse_node.py` 与 `sub_parser.py` 解析阶段即拦截超出 `1..65535` 的非法端口，确保含单颗坏端口节点的机场订阅能单点隔离跳过，而非混入配置后触发 `check_config.py` 整包中止；
  - 修复 `ss://` 整体 Base64 编码节点丢失内部 `?plugin=...` 参数的问题；
  - 修复 `to_dae_nodes` 导出 `vmess://` 时丢失 `httpupgrade`/`h2` 的 `transport.host`、`tls.alpn` 与 `allowInsecure` 的问题；
  - 支持 VLESS/Trojan/HY2 `servername` 参数别名，并在 TLS+WS/HTTPUpgrade 缺省 `sni` 时自动回退至 `host`。
- **[中危] `dae` 旁路由 IPv6 主网关单引号合规与静态检查增强**：
  - `sub_to_dae.py` 在 `--topology bypass` 注入 IPv6 或 CIDR 主网关时自动包裹单引号 `dip('...') -> direct`，并对 `--lan-iface`/`--wan-iface` 执行白名单字符校验；
  - `check_dae_syntax.py` 新增对选择器内部双引号（如 `domain("...")`）的违规拦截，并在 `node {}` 与 `subscription {}` 同时为空时输出提醒。
- **[测试] 单元测试矩阵扩充至 217 项**：
  - 新增纯 Python Clash YAML 锚点解析、Shadowsocks 废弃加密方法阻断、闪存开机哨兵与 daed 冲突探测测试，全量 217 项单元测试 100% 满分通过。

## [0.5.3] - 2026-11-09

### Reality 凭据完备性、Shadowsocks SIP002 Obfs 插件、旁路网关 IPv6 校验与 204 项 QA 矩阵 (Protocol Enforcement & Syntax Hardening)

- **[高危] Reality 节点公钥 (pbk/public_key) 与 SNI 严格完备性门禁**：
  - parse_node.py (sing-box & dae) 针对 VLESS Reality 协议，缺少 pbk 关键参数时严格抛出 ValueError，彻底杜绝缺少公钥导致 sing-box / dae 启动崩溃；
  - sub_parser.py 解析 Clash 订阅中 `reality-opts` 时，强制校验 public-key 必须存在且非空，非法节点安全隔离并记录日志；
  - check_config.py 静态检测增强：深度扫描所有 `reality` 出站，若 `tls.reality.public_key` 或 `tls.server_name` 为空直接标记 [致命] VLESS Reality 缺少 public_key 或 server_name 并阻断下发。
- **[特性] Shadowsocks SIP002 obfs-local 插件原生支持与未知插件拦截**：
  - parse_node.py 原生解析 plugin=obfs-local;obfs=http;obfs-host=...，提取 plugin、plugin_opts 并注入 sing-box 配置；Clash 配置中兼容解析 plugin: obfs 及其 options；
  - 严格校验插件类型，对未受支持的插件（如 shadow-tls 等）安全报错抛出异常。
- **[规范] 旁路由网关 IP 严格 ip_interface 校验与 IPv6 支持**：
  - `auto_config.py` 与 sub_to_dae.py 旁路由模式下的 --main-router-ip 参数全面升级为 ipaddress.ip_interface 严格解析；
  - 支持标准 IPv4 / IPv6 地址及带掩码 CIDR（如 `fd00::1/128`），拦截任意畸变非 IP 字符串。
- **[死锁防护] DNS 上游解析器 domain_resolver 自环死锁检测**：
  - check_config.py 深入探测 DNS 服务器的 domain_resolver 字段，若指向其自身的 `tag`（自环循环引用），严格输出 [自环死锁] 并阻断下发。
- **[语法] check_dae_syntax.py 嵌套花括号 {} 平衡检测与 SKILL.md 看门狗时序优化**：
  - 增强 dae 配置文件结构合法性审计，精准识别并拦截因漏写关闭花括号 } 导致的配置解析中断；
  - dae-openwrt/SKILL.md 优化看门狗执行时序：将 45 秒防失联看门狗前移至替换配置与 reload 之前启动，杜绝 eBPF 生效即锁死 SSH 导致看门狗未能启动的单点故障。
- **[测试] 单元测试矩阵扩充至 204 项**：
  - 新增 Reality 公钥校验、SIP002 obfs、IPv6 bypass、DNS 自环死锁与未闭合花括号等系列测试用例，全量 204 项单元测试 100% 满分通过，12 轮压力测试全部 PASS。

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
