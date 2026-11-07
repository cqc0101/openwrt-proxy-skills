---
name: singbox-openwrt
description: >-
  为 OpenWrt / ImmortalWrt / iStoreOS 软路由网关生成、修改、排查 sing-box (v1.13 与 v1.14+) 生产级科学上网与透明代理配置。
  当用户提及以下任意场景时必须触发：OpenWrt/软路由科学上网、翻墙/出海/梯子/代理配置、导入或更换节点链接(vless/hysteria2/trojan/ss)、
  全屋断网排查、局域网电脑手机无法访问外网/Google/YouTube/ChatGPT、OpenWrt防火墙放行tun0、避免路由器闪存磨损与死锁、
  FakeIP/RealIP分流调整、软路由更换机场订阅、或者从PassWall/OpenClash/HomeProxy迁移寻求更稳定网关代理方案。
---

# sing-box OpenWrt 生产级透明代理架构器

本技能专为 **OpenWrt**、**ImmortalWrt**、**iStoreOS** 软路由网关设计，基于 `shpirt/singbox-config` 底座深度魔改，强化注入 OpenWrt 物理网关的硬件保护、防火墙白名单与零断网自动回滚机制。

---

## 🚨 强制执行红线（任何任务开始前必读）

1. **严禁直接在路由器 `/etc` 下裸改配置**：一切修改必须先写入 `/tmp` 沙盒，经远端 `sing-box check` 通过后再原子替换，并保留快照备份用于自动回滚。
2. **硬件保护红线**：`experimental.cache_file.path` 必须指向 `/tmp/sing-box-cache.db`（防闪存磨损）；TUN 模式必须放行 `tun0`（fw4）；`route.auto_detect_interface: true` 防自环；`route.default_domain_resolver` 防规则集下载死锁；dropbear/sshd 需做 OOM 保护。
3. **绝不盲目猜测**：网络异常先运行 `scripts/probe.sh` / `scripts/diagnose_openwrt.sh` 体检，再下结论。

---

## 📚 知识库路由 (按需读取)

按具体任务读取最小必要 reference，避免一次性加载过载：

| 任务 | 优先查阅 |
| :--- | :--- |
| **OpenWrt 防火墙/闪存/死锁坑点** | [openwrt_pitfalls.md](./references/openwrt_pitfalls.md) |
| **生成流程、版本选择与回显规范** | [workflow.md](./references/workflow.md) |
| **v1.13 vs v1.14 字段门控与架构表** | [config-schema.md](./references/config-schema.md) |
| **OpenWrt/固件/sing-box 版本兼容矩阵（已对官方来源核验）** | [compat-matrix.md](./references/compat-matrix.md) |
| **症状 → 病因 → 修复排障索引（先查这个）** | [troubleshooting-index.md](./references/troubleshooting-index.md) |
| **中国家庭网络场景：机场/光猫/旁路由/IPv6** | [china-scenarios.md](./references/china-scenarios.md) |
| **RealIP vs FakeIP 机制与反污染** | [dns-routing.md](./references/dns-routing.md) |
| **URI 节点格式转换 (VLESS/HY2/SS)** | [node-conversion.md](./references/node-conversion.md) |
| **远程规则集 (.srs) 与分流列表** | [rule-sets.md](./references/rule-sets.md) |
| **连接生命周期与疑难排错速查** | [cookbook.md](./references/cookbook.md) |
| **1.13 TUN FakeIP 软路由基准模板** | [openwrt-1.13-tun-fakeip.json](./assets/templates/openwrt-1.13-tun-fakeip.json) |
| **1.13 TUN RealIP 软路由基准模板** | [openwrt-1.13-tun-realip.json](./assets/templates/openwrt-1.13-tun-realip.json) |
| **1.14 TUN FakeIP 软路由基准模板** | [openwrt-1.14-tun-fakeip.json](./assets/templates/openwrt-1.14-tun-fakeip.json) |
| **1.14 TUN RealIP 软路由基准模板** | [openwrt-1.14-tun-realip.json](./assets/templates/openwrt-1.14-tun-realip.json) |

---

## 🧭 软路由五维工程架构 (Swiss Army Knife Workflow)

本技能采用标准化的五维工程架构，确保从前置探针、配置生成、原子部署、性能调优到智能运维全链路 100% 闭环无故障：

```
[维度一: 环境感知] probe.sh (识别固件版本/包管理器/RAM/ROM/冲突插件)
       │
       ▼
[维度二: 配置生成] auto_config.py + sub_parser.py (脱水节点/订阅清洗/CDN镜像/FakeIP)
       │
       ▼
[维度三: 安全部署] deploy_singbox.sh (快照备份 -> 沙盒 check -> 热重载 -> 存活巡检 -> 自动回滚)
       │
       ▼
[维度四: 性能调优] optimize_network.sh (BBR激活/并发连接数/Go GOMEMLIMIT 防 OOM)
       │
       ▼
[维度五: 智能体检] diagnose_openwrt.sh + doctor.sh (DNS劫持验证/出口测试/日志智能排障)
```

---

## 🔍 维度一：环境感知与自动体检 (Reconnaissance)

在进行任何修改前，AI 必须先调用探针收集软路由系统与硬件画像：

```bash
# 目标软路由本地或 SSH 管道执行探针 (输出彩色全景报告)
sh scripts/probe.sh

# Windows 远程一键调用探针 (支持 -Json 输出结构化数据)
pwsh scripts/probe.ps1 -Router 192.168.1.1
```

**探针核心探测项：**
1. **发行版与包管理器**：精准识别 OpenWrt 原版、ImmortalWrt 还是 iStoreOS；判断包管理器是经典 `opkg`（24.10 及更早版本）还是新系列 `apk`（main/SNAPSHOT 分支）。
2. **内核与 BTF 符号**：检测内核主次版本与 BTF 文件（`/sys/kernel/btf/vmlinux` 或 `/usr/lib/debug/boot/vmlinux`）。
3. **硬件资源评估**：精确区分 x86_64、aarch64、armv7、mips/mipsel 大小端；检测空闲 RAM 与 ROM，ROM 小于 15MB 自动警示并锁定 `/tmp` 缓存。
4. **端口与冲突扫描**：检测 53 端口占用者，深度扫描是否有 PassWall、OpenClash、HomeProxy 等遗留插件未关闭。

---

## ⚙️ 维度二：双引擎配置生成器 (Config Engine)

本技能自带自动化版本探测与规则生成工具 `scripts/auto_config.py` 与通用订阅清洗器 `scripts/sub_parser.py`，实现**零人工干预的自适应版本匹配与全协议机场订阅接入**：

```bash
# 方式 A：指定软路由 IP + 机场通用订阅链接 (自动探测版本、拉取清洗订阅、应用 CDN 镜像、输出生产配置)
python scripts/auto_config.py --router 192.168.1.1 --sub "https://sub.domain.com/api/v1/client/subscribe?token=..." --mirror jsdelivr --out /tmp/config.json

# 方式 B：支持直接传入单个/多个节点链接 (vless://, hysteria2://, trojan://, ss://)
python scripts/auto_config.py --router 192.168.1.1 --node "vless://..." --node "hysteria2://..." --out /tmp/config.json

# 方式 C：离线指定版本与本地 Base64 / Clash YAML 订阅文件
python scripts/auto_config.py --version 1.14 --dns-mode fakeip --sub ./airport_clash.yaml --mirror jsdelivr --out /tmp/config.json
```

**自适应适配机制：**
1. **自动提取版本**：调用 `sing-box version` 提取主次版本号（如 v1.13 或 v1.14）。
2. **规则与语法自动降级/升级**：
   - 若探测为 **v1.13**：自动选用 `openwrt-1.13-tun-fakeip.json`（默认）或 `--dns-mode realip` 的 `openwrt-1.13-tun-realip.json`，启用 `store_rdrc: true`、`independent_cache: true` 及规则集 `download_detour: "direct"`。
   - 若探测为 **v1.14+**：自动选用 `openwrt-1.14-tun-fakeip.json`（默认）或 `--dns-mode realip` 的 `openwrt-1.14-tun-realip.json`，启用 `optimistic: true`、`store_dns: true` 及 `default_http_client`，彻底剔除已废弃的旧字段。
3. **生成后自动静态审计（“一次成功”保障）**：`auto_config.py` 输出前会内置跑一遍 `check_config`——存在悬空引用、非法字段等阻断错误时**绝不输出文件**，先修再发。
4. **国内首启动冷启动死锁消除 (`--mirror jsdelivr`)**：自动将 GitHub 原始链接替换为国内直接秒拉的 jsDelivr CDN 镜像，根除“未翻墙无法下载规则，无规则无法翻墙”的死锁问题。
5. **机场广告过滤与节点上限保护 (`--max-nodes 15`)**：自动剔除“剩余流量/到期时间/官网公告”等干扰垃圾节点，去重并限制节点数，彻底杜绝上百个节点冲垮低配路由器 256MB/512MB 内存。
6. **强制注入 OpenWrt 物理网关防御**：不论哪个版本，一律强制注入 `/tmp/sing-box-cache.db` 闪存保护、`auto_detect_interface: true` 防环、`default_domain_resolver: "alidns"` 防规则集死锁及 `0.0.0.0:9090` Clash API 局域网控制。

---

## 🩺 一键全链路健康体检医生 (Diagnostic Doctor)

软路由部署后用户若反馈“连不上外网/手机无法出海/网页打不开”，严禁盲目猜测！直接运行内置的一键全链路体检脚本：

```bash
# 目标软路由本地执行 (或通过 SSH 管道流式执行)
sh scripts/diagnose_openwrt.sh

# Windows 远程一键体检
pwsh scripts/diagnose_openwrt.ps1 -Router 192.168.1.1
```

**体检覆盖 8 大维度并输出诊断报告：**
1. **硬件与内存**：检测空闲内存、Swap、设备负载，预警 OOM 崩机。
2. **闪存安全**：扫描 `/etc` 盘，核实是否存在高频刷写的 `cache.db`。
3. **核心进程**：检测 `sing-box` / `dae` 是否存活，报告真实 PID 与物理内存占用 (RSS)。
4. **网卡与转发**：检测 `tun0` 网卡是否 UP，检查 `net.ipv4.ip_forward=1` 转发开关。
5. **防火墙放行**：检测 fw4 (nftables) / fw3 (iptables) 是否放行 `tun0`，杜绝局域网数据包被 DROP。
6. **DNS 劫持闭环**：验证 `router.lan` 局域网解析、`baidu.com` 国内真实 IP 解析、`google.com` FakeIP 劫持是否全部正常。
7. **真实出海连通性**：握手 Cloudflare 204，输出落地出口真实公网 IP、国家代码及网络延迟。
8. **自愈建议**：针对未放行网卡或参数异常给出具体的一行修复命令。

---

## 📊 零损耗 Web 可视化面板 (Clash Web UI)

配置默认开放 `0.0.0.0:9090` Clash API，局域网电脑/手机可通过浏览器免安装任何重型 OpenWrt 插件，零闪存与零内存损耗实现可视化管理：
* **在线控制面板**：浏览器直接打开 `http://yacd.haishan.me` 或 `https://metacubex.github.io/metacubexd/`
* **连接参数**：
  * **API 地址 (Host)**：填入软路由 IP（例如 `192.168.1.1` 或 `192.168.6.1`）
  * **端口 (Port)**：`9090`
  * **密钥 (Secret)**：留空（若模板未配 secret）
* **支持功能**：秒级测速、节点策略组一键点选切换、实时全局上传/下载速率与连接追踪。

---

## 🛡️ OpenWrt 必须遵守的 8 项硬规则

### 1. 路由器闪存保护铁律 (Flash Protection)
OpenWrt SPI 闪存擦写寿命极为脆弱，`experimental.cache_file.path` **必须**显式指定在挂载于 RAM 的临时目录：
```json
"experimental": {
  "cache_file": {
    "enabled": true,
    "path": "/tmp/sing-box-cache.db",
    "store_fakeip": true
  }
}
```
**严禁**省略 `path` 或写入 `/etc`，防止高频读写导致芯片物理坏块变砖！

### 2. 路由防环与解析死锁保护 (Anti-Loop & Anti-Deadlock)
在 `route` 模块中必须强制包含以下两项：
```json
"route": {
  "auto_detect_interface": true,
  "default_domain_resolver": "alidns"
}
```
* `auto_detect_interface: true`：自动将节点出站连接绑定到物理 WAN 口，彻底杜绝 TUN 流量自环。
* `default_domain_resolver`：指定国内直连 DNS（如阿里 DNS `223.5.5.5`），确保启动初期拉取远程 `.srs` 规则集与解析 VPS 域名时不会死锁。

### 3. OpenWrt fw4 防火墙 tun0 放行
自 OpenWrt 22.03 起（fw4 / nftables），任何未在防火墙中声明的虚拟网卡流量转发均被默认丢弃（DROP），导致局域网设备无法上网。
* 首次启用 TUN 模式时，必须执行放行指令或调用自带脚本：
  ```bash
  # 注意：不要写死 @zone[0]！zone 顺序不保证 lan 在第一位，必须按 name 定位 lan 区域
  LAN_IDX=$(i=0; while uci get firewall.@zone[$i].name >/dev/null 2>&1; do [ "$(uci get firewall.@zone[$i].name)" = "lan" ] && { echo $i; break; }; i=$((i+1)); done)
  [ -n "$LAN_IDX" ] && uci add_list firewall.@zone[$LAN_IDX].device='tun0' && uci commit firewall && /etc/init.d/firewall reload
  ```
  脚本快捷入口（推荐，脚本已内置上述 zone 定位逻辑）：`bash scripts/setup_openwrt_firewall.sh <路由器IP>`。

### 4. 路由首部双保险 DNS 劫持
所有软路由 TUN 模板的 `route.rules` 前两条必须保持：
```json
{ "action": "sniff" },
{
  "type": "logical",
  "mode": "or",
  "rules": [{ "protocol": "dns" }, { "port": 53 }],
  "action": "hijack-dns"
}
```
**严禁**只用单一的 `"protocol": "dns"`（会导致未被嗅探到的标准 UDP 53 DNS 报文泄漏漏劫持）。

### 5. 严格的版本字段门控 (v1.13 vs v1.14)
* **v1.13 专用**：`independent_cache`、`store_rdrc`、远程规则集 `download_detour: "direct"`。
* **v1.14 专用**：`dns.optimistic`、`store_dns`、`default_http_client`。
* **v1.14 严禁使用**：`independent_cache`、`store_rdrc`、`download_detour`（自 1.14 起已废弃，会产生告警且后续版本可能移除，直接换用新字段）。

### 6. IPv4 纯净防假死原则
除非用户明确确认其宽带 IPv6 链路优质且要求启用，否则默认执行 IPv4-only 策略以防止国内手机 App 打开首页转圈死锁：
* DNS 模块：`"strategy": "ipv4_only"`
* TUN 入站：仅分配 IPv4 子网（`"address": "172.19.0.1/30"`），不给 TUN 配 IPv6 地址。

### 7. 本地局域网 Dnsmasq 打通与反向解析保护 (.lan & PTR)
为了杜绝开启 FakeIP 后导致局域网主机名（如 `router.lan`、`nas.lan`、打印机设备名）解析失败，模板必须内置定向规则将 `.lan`、`.local` 及内网 `PTR` 反向解析无条件送给 `local-dns` 直连解析，严禁为其分配 FakeIP。

### 8. 超小型路由器硬件防爆与 SSH 零卡顿保护
针对 128MB/256MB/512MB RAM 或弱弱多核路由器，执行三层硬件防爆保护：
1. **轻量化规则集裁剪**：不加载包含数万条域名的全局大盘（如 `geosite-geolocation-!cn`），境外非 CN 流量直接依赖 `final: "proxy"` 自然兜底，单此一项节省 70MB+ 内存与 80% 启动 CPU 耗时！
2. **SSH 优先级与 OOM 免疫**：发布脚本自动将 `dropbear/sshd` 设为 `oom_score_adj -1000` 并 `renice -5`，确保极端负载下 SSH 终端零卡顿、绝不断连。
3. **WAN 断线重拨自愈 Hook**：自动在 `/etc/hotplug.d/iface/99-singbox` 注册事件钩子，PPPoE 踢线重拨后秒级自愈。

---

## 🚀 维度三：原子级安全部署与自动回滚 (Safe Deployment)

软路由改错配置会导致全屋断网及无法连接后台。本技能提供完整的原子级安全发布流水线：

```bash
# Linux / macOS 终端
bash scripts/deploy_singbox.sh <路由器IP> <配置文件路径> [SSH用户,默认root] [SSH端口,默认22]

# Windows PowerShell 终端
pwsh scripts/deploy_singbox.ps1 -RouterIP <路由器IP> -ConfigFile <配置文件路径>
```

**发布流水线安全机制：**
1. **沙盒校验**：文件先送至 `/tmp`，远端调用 `nice -n 10 sing-box check` 深度语法与依赖校验；失败直接退出，不触碰生产配置。
2. **状态快照**：自动备份当前网络与服务配置快照。
3. **Go GC 与 OOM 防御**：针对小内存路由器自动向启动脚本注入 `export GOMEMLIMIT=100MiB` 与 `export GOGC=50`，根治内存泄漏死机。
4. **平滑重启与自动回滚**：平滑重启后执行 3 秒进程存活与外网连通性测试；**进程崩溃则全自动秒级还原快照并重启**；外网离线则输出告警与修复指引（放行 tun0 / 运行诊断医生），避免因瞬时网络抖动误回滚正常配置。

---

## ⚡ 维度四：系统级网络调优 (Performance Tuning)

在配置好透明代理后，可调用性能调优脚本激活 BBR 与高并发连接池：

```bash
# 在路由器上执行系统级调优
sh scripts/optimize_network.sh
```

**调优项目明细：**
* **BBR 拥塞控制**：自动探测并激活 `tcp_bbr` + `fq_codel`，优化跨洋高延迟高丢包网络吞吐。
* **高并发连接池**：扩充 `nf_conntrack_max=65536`，优化 `somaxconn=4096` 与 `tcp_max_syn_backlog=4096`。
* **TCP 连接保活**：开启 `tcp_tw_reuse=1`，将 `tcp_fin_timeout` 缩减至 15s，杜绝僵尸连接堆积。

---

## 🩺 维度五：智能运维与日志排错 (Smart Doctor)

当网络出现异常时，AI 可按需调用双重体检医生排障：

```bash
# 1. 全链路网络健康体检 (检测进程、网卡、防火墙、DNS 劫持闭环与出口落地)
sh scripts/diagnose_openwrt.sh
# 或在 Windows 远程运行: pwsh scripts/diagnose_openwrt.ps1 -Router 192.168.1.1

# 2. 智能日志深度分析 (检索 logread，自动分析 TLS证书、时钟不同步、DNS自环、规则集超时)
sh scripts/doctor.sh sing-box
```

---

## 🧪 测试与回归（改动任何脚本/模板后必须执行）

本技能的所有生成逻辑都有回归测试保护，改动后必须全绿才能提交/使用：

```bash
# 仓库根目录（两个技能共用）
python run_tests.py
```

覆盖内容：4 个模板不变量（版本门控/悬空引用/IPv4-only）、节点解析（VLESS/VMess/Trojan/HY2/SS）、
订阅清洗与 dae 导出、生成器自校验与端到端、两个静态审计器、POSIX shell 语法与 LF 行尾。
**新增配置生成规则时，必须同步新增对应测试**；没有测试的“修复”不算修复。
