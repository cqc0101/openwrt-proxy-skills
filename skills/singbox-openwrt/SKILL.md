---
name: singbox-openwrt
description: >-
  为 OpenWrt / ImmortalWrt / iStoreOS 软路由网关生成、修改、排查 sing-box (v1.13 与 v1.14+) 生产级科学上网与透明代理配置。
  当用户提及以下任意场景时必须触发：OpenWrt/软路由科学上网、翻墙/出海/梯子/代理配置、导入或更换节点链接(vless/hysteria2/trojan/ss)、
  全屋断网排查、局域网电脑手机无法访问外网/Google/YouTube/ChatGPT、OpenWrt防火墙放行tun0、避免路由器闪存磨损与死锁、
  FakeIP/RealIP分流调整、软路由更换机场订阅、或者从PassWall/OpenClash/HomeProxy迁移寻求更稳定网关代理方案。
---

# sing-box OpenWrt 生产级透明代理架构器

本技能专为 **OpenWrt**、**ImmortalWrt**、**iStoreOS** 软路由网关设计，强化注入 OpenWrt 物理网关的硬件保护、防火墙白名单与零断网自动回滚机制。

---

## 🚨 强制执行红线（任何任务开始前必读）

1. **严禁直接在路由器 `/etc` 下裸改配置**：一切修改必须先写入 `/tmp` 沙盒，经远端 `sing-box check` 通过后再原子替换，并保留快照备份用于自动回滚。
2. **硬件保护红线**：`experimental.cache_file.path` 必须指向 `/tmp/sing-box-cache.db`（防闪存磨损）；TUN 模式必须放行 `tun0`（fw4）；`route.auto_detect_interface: true` 防自环；`route.default_domain_resolver` 防规则集下载死锁；dropbear/sshd 需做 OOM 保护。
3. **绝不盲目猜测**：网络异常先运行 `scripts/probe.sh -j` 探针和 `scripts/doctor.sh --json` 诊断，再进行针对性修复。

---

## 📚 知识库路由 (按需读取)

按具体任务读取最小必要 reference，避免一次性加载过载：

| 任务 | 优先查阅 |
| :--- | :--- |
| **架构规范、v1.13 vs v1.14 字段门控与基准模板** | [architecture-and-schema.md](./references/architecture-and-schema.md) |
| **RealIP vs FakeIP 机制、DNS 防污染与防循环死锁** | [dns-and-routing.md](./references/dns-and-routing.md) |
| **OpenWrt 防火墙/闪存保护/避坑指南与排障速查** | [openwrt-pitfalls-and-troubleshooting.md](./references/openwrt-pitfalls-and-troubleshooting.md) |
| **模块化规则积木与复杂拓扑组装指南** | [modular-blocks.md](./references/modular-blocks.md) |
| **可复用模块化片段 (Mixins)** | [assets/mixins/](./assets/mixins/) (`inbound_tun.json`, `dns_base.json`, `route_base.json`, `experimental.json`, `outbounds_base.json`) |
| **1.13 TUN FakeIP 软路由基准模板** | [openwrt-1.13-tun-fakeip.json](./assets/templates/openwrt-1.13-tun-fakeip.json) |
| **1.13 TUN RealIP 软路由基准模板** | [openwrt-1.13-tun-realip.json](./assets/templates/openwrt-1.13-tun-realip.json) |
| **1.14 TUN FakeIP 软路由基准模板** | [openwrt-1.14-tun-fakeip.json](./assets/templates/openwrt-1.14-tun-fakeip.json) |
| **1.14 TUN RealIP 软路由基准模板** | [openwrt-1.14-tun-realip.json](./assets/templates/openwrt-1.14-tun-realip.json) |

---

## 🧭 Agent 决策与全链路闭环架构 (Agent Autonomous Workflow)

本技能专为 AI Agent 设计，**大模型负责意图理解、拓扑推理与灵活装配，脚本负责高危确定性操作与底层事实感知**。全链路遵循 7 步工程闭环：

```
[步骤 1: 意图与拓扑推理] LLM 决策 (主路由 vs 旁路由 / FakeIP vs RealIP / 差异化分流 / 避坑策略)
       │
       ▼
[步骤 2: 底层事实感知] probe.sh -j (机器可读 JSON，探测包管理器/RAM/ROM/内核/BTF/冲突插件)
       │
       ▼
[步骤 3: 模块化积木组装] auto_config.py 或 Mixins 动态拼装 (assets/mixins/ + sub_parser.py 清洗节点)
       │
       ▼
[步骤 4: 静态门禁与沙盒预审] check_config.py (引用完整性/版本门控/闪存写保护锁定)
       │
       ▼
[步骤 5: Agent 自主部署与回滚] SSH 管道原子发布 (沙盒 sing-box check -> mv 替换 -> 服务重启)
       │
       ▼
[步骤 6: 最后一公里网关接管] setup_openwrt_network.sh (内核转发 / tun0信任 / MSS钳制 / 53接管 / BBR调优)
       │
       ▼
[步骤 7: 结构化自愈诊断] doctor.sh --json + diagnose_dns.sh --json (解析错误码与自愈命令)
```

---

## 🔍 维度一：环境感知与自动体检 (Reconnaissance)

在进行任何修改前，AI 必须先调用探针收集软路由系统与硬件画像：

```bash
# 目标软路由本地或 SSH 管道执行探针 (输出结构化 JSON，供 Agent 快速解析)
ssh root@192.168.1.1 "sh -s -- -j" < scripts/probe.sh
```

**探针核心探测项：**
1. **发行版与包管理器**：精准识别 OpenWrt 原版、ImmortalWrt 还是 iStoreOS；判断包管理器是经典 `opkg` 还是新系列 `apk`。
2. **内核与 BTF 符号**：检测内核主次版本与 BTF 文件（`/sys/kernel/btf/vmlinux`）。
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
   - 若探测为 **v1.13**：自动选用 `openwrt-1.13-tun-fakeip.json`（默认）或 `--dns-mode realip` 的 `openwrt-1.13-tun-realip.json`，启用 `store_rdrc: true` 与 `independent_cache: true`（注：远程规则集严禁显式配置 `download_detour: "direct"`，不设即默认直连，否则启动即崩）。
   - 若探测为 **v1.14+**：自动选用 `openwrt-1.14-tun-fakeip.json`（默认）或 `--dns-mode realip` 的 `openwrt-1.14-tun-realip.json`，启用 `optimistic: true`、`store_dns: true` 及 `default_http_client`，彻底剔除已废弃的旧字段。
3. **生成后自动静态审计（“一次成功”保障）**：`auto_config.py` 输出前会内置跑一遍 `check_config`——存在悬空引用、非法字段等阻断错误时**绝不输出文件**，先修再发。
4. **国内首启动冷启动死锁消除 (`--mirror jsdelivr`)**：自动将 GitHub 原始链接替换为国内直接秒拉的 jsDelivr CDN 镜像，根除“未翻墙无法下载规则，无规则无法翻墙”的死锁问题。
5. **机场广告过滤与节点上限保护 (`--max-nodes 15`)**：自动剔除垃圾公告节点，去重并限制节点数，彻底杜绝上百个节点冲垮低配路由器 256MB/512MB 内存。
6. **强制注入 OpenWrt 物理网关防御**：不论哪个版本，一律强制注入 `/tmp/sing-box-cache.db` 闪存保护、`auto_detect_interface: true` 防环、`default_domain_resolver: "alidns"` 防规则集死锁及 `0.0.0.0:9090` Clash API 局域网控制。

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
* **纯净 TUN 入站防自环**：TUN 入站严禁开启 `auto_redirect: true`（缺少 `kmod-nft-queue` 内核会导致 nfqueue 崩溃并退化为端口重定向自环死锁），统一使用纯净 L3 原生 TUN（`auto_redirect: false`）。

### 3. OpenWrt 原生网络接管闭环 (`setup_openwrt_network.sh`)
自 OpenWrt 22.03 起（fw4 / nftables），任何未在防火墙中声明的虚拟网卡流量转发均被默认丢弃（DROP），且 Dnsmasq 占着 53 端口。必须直接在路由器上调用原生网络闭环脚本：
```bash
# 在软路由上直接执行闭环接管：
sh /etc/sing-box/setup_openwrt_network.sh
# 若为单网口旁路由，追加 --bypass 开启局域网 NAT 伪装：
sh /etc/sing-box/setup_openwrt_network.sh --bypass
```
**闭环接管执行 5 大核心动作：**
1. **精准定位 LAN Zone**：动态查询 `uci get firewall.@zone[i].name`，严禁硬编码 `@zone[0]`，将 `tun0` 安全注入 lan zone 并开启 `forward=ACCEPT`。
2. **MSS 钳制 (MTU Clamping)**：开启 `mtu_fix='1'`，杜绝因 PPPoE MTU 1492 引起的大包握手卡死。
3. **DNAT 53 端口强制重定向**：将局域网非本机 DNS 请求强制重定向至本机 53 端口。
4. **Dnsmasq 接管与 AAAA 纯净过滤**：开启 `filter_aaaa='1'`，纯净返回 IPv4，根除手机 App 转圈假死。
5. **系统内核网络调优**：写入 `/etc/sysctl.d/99-singbox.conf`，激活 BBR 拥塞控制与 65536 连接池。

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
* **v1.13 专用**：`independent_cache`、`store_rdrc`。
* **v1.14 专用**：`dns.optimistic`、`store_dns`、`default_http_client`。
* **所有版本均禁止**：`download_detour: "direct"`（无论是在 `rule_set` 还是 `http_clients` 中，显式写 `detour: "direct"` 都会在启动期触发 `empty direct outbound` 致命崩溃——直连下载**不设该字段**即为默认直连，切勿画蛇添足）。
* **v1.14 严禁使用**：`independent_cache`、`store_rdrc`（自 1.14 起已废弃，直接换用新字段）。

### 6. IPv4 纯净防假死原则
除非用户明确确认其宽带 IPv6 链路优质且要求启用，否则默认执行 IPv4-only 策略以防止国内手机 App 打开首页转圈死锁：
* DNS 模块：`"strategy": "ipv4_only"`
* TUN 入站：仅分配 IPv4 子网（`"address": "172.19.0.1/30"`），不给 TUN 配 IPv6 地址。

### 7. 本地局域网 Dnsmasq 打通与反向解析保护 (.lan & PTR)
为了杜绝开启 FakeIP 后导致局域网主机名（如 `router.lan`、`nas.lan`）解析失败，模板必须内置定向规则将 `.lan`、`.local` 及内网 `PTR` 反向解析无条件送给 `local-dns` 直连解析，严禁为其分配 FakeIP。

### 8. Canary 域名阻断防 DoH 绕过
针对 Firefox DoH (`use-application-dns.net`) 与 Apple Private Relay (`mask.icloud.com`)，在 DNS 与 Route 规则中显式设为 `reject`，强制内网浏览器和客户端遵循网关分流规则，绝不泄漏。

---

## 🚀 维度三：Agent 自主部署流程 (Autonomous Deployment)

Agent 无需依赖笨重多余的宿主机部署脚本，直接通过标准终端工具自主完成部署与验证：

```bash
# 1. 将生成的配置上传至软路由 /tmp 临时沙盒
ssh root@192.168.1.1 "cat > /tmp/config.json.test" < /tmp/config.json

# 2. 远端沙盒严格语法与依赖校验
ssh root@192.168.1.1 "sing-box check -c /tmp/config.json.test"

# 3. 校验通过后原子替换生产配置并平滑重启服务
ssh root@192.168.1.1 "mv /tmp/config.json.test /etc/sing-box/config.json && uci set sing-box.main.enabled='1' 2>/dev/null; /etc/init.d/sing-box restart"

# 4. 执行网络闭环接管脚本
ssh root@192.168.1.1 "sh -s" < scripts/setup_openwrt_network.sh
```

---

## 🩺 维度四：智能排障与自愈闭环 (Machine-Readable Doctor)

当网络出现异常时，Agent 调用结构化诊断医生排障：

```bash
# 1. 结构化日志与运行状态体检 (输出机器可读 JSON，含 status/issues/suggested_actions)
ssh root@192.168.1.1 "sh -s -- --json" < scripts/doctor.sh

# 2. 专项 DNS 深度防污染与防泄漏健康体检
ssh root@192.168.1.1 "sh -s -- --json" < scripts/diagnose_dns.sh
```

Agent 解析 JSON 响应中的 `suggested_actions` 字段，即可自主执行针对性修复指令（如校准时钟、清理端口冲突、重启 dnsmasq）。

---

## 🧪 测试与回归（改动任何脚本/模板后必须执行）

```bash
# 仓库根目录（两个技能共用）
python run_tests.py
```

覆盖内容：模板不变量（版本门控/悬空引用/IPv4-only）、节点解析（VLESS/VMess/Trojan/HY2/SS）、
订阅清洗与 dae 导出、生成器自校验与端到端、静态审计器、POSIX shell 语法与 LF 行尾。
