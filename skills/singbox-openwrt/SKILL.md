---
name: singbox-openwrt
license: MIT
compatibility: Requires Python 3.8+ on host and SSH access to an OpenWrt / ImmortalWrt / iStoreOS router
description: >-
  在 OpenWrt、ImmortalWrt、iStoreOS 上生成、部署和排查 sing-box 1.13/1.14 配置。适用于订阅导入、FakeIP/RealIP 分流、TUN 防火墙设置及代理断网排查。
---

# sing-box OpenWrt 配置与排障

提供 sing-box 配置生成、远端校验、网络设置和故障诊断。部署前确认固件、引擎版本和拓扑，按下列约束保留恢复路径。

---

## 部署约束

1. **严禁直接在路由器 `/etc` 下裸改配置**：一切修改必须先写入 `/tmp` 沙盒，经远端 `sing-box check` 通过后再备份原配置并原子替换，用于异常时自动回滚。
2. **硬件与网络设置**：`experimental.cache_file.path` 必须指向 `/tmp/sing-box-cache.db`（防闪存磨损）；TUN 模式必须放行 `tun0`（fw4）；`route.auto_detect_interface: true` 防自环；`route.default_domain_resolver` 防规则集下载死锁；dropbear/sshd 需做 OOM 保护。
3. **先采集诊断信息**：网络异常先运行 `scripts/probe.sh -j` 探针和 `scripts/doctor.sh --json` 诊断，再进行针对性修复。

---

## 参考资料

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

## 工作流程

根据用户拓扑选择配置；探针、校验和诊断结果作为部署依据。流程如下：

1. 确认主路由或旁路由拓扑，以及 FakeIP/RealIP 或 dae 接口绑定需求。
2. 运行 `probe.sh -j`，核对内核、引擎版本、资源和冲突服务。
3. 解析订阅、生成配置；按所需分流规则修改配置。
4. 运行静态检查，并在目标设备执行原生校验。
5. 备份配置，再替换文件、重载服务。
6. 按拓扑执行 `setup_openwrt_network.sh`，保留自动恢复直到验证完成。
7. 检查管理连接、DNS 和客户端流量，必要时读取诊断 JSON。

---

## 环境检查

修改前先采集设备信息：

```bash
# 目标软路由本地或 SSH 管道执行探针 (输出结构化 JSON，供 Agent 快速解析)
ssh root@192.168.1.1 "sh -s -- -j" < scripts/probe.sh
```

**探针核心探测项：**

1. **发行版与包管理器**：精准识别 OpenWrt 原版、ImmortalWrt 还是 iStoreOS；判断包管理器是经典 `opkg` 还是新系列 `apk`。
2. **内核与 BTF 符号**：检测内核主次版本与 BTF 文件（`/sys/kernel/btf/vmlinux`）。
3. **硬件资源评估**：精确区分 x86_64、aarch64、armv7、mips/mipsel 大小端；检测空闲 RAM 与 ROM，ROM 小于 15MB 自动警示并锁定 `/tmp` 缓存。
4. **端口与冲突扫描**：检测 53 端口占用者，深度扫描是否有 PassWall、OpenClash、HomeProxy、Nikki 等遗留插件未关闭。

---

## 生成配置

本技能自带自动化版本探测与规则生成工具 `scripts/auto_config.py` 与通用订阅清洗器 `scripts/sub_parser.py`，实现**自适应版本匹配与多协议订阅解析**：

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
3. **生成后自动静态审计（“一次成功”保障）**：`auto_config.py` 输出前会内置跑一遍 `check_config` - 存在悬空引用、重复标签、非法字段等阻断错误时**绝不输出文件**，先修再发。
4. **国内首启动冷启动死锁消除 (`--mirror jsdelivr`)**：自动将 GitHub 原始链接替换为国内直接秒拉的 jsDelivr CDN 镜像，根除“未翻墙无法下载规则，无规则无法翻墙”的死锁问题。
5. **机场广告过滤与节点上限保护 (`--max-nodes 15`)**：自动剔除垃圾公告节点，去重并限制节点数，防止过多节点耗尽 256MB/512MB 内存。
6. **强制注入 OpenWrt 物理网关防御**：不论哪个版本，一律强制注入 `/tmp/sing-box-cache.db` 闪存保护、`auto_detect_interface: true` 防环、`default_domain_resolver` 纯 IP 引导防死锁及 `127.0.0.1:9090` Clash API 本机控制（远程管理使用 SSH 隧道）。

---

## OpenWrt 必须遵守的 8 项硬规则

### 1. 路由器缓存文件位置
频繁写入会消耗闪存擦写寿命，`experimental.cache_file.path` **必须**显式指定在挂载于 RAM 的临时目录：
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

* `auto_detect_interface: true`：自动将节点出站连接绑定到物理 WAN 口，防止 TUN 流量自环。
* `default_domain_resolver`：指定国内直连纯 IP DNS（如阿里 DNS `223.5.5.5`），确保启动初期拉取远程 `.srs` 规则集与解析 VPS 域名时不会死锁。
* **纯净 TUN 入站防自环**：TUN 入站严禁开启 `auto_redirect: true`（缺少 `kmod-nft-queue` 内核会导致 nfqueue 崩溃并退化为端口重定向自环死锁），统一使用纯净 L3 原生 TUN（`auto_redirect: false`）。

### 3. OpenWrt 原生网络接管闭环 (`setup_openwrt_network.sh`)
自 OpenWrt 22.03 起（fw4 / nftables），任何未在防火墙中声明的虚拟网卡流量转发均被默认丢弃（DROP）。必须直接在路由器上调用原生网络闭环脚本：
```bash
# 在软路由上直接执行闭环接管：
sh /etc/sing-box/setup_openwrt_network.sh
# 若为单网口旁路由，追加 --bypass 开启局域网 NAT 伪装 (masq='1')：
sh /etc/sing-box/setup_openwrt_network.sh --bypass
```
**闭环接管执行 5 大核心动作：**

1. **精准定位 LAN Zone**：动态查询 `uci get firewall.@zone[i].name`，严禁硬编码 `@zone[0]`，将 `tun0` 安全注入 lan zone 并开启 `forward=ACCEPT`。
2. **MSS 钳制 (MTU Clamping)**：开启 `mtu_fix='1'`，杜绝因 PPPoE MTU 1492 引起的大包握手卡死。
3. **DNS 转发路径清理**：清理遗留的本机 53 端口 DNAT 重定向规则，确保三层 `tun0` 的 `hijack-dns` 不被本机重定向短路。
4. **Dnsmasq 接管与 AAAA 纯净过滤**：开启 `filter_aaaa='1'`，纯净返回 IPv4，避免无 IPv6 环境下客户端等待 AAAA 超时。
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
* **所有版本均禁止**：`download_detour: "direct"`（无论是在 `rule_set` 还是 `http_clients` 中，显式写 `detour: "direct"` 都会在启动期触发 `empty direct outbound` 致命崩溃 - 直连下载**不设该字段**即为默认直连，切勿画蛇添足）。
* **v1.14 严禁使用**：`independent_cache`、`store_rdrc`（自 1.14 起已废弃，直接换用新字段）。

### 6. IPv4 纯净防假死原则
除非用户明确确认其宽带 IPv6 链路优质且要求启用，否则默认执行 IPv4-only 策略以避免无 IPv6 路由时客户端等待 AAAA 超时：

* DNS 模块：`"strategy": "ipv4_only"`
* TUN 入站：仅分配 IPv4 子网（`"address": "172.19.0.1/30"`），不给 TUN 配 IPv6 地址。

### 7. 本地局域网 Dnsmasq 打通与反向解析保护 (.lan & PTR)
为了杜绝开启 FakeIP 后导致局域网主机名（如 `router.lan`、`nas.lan`）解析失败，模板必须内置定向规则将 `.lan`、`.local` 及内网 `PTR` 反向解析无条件送给 `local-dns` 直连解析，严禁为其分配 FakeIP。

### 8. Canary 域名阻断防 DoH 绕过
针对 Firefox DoH (`use-application-dns.net`) 与 Apple Private Relay (`mask.icloud.com`)，在 DNS 与 Route 规则中显式设为 `reject`，促使浏览器与客户端回退使用网关 DNS 分流。

---

## 部署

可通过 SSH 传输配置并执行校验：

```bash
# 0. [可选：针对 apk 缺包或路由器初始无网死锁] 宿主机 SSH 流式管道 (SSH Stream Pipe) 直灌二进制
# ssh root@192.168.1.1 "cat > /usr/bin/sing-box && chmod 755 /usr/bin/sing-box" < ./sing-box-linux-${ARCH}

# 1. 将生成的配置上传至软路由 /tmp 临时沙盒并执行语法校验
ssh root@192.168.1.1 "cat > /tmp/config.json.test && sing-box check -c /tmp/config.json.test" < /tmp/config.json

# 2. 启动路由器本地 45 秒防失联看门狗 (若重启后 SSH 断联，45 秒后自动还原配置与网络)
ssh root@192.168.1.1 "sh -s -- --watchdog" < scripts/setup_openwrt_network.sh

# 3. 备份快照、原子替换生产配置、设置 UCI 权限并重启服务
ssh root@192.168.1.1 "[ -f /etc/sing-box/config.json ] && cp /etc/sing-box/config.json /tmp/config.json.bak; mv /tmp/config.json.test /etc/sing-box/config.json && uci set sing-box.main.enabled='1' 2>/dev/null && uci set sing-box.main.user='root' 2>/dev/null && uci set sing-box.main.workdir='/tmp/sing-box' 2>/dev/null && uci commit sing-box 2>/dev/null; /etc/init.d/sing-box restart"

# 4. 执行网络闭环接管 (含二级路由私网 DNS 防旁路) 并在全新 SSH 连接中解除看门狗
ssh root@192.168.1.1 "sh -s" < scripts/setup_openwrt_network.sh
ssh root@192.168.1.1 "sh -s -- --confirm" < scripts/setup_openwrt_network.sh
```

---

## 故障诊断

当网络出现异常时，Agent 调用诊断脚本排障：

```bash
# 1. 结构化日志与运行状态体检 (输出机器可读 JSON，含 status/issues/suggested_actions)
ssh root@192.168.1.1 "sh -s -- sing-box --json" < scripts/doctor.sh

# 2. 专项 DNS 深度防污染与防泄漏健康体检
ssh root@192.168.1.1 "sh -s -- --json" < scripts/diagnose_dns.sh
```

Agent 解析 JSON 响应中的 `suggested_actions` 字段，即可自主执行针对性修复指令（如校准时钟、清理端口冲突、重启 dnsmasq）。

---

## 测试与回归（改动任何脚本/模板后必须执行）

```bash
# 仓库根目录（两个技能共用）
python run_tests.py
```

覆盖内容：模板不变量（版本门控/悬空引用/IPv4-only）、节点解析（VLESS/VMess/Trojan/HY2/SS）、
订阅清洗与 dae 导出、生成器自校验与端到端、静态审计器、POSIX shell 语法与 LF 行尾。


## 网络事务与恢复边界（R2S 真机复核）

网络脚本要求 root、flock、sha256sum、tar、mktemp 与 UCI。修改前在 `/etc/proxy-skills-network` 的 0700 私有目录保存完整 firewall/dhcp、受影响 sysctl 文件、引擎配置、运行参数与服务状态。自动启动 45 秒恢复计时器；必须通过新 SSH 连接和实际业务检查后执行 `--confirm`。确认只解除自动回滚，完整基线保留供 `--revert` 使用。两套引擎共享设备锁；先回滚当前引擎，才能切换另一套网络配置。

没有完整基线时 `--revert` 不修改现有配置；备份校验失败或恢复失败时返回非零并保留现场。不要使用旧版 `.network_baseline.bak` 与新版混合部署。开机恢复使用持久化的独立 init 脚本，不依赖 /tmp 或已安装的技能脚本。恢复验证覆盖配置、sysctl 与进程状态；完整流量路径和 DNS 泄漏仍需独立实测，不能只凭该脚本成功判断业务正常。

网络接管前，已运行的裸二进制引擎必须先纳入 `/etc/init.d/dae` 或 `/etc/init.d/sing-box` 服务管理；否则脚本会拒绝接管，因为无法可靠恢复服务生命周期。基线原先停止的引擎在回滚后仍有未托管进程时，恢复会返回失败并保留快照，不能把配置文件恢复当作服务恢复。部署后若 firewall/dhcp 或相关 sysctl 文件被其他工具修改，自动/手动恢复均会拒绝覆盖，需根据保留的快照协调差异。
