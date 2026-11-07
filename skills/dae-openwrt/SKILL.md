---
name: dae-openwrt
description: >-
  为 OpenWrt / ImmortalWrt / iStoreOS 软路由生成、修改、排查原生 dae / daed (Linux 内核级 eBPF 高性能透明代理) 配置文件与服务管理。
  当用户提及以下任意场景时必须触发：dae/daed配置与管理、软路由eBPF出海代理、br-lan/wan网卡绑定、dae 5条拓扑与语法铁律、
  dae规则编写(routing/dns/group)、软路由测试节点与订阅导入、无感平滑热重载(dae reload)、排查dae断网与DNS死循环、或寻找比TUN模式吞吐更高更省CPU的代理方案。
---

# dae OpenWrt eBPF 透明代理架构器

本技能专为 **OpenWrt**、**ImmortalWrt**、**iStoreOS** 软路由网关设计，指导原生 **dae / daed (Linux 内核级 eBPF 高性能透明代理)** 的规则编写、接口绑定约束、DNS 防环防御与生产级平滑热重载。

> **支持边界**：本技能的自动化脚本只管理**原生 dae**（`dae` 二进制 + `/etc/dae/config.dae`）。**daed**（Web 面板版，`/etc/daed`、面板端口 2023）请在 Web 面板中操作；部署脚本检测到只有 daed 时会明确拒绝并提示。另外 eBPF 需要 Linux 5.15+ 与 BTF，多数 iStoreOS / 家用 ARM 固件不满足，探针会自动拦截并建议改用 `singbox-openwrt`。

---

## 🚨 强制执行红线（任何任务开始前必读）

1. **严禁直接在路由器 `/etc` 下裸改配置**：一切修改必须先写入 `/tmp` 沙盒，经远端 `dae validate -c` 通过后再原子替换，并保留快照备份用于自动回滚。
2. **硬件保护红线**：`global` 中 `lan_interface: br-lan` + `wan_interface: auto` + `auto_config_kernel_parameter: true`；部署前关闭流量分载（Flow Offloading，否则报文绕过 eBPF）；dropbear/sshd 需做 OOM 保护。
3. **绝不盲目猜测**：网络异常先运行 `scripts/probe.sh` / `scripts/doctor.sh` 体检，再下结论。

---

## 📚 官方文档与知识库路由 (按需读取)

| 任务 | 优先查阅 |
| :--- | :--- |
| **OpenWrt dae 5 条铁律与内核依赖** | [dae_guidelines.md](./references/dae_guidelines.md) |
| **版本/固件兼容矩阵（apk/opkg、内核、BTF）** | [../singbox-openwrt/references/compat-matrix.md](../singbox-openwrt/references/compat-matrix.md) |
| **出海排障索引（含 dae 专属章节）** | [../singbox-openwrt/references/troubleshooting-index.md](../singbox-openwrt/references/troubleshooting-index.md) |
| **官方路由语法 (domain, dip, pname, mac)** | [routing-syntax.md](./references/routing-syntax.md) |
| **官方 DNS 配置 (DoH/DoT/DoQ, 响应重查)** | [dns-config.md](./references/dns-config.md) |
| **与 AdGuardHome / 外部 DNS 联动防环** | [dns-config.md](./references/dns-config.md) |
| **支持的代理协议与 URI 格式** | [proxy-protocols.md](./references/proxy-protocols.md) |
| **常见故障与连接排错手册** | [troubleshooting.md](./references/troubleshooting.md) |
| **上游官方文档索引（需要原文时查）** | [upstream-docs.md](./references/upstream-docs.md) |
| **OpenWrt 专用基准模板** | [openwrt.dae](./assets/templates/openwrt.dae) |

---

## 🛡️ OpenWrt 必须遵守的 5 条语义与拓扑铁律

在为软路由生成或调整 `.dae` 规则时，必须 100% 执行以下铁律：

### 1. 单引号词法规范
在 `.dae` 规范中，除 `ext:"xxx.dat:tag"` 外部文件引用外，所有包含冒号 `:`、斜杠 `/`、正则表达式或复合协议的字符串，统一使用单引号 `'...'` 包裹，避免解析歧义。
* 推荐：`tcp_check_url: 'http://cp.cloudflare.com'`

### 2. must_direct 防 DNS 死循环铁律
dae 默认拦截所有发往 53 端口的请求。宿主机核心网络组件（`dnsmasq`、`odhcpd`、`netifd`、`uhttpd`）发出的 DNS 查询若被拦截并交回自身，会瞬间形成高频递归死锁并导致路由器断网。必须在 `routing {}` **最顶部**对它们的 53 端口流量放行（官方建议只放行 DNS 流量，不必整进程 must_direct）：
```shell
routing {
    pname(dnsmasq, odhcpd, netifd, uhttpd) && l4proto(udp) && dport(53) -> must_direct
    dip(224.0.0.0/3, 'ff00::/8') -> direct
    dip(geoip:private) -> direct
    ...
}
```
> 副作用提醒：被 `must_direct` 放行的流量 dae 完全不可见。若局域网 DNS 解析器的上游查询走了 must_direct，dae 将学不到这些应答的 域名→IP 映射，`domain()` 规则可能无法匹配客户端流量。在本技能模板拓扑下（dae 的 dns 模块直接应答客户端查询），无此问题。

### 3. 布尔取反（!）合并铁律
两行独立的取反规则在 dae 中是 **OR** 语义：
```shell
!domain(geosite:a) -> my_group
!domain(geosite:b) -> my_group   # 实际含义：非 a 或 非 b 都走代理，大量流量被误送
```
表达“既不属于 A 也不属于 B”时**必须合并写在同一行内**：
```shell
!domain(geosite:a, geosite:b) -> my_group
```

### 4. 路由短路 (First-Match) 六层黄金顺序
规则自上而下匹配，一旦命中立即终止后续规则：
1. **[第 1 层] 核心宿主进程与私网广播保护**：`pname(dnsmasq, ...) -> must_direct` 及 `dip(geoip:private) -> direct`
2. **[第 2 层] 大流量下载与 P2P 绕行**：`pname(aria2c, qbittorrent-nox) -> must_direct` 及 `dscp(0x4) -> direct`
3. **[第 3 层] 海外 QUIC/UDP 443 抑制**：`l4proto(udp) && dport(443) && !domain(geosite:cn) -> block`（规避运营商 UDP 降速）
4. **[第 4 层] 重点海外服务专属分流**：`domain(geosite:google, geosite:openai, ...) -> 专属组`
5. **[第 5 层] 大陆大盘双向白名单直连**：`domain(geosite:cn) -> direct` 及 `dip(geoip:cn) -> direct`
6. **[第 6 层] 终态回落兜底**：`fallback: 默认代理组`

### 5. DNS 污染重查闭环铁律
在 `dns.routing.response` 中配置私网 IP 投毒重查时，正上方首行**必须**加入白名单放行，防止陷入无限递归：
```shell
response {
    upstream(googledns) -> accept # 首行必须放行可信上游！
    ip(geoip:private) && !qname(geosite:cn) -> googledns
    fallback: accept
}
```

---

## 🔌 软路由网卡绑定（global 必填项）

软路由作为局域网网关，在 `global` 块中必须显式声明局域网网桥与外网出口：

```shell
global {
    lan_interface: br-lan     # 绑定局域网网桥，代理整个内网终端
    wan_interface: auto       # 自动识别物理外网出口（PPPoE / DHCP）
    auto_config_kernel_parameter: true # 自动开启 net.ipv4.ip_forward=1 并关闭 ICMP redirects
}
```

---

## 🔍 维度一：环境感知与自动体检 (Reconnaissance)

部署 dae 前必须先调用探针确认软路由内核与 BTF 符号支持：

```bash
# 目标软路由本地或 SSH 管道执行探针 (输出彩色全景报告)
sh scripts/probe.sh

# Windows 远程一键调用探针 (支持 -Json 输出结构化数据)
pwsh scripts/probe.ps1 -Router 192.168.1.1
```

---

## ⚙️ 维度二：dae 配置生成与订阅脱水 (Config Engine)

本技能内置 `assets/templates/openwrt.dae` 基准模板与 `scripts/sub_to_dae.py`，支持将机场 HTTP/HTTPS 订阅、Base64 订阅文本或 Clash 配置一键转换为 dae 原生 `node { ... }` 块：

```bash
# 方式 1：输入机场订阅 URL，清洗垃圾节点并转为 dae 节点语法
python scripts/sub_to_dae.py "https://sub.domain.com/link?token=..." --max 15

# 方式 2：输入本地 Base64 订阅文件，仅保留香港与日本节点
python scripts/sub_to_dae.py ./subscription.txt --include "香港|日本|HK|JP"
```

---

## 🚀 维度三：原子级安全热重载与自动回滚 (Safe Deployment)

dae 的优势在于重载配置时**无需重启内核 eBPF 程序**，已有连接完全不断流。发布脚本执行严格的沙盒验证流水线：

```bash
# Linux / macOS 终端
bash scripts/deploy_dae.sh <路由器IP> <配置文件路径> [SSH用户,默认root] [SSH端口,默认22]

# Windows PowerShell 终端
pwsh scripts/deploy_dae.ps1 -RouterIP <路由器IP> -ConfigFile <配置文件路径>
```

**安全发布流水线：**
1. **内核与 eBPF 硬准入自主探查**：自动检测 `uname -r` 与 BTF 路径；若低于 Linux 5.15 或缺少 BTF/核心程序，**立即中止部署**并给出降级至 `singbox-openwrt` 的清晰指引。
2. **流量分载 (Flow Offloading) 自动治理**：部署脚本自动检测 OpenWrt 流量分载，发现开启则自动将其禁用，彻底杜绝数据包绕过 eBPF 导致代理失效。
3. **SSH 守护与防卡顿**：自动提升 `dropbear/sshd` 为 `oom_score_adj -1000` 并 `renice -5`，杜绝热重载或高负载时 SSH 发生断连或输入卡顿。
4. **远端沙盒语法校验**：在 `/tmp` 中调用 `nice -n 10 dae validate -c /tmp/test.dae`；校验不通过直接中断，不伤及生产运行。
5. **生成快照**：自动将当前配置备份为 `/etc/dae/config.dae.bak.<时间戳>`。
6. **平滑热重载**：执行 `dae reload`，更新分流规则与策略组，保留已有连接与 eBPF maps，零网络颠簸。
7. **WAN 重拨号自愈 Hook**：自动在 `/etc/hotplug.d/iface/99-dae` 植入事件钩子，PPPoE 踢线重拨后秒级自愈。
8. **存活巡检与秒级回滚**：探测进程状态；若异常则全自动复原快照配置并重新重载。

---

## ⚡ 维度四：系统级网络调优 (Performance Tuning)

在配置好 dae 代理后，可调用性能调优脚本激活 BBR 与高并发连接池：

```bash
# 在路由器上执行系统级调优
sh scripts/optimize_network.sh
```

---

## 🩺 维度五：智能运维与日志排错 (Smart Doctor)

当网络出现异常时，AI 可调用双重体检医生排障：

```bash
# 1. 全链路网络健康体检 (检测进程、网卡、防火墙、DNS 劫持闭环与出口落地)
sh scripts/diagnose_openwrt.sh

# 2. 智能日志深度分析 (检索 logread，自动分析 eBPF 加载异常、BTF 缺失等)
sh scripts/doctor.sh dae
```

---

## 🧪 测试与回归（改动任何脚本/模板后必须执行）

```bash
# 仓库根目录（两个技能共用）
python run_tests.py
```

`tests/test_check_dae_syntax.py` 守护 5 条铁律检测（dnsmasq 放行、response 白名单、取反合并、引号规范）；
`tests/test_shell_syntax.py` 守护全部 `.sh` 的 POSIX 语法与 LF 行尾。
**修改 `check_dae_syntax.py` 或模板后必须全绿**；新增检测规则必须同步新增测试。
