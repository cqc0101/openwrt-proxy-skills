---
name: dae-openwrt
license: MIT
compatibility: Requires Python 3.8+ on host and SSH access to an OpenWrt / ImmortalWrt / iStoreOS router (Linux 5.15+ with BTF)
description: >-
  为 OpenWrt / ImmortalWrt / iStoreOS 软路由生成、修改、排查原生 dae (Linux 内核级 eBPF 高性能透明代理) 配置文件与服务管理。
  当用户提及以下任意场景时必须触发：dae配置与管理、软路由eBPF出海代理、br-lan/wan网卡绑定、dae 5条拓扑与语法铁律、
  dae规则编写(routing/dns/group)、软路由测试节点与订阅导入、无感平滑热重载(dae reload)、排查dae断网与DNS死循环、或寻找比TUN模式吞吐更高更省CPU的代理方案。
---

# dae OpenWrt eBPF 透明代理架构器

本技能专为 **OpenWrt**、**ImmortalWrt**、**iStoreOS** 软路由网关设计，指导原生 **dae (Linux 内核级 eBPF 高性能透明代理)** 的规则编写、接口绑定约束、DNS 防环防御与生产级平滑热重载。

> **支持边界**：本技能管理**原生 dae**（`dae` 二进制 / procd `dae` 服务 + `/etc/dae/config.dae`，注意：Web 面板版 `daed` 使用 `/etc/daed/daed.db` 数据库，不读取 `/etc/dae/config.dae`）。eBPF 需要 Linux 5.15+ 与 BTF 支持，若固件不满足条件，探针会自动拦截并建议改用 `singbox-openwrt`。

---

## 🚨 强制执行红线（任何任务开始前必读）

1. **严禁直接在路由器 `/etc` 下裸改配置**：一切修改必须先写入 `/tmp` 沙盒并执行 `chmod 600`（`dae` 强制要求配置文件权限不宽于 `0600`/`0640`），经远端 `dae validate <file>` 通过后再备份原配置并原子替换。
2. **硬件保护红线**：`global` 中 `lan_interface: br-lan` + `wan_interface: auto` + `auto_config_kernel_parameter: true`；部署前关闭流量分载（Flow Offloading，否则报文绕过 eBPF）；dropbear/sshd 需做 OOM 保护。
3. **绝不盲目猜测**：网络异常先运行 `scripts/probe.sh -j` 探针和 `scripts/doctor.sh dae --json` 诊断，再进行针对性修复。
4. **dae validate 语法说明**：dae 官方 CLI 不支持 `-c` 参数（`-c` 是 sing-box 的参数），正确格式为 `dae validate /path/to/config.dae`。
5. **procd 托管与 daed 区分**：ImmortalWrt 官方源的原生 `dae` 包由 procd 管理，启用与热重载使用 `uci set dae.config.enabled='1' && uci commit dae && /etc/init.d/dae reload`（裸二进制模式使用 `dae reload`）；而 `daed` 是 Web 面板独立包，不读取 `/etc/dae/config.dae`。

---

## 📚 知识库路由 (按需读取)

| 任务 | 优先查阅 |
| :--- | :--- |
| **dae 5 条铁律、路由语法与配置规范** | [dae-rules-and-syntax.md](./references/dae-rules-and-syntax.md) |
| **常见故障排查手册与日志分析** | [troubleshooting.md](./references/troubleshooting.md) |
| **OpenWrt 专用基准模板** | [openwrt.dae](./assets/templates/openwrt.dae) |

---

## 🧭 Agent 决策与 eBPF 闭环架构 (Agent Autonomous Workflow)

本技能专为 AI Agent 设计，**大模型负责意图理解、eBPF 拓扑可行性推理与规则灵活装配，脚本负责高危确定性操作与底层事实感知**。全链路遵循 7 步工程闭环：

```
[步骤 1: eBPF 兼容性推理] LLM 评估 (Linux 5.15+ 内核 / BTF 支持 / 流量分载 Offloading 规避)
       │
       ▼
[步骤 2: 底层硬件感知] probe.sh -j (探测 BTF 文件 / 网卡名 / 冲突代理插件)
       │
       ▼
[步骤 3: 原子订阅解析] sub_to_dae.py (清洗节点 / 密码特殊字符安全转义 / 生成 dae link)
       │
       ▼
[步骤 4: 规则积木灵活装配] dae-rules-and-syntax.md (宿主组件 must_direct / 设备 MAC 分流 / 大陆双向直连)
       │
       ▼
[步骤 5: Agent 自主部署与热重载] SSH 管道原子发布 (chmod 600 -> 沙盒 dae validate -> 快照与 mv -> reload)
       │
       ▼
[步骤 6: 软路由网络闭环接管] setup_openwrt_network.sh (关闭 Flow Offloading / 开启 filter_aaaa / MSS 钳制)
       │
       ▼
[步骤 7: 结构化自愈诊断] doctor.sh dae --json + diagnose_dns.sh --json (解析错误码与自愈命令)
```

---

## 🛡️ OpenWrt 必须遵守的 5 条语义与拓扑铁律

在为软路由生成或调整 `.dae` 规则时，必须 严格遵循以下约束：

### 1. 单引号词法规范
在 `.dae` 规范中，除 `ext:"xxx.dat:tag"` 外部文件引用外，所有包含冒号 `:`、斜杠 `/`、正则表达式或复合协议的字符串，统一使用单引号 `'...'` 包裹，避免解析歧义。
* 推荐：`tcp_check_url: 'http://cp.cloudflare.com'`

### 2. must_direct 防 DNS 死循环铁律
dae 默认拦截所有发往 53 端口的请求。宿主机核心网络组件（`dnsmasq`、`odhcpd`、`netifd`、`uhttpd`）发出的 DNS 查询若被拦截并交回自身，会瞬间形成高频递归死锁并导致路由器断网。必须在 `routing {}` **最顶部**对它们的 53 端口流量放行：
```shell
routing {
    pname(dnsmasq, odhcpd, netifd, uhttpd) && l4proto(udp) && dport(53) -> must_direct
    dip(224.0.0.0/3, 'ff00::/8') -> direct
    dip(geoip:private) -> direct
    ...
}
```

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

### 4. 路由短路 (First-Match) 六层匹配顺序
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
# 目标软路由本地或 SSH 管道执行探针 (输出结构化 JSON，供 Agent 快速解析)
ssh root@192.168.1.1 "sh -s -- -j" < scripts/probe.sh
```

---

## ⚙️ 维度二：dae 配置生成与订阅脱水 (Config Engine)

使用 `scripts/sub_to_dae.py` 支持将机场 HTTP/HTTPS 订阅一键清洗并转换为 dae 原生 `node { ... }` 格式：

```bash
# 方式 A：一键合成完整 config.dae（自动注入 openwrt.dae 模板并内置执行 5 条铁律静态审计）
python scripts/sub_to_dae.py "https://sub.domain.com/link?token=..." --max 15 --full --out /tmp/config.dae

# 方式 B：仅导出 node { ... } 节点池语法块
python scripts/sub_to_dae.py "https://sub.domain.com/link?token=..." --max 15 --out /tmp/nodes.dae
```

---

## 🚀 维度三：Agent 自主部署与平滑热重载 (Autonomous Deployment)

dae 的优势在于重载配置时**无需重启内核 eBPF 程序**，已有连接完全不断流。Agent 自主执行标准发布命令：

```bash
# 1. 上传配置到 /tmp 临时沙盒并锁定 0600 权限（dae 强制要求配置文件权限不宽于 0640/0600）
ssh root@192.168.1.1 "cat > /tmp/config.dae.test && chmod 600 /tmp/config.dae.test" < /tmp/config.dae

# 2. 远端沙盒严格语法校验（注意：dae 不支持 -c 参数，直接传文件路径）
ssh root@192.168.1.1 "dae validate /tmp/config.dae.test"

# 3. 启动路由器本地 45 秒防失联看门狗 (必须在替换配置与 reload 前启动，防止 eBPF 规则异常导致 SSH 锁死)
ssh root@192.168.1.1 "sh -s -- --watchdog" < scripts/setup_openwrt_network.sh

# 4. 备份快照、原子替换配置并执行无感平滑热重载
# - OpenWrt/ImmortalWrt procd 管理（原生 dae 包）：使用 /etc/init.d/dae reload
# - 官方裸二进制（非 procd 管理）：使用 dae reload
ssh root@192.168.1.1 "[ -f /etc/dae/config.dae ] && cp /etc/dae/config.dae /tmp/config.dae.bak; mv /tmp/config.dae.test /etc/dae/config.dae && chmod 600 /etc/dae/config.dae && ( [ -x /etc/init.d/dae ] && uci set dae.config.enabled='1' 2>/dev/null && uci commit dae 2>/dev/null && /etc/init.d/dae reload || dae reload )"

# 5. 执行网络闭环脚本并在全新 SSH 连接确认连通后解除看门狗
ssh root@192.168.1.1 "sh -s" < scripts/setup_openwrt_network.sh
ssh root@192.168.1.1 "sh -s -- --confirm" < scripts/setup_openwrt_network.sh
```

---

## 🩺 维度四：智能排障与自愈闭环 (Machine-Readable Doctor)

当网络出现异常时，Agent 调用结构化诊断医生排障：

```bash
# 1. 结构化日志与运行状态体检 (输出机器可读 JSON，含 status/issues/suggested_actions)
ssh root@192.168.1.1 "sh -s -- dae --json" < scripts/doctor.sh

# 2. 专项 DNS 深度防污染与防泄漏健康体检
ssh root@192.168.1.1 "sh -s -- --json" < scripts/diagnose_dns.sh
```

---

## 🧪 测试与回归（改动任何脚本/模板后必须执行）

```bash
# 仓库根目录（两个技能共用）
python run_tests.py
```
