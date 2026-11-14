---
name: dae-openwrt
license: MIT
compatibility: Requires Python 3.8+ on host and SSH access to an OpenWrt / ImmortalWrt / iStoreOS router (Linux 5.15+ with BTF)
description: >-
  在 OpenWrt、ImmortalWrt、iStoreOS 上生成、部署和排查原生 dae 配置。适用于 eBPF 接口绑定、routing/dns/group 规则、订阅导入与热重载；不接管 daed 面板配置。
---

# dae OpenWrt 配置与排障

管理原生 dae 的配置、接口绑定、DNS 规则与服务重载。生成器区分 legacy 与 modern 字段，部署时仍需由目标设备的 dae validate 校验。

> **支持边界**：本技能管理**原生 dae**（`dae` 二进制 / procd `dae` 服务 + `/etc/dae/config.dae`，注意：Web 面板版 `daed` 使用 `/etc/daed/daed.db` 数据库，不读取 `/etc/dae/config.dae`）。eBPF 需要 Linux 5.15+（现代 `dae v2.x` 推荐 5.17+）与 BTF 支持；若为老软路由（Linux < 5.15 或无 BTF），探针会自动识别并建议改用全内核通用的 `singbox-openwrt`。

---

## 部署约束

1. **严禁直接在路由器 `/etc` 下裸改配置**：一切修改必须先写入 `/tmp` 沙盒并执行 `chmod 600`（`dae` 强制要求配置文件权限不宽于 `0600`/`0640`），经远端 `dae validate -c <file>` 通过后再备份原配置并原子替换。
2. **硬件与网络设置**：`global` 中 `lan_interface: br-lan` + `wan_interface: auto` + `auto_config_kernel_parameter: true`；部署前关闭流量分载（Flow Offloading，否则报文绕过 eBPF）；dropbear/sshd 需做 OOM 保护。
3. **先采集诊断信息**：网络异常先运行 `scripts/probe.sh -j` 探针和 `scripts/doctor.sh dae --json` 诊断，再进行针对性修复。
4. **dae validate -c 强制参数规范与新旧版本兼容**：原生 `dae` 官方 CLI（含 v2.1.1+）强制要求传入 `-c` / `--config` 指定配置文件，标准格式为 `dae validate -c /path/to/config.dae`（漏传 `-c` 会报 `Argument "--config" or "-c" is required`）；若需同时兼容极早期版本，可使用 `dae validate -c /tmp/config.dae.test || dae validate /tmp/config.dae.test`。同时，针对老版本 `dae`（`<= v1.0.0`），生成配置时通过 `--router <IP>` 自动探测或显式指定 `--dae-version legacy` 剥离 v2.x 新增字段。
5. **procd 托管与 daed 区分及强互斥检查**：ImmortalWrt 官方源的原生 `dae` 包由 procd 管理，启用与热重载使用 `uci set dae.config.enabled='1' && uci commit dae && /etc/init.d/dae reload`（裸二进制模式使用 `dae reload`）；而 `daed` 是 Web 面板独立包（端口 2023，读取 `/etc/daed/wing.db`，不读取 `/etc/dae/config.dae`）。若 `probe.sh -j` 检出 `daed_conflict: true`，必须严禁下发原生配置，提示用户先执行 `/etc/init.d/daed stop && /etc/init.d/daed disable`。

---

## 参考资料

| 任务 | 优先查阅 |
| :--- | :--- |
| **dae 配置约束、路由语法与配置规范** | [dae-rules-and-syntax.md](./references/dae-rules-and-syntax.md) |
| **常见故障排查手册与日志分析** | [troubleshooting.md](./references/troubleshooting.md) |
| **OpenWrt 专用基准模板** | [openwrt.dae](./assets/templates/openwrt.dae) |

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

## OpenWrt 必须遵守的 配置约束

在为软路由生成或调整 `.dae` 规则时，必须 严格遵循以下约束：

### 1. 单引号词法规范
在 `.dae` 规范中，除 `ext:"xxx.dat:tag"` 外部文件引用外，所有包含冒号 `:`、斜杠 `/`、正则表达式或复合协议的字符串，统一使用单引号 `'...'` 包裹，避免解析歧义。

* 推荐：`tcp_check_url: 'http://cp.cloudflare.com'`

### 2. must_direct 防 DNS 死循环约束
dae 默认拦截所有发往 53 端口的请求。宿主机核心网络组件（`dnsmasq`、`odhcpd`、`netifd`、`uhttpd`）发出的 DNS 查询若被拦截并交回自身，会瞬间形成高频递归死锁并导致路由器断网。必须在 `routing {}` **最顶部**对它们的 53 端口流量放行：
```shell
routing {
    pname(dnsmasq, odhcpd, netifd, uhttpd) && l4proto(udp) && dport(53) -> must_direct
    dip(224.0.0.0/3, 'ff00::/8') -> direct
    dip(geoip:private) -> direct
    ...
}
```

### 3. 布尔取反（!）合并约束
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

### 5. DNS 污染重查闭环与 qname 词法前缀约束
* **response 防环**：在 `dns.routing.response` 中配置私网 IP 投毒重查时，首行**必须**加入 `upstream(googledns) -> accept` 白名单放行，防止无限递归。
* **qname 词法陷阱规避**：`dae v2.1.1` 的 `dns.routing.request` 中 `qname(...)` 解析器 (`addQName`) **强制要求每个参数必须带匹配前缀**（如 `geosite:cn`、`full:example.com`、`suffix:example.com`），严禁写入无前缀单引号域名（如 `qname('use-application-dns.net')`，会触发 `addQName: unsupported key:` 崩溃）或复杂 `geosite:category-ads-all`；**所有域名黑名单与 Canary 阻断一律置于 `routing {}` 的 `domain(suffix: ...)` 中处理**。
```shell
response {
    upstream(googledns) -> accept # 首行必须放行可信上游！
    ip(geoip:private) && !qname(geosite:cn) -> googledns
    fallback: accept
}
```

---

## 软路由网卡绑定（global 必填项）

软路由作为局域网网关，在 `global` 块中必须显式声明局域网网桥与外网出口：

```shell
global {
    lan_interface: br-lan     # 绑定局域网网桥，代理整个内网终端
    wan_interface: auto       # 自动识别物理外网出口（PPPoE / DHCP）
    auto_config_kernel_parameter: true # 自动开启 net.ipv4.ip_forward=1 并关闭 ICMP redirects
}
```

---

## 环境检查

部署 dae 前必须先调用探针确认软路由内核、BTF 符号及已安装的 `dae` 版本：

```bash
# 目标软路由本地或 SSH 管道执行探针 (输出结构化 JSON，含 kernel_ge_515/517 与 dae_version)
ssh root@192.168.1.1 "sh -s -- -j" < scripts/probe.sh
```

---

## 维度二：dae 配置生成与订阅脱水 (Config Engine)

使用 `scripts/sub_to_dae.py` 支持将机场 HTTP/HTTPS 订阅一键清洗并转换为 dae 配置（支持自动探测路由器上的新旧 `dae` 版本）：

```bash
# 方式 A：一键合成完整 config.dae（通过 --router 自动探测远端 dae 版本是 modern 还是 legacy，或手动传 --dae-version legacy 适配 <= v1.0.0）
python scripts/sub_to_dae.py "https://sub.domain.com/link?token=..." --max 15 --full --router 192.168.1.1 --out /tmp/config.dae

# 方式 B：仅导出 node { ... } 节点池语法块
python scripts/sub_to_dae.py "https://sub.domain.com/link?token=..." --max 15 --out /tmp/nodes.dae
```

---

## 维度三：Agent 自主部署与平滑热重载 (Autonomous Deployment)

dae 的优势在于重载配置时**无需重启内核 eBPF 程序**，已有连接完全不断流。Agent 自主执行标准发布命令：

```bash
# 0. [可选：针对 apk 缺包或路由器初始无网死锁] 宿主机 SSH 流式管道 (SSH Stream Pipe) 直灌二进制与 GeoData
# 当 ImmortalWrt 24/25+ (apk) 软件源未收录最新原生 dae 或路由器断网无法拉取时，直接从宿主机流式灌入：
# ssh root@192.168.1.1 "mkdir -p /usr/bin /usr/share/dae /etc/dae && cat > /usr/bin/dae && chmod +x /usr/bin/dae" < ./dae-linux-${ARCH}
# ssh root@192.168.1.1 "cat > /usr/share/dae/geoip.dat" < ./geoip.dat
# ssh root@192.168.1.1 "cat > /usr/share/dae/geosite.dat" < ./geosite.dat

# 1. 上传配置到 /tmp 临时沙盒并锁定 0600 权限（dae 强制要求配置文件权限不宽于 0640/0600）
ssh root@192.168.1.1 "cat > /tmp/config.dae.test && chmod 600 /tmp/config.dae.test" < /tmp/config.dae

# 2. 远端沙盒严格语法校验（优先使用原生 dae v2.1.1+ 强制要求的 -c 参数，并兼容早期版本回退）
ssh root@192.168.1.1 "dae validate -c /tmp/config.dae.test || dae validate /tmp/config.dae.test"

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

## 故障诊断

当网络出现异常时，Agent 调用诊断脚本排障：

```bash
# 1. 结构化日志与运行状态体检 (输出机器可读 JSON，含 status/issues/suggested_actions)
ssh root@192.168.1.1 "sh -s -- dae --json" < scripts/doctor.sh

# 2. 专项 DNS 深度防污染与防泄漏健康体检
ssh root@192.168.1.1 "sh -s -- --json" < scripts/diagnose_dns.sh
```

---

## 测试与回归（改动任何脚本/模板后必须执行）

```bash
# 仓库根目录（两个技能共用）
python run_tests.py
```


## 网络事务与恢复边界（R2S 真机复核）

网络脚本要求 root、flock、sha256sum、tar、mktemp 与 UCI。修改前在 `/etc/proxy-skills-network` 的 0700 私有目录保存完整 firewall/dhcp、受影响 sysctl 文件、引擎配置、运行参数与服务状态。自动启动 45 秒恢复计时器；必须通过新 SSH 连接和实际业务检查后执行 `--confirm`。确认只解除自动回滚，完整基线保留供 `--revert` 使用。两套引擎共享设备锁；先回滚当前引擎，才能切换另一套网络配置。

没有完整基线时 `--revert` 不修改现有配置；备份校验失败或恢复失败时返回非零并保留现场。不要使用旧版 `.network_baseline.bak` 与新版混合部署。开机恢复使用持久化的独立 init 脚本，不依赖 /tmp 或已安装的技能脚本。恢复验证覆盖配置、sysctl 与进程状态；完整流量路径和 DNS 泄漏仍需独立实测，不能只凭该脚本成功判断业务正常。

网络接管前，已运行的裸二进制引擎必须先纳入 `/etc/init.d/dae` 或 `/etc/init.d/sing-box` 服务管理；否则脚本会拒绝接管，因为无法可靠恢复服务生命周期。基线原先停止的引擎在回滚后仍有未托管进程时，恢复会返回失败并保留快照，不能把配置文件恢复当作服务恢复。部署后若 firewall/dhcp 或相关 sysctl 文件被其他工具修改，自动/手动恢复均会拒绝覆盖，需根据保留的快照协调差异。

## 节点切换与实际访问验证

修改节点、诊断断网、双网卡测试或配置自动切换时，先阅读 [节点切换与连通性验证](./references/runtime-checks.md)。使用 `scripts/node_link.py` 安全更新链接参数，使用 `scripts/check_path.py` 从客户端执行有界请求。配置校验和进程存活不能替代节点载入、LAN 转发与 DNS 路径验证。未验证的备用节点不进入自动切换池。
