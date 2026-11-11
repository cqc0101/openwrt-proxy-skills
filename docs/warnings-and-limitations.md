# 生产环境已知边界、使用须知与安全提示

本文档针对使用本项目进行 OpenWrt / ImmortalWrt / iStoreOS 软路由透明代理（sing-box 与 dae）配置的用户，详细梳理已知的架构边界、硬件极限、协议差异与安全隔离机制。请在生产部署前仔细阅读。

---

## 目录

1. [GitHub 认证与凭据零泄漏保证](#1-github-认证与凭据零泄漏保证)
2. [sing-box 版本演进与模板适配警告](#2-sing-box-版本演进与模板适配警告)
3. [Clash YAML 锚点与降级解析器边界](#3-clash-yaml-锚点与降级解析器边界)
4. [daed Web 面板与原生 dae 的双引擎冲突](#4-daed-web-面板与原生-dae-的双引擎冲突)
5. [弱硬件路由性能瓶颈与闪存防磨损](#5-弱硬件路由性能瓶颈与闪存防磨损)
6. [DNS 循环死锁与 FakeIP 引导避坑](#6-dns-循环死锁与-fakeip-引导避坑)
7. [旁路由模式与 IPv6 假死防护](#7-旁路由模式与-ipv6-假死防护)
8. [新老软路由全代际兼容、dae v2.1.1+ 门禁与 apk 流式交付规范](#8-新老软路由全代际兼容dae-v211-门禁与-apk-流式交付规范)

---

## 1. GitHub 认证与凭据零泄漏保证

部分用户在基于本仓库进行二次开发或将自己的配置推送到远程 Git 仓库时，担心本地私钥或认证信息泄露。

* **操作系统级安全隔离**：用户的 GitHub 访问凭据（Personal Access Token、OAuth 会话）存储于 Windows 凭据管理器（DPAPI 加密）或系统的 SSH Agent 中，**绝对不存放在代码仓库的工作目录内**。
* **Git 底层机制隔离**：`.git` 目录（包含远程连接、分支等配置）是 Git 内部数据库，Git 在打包与执行 `git push` 时，**物理级禁止将 `.git/` 自身打包上传**。远程仓库接收的仅是被追踪的代码与配置文件。
* **本地私有配置安全**：包含个人真实节点、公网 IP 或特定配置的文件必须严格受 `.gitignore` 保护（如本仓库默认忽略 `.deploy_key/`、`*.key`、`*.tmp` 等），绝对不要执行 `git add -f` 强制提交私有密钥文件。

---

## 2. sing-box 版本演进与模板适配警告

* **基准版本覆盖**：本项目的模板与积木体系经过严格验证，全面支持 **sing-box 1.13 与 1.14 生产版本**（涵盖 FakeIP / RealIP 双模式及 TUN 转发）。
* **未来版本前瞻警告**：sing-box 上游社区架构演进极其迅速。针对后续可能推出的重大版本（如 1.15+）：**现有模板或将重新适配**。
  > [!WARNING]
  > 在未经过本项目测试矩阵兼容确认前，**请勿盲目在软路由上直接跨大版本替换 sing-box 二进制文件**。若上游版本重构了 DNS 分流规则、Inbound 字段或废弃了关键参数，盲目升级可能导致服务拒绝启动并触发软路由断网。升级前请先在沙盒环境使用 `auto_config.py --check` 与 `check_config.py` 执行静态测试。

---

## 3. Clash YAML 锚点与降级解析器边界

* **纯 Python 降级机制**：为兼容未安装 `PyYAML` 的极简 OpenWrt 路由环境，本项目自研了轻量级纯正则 YAML 解析器，现已原生支持单行标量锚点（`key: &anchor value`）与块级缩进列表锚点。
* **极端复杂 YAML 的理论极限**：
  * 部分商业机场可能采用深度嵌套的复合 YAML 特性，例如多锚点合并（`<<: [*anchor1, *anchor2]`）、三层以上流式行内字典引用、或 `proxy-providers` 外部动态规则文件。这类非标准复杂结构在纯正则降级模式下可能出现字段丢失或别名未展开的情况。
  * **建议措施**：在算力与存储允许的软路由上，强烈建议预装完整版 PyYAML（执行 `opkg install python3-pyyaml` 或 `pip install pyyaml`）。本项目的解析器检测到系统存在 PyYAML 时会自动无缝切换至官方完整引擎。

---

## 4. daed Web 面板与原生 dae 的双引擎冲突

* **底层机制差异**：
  * 原生 **dae** 使用纯文本配置文件（`/etc/dae/config.dae`），由 systemd 或 OpenWrt 的 procd 守护进程管理。
  * 第三方预装固件中的 **daed**（Web 管理面板）通常将节点与规则托管在 SQLite 数据库（如 `wing.db`）中，并通过内部接口动态生成与下发配置。
* **严正避坑警告**：
  > [!CAUTION]
  > **严禁同时开启 daed Web 面板与使用原生脚本直接覆写 `/etc/dae/config.dae`！**
  > 若您在 Web 面板中配置了规则，外部脚本覆写的配置将在面板下一次触发保存或重载时被完全覆盖；反之，脚本的直接修改也可能引发 Web 面板状态不同步或端口竞争。请务必二选一：
  > 1. **全自主脚本化**：禁用并停止 daed Web 面板，完全由本项目的脚本及 procd 负责配置生成与守护；
  > 2. **全面板托管**：仅在 Web 界面中操作，不使用本脚本的外部注入。

---

## 5. 弱硬件路由性能瓶颈与闪存防磨损

* **订阅节点数量截断**：
  * 为保护 128MB / 256MB 弱内存路由，`sub_parser.py` 默认内置了百级巨型订阅并发截断机制（默认筛选并限制至前 12 个健康节点），防止上百个节点并发解析耗尽系统内存。
* **eBPF 内存与算力开销**：
  * dae 依赖 Linux 内核 eBPF JIT 编译与高效 map 映射。在极小内存（≤128MB）或无 Swap 交换分区的设备上，加载巨型 GeoIP/Geosite 规则集仍可能触发 Linux 内核 OOM Killer 杀进程。建议低配设备优先使用 TUN 模式的 sing-box，或通过 U 盘挂载 512MB Swap 交换分区。
* **闪存寿命保护**：
  * 软路由的 SPI Flash 擦写寿命有限。本项目的所有配置生成、语法检查、快照暂存与 DNS 运行时缓存均强制部署在 `/tmp`（RAM 内存虚拟盘）中，严禁高频将动态日志写入物理闪存。

---

## 6. DNS 循环死锁与 FakeIP 引导避坑

* **自环死锁拦截**：
  * 严禁将 `default_domain_resolver` 或 `domain_resolver` 设置为指向自身协议为 `fakeip` 的 DNS 服务器；否则在解析节点域名时，系统将返回虚假 FakeIP，导致出站 TCP 握手无法建立真实连接而引发全屋断网死锁。
* **前置静态校验**：
  * 在部署配置前，必须调用内置门禁脚本：
    ```bash
    python check_config.py -c /path/to/singbox.json
    python check_dae_syntax.py -c /path/to/config.dae
    ```
  * 门禁脚本已内置 FakeIP 死锁扫描、出站 Tag 悬空引用探测与端口范围格式校验。

---

## 7. 旁路由模式与 IPv6 假死防护

* **旁路由 (Bypass Gateway) 必须注入 MASQUERADE**：
  * 当软路由作为旁路由网关运行时，局域网终端的网关指向软路由，但上行直接通过主路由。若旁路由未对转发出海的流量执行源地址伪装（MASQUERADE），将出现“去程走旁路由、回程直连主路由”的非对称路由问题，导致 TCP 握手超时失败。
  * 使用本项目的网络接管脚本时，旁路由模式务必显式指定 `--bypass` 参数（例如 `setup_openwrt_network.sh --bypass 192.168.1.1`），由脚本自动接管 `masq=1` 与防火墙转发规则。
* **双栈 IPv6 假死与 Dnsmasq 净化**：
  * 国内部分运营商虽然下发了 IPv6 地址，但部分海外 VPS 节点未配置稳定的 IPv6 链路，或移动/电信网络存在严重的跨洋 IPv6 丢包。
  * 若终端通过双栈优先使用 IPv6 建立连接，将导致手机/电脑打开国内 App 或访问外网时出现长达数秒的“转圈假死”。
  * 建议通过网络脚本开启 Dnsmasq 的 `filter_aaaa=1`，确保国内域名解析秒级纯净返回 IPv4 地址，彻底杜绝假死。

---

## 8. 新老软路由全代际兼容、dae v2.1.1+ 门禁与 apk 流式交付规范

* **新老版本 `dae` (`<= v1.0.0` vs `v2.1.1+`) 自动适配**：
  * 老版本 `dae`（如软件源中的 `1.0.0-r1`）不识别 `v1.1+/v2.x` 新增的 5 个字段（`bpf_conn_state_map_size`、`auto_sniff_punt`、`bootstrap_resolver`、`optimistic_cache`、`optimistic_cache_ttl`）。使用 `sub_to_dae.py --full --router <IP>` 可自动探测远端版本并切换 `legacy` 模式剥离新字段（也可手动传 `--dae-version legacy`）。
  * 原生 `dae v2.1.1+` 强制要求 `-c` 参数（`dae validate -c /tmp/config.dae.test`），建议统一使用 `dae validate -c /tmp/config.dae.test || dae validate /tmp/config.dae.test` 兼顾新老版本。
* **DNS `request` 模块 `qname()` 词法门禁 (`addQName: unsupported key`)**：
  * `dae v2.1.1+` 的 `dns.routing.request` 中 `qname(...)` 解析器强制要求每个参数携带匹配类型前缀（如 `geosite:cn`、`full:`、`suffix:`、`domain:`），直接写入单引号裸域名列表会触发内核解析崩溃。域名黑名单与 Canary 阻断请统一置于 `routing {}` 的 `domain(suffix: ...)` 中。
* **新一代 `apk` 包管理器与 SSH Stream Pipe 纯本地交付**：
  * 针对 ImmortalWrt/OpenWrt 24/25+ 切换 `apk` 软件源缺包或软路由初始无网死锁，推荐使用宿主机 SSH 流式管道（`ssh root@IP "cat > /usr/bin/dae && chmod 755 /usr/bin/dae" < ./dae`）直接灌装二进制与 `geoip.dat` / `geosite.dat`。
