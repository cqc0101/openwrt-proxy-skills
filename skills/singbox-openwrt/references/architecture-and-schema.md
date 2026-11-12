# sing-box OpenWrt 架构规范与版本字段门控 (Architecture & Schema)

> 本文档为 AI Agent 提供精准的 sing-box 模块构成、OpenWrt 硬件防护基线与多版本字段门控，避免无效大篇幅文档扫描。

---

## 一、 五大正交核心积木与 OpenWrt 防护基线

```
┌────────────────────────────────────────────────────────┐
│ 1. inbounds (入站): TUN 网关 (tun0, auto_route: true)  │
├────────────────────────────────────────────────────────┤
│ 2. outbounds (出站): proxy 策略组 / auto 优选 / 节点池 │
├────────────────────────────────────────────────────────┤
│ 3. dns (解析): hosts -> local-dns -> alidns -> FakeIP  │
├────────────────────────────────────────────────────────┤
│ 4. route (路由): 接口防环 -> 规则集 -> 多维分流规则   │
├────────────────────────────────────────────────────────┤
│ 5. experimental (运行): /tmp 闪存保护缓存 + Clash API  │
└────────────────────────────────────────────────────────┘
```

### 必须强制满足的 3 项硬件底线：
1. **闪存零磨损**：`experimental.cache_file.path` **必须**指向 `/tmp/sing-box-cache.db`，严禁写入 `/etc` 导致 SPI 闪存写穿变砖。
2. **防环与直连解析**：`route.auto_detect_interface: true`，且 `route.default_domain_resolver: "alidns"`，防止代理内核首启时下载规则集死锁。
3. **局域网可视化管理**：`experimental.clash_api.external_controller: "127.0.0.1:9090"`，默认只在本机监听；使用 SSH 隧道接入控制面板，若手动开放 LAN 监听必须配置强口令和防火墙限制。可使用控制面板（`yacd.haishan.me` 或 `metacubexd`）。

---

## 二、 严格的版本字段门控 (Version Gating)

| 模块 / 字段 | sing-box v1.13 | sing-box v1.14+ | 规则与避坑要点 |
| :--- | :--- | :--- | :--- |
| `dns.optimistic` | **禁止使用** | **推荐开启 (`true`)** | 乐观 DNS 缓存，1.14 起新增，加速常用域名查询 |
| `dns.independent_cache` | **必须保留 (`true`)** | **禁止使用** (已废弃) | 1.14+ 混用会产生告警甚至阻断启动 |
| `cache_file.store_dns` | **禁止使用** | **推荐开启 (`true`)** | 1.14+ 持久化存储 DNS 记录至临时数据库 |
| `cache_file.store_rdrc` | **推荐开启 (`true`)** | **禁止使用** (已废弃) | 旧版 RDRC 缓存标识 |
| `route.default_http_client` | **禁止使用** | **必须包含 (`direct-client`)** | 1.14+ 规则集下载必须通过显式 http_client |
| `http_clients` 顶级数组 | **禁止使用** | **必须声明** | 声明 `direct-client`；**严禁**设置 `"detour": "direct"`（会触发 `empty direct outbound` 崩溃），不设 `detour` 字段即为默认直连 |
| `rule_set.download_detour` | **禁止使用** | **禁止使用** (已废弃) | 在 v1.13 或 v1.14 下显式声明 `download_detour: "direct"` 均会在启动期触发致命崩溃；直连下载**不设该字段**即可 |

### 默认工作流与模板推荐：
* 推荐基准模板默认采用 **1.13 TUN FakeIP**（`--dns-mode fakeip`），兼顾内存占用极低与防 DNS 污染能力。

---

## 三、 软路由平台兼容矩阵速查

* **OpenWrt 发行版与包管理器**：
  - **OpenWrt 21.02 / 22.03 / 23.05 / 24.10**：一律使用 `opkg`（注意：APK packages are *not* supported on OpenWrt 24.10 release，`apk` 仅在 snapshot / main 开发分支及 ImmortalWrt 24/25+ 新版中启用）。
  - **ImmortalWrt 24/25+ (`apk`) 与无网冷启动闭环**：当新固件改用 `apk` 且软件源未收录所需版本或路由器初始未联网时，优先使用 **SSH Stream Pipe（流式管道直灌）** 从宿主机直接将二进制与规则集灌入路由器（如 `ssh root@192.168.1.1 "cat > /usr/bin/sing-box && chmod +x /usr/bin/sing-box" < ./sing-box`），彻底摆脱路由器未联网无法装包的死锁。
* **x86_64 / aarch64 (ARMv8)**：完整版 `sing-box` 性能最佳。
* **低内存 / 小闪存 (RAM <= 256MB 或 ROM <= 70MB)**：
  - 安装精简版：`apk add sing-box-tiny` 或 `opkg install sing-box`（约 39MiB）；
  - 自动注入 Go OOM 物理内存限制：`export GOMEMLIMIT=100MiB` 与 `export GOGC=50`；
  - 规则集轻量化裁剪：不加载包含数万条域名的海外大盘，直接依赖 `final: "proxy"` 自然兜底，节省 70MB+ 内存。
* **缺失 nfqueue 内核**（如部分 MT7981 / ImmortalWrt SNAPSHOT 固件）：
  - `auto_detect_interface` 自保会失效，导致国内直连流量被 TUN 自捕获；
  - Agent 必须在配置中将 `route.auto_detect_interface` 替换为显式 `route.default_interface: "<物理WAN网卡名>"`（如 `eth0` 或 `pppoe-wan`）。
