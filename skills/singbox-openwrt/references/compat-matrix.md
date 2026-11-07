# 版本兼容矩阵 (Compatibility Matrix)

> 本文件只收录**已对照官方来源验证过**的事实（官方 release notes / sing-box migration、deprecated 页面 / dae 官方文档）。
> 拿不准的地方一律标注「未验证」。任何新增条目必须先给出来源再写入。

---

## 1. OpenWrt 发行版时间线

| 版本 | 内核 | 防火墙默认 | 包管理器 | 备注 |
| :--- | :--- | :--- | :--- | :--- |
| 21.02 (2021) | 5.4 | fw3（fw4 可选） | opkg | 引入 DSA 交换机框架 |
| 22.03 (2022) | 5.10 | **fw4** (nftables) | opkg | 从本版起 fw4 成为默认 |
| 23.05 (2023) | 5.15 | fw4 | opkg | 最后一个 opkg 稳定系列 |
| 24.10 (2025) | 6.6 | fw4 | **opkg only** | 官方 release notes 明确：APK 不支持，仅 main 分支切到 APK |

- **apk 事实**（[24.10.0 release notes](https://openwrt.org/releases/24.10/notes-24.10.0) 原文）：
  > "OpenWrt 24.10 uses OPKG only, APK packages are *not* supported. Only main branch was changed to APK."
  → 探针判断包管理器必须用 `command -v apk` / `command -v opkg` 实测，**不能按版本号猜**。
- 23.05 → 24.10 可用 `sysupgrade` 保留配置升级；22.03 → 24.10 官方**不支持**直接升级。

## 2. ImmortalWrt 与 iStoreOS

| 家族 | 分支 | 特点 | 出海相关结论 |
| :--- | :--- | :--- | :--- |
| ImmortalWrt | 21.02 / 23.05 / 24.10（与 OpenWrt 同版本号） | 国内源、更多 kmod、默认更多编译特性 | kmod 必须用**同分支同内核**的源安装，跨源混装必炸 |
| iStoreOS | 基于 OpenWrt（以 21.02/22.03 世代为主，新版本跟进中） | x86_64 为主、应用中心、快速配置 | 多数构建内核 < 5.15 或无 BTF → **dae 通常不可用**，以探针实测为准 |

- **kmod 铁律**：kmod 包与内核 ABI 严格绑定。报 `kernel dependency` / 版本不匹配时，只能：换同 Release 官方源、换 ImmortalWrt 同分支源、或重刷匹配的固件。**没有第三种办法**。

## 3. sing-box 版本字段门控（已对照官方 deprecated / migration 页面）

| 字段 | 1.13 | 1.14 | 1.15+ |
| :--- | :--- | :--- | :--- |
| `dns.independent_cache` | ✅ | ❌ 废弃（缓存始终按 transport 隔离） | ❌ |
| `experimental.cache_file.store_rdrc` | ✅ | ❌ 废弃 | ❌ |
| rule-set `download_detour` | ✅ | ❌ 废弃 | ❌ |
| `dns.optimistic` | ❌ | ✅ | ✅ |
| `experimental.cache_file.store_dns` | ❌ | ✅ | ✅ |
| `http_clients` + `route.default_http_client` | ❌（用隐式默认 client） | ✅（隐式默认已废弃，必须显式） | ✅ |
| TUN `stack` 选项 | ✅ | ✅ | ❌ **1.15 起废弃**（用默认栈） |

其他历史边界（生成/排障时的快速判断）：
- `geoip`/`geosite` 原生路由字段：1.8 起移除 → 必须用 rule-set。
- 路由规则动作 `sniff` / `hijack-dns`：1.11 起的新写法（旧 inbound 内 `sniff: true` 已废弃）。
- DNS 规则 `action: "route"` + `server`：1.12 起的新格式（旧 `dns.rules` 的 `outbound` 字段已废弃）。
- TUN `address` 数组：1.10 起合并了旧的 `inet4_address`/`inet6_address`。

## 4. sing-box 安装来源

- **官方 OpenWrt packages feed 有 `sing-box` 包**（`openwrt/packages` 仓库 `net/sing-box`，官方源可 opkg/apk 安装）。
- 但官方包版本**明显落后于上游**（尤其新系列切换期）；追求 1.14+ 新字段时优先用官方二进制或新系列源，并以 `sing-box version` 实测结果选模板。
- 模板选择一律以 `sing-box version` 实测为准，**绝不按固件版本推断**。

## 5. dae 运行前提

- 内核 ≥ 5.15 且带 **BTF**（`/sys/kernel/btf/vmlinux` 或 `/usr/lib/debug/boot/vmlinux`）。
- 官方原版 OpenWrt 默认不带 BTF：第三方源装 `vmlinux-btf`（如 sbwml 的 package 源），或自编译开 `CONFIG_DEBUG_INFO_BTF=y`。
- 常用命令（官方文档确认）：`dae run -c <file>`、`dae validate -c <file>`、`dae reload`、`dae suspend`。
- **选项随版本演进**：`bpf_conn_state_map_size` 等新选项在老版本可能不识别 → 任何配置先过 `dae validate`。
- daed（Web 面板）：配置目录 `/etc/daed`、面板 `http://<IP>:2023`；与原生 dae 的 `/etc/dae/config.dae` 是两套体系。

## 6. 防火墙与网卡框架

| 概念 | 说明 |
| :--- | :--- |
| fw3 | iptables 后端，21.02 默认 |
| fw4 | nftables 后端，22.03+ 默认；**未声明进 zone 的虚拟网卡（tun0）转发会被 DROP** |
| DSA | 21.02 起新交换机框架（`/sys/class/net` 单口模型，`br-lan` 聚合） |
| 放行 tun0 | 必须按 `name=lan` 定位 zone（禁止写死 `@zone[0]`），见 `setup_openwrt_firewall.sh` |

## 7. 包管理器命令对照（探针实测后选用）

| 操作 | opkg（24.10 及更早） | apk（main/SNAPSHOT 系列） |
| :--- | :--- | :--- |
| 更新索引 | `opkg update` | `apk update` |
| 安装 | `opkg install <pkg>` | `apk add <pkg>` |
| 卸载 | `opkg remove <pkg>` | `apk del <pkg>` |
| 已装列表 | `opkg list-installed` | `apk info` |
| 搜索 | `opkg list | grep <kw>` | `apk search <kw>` |

## 8. 闪存与存储速记

- `/tmp` 是 tmpfs（RAM），**高频写文件必须放这里**（如 `/tmp/sing-box-cache.db`）。
- `/etc` 落在 overlay 分区（NOR/NAND 闪存或 UBI），擦写寿命有限 → 严禁高频写入。
- 空间不足症状：`No space left on device`、overlay 满、`Read-only file system`（闪存坏块或 overlay 满）。
