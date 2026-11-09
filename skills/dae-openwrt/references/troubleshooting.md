# dae 排障手册、硬件依赖与协议速查

> 集中归纳 dae eBPF 运行时的底层硬件约束、常见故障病因与针对性解法。

---

## 一、 硬件与内核门禁 (Hard Requirements)

dae 深度依赖 Linux 内核 eBPF TC 与 XDP 特性，必须满足以下两项基线：
1. **Linux 内核版本 >= 5.15**：早期内核（如 4.14、5.4）不支持 BPF CO-RE。
2. **内核开启 BTF 调试符号**：存在 `/sys/kernel/btf/vmlinux` 或 `/usr/lib/debug/boot/vmlinux`。

> **自愈决策**：若探针报告不满足上述两项（常见于部分旧版 ARM / iStoreOS 固件），Agent 应当机立断，引导用户切换至 `singbox-openwrt`（TUN 模式无内核版本硬性限制）。

---

## 二、 核心生产事故与排障矩阵

| 故障现象 | 根本病因 | 针对性排查与自愈指令 |
| :--- | :--- | :--- |
| **启动后全屋断网** | `dnsmasq` 53 端口查询被递归拦截死锁 | 检查 `routing` 首行是否有 `pname(dnsmasq, ...) -> must_direct` |
| **国内直连出海均超时** | OpenWrt 开启了 Flow Offloading (软/硬件流量分载) | 运行 `uci set firewall.@defaults[0].flow_offloading='0' && /etc/init.d/firewall reload` |
| **旁路由客户端断网/假死** | 非对称路由导致客户端 TCP RST | 运行 `sh setup_openwrt_network.sh --bypass` 开启 LAN 伪装 |
| **节点无法连接/握手失败** | 节点未用单引号包裹或 URI 格式不兼容 | 检查节点池中单引号规范；使用 `sub_to_dae.py` 转换 |
| **内存溢出 (OOM) 杀掉进程** | 弱小路由器加载了全量巨型 GeoIP/Geosite | 精简规则集，仅保留 `geosite:cn` 与重点海外服务域名 |

---

## 三、 支持的代理协议 URI 格式

dae 原生支持的单节点链接格式（均需使用单引号包裹）：
* **VLESS Reality**: `'vless://uuid@host:port?security=reality&sni=xxx&pbk=xxx&sid=xxx&type=tcp&flow=xtls-rprx-vision#Tag'`
* **Hysteria 2**: `'hysteria2://password@host:port?sni=xxx&insecure=0#Tag'`
* **Trojan**: `'trojan://password@host:port?sni=xxx#Tag'`
* **Shadowsocks**: `'ss://base64(method:password)@host:port#Tag'`

> **注意**：dae 仅支持原生标准协议 URI，不支持带有复杂客户端扩展私有参数的非常规链接；订阅解析请统一使用 `python scripts/sub_to_dae.py "<URL>" --max 15`。
