# OpenWrt / ImmortalWrt dae (eBPF Transparent Proxy) 架构与配置规范

dae 是一个基于 Linux eBPF 技术的高性能透明代理解决方案。在 OpenWrt / ImmortalWrt 环境下，dae 通过将流量过滤和分流决策直接注入 Linux 内核网络栈底层，大幅减少了传统 TUN / TProxy 模式下的用户空间与内核空间上下文切换，具备极高吞吐量与超低 CPU 资源开销。

---

## 强制执行的 5 条 dae 语义与拓扑铁律

在编写或修改 `.dae` 配置文件时，必须 100% 遵守以下 5 条铁律：

### 1. 单引号词法规范
在 `.dae` 语法中，所有包含冒号 `:`、斜杠 `/` 或特殊符号的字符串（如订阅 URL、节点 URI、`'tcp+udp://...'`、IPv6 CIDR `'ff00::/8'`、MAC 地址、正则表达式等），**统一使用单引号 `'...'` 包裹**（除 `ext:"xxx.dat:tag"` 外部 DAT 文件语法外），避免解析歧义。
* 推荐写法：`my_sub: 'https://example.com/sub'`

### 2. must_direct 防 DNS 死循环铁律
dae 默认会捕获所有发往 53 端口的 UDP 和 TCP 流量。如果宿主机基础网络进程（如 `dnsmasq`、`odhcpd`、`netifd`、`uhttpd`）或局域网外部 DNS 服务器发出的查询被再次捕获并交回给自身，会瞬间形成高频递归死锁并导致路由器断网！
* 必须在 `routing {}` 规则块的**最顶部**写入（按官方建议只对 DNS 流量放行，不必整进程 must_direct）：
  ```shell
  pname(dnsmasq, odhcpd, netifd, uhttpd) && l4proto(udp) && dport(53) -> must_direct
  dip(224.0.0.0/3, 'ff00::/8', geoip:private) -> direct
  ```
* **副作用须知**：`must_direct` 的流量完全绕过 dae 的 DNS 模块。若局域网解析器的上游查询走了 must_direct，dae 学不到这些应答的 域名→IP 映射，`domain()` 规则将无法匹配客户端流量（官方 dns.md 有明确说明）。在 dae 的 dns 模块直接应答客户端查询的拓扑下无此问题。

### 3. 布尔取反（!）合并铁律
在 dae 中，多条单独的取反规则并不会在逻辑上做交集运算。例如两行：
```shell
!domain(geosite:a) -> my_group
!domain(geosite:b) -> my_group
```
实际含义为“非 a 走代理 **或** 非 b 走代理”，会导致大量流量被意外送入代理。
* **正确做法**：必须合并写在同一行内：
  ```shell
  !domain(geosite:a, geosite:b) -> my_group
  ```

### 4. routing {} 自上而下短路（First-Match）六层黄金顺序
dae 规则自上而下匹配，一旦命中立即终止后续规则匹配。所有生产环境配置必须严格依照以下 6 层结构编写：
1. **[第 1 层] 核心宿主进程与私网广播保护**：
   `pname(dnsmasq, ...) -> must_direct` 及 `dip(geoip:private) -> direct`
2. **[第 2 层] 大流量下载与 P2P 绕行**：
   `pname(aria2c, qbittorrent-nox) -> must_direct` 及 `dscp(0x4) -> direct`
3. **[第 3 层] 海外 QUIC/UDP 443 抑制**：
   `l4proto(udp) && dport(443) && !domain(geosite:cn) -> block`（防止运营商 UDP QoS 丢包）
4. **[第 4 层] 重点海外服务专属分流**：
   `domain(geosite:openai, geosite:telegram, ...) -> 专属代理组`
5. **[第 5 层] 大陆大盘双向白名单直连**：
   `domain(geosite:cn) -> direct` 及 `dip(geoip:cn) -> direct`
6. **[第 6 层] 终态回落兜底**：
   `fallback: 默认代理组`

### 5. DNS 污染防御闭环铁律
在 `dns.routing.response` 中配置私网 IP 污染重查（反投毒）时：
```shell
response {
    # 必须在第一行配置可信上游白名单放行！
    upstream(googledns) -> accept
    
    # 命中污染特征才执行二次重查
    ip(geoip:private) && !qname(geosite:cn) -> googledns
    
    fallback: accept
}
```
如果没有首行的 `upstream(googledns) -> accept`，当 `googledns` 的正常查询结果巧合包含私网地址时，会触发二次、三次无限重查，陷入无限递归！

---

## OpenWrt 内核与硬件依赖

1. **内核版本**：建议 Linux 5.15、6.1 或 6.6+。
2. **BTF (BPF Type Format) 关键依赖**：
   * **ImmortalWrt / 自编译固件**：通常内核内置 `CONFIG_DEBUG_INFO_BTF=y`，动态暴露于 `/sys/kernel/btf/vmlinux`。
   * **官方原版 OpenWrt**：默认未开启内核内置 BTF，可通过第三方源（如 sbwml 的 `package_kernel_vmlinux-btf`）安装 `vmlinux-btf` 软件包（提供分离的 BTF 符号文件 `/usr/lib/debug/boot/vmlinux`），或自行编译固件时开启 `CONFIG_DEBUG_INFO_BTF=y`。命令：`opkg install vmlinux-btf`。
3. **内核模块 (kmod)**：
   * `kmod-sched-bpf`
   * `kmod-sched-core`
   * `kmod-bpf`
4. **Sysctl 关键内核参数**：
   在 `global` 块中设置 `auto_config_kernel_parameter: true`，dae 会自动将 `net.ipv4.ip_forward` 置为 `1`，并将 `net.ipv4.conf.all.send_redirects` 置为 `0`。
5. **daed (Web 控制面板)**：
   若使用 daed 网页版本，默认监听端口为 `http://路由器IP:2023`，其节点数据库持久化于 `/etc/daed/wing.db`。
   > 支持边界：daed 使用独立的 `/etc/daed` 配置目录，无法用 `dae reload` 热重载；请在 Web 面板中修改配置。本技能的 deploy 脚本检测到只有 daed 时会拒绝部署。
