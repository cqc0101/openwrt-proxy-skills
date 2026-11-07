# dae 路由语法速查

> 依据 dae 官方 `routing.md` / `example.dae` 整理，原文见 [upstream-docs.md](./upstream-docs.md)。
> 规则**自上而下匹配，命中即停**，因此顺序即优先级。

## 内建出站

| 名称 | 含义 |
| :--- | :--- |
| `direct` | 直连；**发往 53 端口的流量仍会被 dae 的 DNS 模块处理**（用于按域名分流） |
| `must_direct` | 直连且**完全绕过** dae（含 DNS），`direct(must)` 同义；用于防 DNS 回环 |
| `block` | 丢弃 |
| `must_rules` | 不劫持 DNS，但继续匹配后续规则 |
| `must_<group>` / `<group>(must)` | 用该组出站且不劫持 DNS |

## 匹配函数

| 函数 | 说明 | 示例 |
| :--- | :--- | :--- |
| `domain(...)` | 域名匹配；默认后缀匹配 | `domain(geosite:cn)`、`domain(suffix: v2raya.org)`、`domain(full: dns.google)`、`domain(keyword: facebook)`、`domain(regex: '\.goo.*\.com$')` |
| `dip(...)` | 目标 IP / CIDR / geoip / ext 数据 | `dip(geoip:cn)`、`dip(8.8.8.8)`、`dip(101.97.0.0/16)`、`dip(ext:"geoip.dat:cn")` |
| `sip(...)` | 来源 IP | `sip(192.168.0.0/24)` |
| `dport(...)` / `sport(...)` | 端口或端口段 | `dport(80)`、`dport(10080-30000)` |
| `l4proto(...)` | 传输层协议 | `l4proto(tcp)`、`l4proto(udp)` |
| `ipversion(...)` | IP 版本 | `ipversion(4)` |
| `mac(...)` | 源 MAC | `mac('02:42:ac:11:00:02')` |
| `pname(...)` | 本机进程名（仅本机流量有效） | `pname(dnsmasq)`、`pname(aria2c)` |
| `dscp(...)` | DSCP 标记（常用于 BT 绕行） | `dscp(0x4)` |
| `qname(...)` / `qtype(...)` | **仅 DNS 规则**使用 | `qname(geosite:cn)`、`qtype(a, aaaa)` |
| `upstream(...)` | **仅 DNS response 规则**使用 | `upstream(googledns)` |

组合方式：
- `&&` 表示并且：`l4proto(udp) && dport(443) -> block`
- `!` 表示取反：`!domain(geosite:cn)`
- 逗号表示**或**：`dip(geoip:cn, geoip:private)`

## 取反合并（最容易踩的语义坑）

```shell
# 两行 = “不属于 a” 或 “不属于 b”，即绝大多数流量都会命中
!domain(geosite:a) -> proxy
!domain(geosite:b) -> proxy

# 想表达“既不属于 a 也不属于 b”，必须合并成一行
!domain(geosite:a, geosite:b) -> proxy
```

## 顺序与兜底

- `fallback: <组名或内建出站>` 是最后兜底（也叫 default）。
- 建议顺序（本技能模板采用）：
  1. 宿主 DNS 组件 `must_direct` + 私网/广播 `direct`
  2. 下载/P2P 进程 `must_direct` + `dscp(0x4) -> direct`
  3. 境外 UDP 443（QUIC）抑制
  4. 重点海外服务专属组
  5. `domain(geosite:cn)` / `dip(geoip:cn) -> direct`
  6. `fallback: <代理组>`

## 节点组（group）语法

```shell
group {
  proxy {
    filter: name(HK_node)                 # 多行 filter 之间是“或”
    filter: subtag(my_sub) && !name(keyword: 'ExpireAt:')
    filter: name(US_node) [add_latency: -500ms]   # 给延迟加偏移，影响选路
    policy: min_moving_avg                # min / min_avg10 / random / fixed(0)
  }
}
```

## 参数名是严格的

较新版本中，`pname`/`port`/`dip`/`sip`/`mac`/`qtype` 等函数只接受合法参数名（如 `keyword:`、`regex:`、
`geoip:`、`geosite:`、`ext:`）；写错参数名会**直接启动失败**，不再被静默忽略。升级后请复核 routing 段。
