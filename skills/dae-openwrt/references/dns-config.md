# dae DNS 配置要点

> 依据 dae 官方 `dns.md` / `external-dns.md` 整理，原文见 [upstream-docs.md](./upstream-docs.md)。

## 上游（upstream）协议

| scheme | 说明 | 默认端口 |
| :--- | :--- | :--- |
| `udp://host:port` | 明文 UDP | 53 |
| `tcp://host:port` | 明文 TCP | 53 |
| `tcp+udp://host:port` | 同时探测/使用，截断时走 TCP | 53 |
| `https://host:port/path` | DoH | 443，默认路径 `/dns-query` |
| `h3://` / `http3://host:port/path` | DoH3 | 443 |
| `quic://host:port` | DoQ | 853 |
| `tls://host:port` | DoT | 853 |

```shell
dns {
  upstream {
    alidns: 'udp://dns.alidns.com:53'
    googledns: 'tcp+udp://dns.google:53'
  }
}
```

- `udp://` 上游只在应答被截断（TC=1）后重试 TCP；`tcp+udp://` 在任何 UDP 失败后重试。
- 期望大应答（DNSSEC 等）时，优先给 `tcp+udp://` 或 `tcp://`。

## 请求路由（request）

```shell
routing {
  request {
    qname(geosite:cn) -> alidns          # 国内域名走国内上游
    qname(geosite:category-ads-all) -> reject
    sub(my_sub) -> googledns             # 仅作用于“拉取订阅”的解析
    node(name_keyword: hk) -> alidns     # 仅作用于“节点域名”的解析
    fallback: googledns                  # 兜底（也叫 default）
  }
}
```

- 内建出站：`asis`（按客户端原地址查询）、`reject`。
- `sub()` / `node()` / `subnode()` 是**dae 自身解析**用的选择器，只能指向 `upstream` 里定义的名字，不能与
  `qname`/`qtype` 混写在同一行。
- `ipversion_prefer: 4` 的语义是：**已知该域名有 A 记录时**，对 AAAA 返回空应答；不是"只查 v4"。

## 响应路由（response）

```shell
response {
  upstream(googledns) -> accept                                   # 可信上游，直接接受
  ip(geoip:private) && !qname(geosite:cn) -> googledns            # 疑似污染，重查
  fallback: accept
}
```

**铁律**：`upstream(...) -> accept` 必须放在重查规则**之前**，否则可能无限递归重查。

## `must_direct` 与 DNS 可见性（重要副作用）

- 只有命中 `must_direct` 的流量完全绕过 dae；仅写 `direct` 仍会经过 DNS 模块。
- 因此宿主机 DNS 组件（dnsmasq 等）的 53 端口流量应放行，否则会形成回环。
- 但副作用是：**被放行的解析器应答 dae 看不到**，`domain()` 规则可能学不到 域名→IP 映射。
  在不希望出现该副作用的拓扑下，用更精确的规则（限定 `l4proto(udp) && dport(53)`，或按目的地址限定）。

## 局域网客户端与 53 端口

- 客户端发往 dae 主机 53 端口的查询会进入 dae 的 DNS 模块，dae 能看到应答，`domain()` 规则随之生效。
- 若希望由主机自身的解析器直接应答（dae 不可见），显式写
  `l4proto(udp) && dport(53) && dip(<dae 主机地址>) -> must_direct`。
- 端口 53 被其它程序占用会破坏劫持；必要时把该程序改到别的端口。

## 外部 DNS（AdGuardHome / mosdns）联动

**同机部署**：

```shell
routing {
  pname(AdGuardHome) && l4proto(udp) && dport(53) -> must_direct   # 否则上游查询被交回自己 → 回环
  # 保留一条让 DoH 上游走代理的规则
}
dns {
  upstream { adguardhome: 'udp://127.0.0.1:53' }
  routing { request { fallback: adguardhome } }
}
```

**局域网另一台机器**：把 `pname(...)` 换成 `sip(192.168.30.3)` 或 `mac('...')`，并把
`upstream` 指向该机地址；DHCP 下发的 DNS 不要指向这台机器，否则查询在局域网内直达、dae 看不到。

## 缓存与引导解析

| 选项 | 说明 |
| :--- | :--- |
| `optimistic_cache` | 默认 `true`，过期条目在 stale 窗口内仍可返回并发起后台刷新 |
| `optimistic_cache_ttl` | stale 窗口秒数，默认 60；`0` 表示不限制 |
| `max_cache_size` | 缓存条目上限，默认 65536 |
| `fixed_domain_ttl` | 对指定域名固定 TTL；`0` 表示立刻过期 |
| `bootstrap_resolver` | 仅用于启动期解析上游域名/订阅域名，不走代理；格式 `'ip:port'` 或 `'[ipv6]:port'`；未设置时依次使用 119.29.29.29、223.5.5.5 |

```shell
global {
  bootstrap_resolver: '223.5.5.5:53'
}
```
