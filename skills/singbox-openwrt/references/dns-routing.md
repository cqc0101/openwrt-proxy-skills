# DNS、RealIP、FakeIP 与 IPv6

## DNS hijack

TUN 模板前两条 route rule 必须是：

```json
{ "action": "sniff" },
{
  "type": "logical",
  "mode": "or",
  "rules": [{ "protocol": "dns" }, { "port": 53 }],
  "action": "hijack-dns"
}
```

不先 `sniff`，协议检测尚未运行。仅用 `"protocol": "dns"` 会漏掉部分 UDP DNS；结合 `port: 53` 才能稳定捕获。

## RealIP 模板

RealIP 模板使用真实 DNS 响应。设置 `dns.reverse_mapping: true` 后，DNS router 会把非 FakeIP 的 A/AAAA 响应按 TTL 写入 `真实 IP -> domain` 内存映射。连接进入路由时，先查 FakeIP；未命中时查 reverse mapping，再结合 sniff 得到域名规则语义。

1.13 已支持 RealIP 所需的 `dns.reverse_mapping`，因此 1.13 RealIP TUN 可以作为默认稳定模板。1.14 RealIP 是前瞻增强模板，优势是可使用 `dns.optimistic`、`store_dns`、HTTP client 和新的 DNS rule 能力。

`reverse_mapping` 不会校验或纠正 DNS 响应，也不会防止污染；如果海外域名被国内 DNS 返回污染 IP，它只会记录这个污染 IP 的映射。RealIP 模板要避免海外域名 DNS 污染，必须在 DNS rules 中把明确代理/海外 rule-set 路由到 remote DNS。

优势：

- 应用拿真实 IP。
- 浏览器、系统缓存、抓包和日志语义自然。
- 适合大多数 TUN 和浏览器场景。

代价：

- 真实 IP 可能被多个域名共享。
- 映射随 TTL 过期。
- ECH、非 TLS、不可 sniff 流量会降低域名归因确定性。

## FakeIP 模板

FakeIP 模板在 DNS 阶段返回 fake IP，并保存 `fake IP <-> domain` 专用映射。连接进入路由时，如果目标 IP 属于 fake IP 范围，route 可直接反查回域名。

优势：

- 连接阶段域名恢复更确定。
- 可减少应用侧 DNS 等待，因为 A/AAAA 查询直接返回 fake IP。

代价：

- 可能触发浏览器 Local Network Access。
- 可能污染 Service Worker / 浏览器缓存。
- 映射缺失会导致 `missing fakeip record`。
- 规则变更后旧映射可能残留。
- ping/traceroute/日志 IP 语义失真。

FakeIP 不会消除真实解析：proxy outbound 通常把域名交给远端代理解析；direct outbound 仍需本地解析。若主要诉求只是 DNS 延迟，1.14 优先使用 `dns.optimistic`、`store_dns` 和缓存策略；1.13 不支持这些新字段时，优先使用普通 DNS cache、规则简化或浏览器专用 mixed/socks/http inbound。

## FakeIP 生命周期

1. 应用查询 `example.com` 的 A/AAAA。
2. DNS 规则匹配 `fakeip-dns`。
3. FakeIP transport 返回假 IP，不做真实 DNS 查询。
4. 应用连接假 IP。
5. 路由器检测目标在 fake IP 范围内，反查回域名。
6. 路由规则按域名匹配，选择出站。
7. 出站阶段才按出站类型决定是否真实解析。

| 出站类型 | DNS 行为 |
|----------|----------|
| proxy | 通常把域名发给远端代理，本地不解析 |
| direct | 必须本地解析，使用 outbound `domain_resolver` 或 route `default_domain_resolver` |
| socks4 | 协议不支持 FQDN，必须本地解析 |

## DNS 规则默认形态

RealIP 模板默认：

- hosts 优先。
- 国内域名走 `alidns`。
- 明确代理域名走 remote DNS。
- final 默认国内 DNS。

FakeIP 模板默认：

- 国内域名走真实国内 DNS。
- 其它 A/AAAA 可走 `fakeip-dns`。
- `experimental.cache_file.store_fakeip: true` 必须开启。

## IPv6 默认策略

默认使用 IPv4-only：

```json
"strategy": "ipv4_only"
```

除非用户确认真实网络 IPv6 可用并要求完整 IPv6 TUN，否则不要给 TUN inbound 配 IPv6 地址：

```json
"address": "172.19.0.1/30"
```

不要在 IPv6 不通的网络上使用：

```json
"address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"]
```

原因：TUN 配 IPv6 地址后，系统会认为 IPv6 可用。微信等应用可能通过 HTTPDNS 获取 IPv6 地址并绕过 sing-box DNS 模块，随后连接原始 IPv6 IP，导致 `no route to host` 且不稳定回退 IPv4。

| 网络环境 | TUN 地址 | 行为 |
|----------|----------|------|
| 仅 IPv4 | 仅 IPv4 | 所有流量经 TUN，应用原生回退 IPv4 |
| IPv4 + IPv6 | 仅 IPv4 | IPv4 经 TUN，IPv6 绕过 TUN |
| IPv4 + IPv6 | IPv4 + IPv6 | IPv4/IPv6 都经 TUN |
