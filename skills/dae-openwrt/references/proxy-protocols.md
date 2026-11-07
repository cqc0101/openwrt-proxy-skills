# dae 支持的代理协议

> 依据 dae 官方 `proxy-protocols.md` 与 `example.dae` 整理，原文与链接见 [upstream-docs.md](./upstream-docs.md)。

## 协议一览

| 协议 | 支持细节 | URI 格式来源 |
| :--- | :--- | :--- |
| HTTP(S) / naiveproxy | 建议搭配外部 naiveproxy 程序 | `https://[[user:]pass@]host:port/` |
| Socks | Socks4 / Socks4a / Socks5 | `socks5://[[user:]pass@]host:port/` |
| VMess | AEAD（`alterId=0`）；TCP / WS / gRPC / Meek / HTTPUpgrade；支持 TLS | v2rayN / DuckSoft 格式 |
| VLESS | 支持 Reality 与 `xtls-rprx-vision` | v2rayN / DuckSoft 格式 |
| Shadowsocks | AEAD / Stream Ciphers；SIP003 插件（simple-obfs / shadow-tls） | SIP002 / SIP008 |
| ShadowsocksR | — | — |
| Trojan | trojan-gfw / trojan-go | trojan-go URL |
| Tuic | v5 | dae discussion #182 |
| Juicity | — | juicity link format |
| Hysteria2 | — | hysteria2 URI scheme |
| AnyTLS | — | anytls URI scheme |
| 代理链 | 多个 outbound 串联 | `tuic://... -> vmess://...` |
| ShadowTLS | 可直接用 `shadowtls://` | — |

## 配置中的写法

```shell
node {
  'socks5://localhost:1080'
  mylink: 'ss://LINK'
  node1: 'vmess://LINK'
  node2: 'vless://LINK'
  chains: 'tuic://LINK -> vmess://LINK'
  hysteria2: 'hysteria2://password@server-ip:port/?sni=domain'
}

subscription {
  my_sub: 'https://www.example.com/subscription/link'
  another_sub: 'https://example.com/another_sub'
  'https://example.com/no_tag_link'
  'file://relative/path/to/mysub.sub'          # 相对入口配置目录
  persist_sub: 'https-file://example.com/link' # 失败时回退到本地缓存副本
}
```

## 必须注意的两点

1. **字符串统一用单引号**：URI、订阅链接、IPv6 CIDR、MAC、正则都要用 `'...'`（`ext:"file.dat:tag"` 除外）。
2. **IPv6 必须加方括号**：`vless://uuid@[240e:123:456::1]:443`。不加方括号时，任何按 `host:port` 解析的
   实现（含 Go 的 `url.Parse`/`net.SplitHostPort`）都会报 `too many colons in address`，节点直接失效。

## TLS 指纹伪装

需要浏览器式 Client Hello 时：

- 全局：`global { tls_implementation: utls }`（`utls_imitate` 默认 `chrome_auto` 即可）；
- 单节点：在链接查询参数中加 `tlsImplementation=utls&utlsImitate=chrome`。

若机场要求不使用自定义 SNI，请省略 `sni` 或置空。

## 基于 QUIC 的协议：拥塞控制覆盖

`tuic` / `juicity` / `hysteria2` 链接支持仅客户端生效的 `cc_override` 参数（不会发给服务器）：

```
tuic://uuid:password@host:443?congestion_control=bbr&cc_override=bbr3
hysteria2://auth@host:443?upmbps=20&downmbps=100&cc_override=bbr3
```

| 协议 | 可用值 |
| :--- | :--- |
| tuic / juicity | `bbr`、`cubic`、`new_reno`、`brutal`、`bbr3` |
| hysteria2 | `bbr`、`brutal`、`bbr3` |

值不受支持时节点会在构造 dialer 阶段**直接失败**（不会静默回退）。`brutal` 需要已知发送速率
（tuic/juicity 用正值的 `cwnd`，hysteria2 用正值的上传速率），否则退回 BBR。

## 外部代理程序（以 naiveproxy 为例）

dae 不用 Chromium 网络栈，naiveproxy 的伪装效果会被削弱，官方建议外挂：

```bash
naiveproxy --listen=socks5://127.0.0.1:1090 --proxy=https://yourlink
```

```shell
node { 'socks5://127.0.0.1:1090' }

routing {
  pname(naiveproxy) -> must_direct   # 绑定了 wan_interface 时必需，防止回环
  ...
}
```

进程名用 `ps -ef` 或看 dae 日志确认；仅绑 `lan_interface` 时不需要这条规则。
