# 节点转换参考

将 Clash YAML、V2Ray 分享信息或手工协议参数转换为 sing-box outbound 时使用本文件。

## 通用字段映射

| Clash / 通用字段 | sing-box |
|------------------|----------|
| `server` / `port` | `"server"` / `"server_port"` |
| `tls: true` | `"tls": { "enabled": true }` |
| `servername` / `sni` | `"tls.server_name"` |
| `skip-cert-verify: true` | `"tls.insecure": true` |
| `client-fingerprint` | `"tls.utls": { "enabled": true, "fingerprint": "..." }` |
| `reality-opts.public-key` | `"tls.reality.public_key"` |
| `reality-opts.short-id` | `"tls.reality.short_id"` |
| `network: ws` | `"transport": { "type": "ws" }` |
| `network: grpc` | `"transport": { "type": "grpc" }` |
| `network: h2` | `"transport": { "type": "http" }` |
| `ws-opts.path` | `"transport.path"` |
| `ws-opts.headers.Host` | `"transport.headers": { "Host": ["..."] }` |
| `grpc-opts.grpc-service-name` | `"transport.service_name"` |

IP 格式服务器地址不需要 `domain_resolver`。

## VLESS

```json
{
  "type": "vless",
  "tag": "node",
  "server": "example.com",
  "server_port": 443,
  "uuid": "uuid",
  "flow": "xtls-rprx-vision",
  "tls": {
    "enabled": true,
    "server_name": "example.com",
    "utls": { "enabled": true, "fingerprint": "chrome" },
    "reality": { "enabled": true, "public_key": "...", "short_id": "..." }
  }
}
```

## VMess

```json
{
  "type": "vmess",
  "tag": "node",
  "server": "example.com",
  "server_port": 443,
  "uuid": "uuid",
  "security": "auto",
  "tls": { "enabled": true, "server_name": "example.com" },
  "transport": {
    "type": "ws",
    "path": "/path",
    "headers": { "Host": ["example.com"] }
  }
}
```

Clash `cipher` 映射到 sing-box `security`。`alter_id` 默认 0；非 0 是旧式 AEAD 前配置。

## Shadowsocks

```json
{
  "type": "shadowsocks",
  "tag": "node",
  "server": "example.com",
  "server_port": 8388,
  "method": "2022-blake3-aes-128-gcm",
  "password": "password"
}
```

Clash `plugin: obfs` 映射为 `"plugin": "obfs-local"` 和 `"plugin_opts": "obfs=http;obfs-host=..."`。

## Trojan

```json
{
  "type": "trojan",
  "tag": "node",
  "server": "example.com",
  "server_port": 443,
  "password": "password",
  "tls": { "enabled": true, "server_name": "example.com" }
}
```

## Hysteria2

```json
{
  "type": "hysteria2",
  "tag": "node",
  "server": "example.com",
  "server_port": 443,
  "password": "password",
  "up_mbps": 100,
  "down_mbps": 200,
  "obfs": { "type": "salamander", "password": "password" },
  "tls": { "enabled": true, "server_name": "example.com" }
}
```

Clash `auth` 映射到 sing-box `password`。

## TUIC

```json
{
  "type": "tuic",
  "tag": "node",
  "server": "example.com",
  "server_port": 443,
  "uuid": "uuid",
  "password": "password",
  "congestion_control": "bbr",
  "udp_relay_mode": "native",
  "tls": { "enabled": true, "server_name": "example.com", "alpn": ["h3"] }
}
```

## ShadowTLS + Shadowsocks

```json
{
  "type": "shadowtls",
  "tag": "st",
  "server": "example.com",
  "server_port": 443,
  "version": 3,
  "password": "st-password",
  "tls": {
    "enabled": true,
    "server_name": "www.microsoft.com",
    "utls": { "enabled": true, "fingerprint": "chrome" }
  }
},
{
  "type": "shadowsocks",
  "tag": "ss-via-st",
  "method": "2022-blake3-aes-128-gcm",
  "password": "ss-password",
  "detour": "st",
  "udp_over_tcp": { "enabled": true }
}
```

## AnyTLS

```json
{
  "type": "anytls",
  "tag": "node",
  "server": "example.com",
  "server_port": 443,
  "password": "password",
  "tls": { "enabled": true, "server_name": "example.com" }
}
```

普通 AnyTLS outbound 至少需要 `server`、`server_port`、`password` 和 `tls`。`padding_scheme` 属于 inbound/user 相关场景，不作为普通 outbound 必填字段。
