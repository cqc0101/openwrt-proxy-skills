# 网络模式与平台行为

## 模式选择

| 模式 | 适用场景 | 限制 |
|------|----------|------|
| TUN/VPN | 默认。捕获所有 IP 流量，适合 SFM/SFA/SFI 和桌面全局代理 | 命令行创建 TUN 通常需要权限 |
| system proxy | mixed inbound + `set_system_proxy`，适合命令行轻量代理 | 只捕获遵循系统代理的应用；应用 DNS 不由 sing-box 控制 |
| manual mixed/socks/http | 浏览器或单应用手动设置代理 | 只影响显式配置代理的应用 |

系统代理和 manual mixed/http 不使用 FakeIP 作为核心路径，因为应用 DNS 不由 TUN 劫持。

## 平台说明

### macOS (SFM) / Android (SFA) / iOS (SFI)

- 通过 Network Extension / VPN API 实现 VPN，无需 root。
- 默认只需要 TUN inbound；VPN 模式捕获浏览器 HTTP/HTTPS。
- `auto_detect_interface: true` 防止路由循环。
- `stack: "mixed"` 兼容性最好。
- 同一 TUN 配置可跨 SFM/SFA/SFI 使用。

SFM 仅在配置包含 `platform.http_proxy.enabled: true` 且偏好设置允许时设置系统代理。

## `set_system_proxy` vs `platform.http_proxy`

| | `set_system_proxy` | `platform.http_proxy` |
|---|---|---|
| 配置位置 | mixed/http inbound 字段 | TUN inbound 的 `platform` 块 |
| 实现 | 调用系统代理设置接口 | 通过 VPN API 设置代理 |
| 适用场景 | 命令行 `sing-box run` | SFM/SFA/SFI 图形客户端 |
| 依赖 TUN | 不依赖 | 必须有 TUN inbound |
| 命令行可用 | 可用 | 不应依赖 CLI 生效；主要由图形客户端 PlatformInterface 消费 |

`platform.http_proxy` 不是代理服务器；它只告诉系统代理地址。实际代理服务器仍由 mixed/http inbound 提供。使用 `platform.http_proxy` 时必须同时添加 mixed/http inbound。

## system proxy 最小结构

system proxy 配置使用 mixed inbound，不包含 TUN inbound、DNS hijack 或 FakeIP：

```json
{
  "inbounds": [
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "127.0.0.1",
      "listen_port": 2080,
      "set_system_proxy": true
    }
  ],
  "route": {
    "auto_detect_interface": true,
    "default_domain_resolver": "alidns"
  }
}
```

v1.13 remote rule-set 可使用 `download_detour`。v1.14 system proxy 配置应使用 `http_clients` + `route.default_http_client` 或 per-rule-set `http_client`。

## 可选 `platform.http_proxy`

默认不需要。仅在以下场景添加：

- 特定应用只认系统 HTTP 代理，不走 TUN 路由。
- 需要 Apple 图形客户端支持的 `bypass_domain` / `match_domain`。

```json
"platform": {
  "http_proxy": {
    "enabled": true,
    "server": "127.0.0.1",
    "server_port": 2080,
    "bypass_domain": ["example.com"],
    "match_domain": ["specific-app.com"]
  }
}
```

同时添加：

```json
{ "type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080 }
```
