# Rule-set 与自定义分流

## URL 规则

`raw.githubusercontent.com` 在国内不稳定。默认使用 jsdelivr CDN：

```text
https://testingcf.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-{name}.srs
https://testingcf.jsdelivr.net/gh/SagerNet/sing-geoip@rule-set/geoip-{code}.srs
```

`@cn` 变体标签的 URL 文件名使用 `@`，例如 `geosite-apple@cn.srs`。备用 CDN 可用 `fastly.jsdelivr.net`。

v1.13 remote rule-set 可使用 `download_detour`。v1.14 模板使用 `http_clients` + `route.default_http_client` 或 per-rule-set `http_client`。

## 常用标签

**Geosite**：

- 国内：`geosite-cn`、`geosite-geolocation-cn`
- 广泛海外：`geosite-geolocation-!cn`
- Google：`geosite-google`、`geosite-google@cn`、`geosite-youtube`、`geosite-google-gemini`
- Microsoft：`geosite-microsoft`、`geosite-microsoft@cn`、`geosite-github`、`geosite-github-copilot`
- Apple：`geosite-apple`、`geosite-apple@cn`、`geosite-apple-intelligence`
- AI：`geosite-openai`、`geosite-anthropic`、`geosite-jetbrains-ai`、`geosite-category-ai-chat-!cn`、`geosite-xai`
- Steam：`geosite-steam`、`geosite-steam@cn`
- 社交：`geosite-telegram`、`geosite-discord`
- 流媒体：`geosite-netflix`、`geosite-spotify`
- 广告：`geosite-category-ads-all`

**Geoip**：国家/地区代码，例如 `geoip-cn`、`geoip-us`、`geoip-jp`、`geoip-sg`。

不要根据站点语言、品牌或 TLD 推断是否属于 `geosite-cn`；需要准确性时验证规则集源。

## 模板内置默认规则

默认规则不需要联网查询，使用模板已有结构：

- 广告拒绝。
- 国内域名/IP 直连。
- 常见海外域名代理。
- AI/Google/Apple/Microsoft/Steam/Telegram 等服务 selector。

## 常见海外站点代理

当用户希望常见海外网站始终走代理，优先使用：

```json
{
  "rule_set": "geosite-geolocation-!cn",
  "action": "route",
  "outbound": "proxy"
}
```

将该规则放在 `geosite-cn` / `geoip-cn -> direct` 之前。

## 自定义域名直连

添加 DNS + route 两条规则，放在 CN/代理兜底前：

```json
{ "domain_suffix": ["example.com"], "action": "route", "server": "local-dns" }
```

```json
{ "domain_suffix": ["example.com"], "action": "route", "outbound": "direct" }
```

`domain_suffix` 不带前导 `.` 时匹配域名本身及所有子域名。

## 自定义域名代理

默认添加 route 规则，放在 `geosite-cn` / `geoip-cn` 和 `final` 之前：

```json
{ "domain_suffix": ["example.com"], "action": "route", "outbound": "proxy" }
```

RealIP 模板且 `dns.final` 是国内 DNS 时，同时添加 remote DNS 规则：

```json
{ "domain_suffix": ["example.com"], "action": "route", "server": "google-dns" }
```

FakeIP 模板下，仅在用户明确要求时使用：

```json
{ "domain_suffix": ["example.com"], "action": "route", "server": "fakeip-dns" }
```

## 自定义规则查找策略

只有用户明确提出自定义规则、服务出口、国家/地区出口或 rule-set 诉求时才联网查询。优先查询官方或可信规则集源。

查不到合适 rule-set 时：

- 域名诉求使用显式 `domain` / `domain_suffix` / `domain_regex`。
- 国家/地区 IP 诉求使用 `geoip-{code}` 或显式 `ip_cidr`。
- 服务出口诉求如果没有 selector，则创建对应 selector 或复用 `proxy`，并在摘要中说明。
