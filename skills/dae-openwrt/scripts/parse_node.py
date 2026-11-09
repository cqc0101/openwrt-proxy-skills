#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
节点 URI 解析与 sing-box outbound 转换器
支持协议：VLESS (Reality/WS/gRPC), Hysteria 2 (含端口跳跃), Trojan, Shadowsocks (SIP002/Base64), VMess
注意：sing-box 的 vless/vmess/trojan outbound 中 `network` 字段只接受 "tcp"/"udp"；
      ws / grpc / h2 等传输层必须写入 `transport` 块。
"""
# [共享脚本] 本文件与 singbox-openwrt/scripts/parse_node.py 完全一致，修改需双份同步！

import re
import sys
import json
import base64
import urllib.parse

# 中文 Windows 控制台 (cp936) 无法编码 emoji/部分字符，统一重配为 UTF-8 输出
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def _b64_decode(s: str) -> str:
    """Base64 解码：自动执行 URL 解码与补齐 padding，同时接受标准与 urlsafe 字母表。

    支持 UTF-8 与 GB18030 中文字符集；若两者均非法则抛出 UnicodeDecodeError。
    """
    s = urllib.parse.unquote(s.strip())
    s = re.sub(r"\s+", "", s)
    s += '=' * (-len(s) % 4)
    raw = base64.urlsafe_b64decode(s)
    try:
        return raw.decode('utf-8')
    except UnicodeDecodeError:
        return raw.decode('gb18030')


def _split_host_port(host_port: str, default_port: int = 443):
    """拆分 'host:port'（IPv6 形如 '[v6]:port' 或裸 '[v6]'），返回 (server, port)。

    容错处理缺端口、非数字端口、裸 IPv6 与 URI 片段。
    """
    if "#" in host_port:
        host_port = host_port.split("#", 1)[0]
    if "?" in host_port:
        host_port = host_port.split("?", 1)[0]
    if "/" in host_port:
        host_port = host_port.split("/", 1)[0]
    host_port = host_port.strip()
    if not host_port:
        raise ValueError("主机地址为空")

    if host_port.startswith("["):
        if "]:" in host_port:
            server_part, port_str = host_port.split("]:", 1)
            server = server_part.lstrip("[").strip()
            port = int(port_str) if port_str.isdigit() else default_port
        else:
            server = host_port.strip("[]").strip()
            port = default_port
    elif ":" in host_port:
        if host_port.count(":") > 1:
            server = host_port.strip()
            port = default_port
        else:
            server_str, port_str = host_port.rsplit(":", 1)
            server = urllib.parse.unquote(server_str).strip("[]").strip()
            port = int(port_str) if port_str.isdigit() else default_port
    else:
        server = urllib.parse.unquote(host_port).strip("[]").strip()
        port = default_port

    if not server:
        raise ValueError(f"无法解析主机地址: {host_port!r}")
    return server, port


def _extract_userinfo_password(parsed) -> str:
    """从 urlparse 结果提取完整密码（保留 user:password 复合格式，兼容 :secret 前导冒号）。"""
    u = urllib.parse.unquote(parsed.username or "")
    p = urllib.parse.unquote(parsed.password or "")
    if u and p:
        return f"{u}:{p}"
    return p or u


def _safe_port(parsed, default_port: int = 443) -> int:
    """安全提取端口，防止非数字端口引发 ValueError 崩溃。"""
    try:
        return parsed.port or default_port
    except ValueError:
        host_port = parsed.netloc.rsplit("@", 1)[-1]
        _, port = _split_host_port(host_port, default_port=default_port)
        return port


def _normalize_port_ranges(raw_spec: str):
    """将 Hysteria2 端口跳跃表达式（如 '20000-50000' 或 '443,20000-30000'）转为 sing-box server_ports 列表。"""
    ranges = []
    first_port = None
    for part in str(raw_spec or "").split(","):
        part = part.strip()
        if not part:
            continue
        m = re.match(r"^(\d{1,5})\s*[-:]\s*(\d{1,5})$", part)
        if m:
            p1, p2 = int(m.group(1)), int(m.group(2))
            if 1 <= p1 <= 65535 and 1 <= p2 <= 65535 and p1 <= p2:
                ranges.append(f"{p1}:{p2}")
                if first_port is None:
                    first_port = p1
        elif part.isdigit():
            p = int(part)
            if 1 <= p <= 65535 and first_port is None:
                first_port = p
    return first_port, ranges


def _build_ws_transport(params, default_host=""):
    """由 URI 参数构建 ws transport 块。"""
    path = params.get("path", [""])[0]
    host = params.get("host", [default_host])[0]
    transport = {
        "type": "ws",
        "path": path or "/"
    }
    if host:
        transport["headers"] = {"Host": host}
    return transport


def _build_grpc_transport(params):
    """由 URI 参数构建 grpc transport 块。"""
    service = params.get("serviceName", params.get("servicename", [""]))[0]
    return {
        "type": "grpc",
        "service_name": service or ""
    }


def _build_httpupgrade_transport(params, default_host=""):
    """由 URI 参数构建 httpupgrade transport 块。"""
    path = params.get("path", [""])[0]
    host = params.get("host", [default_host])[0]
    transport = {
        "type": "httpupgrade",
        "path": path or "/"
    }
    if host:
        transport["host"] = host
    return transport


def _build_http_transport(params, default_host=""):
    """由 URI 参数构建 http (H2/HTTP) transport 块。"""
    path = params.get("path", [""])[0]
    host = params.get("host", [default_host])[0]
    transport = {
        "type": "http",
        "path": path or "/"
    }
    if host:
        hosts = [h.strip() for h in host.split(",") if h.strip()]
        if hosts:
            transport["host"] = hosts
    return transport


def _apply_uri_transport(outbound, net_type: str, params, allow_udp_network: bool = False):
    """统一映射 URI 传输层，对 xhttp/splithttp/kcp/quic 等不支持传输层显式抛出 ValueError，严禁静默退化为裸 TCP。"""
    nt = (net_type or "tcp").strip().lower()
    if nt in ("", "tcp", "none"):
        return
    if nt == "udp" and allow_udp_network:
        outbound["network"] = "udp"
    elif nt == "ws":
        outbound["transport"] = _build_ws_transport(params)
    elif nt == "grpc":
        outbound["transport"] = _build_grpc_transport(params)
    elif nt == "httpupgrade":
        outbound["transport"] = _build_httpupgrade_transport(params)
    elif nt in ("http", "h2"):
        outbound["transport"] = _build_http_transport(params)
    else:
        raise ValueError(f"不支持的传输层类型 (拒绝静默降级为裸 TCP): {nt!r}")


def _extract_alpn_list(params):
    """从 URI 查询参数提取 alpn 列表。"""
    raw = params.get("alpn", [""])[0]
    if not raw:
        return []
    return [x.strip() for x in urllib.parse.unquote(raw).split(",") if x.strip()]


def parse_vless(uri_str):
    parsed = urllib.parse.urlparse(uri_str)
    uuid = urllib.parse.unquote(parsed.username or "")
    server = parsed.hostname
    if not server or not uuid:
        raise ValueError(f"无法解析 VLESS 节点地址 (缺少有效主机或 UUID): {uri_str[:40]}...")
    port = _safe_port(parsed, 443)
    params = urllib.parse.parse_qs(parsed.query)
    raw_frag = urllib.parse.unquote(parsed.fragment).strip() if parsed.fragment else ""
    tag = raw_frag or f"vless-{server}"

    security = params.get("security", [""])[0]
    flow = params.get("flow", [""])[0]
    net_type = params.get("type", ["tcp"])[0].lower()

    outbound = {
        "type": "vless",
        "tag": tag,
        "server": server,
        "server_port": port,
        "uuid": uuid
    }

    _apply_uri_transport(outbound, net_type, params, allow_udp_network=True)

    if flow:
        outbound["flow"] = flow

    if security == "reality":
        pbk = params.get("pbk", [""])[0]
        sid = params.get("sid", [""])[0]
        sni = params.get("sni", [""])[0]
        fp = params.get("fp", ["chrome"])[0]

        outbound["tls"] = {
            "enabled": True,
            "server_name": sni,
            "utls": {
                "enabled": True,
                "fingerprint": fp
            },
            "reality": {
                "enabled": True,
                "public_key": pbk,
                "short_id": sid
            }
        }
    elif security == "tls":
        sni = params.get("sni", [server])[0]
        fp = params.get("fp", ["chrome"])[0]
        insecure = params.get("allowInsecure", params.get("insecure", ["0"]))[0] in ("1", "true", "True")
        outbound["tls"] = {
            "enabled": True,
            "server_name": sni,
            "insecure": insecure,
            "utls": {
                "enabled": True,
                "fingerprint": fp
            }
        }

    alpn_list = _extract_alpn_list(params)
    if alpn_list and "tls" in outbound:
        outbound["tls"]["alpn"] = alpn_list

    return outbound


def parse_hysteria2(uri_str):
    parsed = urllib.parse.urlparse(uri_str)
    password = _extract_userinfo_password(parsed)
    server = parsed.hostname
    if not server or not password:
        raise ValueError(f"无法解析 Hysteria2 节点地址 (缺少有效主机或密码): {uri_str[:40]}...")

    params = urllib.parse.parse_qs(parsed.query)
    port_ranges = []
    try:
        port = parsed.port or 443
    except ValueError:
        host_port = parsed.netloc.rsplit("@", 1)[-1]
        port_spec = host_port.split("]:", 1)[1] if host_port.startswith("[") and "]:" in host_port else (
            host_port.rsplit(":", 1)[1] if ":" in host_port else ""
        )
        first_p, port_ranges = _normalize_port_ranges(port_spec)
        port = first_p or 443

    mport_spec = params.get("mport", params.get("ports", [""]))[0]
    if mport_spec and not port_ranges:
        _, port_ranges = _normalize_port_ranges(mport_spec)

    raw_frag = urllib.parse.unquote(parsed.fragment).strip() if parsed.fragment else ""
    tag = raw_frag or f"hy2-{server}"
    sni = params.get("sni", [server])[0]
    insecure = params.get("insecure", params.get("allowInsecure", ["0"]))[0] in ("1", "true", "True")

    outbound = {
        "type": "hysteria2",
        "tag": tag,
        "server": server,
        "server_port": port,
        "password": password,
        "tls": {
            "enabled": True,
            "server_name": sni,
            "insecure": insecure
        }
    }
    alpn_list = _extract_alpn_list(params)
    if alpn_list:
        outbound["tls"]["alpn"] = alpn_list
    if port_ranges:
        outbound["server_ports"] = port_ranges

    obfs = params.get("obfs", [""])[0]
    if obfs:
        outbound["obfs"] = {
            "type": obfs,
            "password": params.get("obfs-password", [""])[0]
        }

    return outbound


def parse_trojan(uri_str):
    parsed = urllib.parse.urlparse(uri_str)
    password = _extract_userinfo_password(parsed)
    server = parsed.hostname
    if not server or not password:
        raise ValueError(f"无法解析 Trojan 节点地址 (缺少有效主机或密码): {uri_str[:40]}...")
    port = _safe_port(parsed, 443)
    params = urllib.parse.parse_qs(parsed.query)
    raw_frag = urllib.parse.unquote(parsed.fragment).strip() if parsed.fragment else ""
    tag = raw_frag or f"trojan-{server}"
    sni = params.get("sni", [server])[0]
    insecure = params.get("allowInsecure", params.get("insecure", ["0"]))[0] in ("1", "true", "True")
    net_type = params.get("type", ["tcp"])[0].lower()

    outbound = {
        "type": "trojan",
        "tag": tag,
        "server": server,
        "server_port": port,
        "password": password,
        "tls": {
            "enabled": True,
            "server_name": sni,
            "insecure": insecure
        }
    }

    alpn_list = _extract_alpn_list(params)
    if alpn_list:
        outbound["tls"]["alpn"] = alpn_list

    _apply_uri_transport(outbound, net_type, params, allow_udp_network=False)

    return outbound


def parse_shadowsocks(uri_str):
    parsed = urllib.parse.urlparse(uri_str)
    raw_frag = urllib.parse.unquote(parsed.fragment).strip() if parsed.fragment else ""
    tag = raw_frag or "ss-node"

    # 三种形态：
    # 1) ss://method:password@host:port          （明文 userinfo）
    # 2) ss://BASE64(method:password)@host:port  （SIP002，支持百分号编码如 %3D）
    # 3) ss://BASE64(method:password@host:port)  （整体 base64）
    if parsed.password is not None and parsed.username:
        method = urllib.parse.unquote(parsed.username or "")
        password = urllib.parse.unquote(parsed.password)
        server = parsed.hostname
        port = _safe_port(parsed, 8388)
    elif "@" in parsed.netloc:
        encoded_part, host_port = parsed.netloc.rsplit("@", 1)
        decoded = _b64_decode(encoded_part)
        if ":" not in decoded:
            raise ValueError(f"Shadowsocks userinfo 缺少 method:password 分隔符: {uri_str[:40]}...")
        method, password = decoded.split(":", 1)
        server, port = _split_host_port(host_port, default_port=8388)
    else:
        decoded = _b64_decode(parsed.netloc)
        if "#" in decoded:
            decoded, inner_tag = decoded.split("#", 1)
            if not raw_frag and inner_tag.strip():
                tag = urllib.parse.unquote(inner_tag.strip())
        if "?" in decoded:
            decoded = decoded.split("?", 1)[0]
        if "/" in decoded:
            decoded = decoded.split("/", 1)[0]
        if "@" not in decoded:
            raise ValueError(f"无法解析 Shadowsocks 节点地址: {uri_str[:40]}...")
        cred, host_part = decoded.rsplit("@", 1)
        if ":" not in cred:
            raise ValueError(f"Shadowsocks 凭证格式非法: {uri_str[:40]}...")
        method, password = cred.split(":", 1)
        server, port = _split_host_port(host_part, default_port=8388)

    if not server or port is None or not method or not password:
        raise ValueError(f"无法解析 Shadowsocks 节点地址 (缺少主机、端口、加密方式或密码): {uri_str[:40]}...")

    outbound = {
        "type": "shadowsocks",
        "tag": tag,
        "server": server,
        "server_port": port,
        "method": method,
        "password": password
    }
    return outbound


def parse_vmess(uri_str):
    # 部分订阅会在 base64 后追加原生 #节点名 片段；先提取片段作为备用节点名再剥离
    body = uri_str[len("vmess://"):].strip()
    frag_tag = ""
    if "#" in body:
        body, raw_frag = body.split("#", 1)
        frag_tag = urllib.parse.unquote(raw_frag.strip())
    raw_b64 = urllib.parse.unquote(body.strip())
    raw_b64 = re.sub(r"\s+", "", raw_b64)
    if not raw_b64:
        raise ValueError("VMess Base64 内容为空")
    missing_padding = len(raw_b64) % 4
    if missing_padding:
        raw_b64 += '=' * (4 - missing_padding)
    try:
        decoded_bytes = base64.urlsafe_b64decode(raw_b64)
    except Exception as e:
        raise ValueError(f"VMess Base64 解码失败: {e}")

    try:
        try:
            text_json = decoded_bytes.decode('utf-8')
        except UnicodeDecodeError:
            text_json = decoded_bytes.decode('gb18030', errors='ignore')
        data = json.loads(text_json)
    except Exception as e:
        raise ValueError(f"VMess JSON 解码失败: {e}")

    if not isinstance(data, dict):
        raise ValueError(f"VMess 数据格式非法 (非 JSON 对象): {data!r}")

    server = str(data.get("add") or "").strip()
    uuid = str(data.get("id") or "").strip()
    if not server or not uuid:
        raise ValueError(f"VMess 缺少必要字段 (add/id): {data!r}")

    raw_ps = str(data.get("ps") or "").strip()
    tag = raw_ps or frag_tag or f"vmess-{server}"
    try:
        port = int(data.get("port", 443))
    except (ValueError, TypeError):
        port = 443

    try:
        alter_id = int(data.get("aid", 0))
    except (ValueError, TypeError):
        alter_id = 0
    security = str(data.get("scy") or "auto").strip() or "auto"
    net_type = str(data.get("net") or "tcp").strip().lower()
    host = str(data.get("host") or "").strip()
    path = str(data.get("path") or "").strip()
    tls_val = data.get("tls", "")
    tls_enabled = (tls_val is True) or (str(tls_val).strip().lower() in ("tls", "true", "1"))
    sni = str(data.get("sni") or host or server).strip()

    outbound = {
        "type": "vmess",
        "tag": tag,
        "server": server,
        "server_port": port,
        "uuid": uuid,
        "security": security,
        "alter_id": alter_id
    }

    if tls_enabled:
        outbound["tls"] = {
            "enabled": True,
            "server_name": sni
        }
        if str(data.get("allowInsecure", "")).lower() in ("1", "true") or data.get("verify_cert") is False:
            outbound["tls"]["insecure"] = True

    raw_alpn = data.get("alpn")
    if raw_alpn and "tls" in outbound:
        if isinstance(raw_alpn, list):
            alpn_list = [str(x).strip() for x in raw_alpn if str(x).strip()]
        else:
            alpn_list = [x.strip() for x in str(raw_alpn).split(",") if x.strip()]
        if alpn_list:
            outbound["tls"]["alpn"] = alpn_list

    if net_type in ("", "tcp", "none"):
        pass
    elif net_type == "ws":
        outbound["transport"] = {
            "type": "ws",
            "path": path if path else "/"
        }
        if host:
            outbound["transport"]["headers"] = {"Host": host}
    elif net_type == "grpc":
        outbound["transport"] = {
            "type": "grpc",
            "service_name": path
        }
    elif net_type == "httpupgrade":
        outbound["transport"] = {
            "type": "httpupgrade",
            "path": path if path else "/"
        }
        if host:
            outbound["transport"]["host"] = host
    elif net_type in ("http", "h2"):
        outbound["transport"] = {
            "type": "http",
            "path": path if path else "/"
        }
        if host:
            hosts = [h.strip() for h in host.split(",") if h.strip()]
            if hosts:
                outbound["transport"]["host"] = hosts
    else:
        raise ValueError(f"VMess 不支持的传输层类型 (拒绝静默降级为裸 TCP): {net_type!r}")

    return outbound


def parse_tuic(uri_str):
    """解析 TUIC v5 节点 URI: tuic://uuid:password@host:port?congestion_control=bbr&alpn=h3&sni=...#Tag"""
    parsed = urllib.parse.urlparse(uri_str)
    params = urllib.parse.parse_qs(parsed.query)
    uuid = urllib.parse.unquote(parsed.username or "").strip()
    password = urllib.parse.unquote(parsed.password or "").strip()
    if not password and "password" in params:
        password = params.get("password", [""])[0]
    if ":" in uuid and not password:
        uuid, password = uuid.split(":", 1)
    server = parsed.hostname
    if not server or not uuid:
        raise ValueError(f"无法解析 TUIC 节点地址 (缺少有效主机或 UUID): {uri_str[:40]}...")
    port = _safe_port(parsed, 443)
    raw_frag = urllib.parse.unquote(parsed.fragment).strip() if parsed.fragment else ""
    tag = raw_frag or f"tuic-{server}"

    sni = params.get("sni", [server])[0]
    cc = params.get("congestion_control", ["bbr"])[0] or "bbr"
    urm = params.get("udp_relay_mode", ["native"])[0] or "native"
    insecure = params.get("allow_insecure", params.get("allowInsecure", params.get("insecure", ["0"])))[0] in ("1", "true", "True")

    outbound = {
        "type": "tuic",
        "tag": tag,
        "server": server,
        "server_port": port,
        "uuid": uuid,
        "password": password,
        "congestion_control": cc,
        "udp_relay_mode": urm,
        "tls": {
            "enabled": True,
            "server_name": sni,
            "insecure": insecure
        }
    }
    alpn_list = _extract_alpn_list(params)
    if alpn_list:
        outbound["tls"]["alpn"] = alpn_list
    return outbound


def parse_anytls(uri_str):
    """解析 AnyTLS 节点 URI: anytls://password@host:port?sni=...&insecure=0#Tag"""
    parsed = urllib.parse.urlparse(uri_str)
    password = _extract_userinfo_password(parsed)
    server = parsed.hostname
    if not server or not password:
        raise ValueError(f"无法解析 AnyTLS 节点地址 (缺少有效主机或密码): {uri_str[:40]}...")
    port = _safe_port(parsed, 443)
    params = urllib.parse.parse_qs(parsed.query)
    raw_frag = urllib.parse.unquote(parsed.fragment).strip() if parsed.fragment else ""
    tag = raw_frag or f"anytls-{server}"
    sni = params.get("sni", [server])[0]
    insecure = params.get("insecure", params.get("allowInsecure", ["0"]))[0] in ("1", "true", "True")

    outbound = {
        "type": "anytls",
        "tag": tag,
        "server": server,
        "server_port": port,
        "password": password,
        "tls": {
            "enabled": True,
            "server_name": sni,
            "insecure": insecure
        }
    }
    alpn_list = _extract_alpn_list(params)
    if alpn_list:
        outbound["tls"]["alpn"] = alpn_list
    return outbound


def parse_uri(uri_str):
    uri_str = uri_str.strip()
    if uri_str.startswith("vless://"):
        return parse_vless(uri_str)
    elif uri_str.startswith("hysteria2://") or uri_str.startswith("hy2://"):
        return parse_hysteria2(uri_str)
    elif uri_str.startswith("trojan://"):
        return parse_trojan(uri_str)
    elif uri_str.startswith("ss://"):
        return parse_shadowsocks(uri_str)
    elif uri_str.startswith("vmess://"):
        return parse_vmess(uri_str)
    elif uri_str.startswith("tuic://"):
        return parse_tuic(uri_str)
    elif uri_str.startswith("anytls://"):
        return parse_anytls(uri_str)
    else:
        raise ValueError(f"暂不支持或未识别的协议 URI: {uri_str[:15]}...")


def main():
    if len(sys.argv) < 2:
        print("用法: python parse_node.py <节点URI>")
        sys.exit(1)

    uri = sys.argv[1]
    try:
        outbound = parse_uri(uri)
        print(json.dumps(outbound, indent=2, ensure_ascii=False))
    except Exception as e:
        print(f"解析失败: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
