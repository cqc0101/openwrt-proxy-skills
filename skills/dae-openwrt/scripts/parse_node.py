#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
节点 URI 解析与 sing-box outbound 转换器
支持协议：VLESS (Reality/WS/gRPC), Hysteria 2, Trojan, Shadowsocks, VMess
注意：sing-box 的 vless/vmess/trojan outbound 中 `network` 字段只接受 "tcp"/"udp"；
      ws / grpc / h2 等传输层必须写入 `transport` 块。
"""
# [共享脚本] 本文件与 singbox-openwrt/scripts/parse_node.py 完全一致，修改需双份同步！

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
    """Base64 解码：自动补 padding，同时接受标准与 urlsafe 字母表。

    注意不能先 b64decode(validate=False)：它会静默丢弃 '-'/'_' 而不是报错，
    导致 urlsafe 字符串被解出错误字节。
    """
    s = s.strip()
    s += '=' * (-len(s) % 4)
    raw = base64.urlsafe_b64decode(s)
    return raw.decode('utf-8')


def _split_host_port(host_port: str):
    """拆分 'host:port'（IPv6 形如 '[v6]:port'），返回 (server, port)。

    必须从右侧切分：IPv6 地址含多个冒号，从左切会把地址切碎。
    """
    server, port_str = host_port.rsplit(":", 1)
    server = urllib.parse.unquote(server).strip("[]")
    if not server:
        raise ValueError(f"无法解析主机地址: {host_port!r}")
    port = int(port_str)
    return server, port


def _build_ws_transport(params, default_host=""):
    """由 URI 参数构建 ws transport 块；不存在 ws 参数时返回 None。"""
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
    """由 URI 参数构建 grpc transport 块；不存在 grpc 参数时返回 None。"""
    service = params.get("serviceName", params.get("servicename", [""]))[0]
    return {
        "type": "grpc",
        "service_name": service or ""
    }


def parse_vless(uri_str):
    parsed = urllib.parse.urlparse(uri_str)
    uuid = urllib.parse.unquote(parsed.username or "")
    server = parsed.hostname
    port = parsed.port or 443
    params = urllib.parse.parse_qs(parsed.query)
    tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else f"vless-{server}"

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

    # `network` 只接受 tcp/udp；ws/grpc/h2/http 属于 transport
    if net_type in ("tcp", "udp"):
        if net_type == "udp":
            outbound["network"] = "udp"
    elif net_type == "ws":
        outbound["transport"] = _build_ws_transport(params)
    elif net_type == "grpc":
        outbound["transport"] = _build_grpc_transport(params)

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

    return outbound


def parse_hysteria2(uri_str):
    parsed = urllib.parse.urlparse(uri_str)
    password = urllib.parse.unquote(parsed.username or parsed.password or "")
    server = parsed.hostname
    port = parsed.port or 443
    params = urllib.parse.parse_qs(parsed.query)
    tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else f"hy2-{server}"
    sni = params.get("sni", [server])[0]
    insecure = params.get("insecure", ["0"])[0] in ["1", "true", "True"]

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

    obfs = params.get("obfs", [""])[0]
    if obfs:
        outbound["obfs"] = {
            "type": obfs,
            "password": params.get("obfs-password", [""])[0]
        }

    return outbound


def parse_trojan(uri_str):
    parsed = urllib.parse.urlparse(uri_str)
    password = urllib.parse.unquote(parsed.username or "")
    server = parsed.hostname
    port = parsed.port or 443
    params = urllib.parse.parse_qs(parsed.query)
    tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else f"trojan-{server}"
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

    if net_type == "ws":
        outbound["transport"] = _build_ws_transport(params)
    elif net_type == "grpc":
        outbound["transport"] = _build_grpc_transport(params)

    return outbound


def parse_shadowsocks(uri_str):
    parsed = urllib.parse.urlparse(uri_str)
    tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else "ss-node"

    # 三种形态：
    # 1) ss://method:password@host:port          （明文 userinfo）
    # 2) ss://BASE64(method:password)@host:port  （SIP002，IPv6 需带方括号）
    # 3) ss://BASE64(method:password@host:port)  （整体 base64）
    if parsed.password:
        method = urllib.parse.unquote(parsed.username or "")
        password = urllib.parse.unquote(parsed.password)
        server = parsed.hostname
        port = parsed.port
    elif "@" in parsed.netloc:
        encoded_part, host_port = parsed.netloc.rsplit("@", 1)
        decoded = _b64_decode(encoded_part)
        method, password = decoded.split(":", 1)
        server, port = _split_host_port(host_port)
    else:
        decoded = _b64_decode(parsed.netloc)
        cred, host_part = decoded.rsplit("@", 1)
        method, password = cred.split(":", 1)
        server, port = _split_host_port(host_part)

    if not server or port is None:
        raise ValueError(f"无法解析 Shadowsocks 节点地址: {uri_str[:40]}...")

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
    raw_b64 = uri_str[len("vmess://"):].strip()
    missing_padding = len(raw_b64) % 4
    if missing_padding:
        raw_b64 += '=' * (4 - missing_padding)
    # urlsafe_b64decode 同时接受标准与 urlsafe 字母表
    decoded_bytes = base64.urlsafe_b64decode(raw_b64)
    data = json.loads(decoded_bytes.decode('utf-8', errors='ignore'))

    tag = data.get("ps", f"vmess-{data.get('add')}")
    server = data.get("add")
    port = int(data.get("port", 443))
    uuid = data.get("id")
    alter_id = int(data.get("aid", 0))
    security = data.get("scy", "auto") or "auto"
    net_type = data.get("net", "tcp")
    host = data.get("host", "")
    path = data.get("path", "")
    tls = data.get("tls", "")
    sni = data.get("sni", host or server)

    outbound = {
        "type": "vmess",
        "tag": tag,
        "server": server,
        "server_port": port,
        "uuid": uuid,
        "security": security,
        "alter_id": alter_id
    }

    if tls == "tls":
        outbound["tls"] = {
            "enabled": True,
            "server_name": sni
        }

    if net_type == "ws":
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
