#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
通用机场订阅解析与清洗器 (Subscription Parser & Converter)
支持：
1. HTTP/HTTPS 订阅链接在线拉取 (自适应 User-Agent，超时控制)
2. Base64 编码订阅解码 (标准 Base64、URLSafe Base64，自动补齐 Padding)
3. 多行节点 URI 文本 (vless://, hysteria2://, trojan://, ss://)
4. Clash YAML 订阅文件解析 (提取 proxies 列表并转为 sing-box / dae)
5. 智能过滤与去重 (支持关键字包含/排除，去除机场无用广告节点)
6. 弱路由节点上限保护 (默认截取前 N 个优质节点，防止数百节点撑爆 256MB/512MB 内存)
"""
# [共享脚本] 本文件与 dae-openwrt/scripts/sub_parser.py 完全一致，修改需双份同步！

import os
import sys
import json
import re
import base64
import gzip
import zlib
import urllib.request
import urllib.parse
from typing import List, Dict, Any, Tuple

# 中文 Windows 控制台 (cp936) 无法编码 emoji/部分字符，统一重配为 UTF-8 输出
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# 导入同目录的 parse_node 模块
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from parse_node import parse_uri as parse_node

# 尝试导入 PyYAML 处理 Clash 订阅
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


def safe_b64decode(s: str) -> str:
    """安全解码 Base64 字符串（自动补齐 padding，兼容 urlsafe）"""
    s = s.strip().replace("\r", "").replace("\n", "")
    missing_padding = len(s) % 4
    if missing_padding:
        s += '=' * (4 - missing_padding)
    try:
        # 先试标准 Base64
        return base64.b64decode(s).decode('utf-8', errors='ignore')
    except Exception:
        try:
            # 再试 urlsafe Base64
            return base64.urlsafe_b64decode(s).decode('utf-8', errors='ignore')
        except Exception:
            return ""


def _decompress(content: bytes, encoding: str = "") -> bytes:
    """按 Content-Encoding（或魔数）解压响应体。urllib 不会自动解压 gzip/deflate。"""
    enc = (encoding or "").lower().strip()
    try:
        if enc == "gzip" or (not enc and content[:2] == b"\x1f\x8b"):
            return gzip.decompress(content)
        if enc == "deflate":
            try:
                return zlib.decompress(content)
            except zlib.error:
                return zlib.decompress(content, -zlib.MAX_WBITS)  # raw deflate
    except Exception:
        pass  # 解压失败则退回原始字节，交由下游解码逻辑处理
    return content


def fetch_subscription(url: str, timeout: int = 15) -> str:
    """拉取远程订阅内容"""
    headers = {
        # 使用 clash.meta 或 sing-box 的 User-Agent 触发机场下发完整通用订阅
        "User-Agent": "sing-box/1.14.0 (OpenWrt; Linux x86_64)",
        "Accept": "*/*"
    }
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content = _decompress(resp.read(), resp.headers.get("Content-Encoding", ""))
            # 尝试解码
            try:
                return content.decode('utf-8')
            except UnicodeDecodeError:
                return content.decode('latin-1', errors='ignore')
    except Exception as e:
        raise RuntimeError(f"拉取订阅链接失败: {url} -> {e}")


def parse_clash_proxy(p: Dict[str, Any]) -> Dict[str, Any]:
    """将单个 Clash 节点字典转为 sing-box outbound 结构"""
    if not isinstance(p, dict):
        return {}
    name = str(p.get("name", "node")).strip()
    ptype = str(p.get("type", "")).lower()
    server = str(p.get("server", "")).strip()
    if not server:
        return {}
    try:
        port = int(p.get("port", 443))
    except (ValueError, TypeError):
        port = 443

    if ptype == "ss":
        cipher = str(p.get("cipher", ""))
        password = str(p.get("password", ""))
        return {
            "type": "shadowsocks",
            "tag": name,
            "server": server,
            "server_port": port,
            "method": cipher,
            "password": password
        }

    elif ptype == "trojan":
        password = str(p.get("password", ""))
        sni = str(p.get("sni") or p.get("servername") or server)
        alpn = p.get("alpn")
        network = str(p.get("network", "tcp")).lower()
        ob = {
            "type": "trojan",
            "tag": name,
            "server": server,
            "server_port": port,
            "password": password,
            "tls": {
                "enabled": True,
                "server_name": sni,
                "insecure": bool(p.get("skip-cert-verify", False))
            }
        }
        if alpn and isinstance(alpn, list):
            ob["tls"]["alpn"] = alpn
        if network == "ws":
            ws_opts = p.get("ws-opts", {}) if isinstance(p.get("ws-opts"), dict) else {}
            ob["transport"] = {
                "type": "ws",
                "path": ws_opts.get("path", "/") or "/"
            }
            headers = ws_opts.get("headers", {})
            if isinstance(headers, dict) and "Host" in headers:
                ob["transport"]["headers"] = {"Host": headers["Host"]}
        elif network == "grpc":
            grpc_opts = p.get("grpc-opts", {}) if isinstance(p.get("grpc-opts"), dict) else {}
            ob["transport"] = {
                "type": "grpc",
                "service_name": grpc_opts.get("grpc-service-name", "") or ""
            }
        return ob

    elif ptype in ("hysteria2", "hy2"):
        password = str(p.get("password") or p.get("auth") or "")
        sni = str(p.get("sni") or p.get("servername") or server)
        ob = {
            "type": "hysteria2",
            "tag": name,
            "server": server,
            "server_port": port,
            "password": password,
            "tls": {
                "enabled": True,
                "server_name": sni,
                "insecure": bool(p.get("skip-cert-verify", False))
            }
        }
        if "up" in p:
            ob["up_mbps"] = int(re.sub(r"[^\d]", "", str(p["up"])) or 0)
        if "down" in p:
            ob["down_mbps"] = int(re.sub(r"[^\d]", "", str(p["down"])) or 0)
        if "obfs" in p and p.get("obfs"):
            ob["obfs"] = {
                "type": str(p["obfs"]),
                "password": str(p.get("obfs-password", ""))
            }
        return ob

    elif ptype == "vless":
        uuid = str(p.get("uuid", ""))
        flow = str(p.get("flow", ""))
        network = str(p.get("network", "tcp")).lower()
        tls_enabled = bool(p.get("tls", False))

        ob = {
            "type": "vless",
            "tag": name,
            "server": server,
            "server_port": port,
            "uuid": uuid
        }
        if flow:
            ob["flow"] = flow

        # sing-box 的 vless.network 只接受 tcp/udp；ws/grpc 属于 transport
        if network == "udp":
            ob["network"] = "udp"
        elif network == "ws":
            ws_opts = p.get("ws-opts", {}) if isinstance(p.get("ws-opts"), dict) else {}
            ob["transport"] = {
                "type": "ws",
                "path": ws_opts.get("path", "/") or "/"
            }
            headers = ws_opts.get("headers", {})
            if isinstance(headers, dict) and "Host" in headers:
                ob["transport"]["headers"] = {"Host": headers["Host"]}
        elif network == "grpc":
            grpc_opts = p.get("grpc-opts", {}) if isinstance(p.get("grpc-opts"), dict) else {}
            ob["transport"] = {
                "type": "grpc",
                "service_name": grpc_opts.get("grpc-service-name", "") or ""
            }

        reality_opts = p.get("reality-opts", {})
        if reality_opts:
            # Reality 的 SNI 必须是伪装域名：reality-opts 里常只有 public-key/short-id，
            # 域名多在节点顶层的 servername/sni；回退到 server（IP）会导致握手必失败
            sni = reality_opts.get("server-name") or p.get("servername") or p.get("sni") or server
            ob["tls"] = {
                "enabled": True,
                "server_name": str(sni),
                "reality": {
                    "enabled": True,
                    "public_key": reality_opts.get("public-key", ""),
                    "short_id": reality_opts.get("short-id", "")
                },
                "utls": {
                    "enabled": True,
                    "fingerprint": p.get("client-fingerprint", "chrome")
                }
            }
        elif tls_enabled:
            ob["tls"] = {
                "enabled": True,
                "server_name": str(p.get("servername") or p.get("sni") or server),
                "insecure": bool(p.get("skip-cert-verify", False))
            }

        return ob

    elif ptype == "vmess":
        uuid = str(p.get("uuid", ""))
        # Clash YAML 用 alterId，部分旧配置用 aid，两者都兼容
        alter_id = int(p.get("alterId", p.get("aid", 0)))
        cipher = str(p.get("cipher", "auto"))
        tls_enabled = bool(p.get("tls", False))
        network = str(p.get("network", "tcp"))

        ob = {
            "type": "vmess",
            "tag": name,
            "server": server,
            "server_port": port,
            "uuid": uuid,
            "security": cipher,
            "alter_id": alter_id
        }
        if tls_enabled:
            ob["tls"] = {
                "enabled": True,
                "server_name": str(p.get("servername") or p.get("sni") or server),
                "insecure": bool(p.get("skip-cert-verify", False))
            }
        ws_opts = p.get("ws-opts", {})
        if network == "ws":
            ob["transport"] = {
                "type": "ws",
                "path": ws_opts.get("path", "/") if isinstance(ws_opts, dict) else "/"
            }
            if isinstance(ws_opts, dict) and "headers" in ws_opts and "Host" in ws_opts["headers"]:
                ob["transport"]["headers"] = {"Host": ws_opts["headers"]["Host"]}
        elif network == "grpc":
            grpc_opts = p.get("grpc-opts", {}) if isinstance(p.get("grpc-opts"), dict) else {}
            ob["transport"] = {
                "type": "grpc",
                "service_name": grpc_opts.get("grpc-service-name", "") or ""
            }
        return ob

    return None


def parse_subscription_text(text: str) -> List[Dict[str, Any]]:
    """智能解析订阅纯文本（支持 Base64、Clash YAML、多行 URI）"""
    text = text.strip()
    if not text:
        return []

    # 1. 尝试作为 Clash YAML 解析
    if HAS_YAML and ("proxies:" in text or "Proxy:" in text):
        try:
            data = yaml.safe_load(text)
            if isinstance(data, dict):
                proxies = data.get("proxies") or data.get("Proxy") or []
                if isinstance(proxies, list) and len(proxies) > 0:
                    results = []
                    for p in proxies:
                        if isinstance(p, dict):
                            parsed = parse_clash_proxy(p)
                            if parsed:
                                results.append(parsed)
                    if results:
                        return results
        except Exception:
            pass

    # 2. 尝试作为 Base64 解码
    # 机场典型格式：整个订阅是一大串未换行或每 76 字符换行的 base64
    if not text.startswith("vless://") and not text.startswith("hysteria2://") and not text.startswith("hy2://") and not text.startswith("ss://") and not text.startswith("trojan://") and not text.startswith("vmess://"):
        decoded = safe_b64decode(text)
        if decoded and ("vless://" in decoded or "hy2://" in decoded or "hysteria2://" in decoded or "trojan://" in decoded or "ss://" in decoded or "vmess://" in decoded):
            text = decoded

    # 3. 按行解析单个节点 URI
    results = []
    lines = text.splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        try:
            ob = parse_node(line)
            if ob:
                results.append(ob)
        except Exception:
            continue

    return results


def filter_nodes(nodes: List[Dict[str, Any]], 
                 include_pattern: str = None, 
                 exclude_pattern: str = None,
                 max_nodes: int = 15) -> List[Dict[str, Any]]:
    """清洗、过滤与保护节点列表（防止超量节点冲垮弱路由）"""
    # 默认黑名单关键词（排除流量信息、官网公告、重置提醒等非节点项）
    default_exclude = r"剩余流量|到期时间|官网|更新|说明|重置|群组|发布页|套餐|Traffic|Expire|Website"
    
    clean_nodes = []
    seen_tags = {}

    for node in nodes:
        tag = node.get("tag", "").strip()
        
        # 排除广告信息节点
        if re.search(default_exclude, tag, re.IGNORECASE):
            continue
            
        # 用户自定义包含正则
        if include_pattern and not re.search(include_pattern, tag, re.IGNORECASE):
            continue
            
        # 用户自定义排除正则
        if exclude_pattern and re.search(exclude_pattern, tag, re.IGNORECASE):
            continue

        # 标签规范化与重名处理（' 会破坏 .dae 单引号语法，一并剔除）
        base_tag = re.sub(r"[\s/\\:\*\?\"<>\|']+", '-', tag).strip('-')
        if not base_tag:
            base_tag = f"{node.get('type', 'node')}-{node.get('server', 'unknown')}"
        
        if base_tag in seen_tags:
            seen_tags[base_tag] += 1
            final_tag = f"{base_tag}-{seen_tags[base_tag]}"
        else:
            seen_tags[base_tag] = 1
            final_tag = base_tag

        node["tag"] = final_tag
        clean_nodes.append(node)

    # 弱路由内存安全冗余：截取前 max_nodes 个节点
    if max_nodes and len(clean_nodes) > max_nodes:
        clean_nodes = clean_nodes[:max_nodes]

    return clean_nodes


def _uri_host(server) -> str:
    """IPv6 主机在 URI authority 中必须用方括号包裹（RFC 3986）。"""
    host = str(server).strip()
    if host.startswith("[") and host.endswith("]"):
        return host
    return f"[{host}]" if ":" in host else host


def _bare_host(server) -> str:
    """查询参数（sni 等）中的主机名不带方括号。"""
    return str(server).strip().strip("[]")


def to_dae_nodes(nodes: List[Dict[str, Any]]) -> str:
    """将节点导出为 dae node { ... } 语法块。

    dae 使用单引号包裹字符串，因此 tag 与 URI 中的单引号必须先清洗。
    VMess 仅支持 v2rayN 风格 base64(JSON) URI。
    """
    lines = ["node {"]
    for n in nodes:
        raw_tag = n.get("tag", "node")
        tag = re.sub(r"[\s/\\:\*\?\"<>\|']+", '-', str(raw_tag)).strip('-') or "node"
        ntype = n.get("type")
        server = n.get("server")
        port = n.get("server_port")
        if not server or not port:
            continue
        frag = urllib.parse.quote(tag)
        host = _uri_host(server)   # authority 部分：IPv6 必须 [v6]

        if ntype == "hysteria2":
            pw = n.get("password", "")
            tls = n.get("tls", {})
            sni = _bare_host(tls.get("server_name", server))
            insecure = "&insecure=1" if tls.get("insecure") else ""
            obfs = n.get("obfs", {})
            obfs_part = ""
            if obfs and obfs.get("type"):
                obfs_part = f"&obfs={obfs.get('type')}&obfs-password={urllib.parse.quote(str(obfs.get('password', '')))}"
            lines.append(f"  '{tag}': 'hysteria2://{pw}@{host}:{port}?sni={sni}{insecure}{obfs_part}#{frag}'")
        elif ntype == "vless":
            uuid = n.get("uuid", "")
            flow = n.get("flow", "")
            tls = n.get("tls", {})
            flow_part = f"&flow={flow}" if flow else ""
            if tls.get("reality", {}).get("enabled"):
                pbk = tls["reality"].get("public_key", "")
                sid = tls["reality"].get("short_id", "")
                sni = _bare_host(tls.get("server_name", server))
                fp = tls.get("utls", {}).get("fingerprint", "chrome")
                lines.append(f"  '{tag}': 'vless://{uuid}@{host}:{port}?security=reality&sni={sni}&pbk={pbk}&sid={sid}&fp={fp}{flow_part}#{frag}'")
            else:
                sni = _bare_host(tls.get("server_name", server))
                fp = tls.get("utls", {}).get("fingerprint", "chrome")
                insecure = "&allowInsecure=1" if tls.get("insecure") else ""
                lines.append(f"  '{tag}': 'vless://{uuid}@{host}:{port}?security=tls&sni={sni}&fp={fp}{insecure}{flow_part}#{frag}'")
        elif ntype == "trojan":
            pw = n.get("password", "")
            tls = n.get("tls", {})
            sni = _bare_host(tls.get("server_name", server))
            insecure = "&allowInsecure=1" if tls.get("insecure") else ""
            lines.append(f"  '{tag}': 'trojan://{pw}@{host}:{port}?sni={sni}{insecure}#{frag}'")
        elif ntype == "shadowsocks":
            method = n.get("method", "")
            pw = n.get("password", "")
            userpass = base64.b64encode(f"{method}:{pw}".encode()).decode()
            lines.append(f"  '{tag}': 'ss://{userpass}@{host}:{port}#{frag}'")
        elif ntype == "vmess":
            uuid = n.get("uuid", "")
            security = n.get("security", "auto")
            alter_id = int(n.get("alter_id", 0))
            tls = n.get("tls", {})
            transport = n.get("transport", {})
            net_type = transport.get("type", "tcp")
            # gRPC 的服务名存在 service_name；v2rayN 格式用 path 承载 serviceName
            path = transport.get("path") or transport.get("service_name") or ""
            host = ""
            headers = transport.get("headers", {})
            if isinstance(headers, dict):
                host = headers.get("Host", "")
                if isinstance(host, (list, tuple)):
                    host = host[0] if host else ""
            vm = {
                "v": "2",
                "ps": tag,
                "add": server,
                "port": str(port),
                "id": uuid,
                "aid": str(alter_id),
                "scy": security,
                "net": net_type,
                "type": "none" if net_type == "tcp" else net_type,
                "host": host,
                "path": path,
                "tls": "tls" if tls.get("enabled") else "",
                "sni": tls.get("server_name", server) if tls.get("enabled") else ""
            }
            b64 = base64.b64encode(json.dumps(vm, ensure_ascii=False).encode()).decode()
            lines.append(f"  '{tag}': 'vmess://{b64}'")

    lines.append("}")
    return "\n".join(lines)


def extract_node_domains(nodes: List[Dict[str, Any]]) -> List[str]:
    """提取出站节点中所有使用域名的服务器地址（排除纯 IPv4 和 IPv6），用于 DNS 防死锁直连白名单"""
    domains = set()
    ipv4_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    for n in nodes:
        server = n.get("server", "").strip()
        if not server:
            continue
        if ipv4_pattern.match(server) or ":" in server or server.startswith("["):
            continue
        domains.add(server)
    return sorted(list(domains))


def parse_source(source: str, 
                 include: str = None, 
                 exclude: str = None, 
                 max_nodes: int = 15) -> List[Dict[str, Any]]:
    """统一入口：自动识别 URL、本地文件或纯文本并完成解析过滤"""
    content = ""
    source = source.strip()
    if source.startswith("http://") or source.startswith("https://"):
        content = fetch_subscription(source)
    elif os.path.isfile(source):
        with open(source, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    else:
        content = source

    raw_nodes = parse_subscription_text(content)
    clean_nodes = filter_nodes(raw_nodes, include_pattern=include, exclude_pattern=exclude, max_nodes=max_nodes)
    return clean_nodes


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="通用机场订阅解析与清洗工具 (支持 URL/文件/Base64/Clash)")
    parser.add_argument("source", help="订阅来源 (HTTP链接、本地文件路径或Base64/节点文本)")
    parser.add_argument("--include", help="仅保留包含此正则的节点 (如 '香港|日本|HK')")
    parser.add_argument("--exclude", help="排除包含此正则的节点")
    parser.add_argument("--max", type=int, default=15, help="最多保留节点数 (默认 15，防低配路由器 OOM)")
    parser.add_argument("--format", choices=["json", "dae", "tags", "domains"], default="json", help="输出格式 (默认 json)")

    args = parser.parse_args()

    try:
        nodes = parse_source(args.source, include=args.include, exclude=args.exclude, max_nodes=args.max)
        if not nodes:
            print("[!] 未解析到任何有效节点，请检查订阅源或过滤条件", file=sys.stderr)
            sys.exit(1)

        if args.format == "json":
            print(json.dumps(nodes, indent=2, ensure_ascii=False))
        elif args.format == "dae":
            print(to_dae_nodes(nodes))
        elif args.format == "tags":
            for n in nodes:
                print(f"[{n.get('type')}] {n.get('tag')} -> {n.get('server')}:{n.get('server_port')}")
        elif args.format == "domains":
            for d in extract_node_domains(nodes):
                print(d)

        print(f"[+] 成功解析并清洗得到 {len(nodes)} 个优质节点", file=sys.stderr)
    except Exception as e:
        print(f"[-] 解析失败: {e}", file=sys.stderr)
        sys.exit(1)
