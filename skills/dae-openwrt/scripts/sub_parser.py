#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
通用机场订阅解析与清洗器 (Subscription Parser & Converter)
支持：
1. HTTP/HTTPS 订阅链接在线拉取 (自适应 User-Agent，超时与流大小上限保护)
2. Base64 编码订阅解码 (标准 Base64、URLSafe Base64，自动补齐 Padding，兼容 UTF-8/GB18030)
3. 多行节点 URI 文本 (vless://, hysteria2://, trojan://, ss://, vmess://)
4. Clash YAML 订阅文件解析 (提取 proxies 列表并转为 sing-box / dae，单节点异常隔离)
5. 智能过滤与去重 (支持关键字包含/排除，去除机场无用广告节点，全局唯一标签防碰撞)
6. 弱路由节点上限保护 (默认截取前 N 个优质节点，防止数百节点撑爆 256MB/512MB 内存)
"""
# [共享脚本] 本文件与 singbox-openwrt/scripts/sub_parser.py 完全一致，修改需双份同步！

import os
import sys
import json
import re
import base64
import ipaddress
import zlib
import urllib.request
import urllib.parse
from typing import List, Dict, Any

# 单次订阅响应与解压最大字节上限 (10 MiB)，防止 Gzip 炸弹撑爆弱路由内存
MAX_SUB_BYTES = 10 * 1024 * 1024

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

from parse_node import parse_uri as parse_node, _normalize_port_ranges

# 尝试导入 PyYAML 处理 Clash 订阅
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


def safe_b64decode(s: str) -> str:
    """安全解码 Base64 字符串（同时兼容标准与 urlsafe 字母表，支持 UTF-8 与 GB18030）"""
    s = re.sub(r"\s+", "", s or "")
    if not s:
        return ""
    missing_padding = len(s) % 4
    if missing_padding:
        s += '=' * (4 - missing_padding)
    try:
        raw = base64.urlsafe_b64decode(s)
    except Exception:
        try:
            raw = base64.b64decode(s)
        except Exception:
            return ""
    try:
        return raw.decode('utf-8')
    except UnicodeDecodeError:
        try:
            return raw.decode('gb18030')
        except UnicodeDecodeError:
            return raw.decode('utf-8', errors='ignore')


def _decompress(content: bytes, encoding: str = "", max_bytes: int = MAX_SUB_BYTES) -> bytes:
    """按 Content-Encoding（或魔数）安全流式解压响应体，限制最大解压体积防 Gzip Bomb。"""
    enc = (encoding or "").lower().strip()
    try:
        if enc == "gzip" or (not enc and content[:2] == b"\x1f\x8b"):
            dobj = zlib.decompressobj(16 + zlib.MAX_WBITS)
            out = dobj.decompress(content, max_bytes + 1)
            if len(out) > max_bytes:
                raise ValueError(f"订阅解压后体积超过安全上限 ({max_bytes} bytes)")
            return out
        if enc == "deflate":
            try:
                dobj = zlib.decompressobj(zlib.MAX_WBITS)
                out = dobj.decompress(content, max_bytes + 1)
            except zlib.error:
                dobj = zlib.decompressobj(-zlib.MAX_WBITS)
                out = dobj.decompress(content, max_bytes + 1)
            if len(out) > max_bytes:
                raise ValueError(f"订阅解压后体积超过安全上限 ({max_bytes} bytes)")
            return out
    except ValueError:
        raise
    except Exception:
        pass  # 非压缩数据或解压失败则退回原始字节，交由下游解码逻辑处理
    return content


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """仅允许重定向至 http/https 协议，阻断 file:// 等危险协议跳转。"""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlparse(newurl)
        if parsed.scheme.lower() not in ("http", "https"):
            raise urllib.error.URLError(f"拒绝不安全的重定向协议: {parsed.scheme}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_subscription(url: str, timeout: int = 15) -> str:
    """拉取远程订阅内容（带体积上限与安全重定向保护）"""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError(f"仅支持 HTTP/HTTPS 订阅链接: {url}")
    headers = {
        # 使用 clash.meta 或 sing-box 的 User-Agent 触发机场下发完整通用订阅
        "User-Agent": "sing-box/1.14.0 (OpenWrt; Linux x86_64)",
        "Accept": "*/*"
    }
    req = urllib.request.Request(url, headers=headers)
    opener = urllib.request.build_opener(_SafeRedirectHandler)
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw_bytes = resp.read(MAX_SUB_BYTES + 1)
            if len(raw_bytes) > MAX_SUB_BYTES:
                raise RuntimeError(f"订阅响应体积超过安全上限 ({MAX_SUB_BYTES} bytes)")
            content = _decompress(raw_bytes, resp.headers.get("Content-Encoding", ""))
            try:
                return content.decode('utf-8')
            except UnicodeDecodeError:
                try:
                    return content.decode('gb18030')
                except UnicodeDecodeError:
                    return content.decode('latin-1', errors='ignore')
    except Exception as e:
        raise RuntimeError(f"拉取订阅链接失败: {url} -> {e}")


def _apply_clash_alpn(tls_obj: Dict[str, Any], p: Dict[str, Any]):
    alpn = p.get("alpn")
    if not alpn:
        return
    if isinstance(alpn, list):
        cleaned = [str(x).strip() for x in alpn if str(x).strip()]
    else:
        cleaned = [x.strip() for x in str(alpn).split(",") if x.strip()]
    if cleaned:
        tls_obj["alpn"] = cleaned


def _apply_clash_smux(ob: Dict[str, Any], p: Dict[str, Any]):
    smux = p.get("smux")
    if isinstance(smux, dict) and smux.get("enabled") is True:
        proto = str(smux.get("protocol") or "smux").strip() or "smux"
        ob["multiplex"] = {"enabled": True, "protocol": proto}


def _apply_clash_transport(ob: Dict[str, Any], p: Dict[str, Any], allow_udp: bool = False) -> bool:
    """映射 Clash network/transport 字段。若遇到不支持的传输层返回 False（拒绝静默退化为裸 TCP）。"""
    network = str(p.get("network") or "tcp").strip().lower()
    if network in ("", "tcp", "none"):
        return True
    if network == "udp" and allow_udp:
        ob["network"] = "udp"
        return True
    if network == "ws":
        ws_opts = p.get("ws-opts") if isinstance(p.get("ws-opts"), dict) else {}
        ob["transport"] = {
            "type": "ws",
            "path": ws_opts.get("path", "/") or "/"
        }
        headers = ws_opts.get("headers") if isinstance(ws_opts.get("headers"), dict) else {}
        if "Host" in headers and headers["Host"] is not None:
            ob["transport"]["headers"] = {"Host": headers["Host"]}
        return True
    if network == "grpc":
        grpc_opts = p.get("grpc-opts") if isinstance(p.get("grpc-opts"), dict) else {}
        ob["transport"] = {
            "type": "grpc",
            "service_name": grpc_opts.get("grpc-service-name", "") or ""
        }
        return True
    if network == "httpupgrade":
        hu_opts = p.get("httpupgrade-opts") if isinstance(p.get("httpupgrade-opts"), dict) else (
            p.get("ws-opts") if isinstance(p.get("ws-opts"), dict) else {}
        )
        ob["transport"] = {
            "type": "httpupgrade",
            "path": hu_opts.get("path", "/") or "/"
        }
        host = hu_opts.get("host")
        if not host and isinstance(hu_opts.get("headers"), dict):
            host = hu_opts["headers"].get("Host")
        if host:
            ob["transport"]["host"] = str(host)
        return True
    if network in ("http", "h2"):
        h2_opts = p.get("h2-opts") if isinstance(p.get("h2-opts"), dict) else (
            p.get("http-opts") if isinstance(p.get("http-opts"), dict) else {}
        )
        raw_path = h2_opts.get("path", "/")
        if isinstance(raw_path, list):
            path_val = str(raw_path[0]) if raw_path else "/"
        else:
            path_val = str(raw_path or "/")
        ob["transport"] = {
            "type": "http",
            "path": path_val or "/"
        }
        raw_host = h2_opts.get("host")
        if raw_host:
            hosts = [str(x).strip() for x in (raw_host if isinstance(raw_host, list) else [raw_host]) if str(x).strip()]
            if hosts:
                ob["transport"]["host"] = hosts
        return True
    return False


def parse_clash_proxy(p: Dict[str, Any]) -> Dict[str, Any]:
    """将单个 Clash 节点字典转为 sing-box outbound 结构"""
    if not isinstance(p, dict):
        return {}
    name = str(p.get("name") or "node").strip() or "node"
    ptype = str(p.get("type") or "").lower().strip()
    server = str(p.get("server") or "").strip()
    if not server:
        return {}
    try:
        port = int(p.get("port") if p.get("port") is not None else 443)
    except (ValueError, TypeError):
        port = 443

    if ptype == "ss":
        cipher = str(p.get("cipher") or "")
        password = str(p.get("password") or "")
        ob = {
            "type": "shadowsocks",
            "tag": name,
            "server": server,
            "server_port": port,
            "method": cipher,
            "password": password
        }
        _apply_clash_smux(ob, p)
        return ob

    elif ptype == "trojan":
        password = str(p.get("password") or "")
        sni = str(p.get("sni") or p.get("servername") or server)
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
        _apply_clash_alpn(ob["tls"], p)
        if not _apply_clash_transport(ob, p, allow_udp=False):
            return {}
        _apply_clash_smux(ob, p)
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
        _apply_clash_alpn(ob["tls"], p)
        ports_spec = p.get("ports") or p.get("mport")
        if ports_spec:
            _, port_ranges = _normalize_port_ranges(str(ports_spec))
            if port_ranges:
                ob["server_ports"] = port_ranges
        if p.get("up") is not None:
            ob["up_mbps"] = int(re.sub(r"[^\d]", "", str(p["up"])) or 0)
        if p.get("down") is not None:
            ob["down_mbps"] = int(re.sub(r"[^\d]", "", str(p["down"])) or 0)
        if p.get("obfs"):
            ob["obfs"] = {
                "type": str(p["obfs"]),
                "password": str(p.get("obfs-password") or "")
            }
        return ob

    elif ptype == "vless":
        uuid = str(p.get("uuid") or "")
        flow = str(p.get("flow") or "")
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

        if not _apply_clash_transport(ob, p, allow_udp=True):
            return {}

        reality_opts = p.get("reality-opts") if isinstance(p.get("reality-opts"), dict) else {}
        if reality_opts:
            sni = reality_opts.get("server-name") or p.get("servername") or p.get("sni") or server
            ob["tls"] = {
                "enabled": True,
                "server_name": str(sni),
                "reality": {
                    "enabled": True,
                    "public_key": str(reality_opts.get("public-key") or ""),
                    "short_id": str(reality_opts.get("short-id") or "")
                },
                "utls": {
                    "enabled": True,
                    "fingerprint": str(p.get("client-fingerprint") or "chrome")
                }
            }
            _apply_clash_alpn(ob["tls"], p)
        elif tls_enabled:
            ob["tls"] = {
                "enabled": True,
                "server_name": str(p.get("servername") or p.get("sni") or server),
                "insecure": bool(p.get("skip-cert-verify", False))
            }
            _apply_clash_alpn(ob["tls"], p)

        _apply_clash_smux(ob, p)
        return ob

    elif ptype == "vmess":
        uuid = str(p.get("uuid") or "")
        raw_aid = p.get("alterId") if p.get("alterId") is not None else p.get("aid", 0)
        try:
            alter_id = int(raw_aid if raw_aid is not None else 0)
        except (ValueError, TypeError):
            alter_id = 0
        cipher = str(p.get("cipher") or "auto")
        tls_enabled = bool(p.get("tls", False))

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
            _apply_clash_alpn(ob["tls"], p)
        if not _apply_clash_transport(ob, p, allow_udp=False):
            return {}
        _apply_clash_smux(ob, p)
        return ob

    elif ptype == "tuic":
        uuid = str(p.get("uuid") or "").strip()
        password = str(p.get("password") or "").strip()
        if not uuid:
            return {}
        sni = str(p.get("sni") or p.get("servername") or server)
        cc = str(p.get("congestion-controller") or p.get("congestion_control") or "bbr")
        urm = str(p.get("udp-relay-mode") or p.get("udp_relay_mode") or "native")
        ob = {
            "type": "tuic",
            "tag": name,
            "server": server,
            "server_port": port,
            "uuid": uuid,
            "password": password,
            "congestion_control": cc,
            "udp_relay_mode": urm,
            "tls": {
                "enabled": True,
                "server_name": sni,
                "insecure": bool(p.get("skip-cert-verify", False))
            }
        }
        _apply_clash_alpn(ob["tls"], p)
        return ob

    elif ptype == "anytls":
        password = str(p.get("password") or "").strip()
        if not password:
            return {}
        sni = str(p.get("sni") or p.get("servername") or server)
        ob = {
            "type": "anytls",
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
        _apply_clash_alpn(ob["tls"], p)
        _apply_clash_smux(ob, p)
        return ob

    return {}


def parse_subscription_text(text: str) -> List[Dict[str, Any]]:
    """智能解析订阅纯文本（支持 Base64、Clash YAML、多行 URI）"""
    text = text.strip()
    if not text:
        return []

    # 1. 尝试作为 Clash YAML 解析（单节点隔离容错，防止单颗坏节点冲毁整份订阅）
    if "proxies:" in text or "Proxy:" in text:
        if HAS_YAML:
            try:
                data = yaml.safe_load(text)
                if isinstance(data, dict):
                    proxies = data.get("proxies") or data.get("Proxy") or []
                    if isinstance(proxies, list) and len(proxies) > 0:
                        results = []
                        for p in proxies:
                            if isinstance(p, dict):
                                try:
                                    parsed = parse_clash_proxy(p)
                                    if parsed:
                                        results.append(parsed)
                                except Exception:
                                    continue
                        if results:
                            return results
            except Exception:
                pass
        else:
            print("[!] 检测到 Clash YAML 订阅格式，但当前环境未安装 PyYAML，建议安装 PyYAML 或改用通用 Base64/URI 订阅。", file=sys.stderr)

    # 2. 尝试作为 Base64 解码
    # 机场典型格式：整个订阅是一大串未换行或每 76 字符换行的 base64
    if not text.startswith(("vless://", "hysteria2://", "hy2://", "ss://", "trojan://", "vmess://", "tuic://", "anytls://")):
        decoded = safe_b64decode(text)
        if decoded and any(proto in decoded for proto in ("vless://", "hy2://", "hysteria2://", "trojan://", "ss://", "vmess://", "tuic://", "anytls://")):
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
    """清洗、过滤与保护节点列表（防止超量节点冲垮弱路由，确保生成的标签全局唯一无碰撞）"""
    # 默认黑名单关键词（排除流量信息、官网公告、重置提醒等非节点项）
    default_exclude = r"剩余流量|到期时间|官网|更新|说明|重置|群组|发布页|套餐|Traffic|Expire|Website"
    
    clean_nodes = []
    seen_tags = {}
    used_tags = set()

    for node in nodes:
        tag = str(node.get("tag") or "").strip()
        
        # 排除广告信息节点
        if re.search(default_exclude, tag, re.IGNORECASE):
            continue
            
        # 用户自定义包含正则
        if include_pattern and not re.search(include_pattern, tag, re.IGNORECASE):
            continue
            
        # 用户自定义排除正则
        if exclude_pattern and re.search(exclude_pattern, tag, re.IGNORECASE):
            continue

        # 标签规范化与重名防碰撞处理（' 会破坏 .dae 单引号语法，一并剔除）
        base_tag = re.sub(r"[\s/\\:\*\?\"<>\|']+", '-', tag).strip('-')
        if not base_tag:
            base_tag = f"{node.get('type', 'node')}-{node.get('server', 'unknown')}"
        
        count = seen_tags.get(base_tag, 0) + 1
        seen_tags[base_tag] = count
        final_tag = base_tag if count == 1 else f"{base_tag}-{count}"
        while final_tag in used_tags:
            count += 1
            seen_tags[base_tag] = count
            final_tag = f"{base_tag}-{count}"

        used_tags.add(final_tag)
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


def _q(val: Any, safe: str = "") -> str:
    """将密码或查询参数按 RFC 3986 进行百分号编码，防止 #/@/?/&/' 截断 URI。"""
    return urllib.parse.quote(str(val if val is not None else ""), safe=safe).replace("'", "%27")


def _dae_transport_query(n: Dict[str, Any]) -> str:
    """提取 sing-box outbound 的 transport 块并编码为 URI 查询参数（支持 ws / grpc）。"""
    transport = n.get("transport")
    if not isinstance(transport, dict):
        return ""
    ttype = transport.get("type", "").lower()
    if ttype == "ws":
        path = _q(transport.get("path") or "/", safe="/")
        q = f"&type=ws&path={path}"
        headers = transport.get("headers")
        if isinstance(headers, dict) and headers.get("Host"):
            hval = headers["Host"]
            if isinstance(hval, (list, tuple)):
                hval = hval[0] if hval else ""
            if hval:
                q += f"&host={_q(hval)}"
        return q
    elif ttype == "grpc":
        svc = _q(transport.get("service_name") or "")
        return f"&type=grpc&serviceName={svc}"
    elif ttype == "httpupgrade":
        path = _q(transport.get("path") or "/", safe="/")
        q = f"&type=httpupgrade&path={path}"
        host = transport.get("host")
        if host:
            q += f"&host={_q(host)}"
        return q
    elif ttype in ("http", "h2"):
        path = _q(transport.get("path") or "/", safe="/")
        q = f"&type=http&path={path}"
        host = transport.get("host")
        if isinstance(host, (list, tuple)):
            host = host[0] if host else ""
        if host:
            q += f"&host={_q(host)}"
        return q
    return ""


def to_dae_nodes(nodes: List[Dict[str, Any]]) -> str:
    """将节点导出为 dae node { ... } 语法块。

    dae 使用单引号包裹字符串，因此 tag 与 URI 中的单引号及特殊保留字符必须先转义。
    VMess 仅支持 v2rayN 风格 base64(JSON) URI。
    """
    lines = ["node {"]
    used_tags = set()
    tag_counts = {}

    for n in nodes:
        raw_tag = n.get("tag", "node")
        base_tag = re.sub(r"[\s/\\:\*\?\"<>\|']+", '-', str(raw_tag)).strip('-') or "node"
        cnt = tag_counts.get(base_tag, 0) + 1
        tag_counts[base_tag] = cnt
        tag = base_tag if cnt == 1 else f"{base_tag}-{cnt}"
        while tag in used_tags:
            cnt += 1
            tag_counts[base_tag] = cnt
            tag = f"{base_tag}-{cnt}"
        used_tags.add(tag)

        ntype = n.get("type")
        server = n.get("server")
        port = n.get("server_port")
        if not server or not port:
            continue
        frag = _q(tag)
        host = _uri_host(server)   # authority 部分：IPv6 必须 [v6]
        trans_part = _dae_transport_query(n)

        raw_uri = ""
        if ntype == "hysteria2":
            pw = _q(n.get("password", ""), safe=":")
            tls = n.get("tls", {})
            sni = _q(_bare_host(tls.get("server_name") or server), safe=".:-")
            insecure = "&insecure=1" if tls.get("insecure") else ""
            obfs = n.get("obfs", {})
            obfs_part = ""
            if obfs and obfs.get("type"):
                obfs_part = f"&obfs={_q(obfs.get('type'))}&obfs-password={_q(obfs.get('password', ''))}"
            raw_uri = f"hysteria2://{pw}@{host}:{port}?sni={sni}{insecure}{obfs_part}#{frag}"
        elif ntype == "vless":
            uuid = _q(n.get("uuid", ""))
            flow = _q(n.get("flow", ""))
            tls = n.get("tls", {})
            flow_part = f"&flow={flow}" if flow else ""
            if tls.get("reality", {}).get("enabled"):
                pbk = _q(tls["reality"].get("public_key", ""))
                sid = _q(tls["reality"].get("short_id", ""))
                sni = _q(_bare_host(tls.get("server_name") or server), safe=".:-")
                fp = _q(tls.get("utls", {}).get("fingerprint", "chrome"))
                raw_uri = f"vless://{uuid}@{host}:{port}?security=reality&sni={sni}&pbk={pbk}&sid={sid}&fp={fp}{flow_part}{trans_part}#{frag}"
            elif tls.get("enabled"):
                sni = _q(_bare_host(tls.get("server_name") or server), safe=".:-")
                fp = _q(tls.get("utls", {}).get("fingerprint", "chrome"))
                insecure = "&allowInsecure=1" if tls.get("insecure") else ""
                raw_uri = f"vless://{uuid}@{host}:{port}?security=tls&sni={sni}&fp={fp}{insecure}{flow_part}{trans_part}#{frag}"
            else:
                raw_uri = f"vless://{uuid}@{host}:{port}?security=none{flow_part}{trans_part}#{frag}"
        elif ntype == "trojan":
            pw = _q(n.get("password", ""))
            tls = n.get("tls", {})
            sni = _q(_bare_host(tls.get("server_name") or server), safe=".:-")
            insecure = "&allowInsecure=1" if tls.get("insecure") else ""
            raw_uri = f"trojan://{pw}@{host}:{port}?sni={sni}{insecure}{trans_part}#{frag}"
        elif ntype == "shadowsocks":
            method = n.get("method", "")
            pw = n.get("password", "")
            userpass = base64.b64encode(f"{method}:{pw}".encode()).decode()
            raw_uri = f"ss://{userpass}@{host}:{port}#{frag}"
        elif ntype == "vmess":
            uuid = n.get("uuid", "")
            security = n.get("security", "auto")
            alter_id = int(n.get("alter_id", 0))
            tls = n.get("tls", {})
            transport = n.get("transport", {})
            net_type = transport.get("type", "tcp")
            # gRPC 的服务名存在 service_name；v2rayN 格式用 path 承载 serviceName
            path = transport.get("path") or transport.get("service_name") or ""
            ws_host = ""
            headers = transport.get("headers", {})
            if isinstance(headers, dict):
                ws_host = headers.get("Host", "")
                if isinstance(ws_host, (list, tuple)):
                    ws_host = ws_host[0] if ws_host else ""
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
                "host": ws_host,
                "path": path,
                "tls": "tls" if tls.get("enabled") else "",
                "sni": (tls.get("server_name") or server) if tls.get("enabled") else ""
            }
            b64 = base64.b64encode(json.dumps(vm, ensure_ascii=False).encode()).decode()
            raw_uri = f"vmess://{b64}"
        elif ntype == "tuic":
            uuid = _q(n.get("uuid", ""))
            pw = _q(n.get("password", ""))
            tls = n.get("tls", {})
            sni = _q(_bare_host(tls.get("server_name") or server), safe=".:-")
            cc = _q(n.get("congestion_control") or "bbr")
            urm = _q(n.get("udp_relay_mode") or "native")
            insecure = "&allow_insecure=1" if tls.get("insecure") else ""
            raw_uri = f"tuic://{uuid}:{pw}@{host}:{port}?congestion_control={cc}&udp_relay_mode={urm}&sni={sni}{insecure}#{frag}"
        elif ntype == "anytls":
            pw = _q(n.get("password", ""))
            tls = n.get("tls", {})
            sni = _q(_bare_host(tls.get("server_name") or server), safe=".:-")
            insecure = "&insecure=1" if tls.get("insecure") else ""
            raw_uri = f"anytls://{pw}@{host}:{port}?sni={sni}{insecure}#{frag}"

        if raw_uri:
            # 严格防止 URI 中的单引号破坏 .dae 的 '...' 语法定界符（转为合法 RFC 3986 %27）
            safe_uri = raw_uri.replace("'", "%27")
            lines.append(f"  '{tag}': '{safe_uri}'")

    lines.append("}")
    return "\n".join(lines)


def _is_ip_literal(addr: str) -> bool:
    """判断字符串是否为纯 IPv4 或 IPv6 字面量。"""
    s = str(addr or "").strip().strip("[]")
    if not s:
        return False
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def extract_node_domains(nodes: List[Dict[str, Any]]) -> List[str]:
    """提取出站节点中所有使用域名的服务器地址（排除纯 IPv4 和 IPv6），用于 DNS 防死锁直连白名单"""
    domains = set()
    for n in nodes:
        server = str(n.get("server") or "").strip()
        if not server or _is_ip_literal(server):
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
