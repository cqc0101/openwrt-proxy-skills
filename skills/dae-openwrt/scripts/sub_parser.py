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
    if not (1 <= port <= 65535):
        return {}

    if ptype == "ss":
        cipher = str(p.get("cipher") or "").strip()
        password = str(p.get("password") or "")
        deprecated_ciphers = {
            "aes-256-cfb", "aes-128-cfb", "aes-192-cfb", "rc4", "rc4-md5",
            "bf-cfb", "cast5-cfb", "des-cfb", "idea-cfb", "rc2-cfb", "seed-cfb",
            "salsa20", "chacha20", "table",
        }
        if not cipher or not password or cipher.lower() in deprecated_ciphers:
            return {}
        ob = {
            "type": "shadowsocks",
            "tag": name,
            "server": server,
            "server_port": port,
            "method": cipher,
            "password": password
        }
        raw_pl = str(p.get("plugin") or "").strip().lower()
        if raw_pl:
            popts = p.get("plugin-opts") if isinstance(p.get("plugin-opts"), dict) else {}
            if raw_pl in ("obfs", "obfs-local", "simple-obfs"):
                mode = str(popts.get("mode") or "http").strip()
                host = str(popts.get("host") or "").strip()
                ob["plugin"] = "obfs-local"
                ob["plugin_opts"] = f"obfs={mode};obfs-host={host}" if host else f"obfs={mode}"
            elif raw_pl == "v2ray-plugin":
                mode = str(popts.get("mode") or "websocket").strip()
                parts = [f"mode={mode}"]
                if popts.get("tls"):
                    parts.append("tls")
                if popts.get("host"):
                    parts.append(f"host={popts['host']}")
                if popts.get("path"):
                    parts.append(f"path={popts['path']}")
                ob["plugin"] = "v2ray-plugin"
                ob["plugin_opts"] = ";".join(parts)
            else:
                return {}
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
            if not str(reality_opts.get("public-key") or "").strip():
                return {}
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


def _strip_yaml_comment(line: str) -> str:
    """引号感知剥离 YAML 行内注释（仅当 # 位于行首或紧跟空白字符且不在单双引号内时剥离）。"""
    in_sq = False
    in_dq = False
    out = []
    for idx, ch in enumerate(line):
        if ch == "'" and not in_dq:
            in_sq = not in_sq
            out.append(ch)
        elif ch == '"' and not in_sq:
            in_dq = not in_dq
            out.append(ch)
        elif ch == "#" and not in_sq and not in_dq and (idx == 0 or line[idx - 1] in (" ", "\t")):
            break
        else:
            out.append(ch)
    return "".join(out).rstrip()


def _split_yaml_flow(s: str, sep: str = ",") -> List[str]:
    """按顶层分隔符拆分 YAML 流式表达式，严格感知 {}、[] 与单双引号嵌套边界。"""
    parts = []
    curr = []
    brace_depth = 0
    bracket_depth = 0
    in_sq = False
    in_dq = False
    for ch in s:
        if ch == "'" and not in_dq:
            in_sq = not in_sq
            curr.append(ch)
        elif ch == '"' and not in_sq:
            in_dq = not in_dq
            curr.append(ch)
        elif not in_sq and not in_dq:
            if ch == "{":
                brace_depth += 1
                curr.append(ch)
            elif ch == "}":
                brace_depth = max(0, brace_depth - 1)
                curr.append(ch)
            elif ch == "[":
                bracket_depth += 1
                curr.append(ch)
            elif ch == "]":
                bracket_depth = max(0, bracket_depth - 1)
                curr.append(ch)
            elif ch == sep and brace_depth == 0 and bracket_depth == 0:
                parts.append("".join(curr).strip())
                curr = []
            else:
                curr.append(ch)
        else:
            curr.append(ch)
    if curr or s.endswith(sep):
        tail = "".join(curr).strip()
        if tail:
            parts.append(tail)
    return parts


def _parse_yaml_scalar_or_flow(val_str: str, anchors: Dict[str, Dict[str, Any]]) -> Any:
    """解析 YAML 标量、内联列表 [...] 或内联字典 {...}（递归支持嵌套与锚点引用）。"""
    v = val_str.strip()
    if not v:
        return ""
    if v.startswith("{") and v.endswith("}"):
        return _parse_yaml_flow_map(v[1:-1], anchors)
    if v.startswith("[") and v.endswith("]"):
        inner = v[1:-1].strip()
        if not inner:
            return []
        return [_parse_yaml_scalar_or_flow(x, anchors) for x in _split_yaml_flow(inner, ",")]
    if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
        return v[1:-1]
    vl = v.lower()
    if vl in ("null", "~"):
        return None
    if vl == "true":
        return True
    if vl == "false":
        return False
    if re.match(r"^-?\d+$", v):
        try:
            return int(v)
        except ValueError:
            return v
    return v


def _parse_yaml_flow_map(inner: str, anchors: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """解析花括号内部 k: v 列表，支持嵌套字典/列表与 <<: *anchor 继承（显式字段优先于锚点默认值）。"""
    res: Dict[str, Any] = {}
    explicit: Dict[str, Any] = {}
    for part in _split_yaml_flow(inner, ","):
        if ":" not in part:
            continue
        k, v = part.split(":", 1)
        k_s = k.strip().strip("\"'")
        v_s = v.strip()
        if k_s == "<<" and v_s.startswith("*"):
            ref = v_s[1:].strip()
            if ref in anchors:
                for ak, av in anchors[ref].items():
                    res[ak] = av
        else:
            explicit[k_s] = _parse_yaml_scalar_or_flow(v_s, anchors)
    res.update(explicit)
    return res


def parse_clash_yaml_pure_python(text: str) -> List[Dict[str, Any]]:
    """在无 PyYAML 环境下，以纯 Python 标准库解析 Clash YAML 订阅中的 proxies 列表。
    支持：
    1. 流式与块式 YAML 锚点定义 (&anchor) 与引用合并 (<<: *anchor)
    2. 行内注释剥离 (# ...)
    3. 嵌套流式字典 (- {name: ..., ws-opts: {path: /ws, headers: {Host: a.com}}})
    4. 多级缩进块式字典与列表 (ws-opts -> headers -> Host 及 alpn 多行列表)
    """
    clean_lines = [_strip_yaml_comment(raw_l) for raw_l in text.splitlines()]
    anchors: Dict[str, Dict[str, Any]] = {}

    # 1. 扫描流式锚点: key: &anchor { k: v, ... }
    for l in clean_lines:
        m = re.match(r"^\s*([a-zA-Z0-9_-]+)\s*:\s*&([a-zA-Z0-9_-]+)\s*\{(.*)\}\s*$", l)
        if m:
            anchors[m.group(2)] = _parse_yaml_flow_map(m.group(3), anchors)

    # 2. 扫描缩进块式锚点: key: &anchor
    i = 0
    while i < len(clean_lines):
        line = clean_lines[i]
        m = re.match(r"^\s*([a-zA-Z0-9_-]+)\s*:\s*&([a-zA-Z0-9_-]+)\s*$", line)
        if m:
            a_name = m.group(2)
            base_indent = len(line) - len(line.lstrip())
            props: Dict[str, Any] = {}
            i += 1
            while i < len(clean_lines):
                sub_line = clean_lines[i]
                if not sub_line.strip():
                    i += 1
                    continue
                sub_indent = len(sub_line) - len(sub_line.lstrip())
                if sub_indent <= base_indent:
                    break
                if ":" in sub_line:
                    k, v = sub_line.split(":", 1)
                    k_s = k.strip().strip("\"'")
                    v_s = v.strip()
                    if v_s:
                        props[k_s] = _parse_yaml_scalar_or_flow(v_s, anchors)
                i += 1
            anchors[a_name] = props
            continue
        i += 1

    # 3. 定位 proxies / Proxy 节点块起始行
    proxies_idx = -1
    proxies_base_indent = 0
    for idx, l in enumerate(clean_lines):
        if re.match(r"^(?:proxies|Proxy)\s*:", l.strip()):
            proxies_idx = idx
            proxies_base_indent = len(l) - len(l.lstrip())
            break

    if proxies_idx == -1:
        return []

    # 4. 抽取 proxies 下所有顶层节点行块（区分顶层节点 `- ` 与属性内部子列表 `- h2`）
    raw_items: List[List[str]] = []
    curr_item: List[str] = []
    item_dash_indent = None

    for l in clean_lines[proxies_idx + 1:]:
        stripped = l.strip()
        if not stripped:
            continue
        indent = len(l) - len(l.lstrip())

        if indent <= proxies_base_indent and not stripped.startswith("-") and ":" in stripped:
            break

        if stripped.startswith("-"):
            if item_dash_indent is None or indent <= item_dash_indent:
                item_dash_indent = indent
                if curr_item:
                    raw_items.append(curr_item)
                curr_item = [l]
            else:
                if curr_item:
                    curr_item.append(l)
        else:
            if curr_item:
                curr_item.append(l)
    if curr_item:
        raw_items.append(curr_item)

    # 5. 解析每个 proxy 节点并应用多级嵌套与锚点合并
    parsed_proxies: List[Dict[str, Any]] = []
    for item_lines in raw_items:
        first = item_lines[0].strip()
        # 情况 A: 单行内联 - { ... }（支持嵌套花括号）
        inline_m = re.match(r"^-\s*\{(.*)\}\s*$", first)
        if inline_m:
            p_dict = _parse_yaml_flow_map(inline_m.group(1), anchors)
            if p_dict:
                parsed_proxies.append(p_dict)
            continue

        # 情况 B: 多行缩进块 - name: ...（使用缩进栈支持多层嵌套字典与列表）
        p_dict = {}
        first_indent = len(item_lines[0]) - len(item_lines[0].lstrip())
        stack: List[Any] = [(first_indent, p_dict, None)]  # (indent, container_dict, last_empty_key)

        for idx_l, l in enumerate(item_lines):
            s = l.strip()
            indent = len(l) - len(l.lstrip())
            if idx_l == 0 and s.startswith("-"):
                s = s[1:].strip()
                indent = first_indent + 2
                stack = [(first_indent, p_dict, None)]
            if not s:
                continue

            while len(stack) > 1 and indent <= stack[-1][0]:
                stack.pop()

            cur_indent, cur_container, pending_key = stack[-1]

            # 处理多行 YAML 列表项 (例如 alpn: 下的 - h2)
            if s.startswith("-") and (idx_l > 0):
                list_val = _parse_yaml_scalar_or_flow(s[1:].strip(), anchors)
                if pending_key is not None and isinstance(cur_container, dict):
                    existing = cur_container.get(pending_key)
                    if not isinstance(existing, list):
                        cur_container[pending_key] = [list_val]
                    else:
                        existing.append(list_val)
                continue

            if ":" in s:
                k, v = s.split(":", 1)
                k_s = k.strip().strip("\"'")
                v_s = v.strip()

                # 若前一个同级或父级 pending_key 是空字典占位，进入子字典层级
                if pending_key is not None and indent > cur_indent and isinstance(cur_container.get(pending_key), dict):
                    cur_container = cur_container[pending_key]
                    cur_indent = indent
                    stack.append((cur_indent, cur_container, None))

                if not v_s:
                    sub_d: Dict[str, Any] = {}
                    cur_container[k_s] = sub_d
                    stack[-1] = (cur_indent, cur_container, k_s)
                    continue

                if k_s == "<<" and v_s.startswith("*"):
                    ref = v_s[1:].strip()
                    if ref in anchors:
                        for ak, av in anchors[ref].items():
                            cur_container.setdefault(ak, av)
                else:
                    cur_container[k_s] = _parse_yaml_scalar_or_flow(v_s, anchors)
                    stack[-1] = (cur_indent, cur_container, None)

        if p_dict:
            parsed_proxies.append(p_dict)

    return parsed_proxies


def _extract_clash_proxies(text: str) -> List[Dict[str, Any]]:
    """从 Clash YAML 文本提取并转换节点列表（优先 PyYAML，无依赖或失败时回退内置解析器）。"""
    results = []
    if HAS_YAML:
        try:
            data = yaml.safe_load(text)
            if isinstance(data, dict):
                proxies = data.get("proxies") or data.get("Proxy") or []
                if isinstance(proxies, list) and len(proxies) > 0:
                    for p in proxies:
                        if isinstance(p, dict):
                            try:
                                parsed = parse_clash_proxy(p)
                                if parsed:
                                    results.append(parsed)
                            except Exception:
                                continue
        except Exception:
            results = []

    if not results:
        try:
            pure_proxies = parse_clash_yaml_pure_python(text)
            for p in pure_proxies:
                if isinstance(p, dict):
                    try:
                        parsed = parse_clash_proxy(p)
                        if parsed:
                            results.append(parsed)
                    except Exception:
                        continue
        except Exception:
            pass
    return results


def parse_subscription_text(text: str) -> List[Dict[str, Any]]:
    """智能解析订阅纯文本（支持 Base64、Clash YAML、Base64 包裹的 Clash YAML、多行 URI）"""
    text = text.strip()
    if not text:
        return []

    # 1. 尝试直接作为 Clash YAML 解析（单节点隔离容错，防止单颗坏节点冲毁整份订阅）
    if "proxies:" in text or "Proxy:" in text:
        results = _extract_clash_proxies(text)
        if results:
            return results

    # 2. 尝试作为 Base64 解码（兼容 Base64 包裹的节点列表或 Base64 包裹的 Clash YAML）
    if not text.startswith(("vless://", "hysteria2://", "hy2://", "ss://", "trojan://", "vmess://", "tuic://", "anytls://")):
        decoded = safe_b64decode(text)
        if decoded:
            if "proxies:" in decoded or "Proxy:" in decoded:
                results = _extract_clash_proxies(decoded)
                if results:
                    return results
            if any(proto in decoded for proto in ("vless://", "hy2://", "hysteria2://", "trojan://", "ss://", "vmess://", "tuic://", "anytls://")):
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

    deprecated_ciphers = {
        "aes-256-cfb", "aes-128-cfb", "aes-192-cfb", "rc4", "rc4-md5",
        "bf-cfb", "cast5-cfb", "des-cfb", "idea-cfb", "rc2-cfb", "seed-cfb",
        "salsa20", "chacha20", "table",
    }
    for node in nodes:
        if node.get("type") == "shadowsocks" and str(node.get("method") or "").strip().lower() in deprecated_ciphers:
            continue
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

    # 弱路由内存安全冗余：校验 max_nodes 并截取前 max_nodes 个节点
    if max_nodes is not None:
        if int(max_nodes) < 1:
            raise ValueError(f"max_nodes 必须为正整数 (>= 1)，当前值: {max_nodes!r}")
        if len(clean_nodes) > int(max_nodes):
            clean_nodes = clean_nodes[:int(max_nodes)]

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
        tls_obj = n.get("tls") if isinstance(n.get("tls"), dict) else {}
        alpn_vals = tls_obj.get("alpn") if isinstance(tls_obj.get("alpn"), list) else []
        alpn_part = f"&alpn={_q(','.join(str(a) for a in alpn_vals if a), safe=',')}" if alpn_vals else ""

        raw_uri = ""
        if ntype == "hysteria2":
            pw = _q(n.get("password", ""), safe=":")
            tls = tls_obj
            sni = _q(_bare_host(tls.get("server_name") or server), safe=".:-")
            insecure = "&insecure=1" if tls.get("insecure") else ""
            obfs = n.get("obfs", {})
            obfs_part = ""
            if obfs and obfs.get("type"):
                obfs_part = f"&obfs={_q(obfs.get('type'))}&obfs-password={_q(obfs.get('password', ''))}"
            srv_ports = n.get("server_ports") if isinstance(n.get("server_ports"), list) else []
            mport_part = f"&mport={_q(','.join(str(r).replace(':', '-') for r in srv_ports if r), safe=',-')}" if srv_ports else ""
            raw_uri = f"hysteria2://{pw}@{host}:{port}?sni={sni}{insecure}{alpn_part}{mport_part}{obfs_part}#{frag}"
        elif ntype == "vless":
            uuid = _q(n.get("uuid", ""))
            flow = _q(n.get("flow", ""))
            tls = tls_obj
            flow_part = f"&flow={flow}" if flow else ""
            if tls.get("reality", {}).get("enabled"):
                pbk = _q(tls["reality"].get("public_key", ""))
                sid = _q(tls["reality"].get("short_id", ""))
                sni = _q(_bare_host(tls.get("server_name") or server), safe=".:-")
                fp = _q(tls.get("utls", {}).get("fingerprint", "chrome"))
                raw_uri = f"vless://{uuid}@{host}:{port}?security=reality&sni={sni}&pbk={pbk}&sid={sid}&fp={fp}{alpn_part}{flow_part}{trans_part}#{frag}"
            elif tls.get("enabled"):
                sni = _q(_bare_host(tls.get("server_name") or server), safe=".:-")
                fp = _q(tls.get("utls", {}).get("fingerprint", "chrome"))
                insecure = "&allowInsecure=1" if tls.get("insecure") else ""
                raw_uri = f"vless://{uuid}@{host}:{port}?security=tls&sni={sni}&fp={fp}{insecure}{alpn_part}{flow_part}{trans_part}#{frag}"
            else:
                raw_uri = f"vless://{uuid}@{host}:{port}?security=none{flow_part}{trans_part}#{frag}"
        elif ntype == "trojan":
            pw = _q(n.get("password", ""))
            tls = tls_obj
            sni = _q(_bare_host(tls.get("server_name") or server), safe=".:-")
            insecure = "&allowInsecure=1" if tls.get("insecure") else ""
            raw_uri = f"trojan://{pw}@{host}:{port}?sni={sni}{insecure}{alpn_part}{trans_part}#{frag}"
        elif ntype == "shadowsocks":
            method = n.get("method", "")
            pw = n.get("password", "")
            userpass = base64.b64encode(f"{method}:{pw}".encode()).decode()
            pl = str(n.get("plugin") or "").strip()
            pl_opts = str(n.get("plugin_opts") or "").strip()
            pl_query = ""
            if pl:
                full_pl = f"{pl};{pl_opts}" if pl_opts else pl
                pl_query = f"/?plugin={_q(full_pl)}"
            raw_uri = f"ss://{userpass}@{host}:{port}{pl_query}#{frag}"
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
            if not ws_host and transport.get("host"):
                raw_th = transport.get("host")
                if isinstance(raw_th, (list, tuple)):
                    ws_host = ",".join(str(x) for x in raw_th if x)
                else:
                    ws_host = str(raw_th)
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
            if alpn_vals:
                vm["alpn"] = ",".join(str(a) for a in alpn_vals if a)
            if tls.get("insecure"):
                vm["allowInsecure"] = 1
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
            raw_uri = f"tuic://{uuid}:{pw}@{host}:{port}?congestion_control={cc}&udp_relay_mode={urm}&sni={sni}{insecure}{alpn_part}#{frag}"
        elif ntype == "anytls":
            pw = _q(n.get("password", ""))
            tls = tls_obj
            sni = _q(_bare_host(tls.get("server_name") or server), safe=".:-")
            insecure = "&insecure=1" if tls.get("insecure") else ""
            raw_uri = f"anytls://{pw}@{host}:{port}?sni={sni}{insecure}{alpn_part}#{frag}"

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
