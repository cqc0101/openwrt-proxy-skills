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
# [共享脚本] 本文件与 dae-openwrt/scripts/sub_parser.py 完全一致，修改需双份同步！

import os
import sys
import json
import re
import base64
import ipaddress
import zlib
import urllib.request
import urllib.parse
from typing import List, Dict, Any, Tuple, Optional

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
    """安全解码 Base64 字符串（同时兼容标准与 urlsafe 字母表，支持 UTF-8 (含 BOM 剥离) 与 GB18030）"""
    s = re.sub(r"\s+", "", (s or "").replace("\ufeff", ""))
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
        return raw.decode('utf-8-sig')
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
                return content.decode('utf-8-sig')
            except UnicodeDecodeError:
                try:
                    return content.decode('gb18030')
                except UnicodeDecodeError:
                    return content.decode('latin-1', errors='ignore')
    except Exception as e:
        raise RuntimeError(f"拉取订阅链接失败: {url} -> {e}")


def _apply_clash_alpn(tls_obj: Dict[str, Any], p: Dict[str, Any]):
    alpn = p.get("alpn")
    if not alpn or isinstance(alpn, (bool, dict)):
        return
    if isinstance(alpn, list):
        cleaned = [str(x).strip() for x in alpn if x is not None and not isinstance(x, (bool, dict, list)) and str(x).strip()]
    elif isinstance(alpn, str):
        cleaned = [x.strip() for x in alpn.split(",") if x.strip()]
    else:
        cleaned = []
    if cleaned:
        tls_obj["alpn"] = cleaned


def _apply_clash_utls(tls_obj: Dict[str, Any], p: Dict[str, Any], default_fp: str = ""):
    fp = str(p.get("client-fingerprint") or p.get("fingerprint") or default_fp).strip()
    if fp:
        tls_obj["utls"] = {"enabled": True, "fingerprint": fp}


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
        host_val = ws_opts.get("host") or (headers.get("Host") if "Host" in headers else headers.get("host"))
        if host_val:
            ob["transport"]["headers"] = {"Host": str(host_val)}
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
        if raw_host and not isinstance(raw_host, (bool, dict)):
            hosts = [
                str(x).strip()
                for x in (raw_host if isinstance(raw_host, list) else [raw_host])
                if x is not None and not isinstance(x, (bool, dict, list)) and str(x).strip()
            ]
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
    raw_p = p.get("port")
    if isinstance(raw_p, bool):
        return {}
    try:
        port = int(raw_p if raw_p is not None else 443)
    except (ValueError, TypeError):
        return {}
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
        password = str(p.get("password") or "").strip()
        if not password:
            return {}
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
        _apply_clash_utls(ob["tls"], p)
        if not _apply_clash_transport(ob, p, allow_udp=False):
            return {}
        _apply_clash_smux(ob, p)
        return ob

    elif ptype in ("hysteria2", "hy2"):
        password = str(p.get("password") or p.get("auth") or "").strip()
        if not password:
            return {}
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
        ports_spec = p.get("ports") if p.get("ports") is not None else p.get("mport")
        if ports_spec is not None and str(ports_spec).strip() != "" and ports_spec != []:
            _, port_ranges = _normalize_port_ranges(ports_spec)
            if not port_ranges:
                return {}
            ob["server_ports"] = port_ranges
        if p.get("up") is not None and not isinstance(p.get("up"), bool):
            up_val = int(re.sub(r"[^\d]", "", str(p["up"])) or 0)
            if up_val > 0:
                ob["up_mbps"] = up_val
        if p.get("down") is not None and not isinstance(p.get("down"), bool):
            down_val = int(re.sub(r"[^\d]", "", str(p["down"])) or 0)
            if down_val > 0:
                ob["down_mbps"] = down_val
        if isinstance(p.get("obfs"), str) and p["obfs"].strip():
            ob["obfs"] = {
                "type": p["obfs"].strip(),
                "password": str(p.get("obfs-password") or "")
            }
        return ob

    elif ptype == "vless":
        uuid = str(p.get("uuid") or "").strip()
        if not uuid:
            return {}
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
            _apply_clash_utls(ob["tls"], p, default_fp="chrome")
            _apply_clash_alpn(ob["tls"], p)

        _apply_clash_smux(ob, p)
        return ob

    elif ptype == "vmess":
        uuid = str(p.get("uuid") or "").strip()
        if not uuid:
            return {}
        raw_aid = p.get("alterId") if p.get("alterId") is not None else p.get("aid", 0)
        if isinstance(raw_aid, bool) or raw_aid is None:
            alter_id = 0
        else:
            try:
                alter_id = int(raw_aid)
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
            _apply_clash_utls(ob["tls"], p)
            _apply_clash_alpn(ob["tls"], p)
        if not _apply_clash_transport(ob, p, allow_udp=False):
            return {}
        _apply_clash_smux(ob, p)
        return ob

    elif ptype == "tuic":
        uuid = str(p.get("uuid") or "").strip()
        password = str(p.get("password") or "").strip()
        if not uuid or not password:
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
    """引号与转义感知剥离 YAML 行内注释（仅当 # 位于行首或紧跟空白字符且不在单双引号内时剥离）。"""
    in_sq = False
    in_dq = False
    out = []
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if ch == "\\" and in_dq and i + 1 < n:
            out.append(ch)
            out.append(line[i + 1])
            i += 2
            continue
        if ch == "'" and not in_dq:
            if in_sq and i + 1 < n and line[i + 1] == "'":
                out.append("''")
                i += 2
                continue
            in_sq = not in_sq
            out.append(ch)
        elif ch == '"' and not in_sq:
            in_dq = not in_dq
            out.append(ch)
        elif ch == "#" and not in_sq and not in_dq and (i == 0 or line[i - 1] in (" ", "\t")):
            break
        else:
            out.append(ch)
        i += 1
    return "".join(out).rstrip()


def _split_yaml_flow(s: str, sep: str = ",") -> List[str]:
    """按顶层分隔符拆分 YAML 流式表达式，严格感知 {}、[]、单双引号嵌套与转义边界。"""
    parts = []
    curr = []
    brace_depth = 0
    bracket_depth = 0
    in_sq = False
    in_dq = False
    i = 0
    n = len(s)
    while i < n:
        ch = s[i]
        if ch == "\\" and in_dq and i + 1 < n:
            curr.append(ch)
            curr.append(s[i + 1])
            i += 2
            continue
        if ch == "'" and not in_dq:
            if in_sq and i + 1 < n and s[i + 1] == "'":
                curr.append("''")
                i += 2
                continue
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
        i += 1
    if curr or s.endswith(sep):
        tail = "".join(curr).strip()
        if tail:
            parts.append(tail)
    return parts


def _parse_yaml_scalar_or_flow(val_str: str, anchors: Dict[str, Any]) -> Any:
    """解析 YAML 标量、别名引用 (*alias)、内联列表 [...] 或内联字典 {...}（递归支持嵌套与锚点引用）。"""
    v = val_str.strip()
    if not v:
        return ""
    if v.startswith("*") and len(v) > 1 and " " not in v:
        ref = v[1:].strip()
        if ref in anchors:
            import copy as _cp
            return _cp.deepcopy(anchors[ref])
    if v.startswith("{") and v.endswith("}"):
        return _parse_yaml_flow_map(v[1:-1], anchors)
    if v.startswith("[") and v.endswith("]"):
        inner = v[1:-1].strip()
        if not inner:
            return []
        return [_parse_yaml_scalar_or_flow(x, anchors) for x in _split_yaml_flow(inner, ",")]
    if v.startswith('"') and v.endswith('"') and len(v) >= 2:
        return v[1:-1].replace('\\"', '"').replace('\\\\', '\\')
    if v.startswith("'") and v.endswith("'") and len(v) >= 2:
        return v[1:-1].replace("''", "'")
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


def _merge_yaml_anchors(target: Dict[str, Any], v_s: str, anchors: Dict[str, Any]):
    """支持单个锚点 (<<: *a) 或多锚点列表 (<<: [*a, *b]) 合并（遵循 YAML 标准：列表中排在前面的锚点优先级更高）。"""
    import copy as _copy
    v = v_s.strip()
    refs: List[str] = []
    if v.startswith("*"):
        refs.append(v[1:].strip())
    elif v.startswith("[") and v.endswith("]"):
        for item in _split_yaml_flow(v[1:-1], ","):
            it = item.strip()
            if it.startswith("*"):
                refs.append(it[1:].strip())
    for ref in refs:
        if ref in anchors and isinstance(anchors[ref], dict):
            for ak, av in anchors[ref].items():
                if ak not in target:
                    target[ak] = _copy.deepcopy(av)


def _parse_yaml_flow_map(inner: str, anchors: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """解析花括号内部 k: v 列表，支持带冒号引号键名、嵌套字典/列表与 <<: *anchor 继承（显式字段优先于锚点默认值）。"""
    res: Dict[str, Any] = {}
    explicit: Dict[str, Any] = {}
    for part in _split_yaml_flow(inner, ","):
        if ":" not in part:
            continue
        k, v = _split_yaml_kv(part)
        k_s = _unquote_yaml_key(k)
        v_s = v.strip()
        if k_s == "<<":
            _merge_yaml_anchors(res, v_s, anchors)
        else:
            item_anchor = None
            if v_s.startswith("&"):
                m_fa = re.match(r"^&([a-zA-Z0-9_-]+)\s+(.+)$", v_s)
                if m_fa:
                    item_anchor = m_fa.group(1)
                    v_s = m_fa.group(2).strip()
            val_parsed = _parse_yaml_scalar_or_flow(v_s, anchors)
            explicit[k_s] = val_parsed
            if item_anchor:
                import copy as _cp
                anchors[item_anchor] = _cp.deepcopy(val_parsed)
    res.update(explicit)
    return res


def _unquote_yaml_key(k: str) -> str:
    ks = k.strip()
    if len(ks) >= 2 and ks[0] == ks[-1] and ks[0] in ("\"", "'"):
        if ks[0] == "\"":
            return ks[1:-1].replace('\\"', '"').replace("\\\\", "\\")
        return ks[1:-1].replace("''", "'")
    return ks


def _split_yaml_kv(s: str) -> Tuple[str, str]:
    """安全分离 YAML 键值对，兼容引号包裹的键名（含转义引号与冒号）与包含 URL/路径的值。"""
    s = s.strip()
    if s.startswith("'"):
        i = 1
        end_q = -1
        while i < len(s):
            if s[i] == "'":
                if i + 1 < len(s) and s[i + 1] == "'":
                    i += 2
                    continue
                end_q = i
                break
            i += 1
        if end_q != -1:
            colon_idx = s.find(":", end_q)
            if colon_idx != -1:
                return s[:colon_idx].strip(), s[colon_idx + 1:].strip()
    elif s.startswith('"'):
        i = 1
        end_q = -1
        while i < len(s):
            if s[i] == "\\" and i + 1 < len(s):
                i += 2
                continue
            if s[i] == '"':
                end_q = i
                break
            i += 1
        if end_q != -1:
            colon_idx = s.find(":", end_q)
            if colon_idx != -1:
                return s[:colon_idx].strip(), s[colon_idx + 1:].strip()
    m = re.search(r":(?:\s+|$)", s)
    if m:
        c_pos = m.start()
        return s[:c_pos].strip(), s[c_pos + 1:].strip()
    if ":" in s:
        k, v = s.split(":", 1)
        return k.strip(), v.strip()
    return s, ""


def parse_clash_yaml_pure_python(text: str) -> List[Dict[str, Any]]:
    """在无 PyYAML 环境下，以纯 Python 标准库解析 Clash YAML 订阅中的 proxies 列表。
    支持：
    1. 流式与块式 YAML 锚点定义 (&anchor) 与引用合并 (<<: *anchor)
    2. 行内注释剥离 (# ...)
    3. 嵌套流式字典 (- {name: ..., ws-opts: {path: /ws, headers: {Host: a.com}}})
    4. 多级缩进块式字典与列表 (ws-opts -> headers -> Host 及 alpn 多行列表)
    """
    text = (text or "").lstrip("\ufeff")
    clean_lines = [_strip_yaml_comment(raw_l.lstrip("\ufeff")) for raw_l in text.splitlines()]
    anchors: Dict[str, Dict[str, Any]] = {}

    # 1. 预备锚点容器（在下方单遍顺序扫描中统一解析流式与块式锚点，确保跨形态先后引用 100% 互通）

    def _parse_indented_block(norm_lines: List[Tuple[int, str]]) -> Any:
        import copy as _copy
        if not norm_lines:
            return {}
        # 若块级锚点本身是一个纯列表（如 common_alpn: &a \n - h2 \n - http/1.1）
        if all(s.startswith("-") for _, s in norm_lines):
            res_list = [_parse_yaml_scalar_or_flow(s[1:].strip(), anchors) for _, s in norm_lines]
            return res_list
        p_dict: Dict[str, Any] = {}
        stack: List[Tuple[int, Any, str]] = [(norm_lines[0][0], p_dict, "dict")]
        pending_key: Optional[str] = None
        pending_anchor: Optional[str] = None
        inline_anchor_name: Optional[str] = None
        root_indent_locked = False

        for indent, s in norm_lines:
            if s.startswith("&"):
                if ":" not in s:
                    inline_anchor_name = s[1:].strip()
                    continue
                m_anc = re.match(r"^&([a-zA-Z0-9_-]+)\s+(.*)$", s)
                if m_anc:
                    inline_anchor_name = m_anc.group(1)
                    s = m_anc.group(2).strip()
            if not root_indent_locked and len(stack) == 1 and not p_dict and pending_key is None:
                stack[0] = (indent, p_dict, "dict")
                root_indent_locked = True

            if pending_key is not None:
                if indent > stack[-1][0] or (indent == stack[-1][0] and s.startswith("-")):
                    parent_indent, parent_container, parent_type = stack[-1]
                    if s.startswith("-"):
                        child_list: List[Any] = []
                        parent_container[pending_key] = child_list
                        if pending_anchor:
                            anchors[pending_anchor] = child_list
                        stack.append((indent, child_list, "list"))
                    else:
                        child_dict: Dict[str, Any] = {}
                        parent_container[pending_key] = child_dict
                        if pending_anchor:
                            anchors[pending_anchor] = child_dict
                        stack.append((indent, child_dict, "dict"))
                    pending_key = None
                    pending_anchor = None
                else:
                    stack[-1][1][pending_key] = None
                    pending_key = None
                    pending_anchor = None

            while len(stack) > 1 and indent < stack[-1][0]:
                stack.pop()
            while len(stack) > 1 and stack[-1][2] == "list" and not s.startswith("-"):
                stack.pop()

            cur_indent, cur_container, cur_type = stack[-1]

            if cur_type == "list" and s.startswith("-"):
                val_str = s[1:].strip()
                val = _parse_yaml_scalar_or_flow(val_str, anchors)
                cur_container.append(val)
                continue

            k, v = _split_yaml_kv(s)
            k_s = _unquote_yaml_key(k)
            v_s = v.strip()

            item_anchor = None
            if v_s.startswith("&"):
                m_anc_v = re.match(r"^&([a-zA-Z0-9_-]+)(?:\s+(.*))?$", v_s)
                if m_anc_v:
                    item_anchor = m_anc_v.group(1)
                    v_s = (m_anc_v.group(2) or "").strip()

            if not v_s:
                pending_key = k_s
                pending_anchor = item_anchor
                continue

            if k_s == "<<":
                _merge_yaml_anchors(cur_container, v_s, anchors)
                pending_key = None
                pending_anchor = None
            else:
                parsed_val = _parse_yaml_scalar_or_flow(v_s, anchors)
                cur_container[k_s] = parsed_val
                if item_anchor:
                    anchors[item_anchor] = parsed_val
                pending_key = None
                pending_anchor = None

        if pending_key is not None and stack:
            stack[-1][1][pending_key] = None
            pending_key = None
            pending_anchor = None

        if inline_anchor_name:
            anchors[inline_anchor_name] = _copy.deepcopy(p_dict)

        return p_dict

    # 2. 按文档顺序扫描单行锚点 (key: &a {...} / [...] / scalar / - &a {...}) 与多行块式锚点 (key: &a / - &a)
    i = 0
    while i < len(clean_lines):
        line = clean_lines[i]
        m_inline = re.match(r"^\s*([a-zA-Z0-9_.\-\"']+)\s*:\s*&([a-zA-Z0-9_-]+)\s+(.+?)\s*$", line)
        if m_inline:
            anchors[m_inline.group(2)] = _parse_yaml_scalar_or_flow(m_inline.group(3), anchors)
            i += 1
            continue
        m_list_flow = re.match(r"^\s*-\s*&([a-zA-Z0-9_-]+)\s*\{(.*)\}\s*$", line)
        if m_list_flow:
            anchors[m_list_flow.group(1)] = _parse_yaml_flow_map(m_list_flow.group(2), anchors)
            i += 1
            continue
        m_list_block = re.match(r"^\s*-\s*&([a-zA-Z0-9_-]+)(?:\s+(.*))?$", line)
        if m_list_block and not (m_list_block.group(2) or "").strip().startswith("{"):
            a_name = m_list_block.group(1)
            dash_indent = len(line) - len(line.lstrip())
            rem = (m_list_block.group(2) or "").strip()
            anchor_norm = []
            if rem:
                dash_idx = line.index("-")
                after = line[dash_idx + 1:]
                c_indent = dash_idx + 1 + (len(after) - len(after.lstrip()))
                anchor_norm.append((c_indent, f"&{a_name} {rem}"))
            i += 1
            while i < len(clean_lines):
                sub_line = clean_lines[i]
                stripped_sub = sub_line.strip()
                if not stripped_sub:
                    i += 1
                    continue
                sub_indent = len(sub_line) - len(sub_line.lstrip())
                if sub_indent <= dash_indent:
                    break
                anchor_norm.append((sub_indent, stripped_sub))
                i += 1
            if anchor_norm:
                anchors[a_name] = _parse_indented_block(anchor_norm)
            continue
        m = re.match(r"^\s*([a-zA-Z0-9_.\-\"']+)\s*:\s*&([a-zA-Z0-9_-]+)\s*$", line)
        if m:
            a_name = m.group(2)
            base_indent = len(line) - len(line.lstrip())
            anchor_norm = []
            i += 1
            while i < len(clean_lines):
                sub_line = clean_lines[i]
                stripped_sub = sub_line.strip()
                if not stripped_sub:
                    i += 1
                    continue
                sub_indent = len(sub_line) - len(sub_line.lstrip())
                is_list_anchor = (not anchor_norm) or anchor_norm[0][1].startswith("-")
                if sub_indent < base_indent or (sub_indent == base_indent and not (is_list_anchor and stripped_sub.startswith("-"))):
                    break
                anchor_norm.append((sub_indent, stripped_sub))
                i += 1
            anchors[a_name] = _parse_indented_block(anchor_norm)
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
        # 情况 A: 单行内联 - { ... } 或 - &anchor { ... }（支持嵌套花括号与内联锚点）
        inline_m = re.match(r"^-\s*(?:&([a-zA-Z0-9_-]+)\s*)?\{(.*)\}\s*$", first)
        if inline_m:
            import copy as _copy
            a_inline, flow_body = inline_m.group(1), inline_m.group(2)
            p_dict = _parse_yaml_flow_map(flow_body, anchors)
            if p_dict:
                if a_inline:
                    anchors[a_inline] = _copy.deepcopy(p_dict)
                parsed_proxies.append(p_dict)
            continue

        # 情况 B: 多行缩进块 - name: ...（使用标准缩进栈支持多层嵌套字典与列表）
        norm_lines: List[Tuple[int, str]] = []
        for idx_l, raw_l in enumerate(item_lines):
            stripped = raw_l.strip()
            if not stripped:
                continue
            indent = len(raw_l) - len(raw_l.lstrip())
            if idx_l == 0 and stripped.startswith("-"):
                dash_idx = raw_l.index("-")
                after = raw_l[dash_idx + 1:]
                content = after.strip()
                if content:
                    content_indent = dash_idx + 1 + (len(after) - len(after.lstrip()))
                    norm_lines.append((content_indent, content))
            else:
                norm_lines.append((indent, stripped))

        if not norm_lines:
            continue

        p_dict = _parse_indented_block(norm_lines)
        if isinstance(p_dict, dict) and p_dict:
            parsed_proxies.append(p_dict)

    return parsed_proxies


def _extract_clash_proxies(text: str) -> List[Dict[str, Any]]:
    """从 Clash YAML 文本提取并转换节点列表（优先 PyYAML，无依赖或失败时回退内置解析器）。"""
    text = (text or "").lstrip("\ufeff")
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
    text = (text or "").lstrip("\ufeff").strip()
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
        line = line.lstrip("\ufeff").strip()
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
        if isinstance(max_nodes, bool) or int(max_nodes) < 1:
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
            host = ",".join(str(x).strip() for x in host if str(x).strip())
        if host:
            q += f"&host={_q(host, safe=',')}"
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
        ntype = n.get("type")
        server = str(n.get("server") or "").strip()
        port = n.get("server_port")
        if not server or isinstance(port, bool) or not isinstance(port, int) or not (1 <= port <= 65535):
            continue
        raw_tag = n.get("tag") or "node"
        base_tag = re.sub(r"[\s/\\:\*\?\"<>\|']+", '-', str(raw_tag)).strip('-') or "node"
        cnt = tag_counts.get(base_tag, 0) + 1
        tag = base_tag if cnt == 1 else f"{base_tag}-{cnt}"
        while tag in used_tags:
            cnt += 1
            tag = f"{base_tag}-{cnt}"
        frag = _q(tag)
        host = _uri_host(server)   # authority 部分：IPv6 必须 [v6]
        trans_part = _dae_transport_query(n)
        tls_obj = n.get("tls") if isinstance(n.get("tls"), dict) else {}
        reality_obj = tls_obj.get("reality") if isinstance(tls_obj.get("reality"), dict) else {}
        utls_obj = tls_obj.get("utls") if isinstance(tls_obj.get("utls"), dict) else {}
        alpn_vals = [str(a).strip() for a in (tls_obj.get("alpn") if isinstance(tls_obj.get("alpn"), list) else []) if a is not None and not isinstance(a, (bool, dict, list)) and str(a).strip()]
        alpn_part = f"&alpn={_q(','.join(alpn_vals), safe=',')}" if alpn_vals else ""

        raw_uri = ""
        if ntype == "hysteria2":
            pw = _q(n.get("password", ""), safe=":")
            if not pw:
                continue
            tls = tls_obj
            sni = _q(_bare_host(tls.get("server_name") or server), safe=".:-")
            insecure = "&insecure=1" if tls.get("insecure") else ""
            obfs = n.get("obfs") if isinstance(n.get("obfs"), dict) else {}
            obfs_part = ""
            if obfs.get("type"):
                obfs_part = f"&obfs={_q(obfs.get('type'))}&obfs-password={_q(obfs.get('password') or '')}"
            srv_ports = n.get("server_ports") if isinstance(n.get("server_ports"), list) else []
            mport_part = f"&mport={_q(','.join(str(r).replace(':', '-') for r in srv_ports if r is not None and str(r).strip()), safe=',-')}" if srv_ports else ""
            raw_uri = f"hysteria2://{pw}@{host}:{port}?sni={sni}{insecure}{alpn_part}{mport_part}{obfs_part}#{frag}"
        elif ntype == "vless":
            uuid = _q(n.get("uuid", ""))
            if not uuid:
                continue
            flow = _q(n.get("flow") or "")
            tls = tls_obj
            flow_part = f"&flow={flow}" if flow else ""
            if reality_obj.get("enabled"):
                pbk = _q(reality_obj.get("public_key") or "")
                if not pbk:
                    continue
                sid = _q(reality_obj.get("short_id") or "")
                sni = _q(_bare_host(tls.get("server_name") or server), safe=".:-")
                fp = _q(utls_obj.get("fingerprint") or "chrome")
                raw_uri = f"vless://{uuid}@{host}:{port}?security=reality&sni={sni}&pbk={pbk}&sid={sid}&fp={fp}{alpn_part}{flow_part}{trans_part}#{frag}"
            elif tls.get("enabled"):
                sni = _q(_bare_host(tls.get("server_name") or server), safe=".:-")
                fp = _q(utls_obj.get("fingerprint") or "chrome")
                insecure = "&allowInsecure=1" if tls.get("insecure") else ""
                raw_uri = f"vless://{uuid}@{host}:{port}?security=tls&sni={sni}&fp={fp}{insecure}{alpn_part}{flow_part}{trans_part}#{frag}"
            else:
                raw_uri = f"vless://{uuid}@{host}:{port}?security=none{flow_part}{trans_part}#{frag}"
        elif ntype == "trojan":
            pw = _q(n.get("password", ""))
            if not pw:
                continue
            tls = tls_obj
            sni = _q(_bare_host(tls.get("server_name") or server), safe=".:-")
            insecure = "&allowInsecure=1" if tls.get("insecure") else ""
            tr_fp = utls_obj.get("fingerprint", "") if utls_obj.get("enabled") else ""
            fp_part = f"&fp={_q(tr_fp)}" if tr_fp else ""
            raw_uri = f"trojan://{pw}@{host}:{port}?sni={sni}{insecure}{fp_part}{alpn_part}{trans_part}#{frag}"
        elif ntype == "shadowsocks":
            method = n.get("method", "")
            pw = n.get("password", "")
            if not method or not pw:
                continue
            userpass = base64.b64encode(f"{method}:{pw}".encode()).decode()
            pl = str(n.get("plugin") or "").strip()
            pl_opts = str(n.get("plugin_opts") or "").strip()
            pl_query = ""
            if pl:
                full_pl = f"{pl};{pl_opts}" if pl_opts else pl
                pl_query = f"/?plugin={_q(full_pl)}"
            raw_uri = f"ss://{userpass}@{host}:{port}{pl_query}#{frag}"
        elif ntype == "vmess":
            uuid = str(n.get("uuid") or "").strip()
            if not uuid:
                continue
            security = str(n.get("security") or "auto")
            raw_aid = n.get("alter_id", 0)
            if isinstance(raw_aid, bool) or raw_aid is None:
                alter_id = 0
            else:
                try:
                    alter_id = int(raw_aid)
                except (ValueError, TypeError):
                    alter_id = 0
            tls = tls_obj
            transport = n.get("transport") if isinstance(n.get("transport"), dict) else {}
            net_type = str(transport.get("type") or "tcp")
            # gRPC 的服务名存在 service_name；v2rayN 格式用 path 承载 serviceName
            path = str(transport.get("path") or transport.get("service_name") or "")
            ws_host = ""
            headers = transport.get("headers")
            if isinstance(headers, dict):
                ws_host = headers.get("Host", "")
                if isinstance(ws_host, (list, tuple)):
                    ws_host = ws_host[0] if ws_host else ""
            if not ws_host and transport.get("host"):
                raw_th = transport.get("host")
                if isinstance(raw_th, (list, tuple)):
                    ws_host = ",".join(str(x) for x in raw_th if x is not None and str(x).strip())
                else:
                    ws_host = str(raw_th)
            vm = {
                "v": "2",
                "ps": tag,
                "add": _bare_host(server),
                "port": str(port),
                "id": uuid,
                "aid": str(alter_id),
                "scy": security,
                "net": net_type,
                "type": "none" if net_type == "tcp" else net_type,
                "host": str(ws_host or ""),
                "path": path,
                "tls": "tls" if tls.get("enabled") else "",
                "sni": _bare_host(tls.get("server_name") or server) if tls.get("enabled") else ""
            }
            if alpn_vals:
                vm["alpn"] = ",".join(alpn_vals)
            if utls_obj.get("enabled") and utls_obj.get("fingerprint"):
                vm["fp"] = str(utls_obj["fingerprint"])
            if tls.get("insecure"):
                vm["allowInsecure"] = 1
            b64 = base64.b64encode(json.dumps(vm, ensure_ascii=False).encode()).decode()
            raw_uri = f"vmess://{b64}"
        elif ntype == "tuic":
            uuid = _q(n.get("uuid", ""))
            pw = _q(n.get("password", ""))
            if not uuid or not pw:
                continue
            tls = tls_obj
            sni = _q(_bare_host(tls.get("server_name") or server), safe=".:-")
            cc = _q(n.get("congestion_control") or "bbr")
            urm = _q(n.get("udp_relay_mode") or "native")
            insecure = "&allow_insecure=1" if tls.get("insecure") else ""
            raw_uri = f"tuic://{uuid}:{pw}@{host}:{port}?congestion_control={cc}&udp_relay_mode={urm}&sni={sni}{insecure}{alpn_part}#{frag}"
        elif ntype == "anytls":
            pw = _q(n.get("password", ""))
            if not pw:
                continue
            tls = tls_obj
            sni = _q(_bare_host(tls.get("server_name") or server), safe=".:-")
            insecure = "&insecure=1" if tls.get("insecure") else ""
            raw_uri = f"anytls://{pw}@{host}:{port}?sni={sni}{insecure}{alpn_part}#{frag}"

        if raw_uri:
            tag_counts[base_tag] = cnt
            used_tags.add(tag)
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
