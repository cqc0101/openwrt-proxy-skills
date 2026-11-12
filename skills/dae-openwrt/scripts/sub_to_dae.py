#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dae 节点与完整配置生成器 (支持输出 node 语法块，或注入 openwrt.dae 模板生成完整配置并自动静态审计)
支持自适应兼容老版本 dae (<= v1.0.0, legacy) 与新版本 dae (v1.1+ / v2.1.1+, modern)。
自包含：本技能自带 sub_parser.py / parse_node.py / check_dae_syntax.py。
"""

import ipaddress
import os
import re
import subprocess
import sys
import tempfile

# 中文 Windows 控制台 (cp936) 无法编码 emoji/部分字符，统一重配为 UTF-8 输出
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_PATH = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "assets", "templates", "openwrt.dae"))
CANDIDATES = [
    SCRIPT_DIR,
    os.path.abspath(os.path.join(SCRIPT_DIR, "..", "..", "singbox-openwrt", "scripts")),
]

SUB_PARSER_DIR = next((p for p in CANDIDATES if os.path.isfile(os.path.join(p, "sub_parser.py"))), None)
if SUB_PARSER_DIR is None:
    print("[-] 找不到 sub_parser.py！", file=sys.stderr)
    sys.exit(1)

if SUB_PARSER_DIR not in sys.path:
    sys.path.insert(0, SUB_PARSER_DIR)
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from sub_parser import parse_source, to_dae_nodes, redact_sensitive_text
from check_dae_syntax import check_dae_syntax

# 仅在 dae v1.1+ / v2.x 中引入的新字段；老版本 dae (v0.3 ~ v1.0.0) 不识别这些字段会导致 validate 报错
MODERN_ONLY_DAE_KEYS = (
    "bpf_conn_state_map_size",
    "auto_sniff_punt",
    "bootstrap_resolver",
    "optimistic_cache",
    "optimistic_cache_ttl",
)


def dae_version_ge(ver_str: str, min_major: int, min_minor: int) -> bool:
    """按主/次版本号比较 dae 版本，例如 '2.1.1' >= (1, 1) -> True，'1.0.0-r1' >= (1, 1) -> False。"""
    m = re.search(r"v?(\d+)\.(\d+)", str(ver_str or ""))
    if not m:
        return False
    maj, mnr = int(m.group(1)), int(m.group(2))
    return (maj > min_major) or (maj == min_major and mnr >= min_minor)


def detect_remote_dae_version(host, user="root", port=22, timeout=5, key_path=None, strict_host_key=None, known_hosts=None):
    """通过 SSH 远程执行 dae --version 探测软路由上的 dae 版本（含参数注入防护与 SSH 主机密钥安全门控）。"""
    host_str = str(host or "").strip()
    user_str = str(user or "root").strip()
    if not host_str or host_str.startswith("-") or re.search(r"\s", host_str):
        raise ValueError(f"非法的目标主机地址: {host!r}")
    if not user_str or user_str.startswith("-") or re.search(r"\s", user_str):
        raise ValueError(f"非法的 SSH 用户名: {user!r}")
    if isinstance(port, bool) or not (1 <= int(port) <= 65535):
        raise ValueError(f"SSH 端口超出合法范围 (1-65535): {port!r}")
    if isinstance(timeout, bool) or not (1 <= int(timeout) <= 60):
        raise ValueError(f"SSH 超时超出合法范围 (1-60s): {timeout!r}")
    if key_path is not None:
        kp = str(key_path).strip()
        if not kp or kp.startswith("-") or re.search(r"[\r\n]", kp) or not os.path.isfile(kp):
            raise ValueError(f"非法的 SSH 私钥路径: {key_path!r}")
        key_path = kp

    if strict_host_key is None:
        strict_env = (
            os.environ.get("OPENWRT_SSH_STRICT_HOST_KEY", "").strip()
            or os.environ.get("OPENWRT_STRICT_SSH", "").strip()
        )
        strict_host_key = strict_env.lower() in ("1", "true", "yes")
    if known_hosts is None:
        known_hosts = (
            os.environ.get("OPENWRT_SSH_KNOWN_HOSTS", "").strip()
            or os.environ.get("OPENWRT_KNOWN_HOSTS", "").strip()
            or None
        )

    hk_mode = "yes" if strict_host_key else "accept-new"
    ssh_cmd = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", f"StrictHostKeyChecking={hk_mode}",
        "-o", f"ConnectTimeout={int(timeout)}",
        "-p", str(int(port)),
    ]
    if known_hosts:
        kh_str = str(known_hosts).strip()
        if not kh_str or kh_str.startswith("-") or re.search(r"[\r\n\s]", kh_str):
            raise ValueError(f"非法的 known_hosts 路径: {known_hosts!r}")
        if os.name != "nt" and os.path.isfile(kh_str) and (os.stat(kh_str).st_mode & 0o022):
            raise PermissionError(f"known_hosts 权限不安全，拒绝使用可被其他用户篡改的文件: {kh_str}")
        ssh_cmd.extend(["-o", f"UserKnownHostsFile={kh_str}"])
    if key_path:
        ssh_cmd.extend(["-i", str(key_path)])
    ssh_cmd.extend([
        "--",
        f"{user_str}@{host_str}",
        "dae --version"
    ])
    try:
        res = subprocess.run(
            ssh_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout + 2,
        )
        combined_err = f"{res.stderr or ''}\n{res.stdout or ''}"
        if "REMOTE HOST IDENTIFICATION HAS CHANGED" in combined_err or "Host key verification failed" in combined_err:
            raise RuntimeError(
                f"[SSH_HOST_KEY_MISMATCH] 远程软路由 ({host_str}) SSH 主机密钥校验失败或发生变化，疑似中间人风险，已安全阻断！"
            )
        out = (res.stdout or "").strip()
        m = (
            re.search(r"\bdae\s+version\s+(v?\d+\.\d+[^\s]*)", out, re.IGNORECASE)
            or re.match(r"^(v?\d+\.\d+(?:\.\d+)?(?:-[a-zA-Z0-9._-]+)?)$", out)
        )
        ver_token = m.group(1) if m else ""
        if ver_token:
            if dae_version_ge(ver_token, 1, 1):
                return "modern", out
            print(
                f"[!] 探测到老版本 dae ({out} < v1.1)，自动切换为 legacy 兼容模式（剥离 v2.x 专属字段以保 100% 通过校验）",
                file=sys.stderr,
            )
            return "legacy", out
        err_msg = (res.stderr or out or "无输出").strip().splitlines()[0] if (res.stderr or out) else "无响应"
        print(f"[!] 远程探测未返回标准版本号 ({err_msg})，默认采用 modern (v2.x) 规范生成", file=sys.stderr)
        return "modern", out if out else "Fallback-modern"
    except RuntimeError:
        raise
    except Exception as e:
        print(f"[!] 无法探测远程 dae 版本 ({redact_sensitive_text(str(e))})，默认采用 modern (v2.x) 规范生成", file=sys.stderr)
        return "modern", "Fallback-modern"


def build_full_dae_config(
    nodes,
    lan_iface="br-lan",
    wan_iface="auto",
    topology="main",
    main_router_ip=None,
    ram_mb=None,
    dae_version="modern",
    template_path=None,
):
    """读取 openwrt.dae 基准模板，注入清洗后的 node 块、接口、旁路由规则及版本兼容裁剪，返回完整配置文本。"""
    if dae_version not in ("modern", "legacy"):
        raise ValueError(f"不支持的 dae_version={dae_version!r}，可选值为 'modern' 或 'legacy'")

    tpl_file = template_path or TEMPLATE_PATH
    if not os.path.isfile(tpl_file):
        raise FileNotFoundError(f"找不到 dae 模板文件: {tpl_file}")
    with open(tpl_file, "r", encoding="utf-8-sig") as f:
        tpl_text = f.read()

    node_block = to_dae_nodes(nodes)
    # 替换模板中的 node { ... } 块（锚定行首闭括号，防止注释或密码中的 } 提前截断）
    merged = re.sub(r"(?ms)^node\s*\{.*?^\}", lambda _: node_block, tpl_text, count=1)
    for _if_label, _if_val in (("lan_interface", lan_iface), ("wan_interface", wan_iface)):
        if _if_val is not None:
            _if_s = str(_if_val).strip()
            if not _if_s or _if_s.startswith("-") or not re.match(r"^[a-zA-Z0-9_.\-@:,]+$", _if_s):
                raise ValueError(f"非法的网卡接口名 ({_if_label}={_if_val!r})")
    if lan_iface and lan_iface != "br-lan":
        merged = re.sub(r"(?m)^(\s*lan_interface:\s*)\S+", lambda m: f"{m.group(1)}{lan_iface.strip()}", merged)
    if wan_iface and wan_iface != "auto":
        merged = re.sub(r"(?m)^(\s*wan_interface:\s*)\S+", lambda m: f"{m.group(1)}{wan_iface.strip()}", merged)
    if topology == "bypass":
        if not main_router_ip:
            print("[!] 提示: 旁路由模式 (--topology bypass) 未指定 --main-router-ip，建议指定主路由 IP 以配置直接放行规则。", file=sys.stderr)
        else:
            raw_gw = str(main_router_ip).strip()
            try:
                gw_if = ipaddress.ip_interface(raw_gw)
                gw_ip = str(gw_if.ip) if "/" not in raw_gw else str(gw_if)
            except ValueError as e:
                raise ValueError(f"非法的旁路由主网关 IP (--main-router-ip={main_router_ip!r}): {e}")
            gw_expr = f"'{gw_ip}'" if (":" in gw_ip or "/" in gw_ip) else gw_ip
            merged = re.sub(
                r"(?m)^(\s*pname\([^)]*dnsmasq[^)]*\)[^\n]*->\s*must_direct\s*)$",
                lambda m: f"{m.group(1)}\n    dip({gw_expr}) -> direct",
                merged,
                count=1,
            )
    if ram_mb is not None:
        if isinstance(ram_mb, bool) or int(ram_mb) <= 0:
            raise ValueError(f"--ram-mb 必须为正整数 (> 0)，当前值: {ram_mb!r}")
        r_mb = int(ram_mb)
        map_sz = 32768 if r_mb < 256 else (65536 if r_mb < 512 else 131072)
        merged = re.sub(
            r"(?m)^(\s*bpf_conn_state_map_size:\s*)\d+",
            lambda m: f"{m.group(1)}{map_sz}",
            merged,
        )
    if dae_version == "legacy":
        # 剥离仅 dae v1.1+/v2.x 支持的新字段，确保老版本 dae (v0.3 ~ v1.0.0) 100% 通过 dae validate
        key_alt = "|".join(re.escape(k) for k in MODERN_ONLY_DAE_KEYS)
        merged = re.sub(rf"(?m)^[ \t]*(?:{key_alt}):[^\n]*\n?", "", merged)
    return merged


def main():
    if len(sys.argv) < 2:
        print("用法: python sub_to_dae.py <机场订阅URL / Base64文件 / Clash配置> [--max 15] [--include 正则] [--full] [--dae-version modern|legacy] [-o /tmp/config.dae]")
        sys.exit(1)

    import argparse
    parser = argparse.ArgumentParser(description="dae 订阅转换与完整配置生成工具 (兼容新旧全版本 dae)")
    parser.add_argument("source", help="订阅来源 (URL/文件/Base64/单节点URI)")
    parser.add_argument("--max", type=int, default=15, help="保留最大节点数 (默认 15)")
    parser.add_argument("--allow-private-sub", action="store_true", help="允许从内网/本地 IP 拉取自建订阅转换服务 (如 Subconverter)")
    parser.add_argument("--allow-private-target", action="append", default=None, help="精确允许的私网订阅目标白名单 (如 192.168.1.10:25500 或 sub.home.arpa:443)")
    parser.add_argument("--include", help="包含节点匹配正则")
    parser.add_argument("--exclude", help="排除节点匹配正则")
    parser.add_argument("--full", action="store_true", help="注入 openwrt.dae 模板生成完整配置文件并执行内置 5 条铁律静态审计")
    parser.add_argument("--lan-iface", default="br-lan", help="完整配置模式下的局域网接口 (默认: br-lan)")
    parser.add_argument("--wan-iface", default="auto", help="完整配置模式下的外网接口 (默认: auto)")
    parser.add_argument("--topology", choices=["main", "bypass"], default="main", help="网络拓扑模式 (默认: main，旁路由请指定 bypass)")
    parser.add_argument("--main-router-ip", default=None, help="旁路由模式下的主路由 IP (如 192.168.1.1)")
    parser.add_argument("--ram-mb", type=int, default=None, help="目标路由器物理内存 MB (低于 512MB 时自动调小 bpf_conn_state_map_size 防 OOM)")
    parser.add_argument("--router", help="软路由 IP (指定后将自动通过 SSH 探测路由器上安装的 dae 版本是 modern 还是 legacy)")
    parser.add_argument("--user", default="root", help="SSH 用户名 (默认: root)")
    parser.add_argument("--port", type=int, default=22, help="SSH 端口 (默认: 22)")
    parser.add_argument("--key", help="SSH 私钥文件路径 (可选，用于远程探测 dae 版本)")
    parser.add_argument("--strict-host-key", action="store_true", help="强制要求目标路由器已在 known_hosts 中注册 (StrictHostKeyChecking=yes)")
    parser.add_argument("--known-hosts", default=None, help="自定义 SSH known_hosts 文件路径")
    parser.add_argument(
        "--dae-version",
        choices=["modern", "legacy"],
        default=None,
        help="目标 dae 版本模式：modern (适配 v1.1+/v2.1.1+，默认) 或 legacy (适配 <= v1.0.0 老版本，自动剥离新字段)",
    )
    parser.add_argument("-o", "--out", help="输出文件路径 (不指定则输出到标准输出)")

    args = parser.parse_args()

    try:
        nodes = parse_source(args.source, include=args.include, exclude=args.exclude, max_nodes=args.max, allow_private=args.allow_private_sub or None, allowed_private_targets=args.allow_private_target)
    except Exception as e:
        print(f"[-] 解析订阅失败: {redact_sensitive_text(str(e))}", file=sys.stderr)
        sys.exit(1)
    if not nodes:
        print("[-] 未能解析出有效节点", file=sys.stderr)
        sys.exit(1)

    if args.full:
        target_dae_ver = args.dae_version or "modern"
        try:
            if args.router and not args.dae_version:
                print(f"[*] 正在连接软路由 {args.user}@{args.router}:{args.port} 探测 dae 版本...", file=sys.stderr)
                target_dae_ver, raw_ver = detect_remote_dae_version(args.router, args.user, args.port, key_path=args.key, strict_host_key=args.strict_host_key or None, known_hosts=args.known_hosts)
                print(f"[+] 探测到远端 dae 版本: {raw_ver} -> 选用配置模式: {target_dae_ver}", file=sys.stderr)
            out_text = build_full_dae_config(
                nodes,
                lan_iface=args.lan_iface,
                wan_iface=args.wan_iface,
                topology=args.topology,
                main_router_ip=args.main_router_ip,
                ram_mb=args.ram_mb,
                dae_version=target_dae_ver,
            )
        except (ValueError, RuntimeError) as e:
            print(f"[FATAL] 参数校验失败: {e}", file=sys.stderr)
            sys.exit(1)
        with tempfile.NamedTemporaryFile("w", suffix=".dae", delete=False, encoding="utf-8") as tf:
            tf.write(out_text)
            tmp_dae = tf.name
        try:
            errors, warnings = check_dae_syntax(tmp_dae)
        finally:
            if os.path.exists(tmp_dae):
                os.remove(tmp_dae)
        for w in warnings:
            print(f"[!] {w}", file=sys.stderr)
        if errors:
            print(f"[FATAL] 生成的 dae 配置未通过静态审计（共 {len(errors)} 个阻断错误）：", file=sys.stderr)
            for err in errors:
                print(f"  - {err}", file=sys.stderr)
            sys.exit(3)
    else:
        out_text = to_dae_nodes(nodes)

    if args.out:
        with open(args.out, "w", encoding="utf-8", newline="\n") as f:
            f.write(out_text if out_text.endswith("\n") else out_text + "\n")
        print(f"[+] 成功转换 {len(nodes)} 个节点并写入: {args.out}", file=sys.stderr)
    else:
        print(out_text)
        print(f"[+] 成功转换 {len(nodes)} 个节点到 dae 语法格式", file=sys.stderr)


if __name__ == "__main__":
    main()
