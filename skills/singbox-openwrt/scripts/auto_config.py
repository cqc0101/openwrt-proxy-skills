#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OpenWrt sing-box 智能内核版本探测与专属配置生成器 (v2.0)
功能：
1. SSH 远程探测目标软路由的 sing-box 真实版本 (v1.13 / v1.14+)
2. 根据版本自适应加载经过裁剪强化的 OpenWrt 专属模板 (FakeIP / RealIP)
3. 强制注入 OpenWrt 硬件防护字段 (/tmp 闪存防磨损、路由防环、0.0.0.0 Clash API)
4. 支持单节点注入 (--node) 与通用机场订阅批量注入 (--sub: 支持 URL / Base64 / Clash YAML)
5. 支持国内首启 CDN 规则集镜像加速 (--mirror: 彻底根除国内冷启动规则集下载死锁)
"""

import os
import sys
import json
import re
import argparse
import subprocess

# 中文 Windows 控制台 (cp936) 无法编码 emoji/部分字符，统一重配为 UTF-8 输出
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "assets", "templates"))

if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from parse_node import parse_uri
from sub_parser import parse_source, extract_node_domains

def version_ge(major_minor: str, min_major: int, min_minor: int) -> bool:
    """按主/次版本号做数值比较，避免 float('1.20') < 1.14 之类的坑。"""
    try:
        parts = major_minor.split(".")
        maj = int(parts[0])
        mnr = int(parts[1]) if len(parts) > 1 else 0
    except (ValueError, IndexError):
        return False
    return (maj > min_major) or (maj == min_major and mnr >= min_minor)


def detect_remote_version(host, user="root", port=22, timeout=5, key_path=None):
    """通过 SSH 远程执行 sing-box version 探测版本"""
    ssh_cmd = [
        "ssh",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", f"ConnectTimeout={timeout}",
        "-p", str(port),
    ]
    if key_path:
        ssh_cmd.extend(["-i", key_path])
    ssh_cmd.extend([
        f"{user}@{host}",
        "sing-box version 2>&1 | head -n 1"
    ])
    try:
        res = subprocess.run(ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout + 2)
        out = res.stdout.strip()
        match = re.search(r"sing-box version\s+(\d+\.\d+)", out)
        if match:
            major_minor = match.group(1)
            if version_ge(major_minor, 1, 14):
                return "1.14", out
            elif version_ge(major_minor, 1, 13):
                return "1.13", out
            else:
                print(f"[!] 目标软路由 sing-box 版本为 {out} (< 1.13)，建议升级至 1.14+ 现代版本以获得最佳稳定性与字段支持；已选用 1.13 基础规范兼容生成", file=sys.stderr)
                return "1.13", out
        return "1.13", out if out else "Unknown"
    except Exception as e:
        print(f"[!] 无法探测远程版本 ({e})，默认降级使用 1.13 稳定规范", file=sys.stderr)
        return "1.13", "Fallback-1.13"

def apply_cdn_mirror(config, mirror_type="jsdelivr"):
    """为 remote rule_set 注入国内可访问的 CDN 镜像源，解决国内冷启动死锁"""
    if mirror_type == "direct":
        return config

    rule_sets = config.get("route", {}).get("rule_set", [])
    for rs in rule_sets:
        url = rs.get("url", "")
        if "raw.githubusercontent.com" in url:
            if mirror_type == "jsdelivr":
                # 将 raw.githubusercontent.com/USER/REPO/BRANCH/PATH 转换为 testingcf.jsdelivr.net/gh/USER/REPO@BRANCH/PATH
                # 例如: raw.githubusercontent.com/SagerNet/sing-ruleset/ruleset/geoip-cn.srs
                m = re.match(r"https?://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.*)", url)
                if m:
                    user, repo, branch, path = m.groups()
                    rs["url"] = f"https://testingcf.jsdelivr.net/gh/{user}/{repo}@{branch}/{path}"
            elif mirror_type == "ghproxy":
                rs["url"] = f"https://ghproxy.net/{url}"
            elif mirror_type == "fastly":
                m = re.match(r"https?://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.*)", url)
                if m:
                    user, repo, branch, path = m.groups()
                    rs["url"] = f"https://fastly.jsdelivr.net/gh/{user}/{repo}@{branch}/{path}"
    return config

def build_config(version="1.13", dns_mode="fakeip", node_uris=None, sub_source=None, mirror="jsdelivr", max_nodes=15, wan_iface=None, dns_cn="alidns", dns_remote="google-dns", topology="main", main_router_ip=None):
    template_file = f"openwrt-{version}-tun-{dns_mode}.json"
    template_path = os.path.join(TEMPLATES_DIR, template_file)

    if not os.path.exists(template_path):
        # 严禁静默兜底：用户明确要 RealIP 时绝不允许悄悄生成 FakeIP 配置
        available = ", ".join(sorted(f for f in os.listdir(TEMPLATES_DIR) if f.endswith(".json"))) or "(无)"
        print(f"[FATAL] 找不到模板 {template_file}！", file=sys.stderr)
        print(f"       请求: sing-box v{version} + {dns_mode.upper()} 模式", file=sys.stderr)
        print(f"       assets/templates/ 目录现有模板: {available}", file=sys.stderr)
        print(f"       请检查 --version / --dns-mode 组合是否正确。", file=sys.stderr)
        sys.exit(2)

    with open(template_path, 'r', encoding='utf-8') as f:
        config = json.load(f)

    # 1. 强制注入 OpenWrt 防护字段（杜绝漏配）
    if "experimental" not in config:
        config["experimental"] = {}
    if "cache_file" not in config["experimental"]:
        config["experimental"]["cache_file"] = {"enabled": True}

    # 闪存写保护锁定在 /tmp
    config["experimental"]["cache_file"]["path"] = "/tmp/sing-box-cache.db"

    # Clash API 监听全网段，允许局域网设备控制与面板接入
    if "clash_api" not in config["experimental"]:
        config["experimental"]["clash_api"] = {}
    config["experimental"]["clash_api"]["external_controller"] = "0.0.0.0:9090"
    config["experimental"]["clash_api"].pop("external_ui", None)

    # 纯净 TUN 模式保护：禁用 auto_redirect 杜绝缺少 nfqueue 模块时的流量自环
    for ib in config.get("inbounds", []):
        if ib.get("type") == "tun":
            ib["auto_redirect"] = False

    # 路由防环与防死锁
    if "route" not in config:
        config["route"] = {}
    if wan_iface:
        # 显式 WAN 接口模式：缺 nfqueue 模块的内核（真机验证：Oray X1 Pro / ImmortalWrt SNAPSHOT）
        # auto_detect_interface 的自保会失效，直连流量被 TUN 自捕获（国内全 RST）
        config["route"].pop("auto_detect_interface", None)
        config["route"]["default_interface"] = wan_iface
    else:
        config["route"]["auto_detect_interface"] = True
    config["route"]["default_domain_resolver"] = "alidns"

    # 1.1 自定义 DNS 解析上游配置 (国内与海外防污染)
    dns_servers = config.get("dns", {}).get("servers", [])

    def _configure_dns_server(entry, val, presets, detour=None):
        val_str = val.strip()
        val_lower = val_str.lower()
        entry.pop("path", None)
        entry.pop("server_port", None)
        if val_lower in presets:
            srv, stype = presets[val_lower]
            entry["server"] = srv
            entry["type"] = stype
        elif val_lower.startswith(("https://", "http://")):
            import urllib.parse as _up
            parsed = _up.urlparse(val_str)
            entry["server"] = parsed.hostname or val_str
            entry["type"] = "https" if val_lower.startswith("https://") else "http"
            if parsed.port:
                entry["server_port"] = parsed.port
            if parsed.path and parsed.path not in ("/", "/dns-query"):
                entry["path"] = parsed.path
        else:
            entry["server"] = val_str
            entry["type"] = "udp"
        if detour:
            entry["detour"] = detour

    cn_server_entry = next((s for s in dns_servers if s.get("tag") == "alidns"), None)
    if cn_server_entry and dns_cn:
        _configure_dns_server(cn_server_entry, dns_cn, {
            "alidns": ("223.5.5.5", "udp"),
            "ali": ("223.5.5.5", "udp"),
            "223.5.5.5": ("223.5.5.5", "udp"),
            "dnspod": ("119.29.29.29", "udp"),
            "tencent": ("119.29.29.29", "udp"),
            "119.29.29.29": ("119.29.29.29", "udp"),
            "114": ("114.114.114.114", "udp"),
            "114.114.114.114": ("114.114.114.114", "udp"),
        })

    remote_server_entry = next((s for s in dns_servers if s.get("tag") == "google-dns"), None)
    if remote_server_entry and dns_remote:
        _configure_dns_server(remote_server_entry, dns_remote, {
            "google": ("8.8.8.8", "https"),
            "google-dns": ("8.8.8.8", "https"),
            "8.8.8.8": ("8.8.8.8", "https"),
            "cloudflare": ("1.1.1.1", "https"),
            "cf": ("1.1.1.1", "https"),
            "1.1.1.1": ("1.1.1.1", "https"),
            "quad9": ("9.9.9.9", "https"),
            "9.9.9.9": ("9.9.9.9", "https"),
        }, detour="proxy")

    # 2. 注入规则集国内镜像源（防冷启动死锁）
    if mirror and mirror != "direct":
        config = apply_cdn_mirror(config, mirror)

    # 3. 收集并解析节点
    parsed_outbounds = []
    
    # 3.1 单节点收集
    if node_uris:
        for u in node_uris:
            try:
                ob = parse_uri(u)
                parsed_outbounds.append(ob)
            except Exception as e:
                print(f"[!] 忽略无效节点 URI: {e}", file=sys.stderr)

    # 3.2 机场订阅或文件收集
    if sub_source:
        try:
            sub_nodes = parse_source(sub_source, max_nodes=max_nodes)
            parsed_outbounds.extend(sub_nodes)
        except Exception as e:
            print(f"[!] 解析订阅源失败: {e}", file=sys.stderr)

    # 4. 组装节点与策略组
    if parsed_outbounds:
        # 与模板内置出站重名的节点标签必须避让，否则节点会被去重逻辑丢弃，
        # 而 urltest/selector 里仍引用同名内置出站（如 direct/auto），造成错误路由或自引用
        reserved = {"proxy", "auto", "ai", "direct", "block"}
        clean_obs = []
        seen_tags = set()
        for o in parsed_outbounds:
            tag = o.get("tag", "node")
            if tag in reserved:
                tag = f"{tag}-node"
            if tag in seen_tags:
                tag = f"{tag}-{len(seen_tags)}"
            o["tag"] = tag
            seen_tags.add(tag)
            clean_obs.append(o)

        if max_nodes and len(clean_obs) > max_nodes:
            clean_obs = clean_obs[:max_nodes]

        # 4.1 节点域名直连防死锁注入 (Bootstrap DNS Protection)
        node_domains = extract_node_domains(clean_obs)
        if node_domains:
            for n in clean_obs:
                if n.get("server") in node_domains:
                    n["domain_resolver"] = "alidns"

            dns_rules = config.get("dns", {}).get("rules", [])
            dns_insert_idx = 1 if dns_rules and dns_rules[0].get("server") == "hosts" else 0
            dns_rules.insert(dns_insert_idx, {
                "action": "route",
                "domain": node_domains,
                "server": "alidns"
            })
            config["dns"]["rules"] = dns_rules

            route_rules = config.get("route", {}).get("rules", [])
            route_insert_idx = 0
            for idx, rr in enumerate(route_rules):
                if rr.get("action") in ["sniff", "hijack-dns"]:
                    route_insert_idx = idx + 1
            route_rules.insert(route_insert_idx, {
                "action": "route",
                "domain": node_domains,
                "outbound": "direct"
            })
            config["route"]["rules"] = route_rules

        node_tags = [o["tag"] for o in clean_obs]

        if node_tags:
            outbounds = config.get("outbounds", [])
            # 过滤掉模板中的默认假占位节点 (如 US-Node)，避免混淆与无效探测
            outbounds = [o for o in outbounds if o.get("tag") != "US-Node"]

            for ob in outbounds:
                if ob.get("tag") == "proxy" and ob.get("type") == "selector":
                    base_tags = [t for t in ob.get("outbounds", []) if t in ["auto", "direct"]]
                    ob["outbounds"] = base_tags + node_tags
                elif ob.get("tag") == "auto" and ob.get("type") == "urltest":
                    ob["outbounds"] = node_tags
                elif ob.get("tag") == "ai" and ob.get("type") == "selector":
                    ob["outbounds"] = ["proxy"] + node_tags
            
            # 将新节点保持正序插入到 direct / block 之前
            # 找到 direct 或 block 的位置作为插入锚点
            insert_idx = len(outbounds)
            for i, o in enumerate(outbounds):
                if o.get("tag") in ["direct", "block"]:
                    insert_idx = i
                    break

            # 过滤掉已存在的同 tag 节点后插入
            existing_tags = {o.get("tag") for o in outbounds}
            nodes_to_insert = [n for n in clean_obs if n["tag"] not in existing_tags]
            outbounds[insert_idx:insert_idx] = nodes_to_insert
            config["outbounds"] = outbounds

    # 5. 旁路由拓扑 (Bypass Gateway) 适配
    if topology == "bypass":
        if main_router_ip:
            cidr = f"{main_router_ip}/32" if "/" not in main_router_ip else main_router_ip
            route_rules = config.get("route", {}).get("rules", [])
            route_insert_idx = 0
            for idx, rr in enumerate(route_rules):
                if rr.get("action") in ["sniff", "hijack-dns"]:
                    route_insert_idx = idx + 1
            route_rules.insert(route_insert_idx, {
                "ip_cidr": [cidr],
                "action": "route",
                "outbound": "direct"
            })
            config["route"]["rules"] = route_rules

    return config

def main():
    parser = argparse.ArgumentParser(description="OpenWrt sing-box 智能版本探测与配置生成器 (v2.0)")
    parser.add_argument("--router", help="软路由 IP (指定后将自动 SSH 探测其安装的 sing-box 版本)")
    parser.add_argument("--user", default="root", help="SSH 用户名 (默认: root)")
    parser.add_argument("--port", type=int, default=22, help="SSH 端口 (默认: 22)")
    parser.add_argument("--key", help="SSH 私钥文件路径 (可选，用于探测软路由版本)")
    parser.add_argument("--version", choices=["1.13", "1.14"], help="手动强制指定版本 (若未指定 --router 时有效，默认 1.13)")
    parser.add_argument("--dns-mode", choices=["fakeip", "realip"], default="fakeip", help="DNS 分流模式 (默认: fakeip)")
    parser.add_argument("--node", action="append", help="节点链接 (支持多个 --node 注入)")
    parser.add_argument("--sub", help="机场订阅 (支持 HTTP/HTTPS URL、本地文件路径或 Base64 订阅文本)")
    parser.add_argument("--mirror", choices=["jsdelivr", "ghproxy", "fastly", "direct"], default="jsdelivr", help="规则集国内镜像加速 (默认 jsdelivr，彻底避免国内首启下载死锁)")
    parser.add_argument("--max-nodes", type=int, default=15, help="最多注入的节点数 (默认 15，保护弱路由内存)")
    parser.add_argument("--wan-iface", help="显式指定 WAN 接口 (如 eth0/pppoe-wan)；部分内核缺 nfqueue 模块时 auto_detect_interface 会使国内直连被 TUN 自捕获，此时必须显式指定")
    parser.add_argument("--dns-cn", default="alidns", help="国内 DNS 解析上游 (支持: alidns / dnspod / 114 或自定义 IP/URL，默认: alidns)")
    parser.add_argument("--dns-remote", default="google-dns", help="海外/被墙防污染 DNS 解析上游 (支持: google-dns / cloudflare / quad9 或自定义 IP/URL，默认: google-dns)")
    parser.add_argument("--topology", choices=["main", "bypass"], default="main", help="网络拓扑模式 (默认: main，旁路由模式请指定 bypass)")
    parser.add_argument("--main-router-ip", default=None, help="主路由 IP 地址 (旁路由模式下显式指定直连放行，如 192.168.1.1)")
    parser.add_argument("-o", "--out", help="输出配置文件路径 (不指定则输出到标准输出)")

    args = parser.parse_args()

    detected_ver = args.version or "1.13"
    if args.router:
        print(f"[*] 正在连接软路由 {args.user}@{args.router}:{args.port} 探测 sing-box 核心版本...", file=sys.stderr)
        v, raw_ver = detect_remote_version(args.router, args.user, args.port, key_path=args.key)
        print(f"[+] 探测到软路由内核版本: {raw_ver} -> 匹配规则集版本: v{v}", file=sys.stderr)
        detected_ver = v

    print(f"[*] 正在为 sing-box v{detected_ver} 生成 OpenWrt ({args.dns_mode.upper()} 模式, 拓扑: {args.topology}) 专属适配规则...", file=sys.stderr)
    if args.topology == "bypass":
        print(f"[i] 旁路由模式：生成后请运行 'sh setup_openwrt_network.sh --bypass' 开启 LAN 伪装以防非对称路由丢包。", file=sys.stderr)
    config = build_config(
        version=detected_ver, 
        dns_mode=args.dns_mode, 
        node_uris=args.node,
        sub_source=args.sub,
        mirror=args.mirror,
        max_nodes=args.max_nodes,
        wan_iface=args.wan_iface,
        dns_cn=args.dns_cn,
        dns_remote=args.dns_remote,
        topology=args.topology,
        main_router_ip=args.main_router_ip
    )

    # 生成后自动静态审计：存在任何阻断错误绝不输出（“一次成功”保障）
    from check_config import check_config_obj
    errors, warnings = check_config_obj(config)
    for w in warnings:
        print(f"[!] {w}", file=sys.stderr)
    if errors:
        print(f"[FATAL] 生成的配置未通过静态审计，已中止输出（共 {len(errors)} 个阻断错误）：", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        sys.exit(3)

    out_json = json.dumps(config, indent=2, ensure_ascii=False)
    if args.out:
        with open(args.out, 'w', encoding='utf-8') as f:
            f.write(out_json)
        print(f"[+] 专属配置已生成并保存至: {args.out}", file=sys.stderr)
    else:
        print(out_json)

if __name__ == "__main__":
    main()
