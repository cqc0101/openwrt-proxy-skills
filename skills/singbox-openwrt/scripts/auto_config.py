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
from sub_parser import parse_source

def version_ge(major_minor: str, min_major: int, min_minor: int) -> bool:
    """按主/次版本号做数值比较，避免 float('1.20') < 1.14 之类的坑。"""
    try:
        parts = major_minor.split(".")
        maj = int(parts[0])
        mnr = int(parts[1]) if len(parts) > 1 else 0
    except (ValueError, IndexError):
        return False
    return (maj > min_major) or (maj == min_major and mnr >= min_minor)


def detect_remote_version(host, user="root", port=22, timeout=5):
    """通过 SSH 远程执行 sing-box version 探测版本"""
    ssh_cmd = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", f"ConnectTimeout={timeout}",
        "-p", str(port),
        f"{user}@{host}",
        "sing-box version 2>&1 | head -n 1"
    ]
    try:
        res = subprocess.run(ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout + 2)
        out = res.stdout.strip()
        match = re.search(r"sing-box version\s+(\d+\.\d+)", out)
        if match:
            major_minor = match.group(1)
            if version_ge(major_minor, 1, 14):
                return "1.14", out
            else:
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

def build_config(version="1.13", dns_mode="fakeip", node_uris=None, sub_source=None, mirror="jsdelivr", max_nodes=15, wan_iface=None):
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
        # 去重并截断节点，防弱路由 OOM
        clean_obs = []
        seen_tags = set()
        for o in parsed_outbounds:
            tag = o.get("tag", "node")
            if tag in seen_tags:
                tag = f"{tag}-{len(seen_tags)}"
                o["tag"] = tag
            seen_tags.add(tag)
            clean_obs.append(o)

        if max_nodes and len(clean_obs) > max_nodes:
            clean_obs = clean_obs[:max_nodes]

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

    return config

def main():
    parser = argparse.ArgumentParser(description="OpenWrt sing-box 智能版本探测与配置生成器 (v2.0)")
    parser.add_argument("--router", help="软路由 IP (指定后将自动 SSH 探测其安装的 sing-box 版本)")
    parser.add_argument("--user", default="root", help="SSH 用户名 (默认: root)")
    parser.add_argument("--port", type=int, default=22, help="SSH 端口 (默认: 22)")
    parser.add_argument("--version", choices=["1.13", "1.14"], help="手动强制指定版本 (若未指定 --router 时有效，默认 1.13)")
    parser.add_argument("--dns-mode", choices=["fakeip", "realip"], default="fakeip", help="DNS 分流模式 (默认: fakeip)")
    parser.add_argument("--node", action="append", help="节点链接 (支持多个 --node 注入)")
    parser.add_argument("--sub", help="机场订阅 (支持 HTTP/HTTPS URL、本地文件路径或 Base64 订阅文本)")
    parser.add_argument("--mirror", choices=["jsdelivr", "ghproxy", "fastly", "direct"], default="jsdelivr", help="规则集国内镜像加速 (默认 jsdelivr，彻底避免国内首启下载死锁)")
    parser.add_argument("--max-nodes", type=int, default=15, help="最多注入的节点数 (默认 15，保护弱路由内存)")
    parser.add_argument("--wan-iface", help="显式指定 WAN 接口 (如 eth0/pppoe-wan)；部分内核缺 nfqueue 模块时 auto_detect_interface 会使国内直连被 TUN 自捕获，此时必须显式指定")
    parser.add_argument("--out", help="输出配置文件路径 (不指定则输出到标准输出)")

    args = parser.parse_args()

    detected_ver = args.version or "1.13"
    if args.router:
        print(f"[*] 正在连接软路由 {args.user}@{args.router}:{args.port} 探测 sing-box 核心版本...", file=sys.stderr)
        v, raw_ver = detect_remote_version(args.router, args.user, args.port)
        print(f"[+] 探测到软路由内核版本: {raw_ver} -> 匹配规则集版本: v{v}", file=sys.stderr)
        detected_ver = v

    print(f"[*] 正在为 sing-box v{detected_ver} 生成 OpenWrt ({args.dns_mode.upper()} 模式) 专属适配规则...", file=sys.stderr)
    config = build_config(
        version=detected_ver, 
        dns_mode=args.dns_mode, 
        node_uris=args.node,
        sub_source=args.sub,
        mirror=args.mirror,
        max_nodes=args.max_nodes,
        wan_iface=args.wan_iface
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
