#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OpenWrt sing-box 静态合规与防坑深度审计工具 (v3.1)
检查内容：
1. 废弃语法 (inbounds 中的 sniff, inet4_address 等)
2. 路由防环与防死锁 (auto_detect_interface, default_domain_resolver 纯 IP 校验)
3. 闪存磨损保护 (experimental.cache_file.path 必须指向 /tmp 或外部盘)
4. 引用完整性与悬空检查 (Rule-set 含嵌套 logical 规则, Outbounds, route.final, selector.default, DNS servers, HTTP clients)
5. 全局重复 Tag 冲突检测与空策略组检测
6. 版本字段门控 (1.13 与 1.14 专属字段混用检测)
7. outbound.network 枚举合法性 (只接受 tcp/udp)

本模块同时被 auto_config.py 复用：生成配置后先过 check_config_obj，
有阻断错误绝不输出（保证“一次成功”）。
"""

import sys
import os
import json
import ipaddress

# 中文 Windows 控制台 (cp936) 无法编码 emoji/部分字符，统一重配为 UTF-8 输出
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def _is_ip_literal(addr: str) -> bool:
    """使用标准库 ipaddress 严格校验纯 IPv4 / IPv6 字面量，防止 'dns.alidns.com:53' 等带冒号域名绕过。"""
    s = str(addr or "").strip().strip("[]")
    if not s:
        return False
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _iter_rules_recursive(rules):
    """递归遍历规则列表（包含 type=logical 的嵌套子规则），返回 (top_idx, rule_dict)。"""
    for idx, r in enumerate(rules or []):
        if not isinstance(r, dict):
            continue
        yield idx, r
        if r.get("type") == "logical" and isinstance(r.get("rules"), list):
            for _, sub_r in _iter_rules_recursive(r.get("rules")):
                yield idx, sub_r


def check_config_obj(cfg):
    """对已解析的配置字典做静态审计，返回 (errors, warnings)。"""
    errors = []
    warnings = []

    if not isinstance(cfg, dict):
        return ["[数据结构错误] 顶层配置必须是 JSON 对象 (dict)"], []

    # 规范化顶层对象，防止 None 穿透崩溃
    dns = cfg.get("dns") if isinstance(cfg.get("dns"), dict) else {}
    route = cfg.get("route") if isinstance(cfg.get("route"), dict) else {}
    outbounds = [o for o in (cfg.get("outbounds") or []) if isinstance(o, dict)]
    inbounds = [i for i in (cfg.get("inbounds") or []) if isinstance(i, dict)]
    http_clients = [c for c in (cfg.get("http_clients") or []) if isinstance(c, dict)]

    if cfg.get("dns") is not None and not isinstance(cfg.get("dns"), dict):
        errors.append("[数据结构错误] dns 模块必须是对象 (dict)")
    if cfg.get("route") is not None and not isinstance(cfg.get("route"), dict):
        errors.append("[数据结构错误] route 模块必须是对象 (dict)")
    if cfg.get("outbounds") is not None and not isinstance(cfg.get("outbounds"), list):
        errors.append("[数据结构错误] outbounds 模块必须是列表 (list)")
    if cfg.get("inbounds") is not None and not isinstance(cfg.get("inbounds"), list):
        errors.append("[数据结构错误] inbounds 模块必须是列表 (list)")

    # 0. 检查各模块是否存在重复 Tag 冲突
    def _collect_tags(items, module_name):
        seen = set()
        for idx, item in enumerate(items or []):
            if not isinstance(item, dict):
                continue
            t = item.get("tag")
            if t:
                if t in seen:
                    errors.append(f"[重复标签] {module_name}[{idx}] 存在重复的 tag: '{t}'！")
                seen.add(t)
        return seen

    dns_servers = _collect_tags(dns.get("servers"), "dns.servers")
    all_outbounds = _collect_tags(outbounds, "outbounds")
    all_inbounds = _collect_tags(inbounds, "inbounds")
    all_rulesets = _collect_tags(route.get("rule_set"), "route.rule_set")
    all_http_clients = _collect_tags(http_clients, "http_clients")
    _ = all_inbounds

    # 1. 检查 route 模块
    if not route:
        warnings.append("未配置 route 块，路由行为将全部依赖默认设置。")
    else:
        if not route.get("auto_detect_interface") and not route.get("default_interface"):
            warnings.append("[防环风险] route 块中未开启 'auto_detect_interface: true' 或 'default_interface'，在 TUN 模式下可能引发路由自环！")

        resolver = route.get("default_domain_resolver")
        if not resolver:
            warnings.append("[解析死锁风险] route 块未指定 'default_domain_resolver'。启动阶段拉取规则集可能陷入 DNS 递归死锁！")
        elif resolver not in dns_servers:
            errors.append(f"[悬空引用] route.default_domain_resolver 指向 '{resolver}'，但在 dns.servers 中未找到此 tag！")
        else:
            # 校验引导 DNS 自身地址不能是域名（否则启动初期解析该域名必陷入递归死锁）
            resolver_entry = next((s for s in (dns.get("servers") or []) if isinstance(s, dict) and s.get("tag") == resolver), None)
            if resolver_entry:
                r_server = str(resolver_entry.get("server", "")).strip()
                r_type = resolver_entry.get("type", "")
                if r_server and r_type not in ("local", "hosts", "fakeip"):
                    if not _is_ip_literal(r_server):
                        errors.append(f"[致命递归死锁] route.default_domain_resolver 指向的 '{resolver}' 服务器地址为域名 '{r_server}'！引导解析器自身地址必须为纯 IP，否则启动即陷入 DNS 递归死锁！")

        http_client = route.get("default_http_client")
        if http_client and http_client not in all_http_clients:
            errors.append(f"[悬空引用] route.default_http_client 声明为 '{http_client}'，但顶级 http_clients 中未找到该 client！")

        final_ob = route.get("final")
        if final_ob and final_ob not in all_outbounds:
            errors.append(f"[悬空引用] route.final 指向不存在的 outbound: '{final_ob}'！")

        rules = [r for r in (route.get("rules") or []) if isinstance(r, dict)]
        has_sniff = any(r.get("action") == "sniff" for r in rules)
        has_hijack_dns = any(r.get("action") == "hijack-dns" for r in rules)

        if not has_sniff:
            warnings.append("[建议] route.rules 首部未发现 {'action': 'sniff'} 嗅探规则。")
        if not has_hijack_dns:
            warnings.append("[DNS 风险] route.rules 中未发现 {'action': 'hijack-dns'} 规则，局域网 DNS 可能无法被截获。")

        # 检查 route.rules（含嵌套 logical 子规则）中的 outbound 和 rule_set 引用
        for idx, r in _iter_rules_recursive(rules):
            ob = r.get("outbound")
            if ob and ob not in all_outbounds:
                errors.append(f"[悬空引用] route.rules[{idx}] 引用了不存在的 outbound: '{ob}'！")

            rs_field = r.get("rule_set", [])
            if isinstance(rs_field, str):
                rs_field = [rs_field]
            elif not isinstance(rs_field, list):
                rs_field = []
            for rs in rs_field:
                if rs not in all_rulesets:
                    errors.append(f"[悬空引用] route.rules[{idx}] 引用了未在 route.rule_set 中定义的规则集: '{rs}'！")

    # 2. 检查 dns 模块的引用完整性（含嵌套 logical 子规则）
    dns_rules = [dr for dr in (dns.get("rules") or []) if isinstance(dr, dict)]
    for idx, dr in _iter_rules_recursive(dns_rules):
        target_server = dr.get("server")
        if target_server and target_server not in dns_servers and target_server != "hosts":
            errors.append(f"[悬空引用] dns.rules[{idx}] 指向不存在的 DNS server: '{target_server}'！")

        rs_field = dr.get("rule_set", [])
        if isinstance(rs_field, str):
            rs_field = [rs_field]
        elif not isinstance(rs_field, list):
            rs_field = []
        for rs in rs_field:
            if rs not in all_rulesets:
                errors.append(f"[悬空引用] dns.rules[{idx}] 引用了未定义的规则集: '{rs}'！")

    final_dns = dns.get("final")
    if final_dns and final_dns not in dns_servers:
        errors.append(f"[悬空引用] dns.final 指向不存在的 DNS server: '{final_dns}'！")

    for idx, s in enumerate(dns.get("servers") or []):
        if not isinstance(s, dict):
            continue
        s_detour = s.get("detour")
        if s_detour and s_detour not in all_outbounds:
            errors.append(f"[悬空引用] dns.servers[{idx}]({s.get('tag')}) 的 detour 指向未定义的 outbound: '{s_detour}'！")
        s_resolver = s.get("domain_resolver")
        if s_resolver:
            if s_resolver not in dns_servers:
                errors.append(f"[悬空引用] dns.servers[{idx}]({s.get('tag')}) 的 domain_resolver 指向未定义的 DNS server: '{s_resolver}'！")
            elif s.get("tag") and s_resolver == s.get("tag"):
                errors.append(f"[自环死锁] dns.servers[{idx}]({s.get('tag')}) 的 domain_resolver 不能指向自身 '{s_resolver}'！")

    # 3. 检查 outbounds 模块及内部引用
    for idx, ob in enumerate(outbounds):
        ob_type = ob.get("type", "")
        ob_tag = ob.get("tag")
        if ob_type in ["selector", "urltest"]:
            sub_obs = ob.get("outbounds")
            if not isinstance(sub_obs, list) or len(sub_obs) == 0:
                errors.append(f"[空策略组] outbound[{idx}]({ob_tag}) 的 outbounds 列表不能为空！")
            else:
                for so in sub_obs:
                    if so not in all_outbounds:
                        errors.append(f"[悬空引用] outbound[{idx}]({ob_tag}) 列表中引用了未定义的 outbound: '{so}'！")
                    elif ob_tag and so == ob_tag:
                        errors.append(f"[自环引用] outbound[{idx}]({ob_tag}) 列表中不能自引用自身 '{ob_tag}'！")
                if ob_type == "selector" and ob.get("default"):
                    def_tag = ob.get("default")
                    if def_tag not in sub_obs:
                        errors.append(f"[悬空引用] outbound[{idx}]({ob_tag}) 的 default 指向 '{def_tag}'，但该标签不在其 outbounds 列表中！")
                elif ob_type == "urltest" and "default" in ob:
                    errors.append(f"[非法字段] outbound[{idx}]({ob_tag}) 类型为 urltest，不支持 'default' 字段（仅 selector 支持）！")

        # 检查代理链与 detour 引用完整性
        ob_detour = ob.get("detour")
        if ob_detour:
            if ob_detour not in all_outbounds:
                errors.append(f"[悬空引用] outbound[{idx}]({ob_tag}) 的 detour 指向未定义的 outbound: '{ob_detour}'！")
            elif ob_tag and ob_detour == ob_tag:
                errors.append(f"[自环引用] outbound[{idx}]({ob_tag}) 的 detour 不能指向自身！")

        # network 字段只接受 tcp/udp；ws/grpc 必须走 transport（常见笔误）
        net = ob.get("network")
        if net and net not in ("tcp", "udp"):
            errors.append(f"[非法字段] outbound[{idx}]({ob_tag}) 的 'network' 设为 '{net}'，sing-box 只接受 'tcp'/'udp'！ws/grpc 请使用 'transport' 块。")

        # 检查 transport.type 合法性（拦截手改配置中的 xhttp/splithttp/kcp 等不支持传输层）
        trans = ob.get("transport")
        if isinstance(trans, dict):
            ttype = str(trans.get("type") or "").strip().lower()
            if ttype and ttype not in ("ws", "grpc", "http", "httpupgrade", "quic"):
                errors.append(f"[非法传输层] outbound[{idx}]({ob_tag}) 的 transport.type '{ttype}' 不受 sing-box 标准传输层支持（仅支持 ws/grpc/http/httpupgrade/quic）！")

        # 检查代理节点端口范围合法性 (1..65535) 与 Reality 必填字段
        if ob_type in ("vless", "vmess", "trojan", "shadowsocks", "hysteria2", "tuic", "anytls") and "server_port" in ob:
            sp = ob.get("server_port")
            if not isinstance(sp, int) or isinstance(sp, bool) or not (1 <= sp <= 65535):
                errors.append(f"[非法端口] outbound[{idx}]({ob_tag}) 的 server_port '{sp}' 超出合法端口范围 (1-65535)！")

        # 检查 Shadowsocks 加密方法合法性（拦截 sing-box 不支持的废弃流加密方法）
        if ob_type == "shadowsocks":
            ss_method = str(ob.get("method") or "").strip().lower()
            deprecated_ciphers = {
                "aes-256-cfb", "aes-128-cfb", "aes-192-cfb", "rc4-md5",
                "bf-cfb", "cast5-cfb", "des-cfb", "idea-cfb", "rc2-cfb", "seed-cfb",
                "salsa20", "chacha20"
            }
            if ss_method in deprecated_ciphers:
                errors.append(f"[废弃加密] outbound[{idx}]({ob_tag}) shadowsocks 使用了 sing-box 已废弃/不支持的加密方法 '{ss_method}'！请使用 2022-blake3 或 AEAD (aes-gcm / chacha20-poly1305)。")

        tls_cfg = ob.get("tls")
        if isinstance(tls_cfg, dict):
            reality_cfg = tls_cfg.get("reality")
            if isinstance(reality_cfg, dict) and reality_cfg.get("enabled") is True:
                if not str(reality_cfg.get("public_key") or "").strip():
                    errors.append(f"[Reality 配置残缺] outbound[{idx}]({ob_tag}) 启用了 Reality，但缺少 public_key！")
                if not str(tls_cfg.get("server_name") or "").strip():
                    errors.append(f"[Reality 配置残缺] outbound[{idx}]({ob_tag}) 启用了 Reality，但缺少 tls.server_name (SNI)！")

    # 4. 检查 inbounds 模块
    for idx, ib in enumerate(inbounds):
        ib_type = ib.get("type", "")
        if "sniff" in ib or "sniff_override_destination" in ib:
            errors.append(f"inbounds[{idx}] 发现已废弃字段 'sniff'！sing-box 1.12+ 必须在 route.rules 中使用 {{'action': 'sniff'}}。")
        if ib_type == "tun":
            if "inet4_address" in ib or "inet6_address" in ib:
                errors.append(f"inbounds[{idx}](tun) 包含已废弃的 'inet4_address'/'inet6_address'，请合并至 'address' 数组。")
            addr_field = ib.get("address")
            if addr_field is not None:
                addr_list = [addr_field] if isinstance(addr_field, str) else (addr_field if isinstance(addr_field, list) else [])
                for a_item in addr_list:
                    a_str = str(a_item or "").strip()
                    if "/" not in a_str:
                        errors.append(f"[非法 TUN 地址] inbounds[{idx}](tun) 的 address '{a_str}' 缺少 CIDR 掩码前缀（如 '/30'）！")
                    else:
                        try:
                            ipaddress.ip_interface(a_str)
                        except ValueError:
                            errors.append(f"[非法 TUN 地址] inbounds[{idx}](tun) 的 address '{a_str}' 不是合法的 IP CIDR！")
            if ib.get("stack") is not None:
                warnings.append(f"inbounds[{idx}](tun) 显式设置了 'stack'，该选项自 sing-box 1.15 起已废弃，建议删除以使用默认值。")
            if ib.get("auto_redirect") is True:
                warnings.append(f"inbounds[{idx}](tun) 启用了 'auto_redirect': true！OpenWrt 环境下缺少 nfqueue 模块时将导致流量自环死锁，强烈推荐设为 false。")

    # 5. 检查 experimental.cache_file 闪存磨损保护
    exp = cfg.get("experimental") if isinstance(cfg.get("experimental"), dict) else {}
    cache_file = exp.get("cache_file") if isinstance(exp.get("cache_file"), dict) else {}
    if cache_file.get("enabled"):
        cpath = cache_file.get("path", "")
        if not cpath:
            warnings.append("[闪存高危] experimental.cache_file 未指定 path，将写入默认目录！强烈建议指定 '/tmp/sing-box-cache.db' 以保护路由器闪存。")
        elif not (cpath.startswith("/tmp/") or cpath.startswith("/mnt/") or cpath.startswith("/media/")):
            warnings.append(f"[闪存高危] experimental.cache_file.path 设为 '{cpath}'！强烈建议设置在 '/tmp/sing-box-cache.db'。")

    # 6. 版本门控混合检测（1.13 与 1.14 字段混用最常见的两类事故）
    rule_sets = [r for r in (route.get("rule_set") or []) if isinstance(r, dict)]
    has_legacy = any([
        "independent_cache" in dns,
        "store_rdrc" in cache_file,
        any(r.get("download_detour") for r in rule_sets),
    ])
    has_modern = any([
        "optimistic" in dns,
        "store_dns" in cache_file,
        "default_http_client" in route,
        "http_clients" in cfg,
    ])
    if has_legacy and has_modern:
        warnings.append("[版本混用] 配置同时包含 1.13 专属字段 (independent_cache/store_rdrc/download_detour) 与 1.14+ 字段 (optimistic/store_dns/default_http_client)！请确认目标 sing-box 版本后只保留一套。")

    # 6.5 规则集下载 detour 指向 direct 的致命模式（启动期崩溃，真机验证）
    for idx, client in enumerate(http_clients):
        if not isinstance(client, dict):
            continue
        if client.get("detour") == "direct":
            errors.append(f"[致命模式] http_clients[{idx}]({client.get('tag')}) 的 detour 指向 'direct'。"
                          "sing-box 启动期下载规则集时会报 'detour to an empty direct outbound makes no sense' 并退出。"
                          "直连下载请删除 detour 字段（不设即直连）。")
        elif client.get("detour") and client.get("detour") not in all_outbounds:
            errors.append(f"[悬空引用] http_clients[{idx}]({client.get('tag')}) 的 detour 指向未定义的 outbound: '{client.get('detour')}'！")

    for idx, rs in enumerate(route.get("rule_set") or []):
        if not isinstance(rs, dict):
            continue
        if rs.get("download_detour") == "direct":
            errors.append(f"[致命模式] route.rule_set[{idx}]({rs.get('tag')}) 的 download_detour 指向 'direct'，"
                          "启动期同样会触发 'empty direct outbound' 崩溃；直连下载请删除该字段。")
        elif rs.get("download_detour") and rs.get("download_detour") not in all_outbounds:
            errors.append(f"[悬空引用] route.rule_set[{idx}]({rs.get('tag')}) 的 download_detour 指向未定义的 outbound: '{rs.get('download_detour')}'！")

    # 6.6 auto_detect_interface 与 default_interface 冲突检测
    if route.get("auto_detect_interface") and route.get("default_interface"):
        warnings.append("[配置冲突] route 同时启用 auto_detect_interface 与 default_interface，运行时会互相覆盖；"
                        "请只保留其一（缺 nfqueue 模块的设备推荐显式 default_interface）。")

    # 7. 节点服务器域名解析防死锁闭环审计 (Bootstrap DNS Check)
    node_domains = set()
    for ob in outbounds:
        if ob.get("type") in ("vless", "hysteria2", "trojan", "shadowsocks", "vmess", "tuic", "anytls"):
            srv = str(ob.get("server") or "").strip()
            if srv and not _is_ip_literal(srv):
                node_domains.add(srv)

    if node_domains:
        has_resolver = bool(route.get("default_domain_resolver"))
        explicit_domains = set()
        for _, dr in _iter_rules_recursive(dns_rules):
            d_field = dr.get("domain", [])
            if isinstance(d_field, str):
                d_field = [d_field]
            elif isinstance(d_field, list):
                explicit_domains.update(d_field)

        uncovered = node_domains - explicit_domains
        if not has_resolver and uncovered:
            warnings.append(
                f"[启动死锁隐患] 出站节点使用了域名 ({list(uncovered)[:3]})，但未指定 route.default_domain_resolver，"
                "且未在 dns.rules 显式指定直连 DNS 解析器！节点建连时可能陷入 DNS 递归死锁。"
            )

    return errors, warnings


def check_singbox_config(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            cfg = json.load(f)
    except Exception as e:
        return [f"JSON 解析失败: {e}"], []
    return check_config_obj(cfg)


def main():
    if len(sys.argv) < 2:
        print("用法: python check_config.py <配置文件路径>")
        sys.exit(1)

    filepath = sys.argv[1]
    if not os.path.exists(filepath):
        print(f"错误: 目标文件不存在: {filepath}")
        sys.exit(1)

    print(f"[*] 正在深度审计 sing-box 配置文件: {filepath}")
    errors, warnings = check_singbox_config(filepath)

    if errors:
        print(f"\n[!] 发现 {len(errors)} 个严重阻断错误:")
        for e in errors:
            print(f"  - [ERROR] {e}")

    if warnings:
        print(f"\n[!] 发现 {len(warnings)} 个优化建议:")
        for w in warnings:
            print(f"  - [WARN] {w}")

    if not errors and not warnings:
        print("\n[+] 静态审计通过，未发现明显违规。")
    elif not errors:
        print("\n[+] 语法合法无致命错误。")
    else:
        print("\n[x] 检查未通过，请修复后重试。")
        sys.exit(1)

    print("[i] 提示：本工具仅做静态检查，部署前请务必以远端 'sing-box check -c <file>' 的结论为准。")
    return 0


if __name__ == '__main__':
    main()
