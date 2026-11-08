#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OpenWrt sing-box 静态合规与防坑深度审计工具 (v3.0)
检查内容：
1. 废弃语法 (inbounds 中的 sniff, inet4_address 等)
2. 路由防环与防死锁 (auto_detect_interface, default_domain_resolver)
3. 闪存磨损保护 (experimental.cache_file.path 必须指向 /tmp 或外部盘)
4. 引用完整性与悬空检查 (Rule-set, Outbounds, DNS servers, HTTP clients)
5. 版本字段门控 (1.13 与 1.14 专属字段混用检测)
6. outbound.network 枚举合法性 (只接受 tcp/udp)

本模块同时被 auto_config.py 复用：生成配置后先过 check_config_obj，
有阻断错误绝不输出（保证“一次成功”）。
"""

import sys
import os
import json

# 中文 Windows 控制台 (cp936) 无法编码 emoji/部分字符，统一重配为 UTF-8 输出
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def check_config_obj(cfg):
    """对已解析的配置字典做静态审计，返回 (errors, warnings)。"""
    errors = []
    warnings = []

    # 收集全部已定义的各类 Tag，用于全链路引用完整性校验
    dns_servers = {s.get("tag") for s in cfg.get("dns", {}).get("servers", []) if s.get("tag")}
    all_outbounds = {o.get("tag") for o in cfg.get("outbounds", []) if o.get("tag")}
    all_rulesets = {r.get("tag") for r in cfg.get("route", {}).get("rule_set", []) if r.get("tag")}
    all_http_clients = {c.get("tag") for c in cfg.get("http_clients", []) if c.get("tag")}

    # 1. 检查 route 模块
    route = cfg.get("route", {})
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

        http_client = route.get("default_http_client")
        if http_client and http_client not in all_http_clients:
            errors.append(f"[悬空引用] route.default_http_client 声明为 '{http_client}'，但顶级 http_clients 中未找到该 client！")

        rules = route.get("rules", [])
        has_sniff = any(r.get("action") == "sniff" for r in rules)
        has_hijack_dns = any(r.get("action") == "hijack-dns" for r in rules)

        if not has_sniff:
            warnings.append("[建议] route.rules 首部未发现 {'action': 'sniff'} 嗅探规则。")
        if not has_hijack_dns:
            warnings.append("[DNS 风险] route.rules 中未发现 {'action': 'hijack-dns'} 规则，局域网 DNS 可能无法被截获。")

        # 检查 route.rules 中的 outbound 和 rule_set 引用
        for idx, r in enumerate(rules):
            ob = r.get("outbound")
            if ob and ob not in all_outbounds:
                errors.append(f"[悬空引用] route.rules[{idx}] 引用了不存在的 outbound: '{ob}'！")

            rs_field = r.get("rule_set", [])
            if isinstance(rs_field, str):
                rs_field = [rs_field]
            for rs in rs_field:
                if rs not in all_rulesets:
                    errors.append(f"[悬空引用] route.rules[{idx}] 引用了未在 route.rule_set 中定义的规则集: '{rs}'！")

    # 2. 检查 dns 模块的引用完整性
    dns = cfg.get("dns", {})
    dns_rules = dns.get("rules", [])
    for idx, dr in enumerate(dns_rules):
        target_server = dr.get("server")
        if target_server and target_server not in dns_servers and target_server != "hosts":
            errors.append(f"[悬空引用] dns.rules[{idx}] 指向不存在的 DNS server: '{target_server}'！")

        rs_field = dr.get("rule_set", [])
        if isinstance(rs_field, str):
            rs_field = [rs_field]
        for rs in rs_field:
            if rs not in all_rulesets:
                errors.append(f"[悬空引用] dns.rules[{idx}] 引用了未定义的规则集: '{rs}'！")

    final_dns = dns.get("final")
    if final_dns and final_dns not in dns_servers:
        errors.append(f"[悬空引用] dns.final 指向不存在的 DNS server: '{final_dns}'！")

    # 3. 检查 outbounds 模块及内部引用
    outbounds = cfg.get("outbounds", [])
    for idx, ob in enumerate(outbounds):
        ob_type = ob.get("type", "")
        if ob_type in ["selector", "urltest"]:
            sub_obs = ob.get("outbounds", [])
            for so in sub_obs:
                if so not in all_outbounds:
                    errors.append(f"[悬空引用] outbound[{idx}]({ob.get('tag')}) 列表中引用了未定义的 outbound: '{so}'！")

        # network 字段只接受 tcp/udp；ws/grpc 必须走 transport（常见笔误）
        net = ob.get("network")
        if net and net not in ("tcp", "udp"):
            errors.append(f"[非法字段] outbound[{idx}]({ob.get('tag')}) 的 'network' 设为 '{net}'，sing-box 只接受 'tcp'/'udp'！ws/grpc 请使用 'transport' 块。")

    # 4. 检查 inbounds 模块
    inbounds = cfg.get("inbounds", [])
    for idx, ib in enumerate(inbounds):
        ib_type = ib.get("type", "")
        if "sniff" in ib or "sniff_override_destination" in ib:
            errors.append(f"inbounds[{idx}] 发现已废弃字段 'sniff'！sing-box 1.12+ 必须在 route.rules 中使用 {{'action': 'sniff'}}。")
        if ib_type == "tun":
            if "inet4_address" in ib or "inet6_address" in ib:
                errors.append(f"inbounds[{idx}](tun) 包含已废弃的 'inet4_address'/'inet6_address'，请合并至 'address' 数组。")
            if ib.get("stack") is not None:
                warnings.append(f"inbounds[{idx}](tun) 显式设置了 'stack'，该选项自 sing-box 1.15 起已废弃，建议删除以使用默认值。")

    # 5. 检查 experimental.cache_file 闪存磨损保护
    exp = cfg.get("experimental", {})
    cache_file = exp.get("cache_file", {})
    if cache_file.get("enabled"):
        cpath = cache_file.get("path", "")
        if not cpath:
            warnings.append("[闪存高危] experimental.cache_file 未指定 path，将写入默认目录！强烈建议指定 '/tmp/sing-box-cache.db' 以保护路由器闪存。")
        elif not (cpath.startswith("/tmp/") or cpath.startswith("/mnt/") or cpath.startswith("/media/")):
            warnings.append(f"[闪存高危] experimental.cache_file.path 设为 '{cpath}'！强烈建议设置在 '/tmp/sing-box-cache.db'。")

    # 6. 版本门控混合检测（1.13 与 1.14 字段混用最常见的两类事故）
    has_legacy = any([
        "independent_cache" in dns,
        "store_rdrc" in cache_file,
        any(r.get("download_detour") for r in cfg.get("route", {}).get("rule_set", [])),
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
    for idx, client in enumerate(cfg.get("http_clients") or []):
        if client.get("detour") == "direct":
            errors.append(f"[致命模式] http_clients[{idx}]({client.get('tag')}) 的 detour 指向 'direct'。"
                          "sing-box 启动期下载规则集时会报 'detour to an empty direct outbound makes no sense' 并退出。"
                          "直连下载请删除 detour 字段（不设即直连）。")
    for idx, rs in enumerate(cfg.get("route", {}).get("rule_set") or []):
        if rs.get("download_detour") == "direct":
            errors.append(f"[致命模式] route.rule_set[{idx}]({rs.get('tag')}) 的 download_detour 指向 'direct'，"
                          "启动期同样会触发 'empty direct outbound' 崩溃；直连下载请删除该字段。")

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
