#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dae 配置文件 5 条铁律静态合规检测工具（启发式检查）
注意：本工具只做静态模式匹配，最终结论必须由远端 `dae validate -c <file>` 确认（原生 dae v2.1.1+ 强制要求 -c 参数）。
"""

import sys
import os
import re
import urllib.parse

# 中文 Windows 控制台 (cp936) 无法编码 emoji/部分字符，统一重配为 UTF-8 输出
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def _strip_comments(line: str) -> str:
    """感知单双引号边界与反斜杠转义剥离行首与行尾 # 注释，防止误截断节点 URI 中的 #fragment。"""
    s = line.strip()
    if s.startswith("#"):
        return ""
    in_single = False
    in_double = False
    out = []
    i = 0
    n = len(s)
    while i < n:
        ch = s[i]
        if ch == "\\" and (in_single or in_double) and i + 1 < n:
            out.append(ch)
            out.append(s[i + 1])
            i += 2
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
            out.append(ch)
        elif ch == '"' and not in_single:
            in_double = not in_double
            out.append(ch)
        elif ch == "#" and not in_single and not in_double:
            break
        else:
            out.append(ch)
        i += 1
    return "".join(out).strip()


def _mask_quoted_strings(text: str) -> str:
    """将单双引号内部的内容掩码为空格（保留引号定界符与换行），防止规则参数或节点 URI 内的 ->、{、}、: 干扰语法结构解析。"""
    out = []
    in_s = False
    in_d = False
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == "\\" and (in_s or in_d) and i + 1 < n:
            out.append("  ")
            i += 2
            continue
        if c == "'" and not in_d:
            in_s = not in_s
            out.append(c)
        elif c == '"' and not in_s:
            in_d = not in_d
            out.append(c)
        elif in_s or in_d:
            out.append(" " if c != "\n" else "\n")
        else:
            out.append(c)
        i += 1
    return "".join(out)


def _extract_named_block(text, block_name, start_pos=0):
    masked = _mask_quoted_strings(text)
    pat = re.compile(r"\b" + re.escape(block_name) + r"\s*\{")
    m = pat.search(masked, start_pos)
    if not m:
        return None, -1, -1
    depth = 1
    i = m.end()
    while i < len(masked) and depth > 0:
        c = masked[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
        i += 1
    return (text[m.end():i - 1] if depth == 0 else None), m.start(), i


def _extract_kv_keys(body: str):
    """在引号感知状态机下提取 node / upstream 块中的键名（支持裸键名与单/双引号包裹键名，绝不误匹配冒号后的 URI 内容）。"""
    keys = set()
    for raw_l in body.splitlines():
        l = raw_l.strip()
        if not l:
            continue
        # 支持单行多个 key: 'val' 定义：扫描引号外的 ':'，并提取紧邻 ':' 左侧的标识符或引号包裹标识符
        in_s = False
        in_d = False
        i = 0
        seg_start = 0
        while i < len(l):
            ch = l[i]
            if ch == "\\" and (in_s or in_d) and i + 1 < len(l):
                i += 2
                continue
            if ch == "'" and not in_d:
                in_s = not in_s
            elif ch == '"' and not in_s:
                in_d = not in_d
            elif not in_s and not in_d and ch == ":":
                left = l[seg_start:i].strip()
                m_k = re.search(r"(?:^|\s)['\"]?([a-zA-Z0-9_-]+)['\"]?$", left)
                if m_k:
                    keys.add(m_k.group(1))
                # 跳过冒号右侧的引号值或非空白 token
                j = i + 1
                while j < len(l) and l[j].isspace():
                    j += 1
                if j < len(l) and l[j] in ("'", '"'):
                    q_ch = l[j]
                    j += 1
                    while j < len(l):
                        if l[j] == "\\" and j + 1 < len(l):
                            j += 2
                            continue
                        if l[j] == q_ch:
                            j += 1
                            break
                        j += 1
                else:
                    while j < len(l) and not l[j].isspace():
                        j += 1
                seg_start = j
                i = j
                continue
            i += 1
    return keys


def _extract_group_names(group_body: str):
    """在引号与花括号层级感知下提取 group 块顶层定义的策略组名（支持单/双引号包裹组名，忽略组内 filter 正则如 '{1,2}'）。"""
    groups = set()
    in_s = False
    in_d = False
    depth = 0
    i = 0
    seg_start = 0
    while i < len(group_body):
        ch = group_body[i]
        if ch == "\\" and (in_s or in_d) and i + 1 < len(group_body):
            i += 2
            continue
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        elif not in_s and not in_d:
            if ch == "{":
                if depth == 0:
                    left = group_body[seg_start:i].strip()
                    m_g = re.search(r"(?:^|\s)['\"]?([a-zA-Z0-9_-]+)['\"]?$", left)
                    if m_g:
                        groups.add(m_g.group(1))
                depth += 1
            elif ch == "}":
                depth = max(0, depth - 1)
                if depth == 0:
                    seg_start = i + 1
        i += 1
    return groups


def _extract_rule_targets(body: str):
    targets = []
    for r_line in body.splitlines():
        r_line = r_line.strip()
        if not r_line:
            continue
        in_s = False
        in_d = False
        i_idx = 0
        while i_idx < len(r_line):
            c_ch = r_line[i_idx]
            if c_ch == "\\" and (in_s or in_d) and i_idx + 1 < len(r_line):
                i_idx += 2
                continue
            if c_ch == "'" and not in_d:
                in_s = not in_s
            elif c_ch == '"' and not in_s:
                in_d = not in_d
            elif not in_s and not in_d:
                if r_line[i_idx:i_idx+2] == "->":
                    after_str = r_line[i_idx+2:].strip()
                    m_tgt = re.match(r"^['\"]?([a-zA-Z0-9_-]+)['\"]?", after_str)
                    if m_tgt:
                        targets.append(m_tgt.group(1))
                elif r_line[i_idx:].startswith("fallback:") and (i_idx == 0 or not re.match(r"[a-zA-Z0-9_-]", r_line[i_idx - 1])):
                    after_fb = r_line[i_idx + len("fallback:"):].strip()
                    m_fb = re.match(r"^['\"]?([a-zA-Z0-9_-]+)['\"]?", after_fb)
                    if m_fb:
                        targets.append(m_fb.group(1))
            i_idx += 1
    return targets


def _split_top_level_args(arg_str: str):
    """按顶层逗号拆分函数参数（忽略单双引号内部如正则 {1,2} 的逗号）。"""
    parts = []
    cur = []
    in_s = False
    in_d = False
    i = 0
    while i < len(arg_str):
        c = arg_str[i]
        if c == "\\" and (in_s or in_d) and i + 1 < len(arg_str):
            cur.append(c)
            cur.append(arg_str[i + 1])
            i += 2
            continue
        if c == "'" and not in_d:
            in_s = not in_s
            cur.append(c)
        elif c == '"' and not in_s:
            in_d = not in_d
            cur.append(c)
        elif c == "," and not in_s and not in_d:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
        i += 1
    if cur or arg_str.strip():
        parts.append("".join(cur).strip())
    return [p for p in parts if p]


def check_dae_syntax(filepath):
    errors = []
    warnings = []

    with open(filepath, 'r', encoding='utf-8-sig') as f:
        raw_lines = f.readlines()

    lines = [_strip_comments(l) for l in raw_lines]
    content = "\n".join(lines)

    # 1. 检查双引号、未闭合的单引号以及花括号 { } 配对平衡
    brace_depth = 0
    for idx, line in enumerate(lines, 1):
        if not line:
            continue
        in_sq = False
        in_dq = False
        idx_c = 0
        while idx_c < len(line):
            ch = line[idx_c]
            if ch == "\\" and (in_sq or in_dq) and idx_c + 1 < len(line):
                idx_c += 2
                continue
            if ch == "'" and not in_dq:
                in_sq = not in_sq
            elif ch == '"' and not in_sq:
                in_dq = not in_dq
            elif not in_sq and not in_dq:
                if ch == "{":
                    brace_depth += 1
                elif ch == "}":
                    brace_depth -= 1
                    if brace_depth < 0:
                        errors.append(f"第 {idx} 行存在多余的右花括号 '}}': {line}")
                        brace_depth = 0
            idx_c += 1
        if in_sq:
            errors.append(f"第 {idx} 行存在未配对闭合的单引号: {line}。请检查密码或名称中是否含有未转义的 '。")
        if in_dq:
            errors.append(f"第 {idx} 行存在未配对闭合的双引号: {line}。")
        line_no_sq = re.sub(r"'((?:\\.|[^'])*)'", "''", line)
        line_no_ext = re.sub(r'ext:\s*"[^"]*"', "", line_no_sq)
        if '"' in line_no_ext:
            matches = re.findall(r'([\w\'\-]+:\s*"[^"]*"|->\s*"[^"]*"|\w+\([^)]*"[^"]*"[^)]*\))', line_no_ext)
            if matches:
                for m in matches:
                    errors.append(f"第 {idx} 行疑似违反单引号规范: {m}。建议统一使用单引号 '...'（ext:\"file.dat:tag\" 除外）。")
            else:
                errors.append(f"第 {idx} 行疑似违反单引号规范: {line}。建议统一使用单引号 '...'（ext:\"file.dat:tag\" 除外）。")
    if brace_depth != 0:
        errors.append(f"[语法块未闭合] 配置文件中存在 {brace_depth} 个未闭合的左花括号 '{{'，请检查 global/node/dns/routing 块是否缺少 '}}'！")

    # 2. 检查 lan_interface 与 wan_interface 绑定
    if "lan_interface" not in content:
        warnings.append("[网卡绑定提醒] global 块中未显式声明 'lan_interface'。软路由代理局域网流量建议绑定 'lan_interface: br-lan'。")
    if "wan_interface" not in content:
        warnings.append("[网卡绑定提醒] global 块中未声明 'wan_interface: auto'。")

    # 3. 检查 must_direct 防环（宿主机 DNS 组件保护）
    has_dnsmasq_protect = re.search(r'pname\([^)]*dnsmasq[^)]*\)(?:(?!->)[^{}])*->\s*must_direct', content, re.DOTALL)
    if not has_dnsmasq_protect:
        errors.append("[DNS 死循环高危] routing 规则中未发现针对 dnsmasq 的 'must_direct' 放行规则！"
                      "在 OpenWrt 上，宿主机 DNS 组件的 53 端口流量必须于规则顶部放行，否则极易形成 DNS 回环死锁。")

    # 4. 检查布尔取反 (!) 合并
    neg_rule_count = len(re.findall(r'(?m)^\s*!domain\(', content))
    if neg_rule_count > 1:
        warnings.append("[取反合并建议] 发现多条独立的 '!domain(...)' 规则。"
                        "在 dae 语义中，'既不属于 A 也不属于 B' 必须合并写在同一行内"
                        "（如 '!domain(geosite:a, geosite:b) -> proxy'），拆成两行会变成 OR 逻辑，大量流量被误送代理。")

    # 5. 检查 DNS 污染重查闭环（使用引号与花括号配对感知的 _extract_named_block，防止正则量词 '{1,2}' 提前截断 response 块）
    if "ip(geoip:private)" in content:
        resp_blocks = []
        _r_pos = 0
        while _r_pos < len(content):
            _rb, _, _r_end = _extract_named_block(content, "response", _r_pos)
            if _rb is None or _r_end <= _r_pos:
                break
            resp_blocks.append(_rb)
            _r_pos = _r_end
        for block in resp_blocks:
            m_relookup = re.search(r"ip\(geoip:private\)(?:(?!->)[^\n])*->\s*['\"]?(?!accept\b|reject\b|asis\b|must_asis\b)[a-zA-Z0-9_-]+", block)
            if m_relookup:
                m_accept = re.search(r"upstream\([^)]*\)\s*->\s*['\"]?accept\b", block)
                if not m_accept or m_accept.start() >= m_relookup.start():
                    errors.append("[DNS 投毒死循环高危] 配置了私网 IP 污染重查，但 response 块中缺少位于其前的"
                                  "可信上游白名单放行（'upstream(...) -> accept'），会导致无限递归重查！")
                    break

    # 5.5 检查 group、node 与 dns.upstream 引用完整性（基于引号掩码 AST 提取，杜绝引号内字符误判）
    node_body, _, _ = _extract_named_block(content, "node")
    defined_nodes = set()
    if node_body is not None:
        defined_nodes = _extract_kv_keys(node_body)
        for uri_m in re.findall(r"'((?:\\.|[^'])*)'|\"((?:\\.|[^\"])*)\"", node_body):
            uri_s = uri_m[0] or uri_m[1]
            if "#" in uri_s:
                frag = urllib.parse.unquote(uri_s.split("#", 1)[1].strip())
                if frag:
                    defined_nodes.add(frag)

    group_body, _, _ = _extract_named_block(content, "group")
    defined_groups = _extract_group_names(group_body) if group_body is not None else set()
    if group_body is not None or node_body is not None:
        builtin_outbounds = {"direct", "must_direct", "block", "must_rules"}
        valid_outbounds = builtin_outbounds | defined_groups | defined_nodes
        dns_body, dns_s, dns_e = _extract_named_block(content, "dns")
        content_without_dns = (content[:dns_s] + content[dns_e:]) if dns_s != -1 else content
        rt_body, _, _ = _extract_named_block(content_without_dns, "routing")
        if rt_body:
            for tgt in _extract_rule_targets(rt_body):
                if tgt not in valid_outbounds:
                    errors.append(f"[悬空出站引用] routing 规则引用了未在 group 或 node 块中定义的出站目标: '{tgt}'！")

    dns_body, _, _ = _extract_named_block(content, "dns")
    if dns_body is not None:
        # 5.2 检查 qname(...) 是否包含无前缀裸域名/单引号域名（基于引号掩码与顶层逗号切分，避免误伤正则 '{1,2}' 或 '(a|b)'）
        masked_dns = _mask_quoted_strings(dns_body)
        for m_qn in re.finditer(r"\bqname\s*\(", masked_dns):
            start_idx = m_qn.end()
            p_depth = 1
            k_idx = start_idx
            while k_idx < len(masked_dns) and p_depth > 0:
                if masked_dns[k_idx] == "(":
                    p_depth += 1
                elif masked_dns[k_idx] == ")":
                    p_depth -= 1
                k_idx += 1
            if p_depth == 0:
                qn_inner = dns_body[start_idx:k_idx - 1]
                for arg in _split_top_level_args(qn_inner):
                    if not re.match(r"^(?:geosite|full|domain|suffix|keyword|regex|regexp|ext)\s*:", arg):
                        errors.append(
                            f"[DNS qname 语法崩溃高危] dns 块中 qname({qn_inner.strip()}) 含有无匹配前缀的参数 '{arg}'！"
                            "dae v2.1.1 的 addQName 解析器要求所有 qname 参数必须显式携带前缀（如 full:/suffix:/domain:/geosite:），"
                            "无前缀或直接单引号域名会触发 'addQName: unsupported key:' 致命错误；建议将域名阻断移入 routing 块的 domain(...) -> block。"
                        )
                    elif re.match(r"^geosite\s*:\s*category-ads(?:-all)?\b", arg):
                        warnings.append(
                            "[DNS qname 兼容性建议] 检测到在 dns 块中使用 'qname(geosite:category-ads-all)'；"
                            "部分新版 geosite.dat 含特殊前缀属性可能触发 dae DNS 解析器异常，建议移入 routing 块改写为 'domain(geosite:category-ads-all) -> block'。"
                        )
        up_body, _, _ = _extract_named_block(dns_body, "upstream")
        dns_rt_body, _, _ = _extract_named_block(dns_body, "routing")
        if up_body is not None and dns_rt_body is not None:
            defined_ups = _extract_kv_keys(up_body)
            builtin_dns_actions = {"accept", "reject", "asis", "must_asis", "must_rules"}
            for tgt in _extract_rule_targets(dns_rt_body):
                if tgt not in builtin_dns_actions and tgt not in defined_ups:
                    errors.append(f"[悬空 DNS 上游引用] dns.routing 引用了未在 upstream 块中定义的 DNS 上游: '{tgt}'！")

    # 6. 检查 node 与 subscription 是否同时为空（模板未注入真实节点提醒）
    sub_body, _, _ = _extract_named_block(content, "subscription")
    if node_body is not None and sub_body is not None:
        if not node_body.strip() and not sub_body.strip():
            warnings.append("[空节点池提醒] node 与 subscription 块均为空，部署前请使用 sub_to_dae.py 注入真实节点或订阅。")

    return errors, warnings


def main():
    args = [a for a in sys.argv[1:] if a not in ("-c", "--config")]
    if not args:
        print("用法: python check_dae_syntax.py [-c] <dae配置文件路径>")
        sys.exit(1)

    filepath = args[0]
    if not os.path.exists(filepath):
        print(f"错误: 文件不存在: {filepath}")
        sys.exit(1)

    print(f"[*] 正在审计 dae 配置文件: {filepath}")
    errors, warnings = check_dae_syntax(filepath)

    if errors:
        print(f"\n[!] 发现 {len(errors)} 个严重阻断问题:")
        for e in errors:
            print(f"  - [ERROR] {e}")

    if warnings:
        print(f"\n[!] 发现 {len(warnings)} 个优化建议:")
        for w in warnings:
            print(f"  - [WARN] {w}")

    if not errors and not warnings:
        print("\n[+] 静态启发式检查通过，未发现明显违规。")
    elif not errors:
        print("\n[+] 无致命问题，请评估上方建议。")
    else:
        print("\n[x] 检查未通过，请修复后重试。")
        sys.exit(1)

    print("[i] 提示：本工具仅做静态检查，部署前请务必以远端 'dae validate -c <file>' 的结论为准。")
    return 0


if __name__ == "__main__":
    main()
