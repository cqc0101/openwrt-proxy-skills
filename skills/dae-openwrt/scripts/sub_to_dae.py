#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dae 节点与机场订阅转换器 (将通用机场订阅转为 dae 原生 node 语法块)
依赖兄弟技能 singbox-openwrt 的 scripts/sub_parser.py（仓库内相对路径）。
"""

import os
import sys

# 中文 Windows 控制台 (cp936) 无法编码 emoji/部分字符，统一重配为 UTF-8 输出
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# 仓库布局: <root>/skills/dae-openwrt/scripts 与 <root>/skills/singbox-openwrt/scripts 平级
CANDIDATES = [
    os.path.abspath(os.path.join(SCRIPT_DIR, "..", "..", "singbox-openwrt", "scripts")),
    os.path.abspath(os.path.join(SCRIPT_DIR, "..", "singbox-openwrt", "scripts")),
    os.path.abspath(os.path.join(SCRIPT_DIR, "singbox-openwrt", "scripts")),
]

SINGBOX_SCRIPTS = next((p for p in CANDIDATES if os.path.isfile(os.path.join(p, "sub_parser.py"))), None)
if SINGBOX_SCRIPTS is None:
    print("[-] 找不到 singbox-openwrt/scripts/sub_parser.py！", file=sys.stderr)
    print("    本工具依赖兄弟技能 singbox-openwrt，请保持两个技能目录同处一个仓库根下。", file=sys.stderr)
    sys.exit(1)

if SINGBOX_SCRIPTS not in sys.path:
    sys.path.insert(0, SINGBOX_SCRIPTS)

from sub_parser import parse_source, to_dae_nodes


def main():
    if len(sys.argv) < 2:
        print("用法: python sub_to_dae.py <机场订阅URL / Base64文件 / Clash配置> [--max 15] [--include 正则]")
        sys.exit(1)

    import argparse
    parser = argparse.ArgumentParser(description="dae 订阅转换工具")
    parser.add_argument("source", help="订阅来源 (URL/文件/Base64)")
    parser.add_argument("--max", type=int, default=15, help="保留最大节点数 (默认 15)")
    parser.add_argument("--include", help="包含节点匹配正则")
    parser.add_argument("--exclude", help="排除节点匹配正则")

    args = parser.parse_args()

    nodes = parse_source(args.source, include=args.include, exclude=args.exclude, max_nodes=args.max)
    if not nodes:
        print("[-] 未能解析出有效节点", file=sys.stderr)
        sys.exit(1)

    print(to_dae_nodes(nodes))
    print(f"[+] 成功转换 {len(nodes)} 个节点到 dae 语法格式", file=sys.stderr)


if __name__ == "__main__":
    main()
