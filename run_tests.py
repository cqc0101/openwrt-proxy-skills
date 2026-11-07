#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
一键回归入口：python run_tests.py
覆盖：模板不变量 / 节点解析 / 订阅清洗 / 生成器自校验 / dae 检查器 / sing-box 审计器 / shell 语法 / 行尾规范
任何一处失败都会以非零退出码中止（供 CI 使用）。
"""

import sys
import unittest

if __name__ == "__main__":
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    suite = unittest.defaultTestLoader.discover("tests")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
