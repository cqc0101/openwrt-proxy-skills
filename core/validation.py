# -*- coding: utf-8 -*-
"""六层配置与部署验证统一接口 (VAL-001, Section 9: L0 输入 -> L1 结构 -> L2 版本 -> L3 原生引擎 -> L4 设备部署 -> L5 业务连通)。"""

import ipaddress
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
SINGBOX_SCRIPTS = REPO_ROOT / "skills" / "singbox-openwrt" / "scripts"
DAE_SCRIPTS = REPO_ROOT / "skills" / "dae-openwrt" / "scripts"
for _p in (str(SINGBOX_SCRIPTS), str(DAE_SCRIPTS)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from check_config import check_config_obj as _check_singbox_dict
from check_dae_syntax import check_dae_syntax as _check_dae_file, _strip_comments as _strip_dae_comments
from sub_parser import redact_sensitive_text


ENGINE_CAPABILITY_TABLE: Dict[str, Dict[str, Any]] = {
    "sing-box": {
        "1.13": {
            "status": "supported",
            "supported_fields": ("independent_cache", "store_rdrc", "download_detour"),
            "forbidden_fields": ("optimistic", "store_dns", "default_http_client", "http_clients"),
        },
        "1.14": {
            "status": "supported",
            "supported_fields": ("optimistic", "store_dns", "default_http_client", "http_clients"),
            "forbidden_fields": ("independent_cache", "store_rdrc", "download_detour"),
        },
    },
    "dae": {
        "legacy": {
            "status": "supported",
            "forbidden_fields": (
                "bpf_conn_state_map_size",
                "auto_sniff_punt",
                "bootstrap_resolver",
                "optimistic_cache",
                "optimistic_cache_ttl",
            ),
        },
        "modern": {
            "status": "supported",
            "forbidden_fields": (),
        },
    },
}


def _check_singbox_forbidden_fields_ast(cfg_obj: Dict[str, Any], forbidden_fields: Sequence[str]) -> List[str]:
    """基于 JSON AST 精确检查 sing-box 顶层与子模块是否混用版本禁用字段，避免节点名称/字符串误报。"""
    found: List[str] = []
    dns_blk = cfg_obj.get("dns") if isinstance(cfg_obj.get("dns"), dict) else {}
    route_blk = cfg_obj.get("route") if isinstance(cfg_obj.get("route"), dict) else {}
    exp_blk = cfg_obj.get("experimental") if isinstance(cfg_obj.get("experimental"), dict) else {}
    cache_blk = exp_blk.get("cache_file") if isinstance(exp_blk.get("cache_file"), dict) else {}
    rule_sets = [r for r in (route_blk.get("rule_set") or []) if isinstance(r, dict)]

    for f_name in forbidden_fields:
        if f_name in ("independent_cache", "optimistic") and f_name in dns_blk:
            found.append(f_name)
        elif f_name in ("store_rdrc", "store_dns") and f_name in cache_blk:
            found.append(f_name)
        elif f_name == "default_http_client" and "default_http_client" in route_blk:
            found.append(f_name)
        elif f_name == "http_clients" and "http_clients" in cfg_obj:
            found.append(f_name)
        elif f_name == "download_detour" and any("download_detour" in rs for rs in rule_sets):
            found.append(f_name)
    return found


@dataclass(frozen=True)
class LayerResult:
    layer: str
    name: str
    passed: bool
    failure_action: str
    errors: Tuple[str, ...] = ()
    warnings: Tuple[str, ...] = ()


@dataclass
class ValidationReport:
    engine: str
    version: str
    layers: List[LayerResult] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(l.passed for l in self.layers)

    @property
    def failed_layer(self) -> Optional[str]:
        for l in self.layers:
            if not l.passed:
                return l.layer
        return None

    @property
    def recommended_action(self) -> str:
        for l in self.layers:
            if not l.passed:
                return l.failure_action
        return "commit"


class SixLayerValidator:
    """L0~L5 六层验证流水线：明确区分输入拒绝、生成阻断、部署阻断与回滚/人工介入。"""

    def validate_l0_inputs(
        self,
        engine: str,
        version: str,
        max_nodes: int = 15,
        topology: str = "main",
        main_router_ip: Optional[str] = None,
        port: int = 22,
    ) -> LayerResult:
        errs: List[str] = []
        if engine not in ("sing-box", "dae"):
            errs.append(f"不支持的代理引擎: {engine!r}")
        if isinstance(max_nodes, bool) or not isinstance(max_nodes, int) or not (1 <= max_nodes <= 200):
            errs.append(f"max_nodes 超出安全范围 (1-200): {max_nodes!r}")
        if isinstance(port, bool) or not isinstance(port, int) or not (1 <= port <= 65535):
            errs.append(f"端口超出合法范围 (1-65535): {port!r}")
        if topology not in ("main", "bypass"):
            errs.append(f"非法的网络拓扑类型: {topology!r}")
        if main_router_ip is not None:
            try:
                gw_if = ipaddress.ip_interface(str(main_router_ip).strip())
                if gw_if.ip.is_loopback or gw_if.ip.is_unspecified or gw_if.ip.is_multicast:
                    errs.append(f"旁路由主网关 IP 不能为回环、未指定或多播地址: {main_router_ip!r}")
            except ValueError as e:
                errs.append(f"非法的旁路由主网关 IP: {e}")
        return LayerResult("L0", "input_validation", len(errs) == 0, "reject_input", tuple(errs))

    def validate_l1_l2_structure_and_version(
        self,
        engine: str,
        version: str,
        config_path: Path,
    ) -> Tuple[LayerResult, LayerResult]:
        l1_errs: List[str] = []
        l1_warns: List[str] = []
        l2_errs: List[str] = []

        cap_branch = ENGINE_CAPABILITY_TABLE.get(engine, {}).get(version)
        if not cap_branch or cap_branch.get("status") != "supported":
            l2_errs.append(f"引擎 {engine} 版本分支 {version!r} 状态未知或不受支持 (unknown/unsupported)")

        p = Path(config_path)
        if not p.is_file():
            l1_errs.append(f"配置文件不存在: {p}")
            return (
                LayerResult("L1", "structure_validation", False, "block_generation", tuple(l1_errs)),
                LayerResult("L2", "version_validation", len(l2_errs) == 0, "block_generation", tuple(l2_errs)),
            )

        raw_text = p.read_text(encoding="utf-8-sig")
        if engine == "sing-box":
            try:
                cfg_obj = json.loads(raw_text)
            except Exception as e:
                l1_errs.append(f"JSON 语法解析失败: {e}")
                cfg_obj = None
            if not isinstance(cfg_obj, dict):
                l1_errs.append("sing-box 配置顶层必须是 JSON 对象")
            if isinstance(cfg_obj, dict):
                e_list, w_list = _check_singbox_dict(cfg_obj)
                l1_errs.extend(e_list)
                l1_warns.extend(w_list)
                if cap_branch:
                    bad_hits = _check_singbox_forbidden_fields_ast(cfg_obj, cap_branch.get("forbidden_fields", ()))
                    for bad_f in bad_hits:
                        l2_errs.append(f"sing-box {version} 禁止混用不兼容字段: {bad_f}")
        elif engine == "dae":
            e_list, w_list = _check_dae_file(str(p))
            l1_errs.extend(e_list)
            l1_warns.extend(w_list)
            if cap_branch:
                stripped_lines = [_strip_dae_comments(line) for line in raw_text.splitlines()]
                clean_dae = "\n".join(line for line in stripped_lines if line)
                for bad_f in cap_branch.get("forbidden_fields", ()):
                    if re.search(rf"(?m)^[ \t]*{re.escape(bad_f)}\s*:", clean_dae):
                        l2_errs.append(f"dae {version} 模式不支持新字段: {bad_f}")
        else:
            l1_errs.append(f"不支持的代理引擎: {engine!r}")

        return (
            LayerResult("L1", "structure_validation", len(l1_errs) == 0, "block_generation", tuple(l1_errs), tuple(l1_warns)),
            LayerResult("L2", "version_validation", len(l2_errs) == 0, "block_generation", tuple(l2_errs)),
        )

    def validate_l3_native_engine(
        self,
        config_path: Path,
        native_check_fn: Callable[[Path], Tuple[bool, str]],
    ) -> LayerResult:
        ok, raw_msg = native_check_fn(Path(config_path))
        safe_msg = redact_sensitive_text(raw_msg or "")
        errs = () if ok else (safe_msg or "原生引擎配置检查失败",)
        return LayerResult("L3", "native_engine_validation", bool(ok), "block_deployment", errs)

    def validate_l4_device_deployment(
        self,
        config_path: Path,
        service_running: bool,
        port_listening: bool,
        fatal_logs: Sequence[str] = (),
    ) -> LayerResult:
        errs: List[str] = []
        p = Path(config_path)
        if not p.is_file() or p.stat().st_size == 0:
            errs.append(f"生产配置文件缺失或为空: {p}")
        if not service_running:
            errs.append("代理核心服务进程未运行")
        if not port_listening:
            errs.append("关键监听端口 (53/9090) 未就绪")
        for fl in fatal_logs:
            errs.append(f"运行日志存在致命错误: {redact_sensitive_text(fl)}")
        return LayerResult("L4", "device_deployment_validation", len(errs) == 0, "rollback", tuple(errs))

    def validate_l5_business_health(
        self,
        ssh_channel_ok: bool,
        lan_wan_ok: bool,
        dns_ok: bool,
        proxy_egress_ok: bool,
    ) -> LayerResult:
        errs: List[str] = []
        if not ssh_channel_ok:
            errs.append("SSH 管理通道异常")
        if not lan_wan_ok:
            errs.append("LAN/WAN 基础路由连通性异常")
        if not dns_ok:
            errs.append("DNS 解析探测失败或发生污染/自环")
        if not proxy_egress_ok:
            errs.append("代理分流出口连通性探测失败")
        return LayerResult("L5", "business_health_validation", len(errs) == 0, "rollback_or_needs_human", tuple(errs))
