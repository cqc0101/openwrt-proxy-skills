# -*- coding: utf-8 -*-
"""独立 Policy Engine、Action Registry、Repair Registry 与计划哈希授权绑定 (POL-001, EXE-001, EXE-002, REP-002)。"""

import hashlib
import json
import time
import threading
import math

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple


_APPROVAL_LOCK = threading.Lock()
RISK_ORDER: Dict[str, int] = {"R0": 0, "R1": 1, "R2": 2, "R3": 3, "R4": 4}


class PolicyViolationError(RuntimeError):
    """策略引擎拒绝执行异常，携带机器可审计的 reason_code。"""
    def __init__(self, reason_code: str, message: str):
        super().__init__(f"[{reason_code}] {message}")
        self.reason_code = reason_code
        self.detail = message


@dataclass(frozen=True)
class ActionSpec:
    action_id: str
    risk: str
    timeout: int
    idempotent: bool
    requires_approval: bool
    preconditions: Tuple[str, ...] = ()
    verification: Optional[str] = None
    rollback: Optional[str] = None
    allowed_params: Tuple[str, ...] = ()


ACTION_REGISTRY: Dict[str, ActionSpec] = {
    "probe_env": ActionSpec(
        action_id="probe_env",
        risk="R0",
        timeout=15,
        idempotent=True,
        requires_approval=False,
        allowed_params=("json",),
    ),
    "doctor_diagnose": ActionSpec(
        action_id="doctor_diagnose",
        risk="R0",
        timeout=15,
        idempotent=True,
        requires_approval=False,
        allowed_params=("service", "json"),
    ),
    "diagnose_dns": ActionSpec(
        action_id="diagnose_dns",
        risk="R0",
        timeout=20,
        idempotent=True,
        requires_approval=False,
        allowed_params=("json",),
    ),
    "generate_singbox_config": ActionSpec(
        action_id="generate_singbox_config",
        risk="R1",
        timeout=30,
        idempotent=True,
        requires_approval=False,
        allowed_params=("version", "dns_mode", "topology", "max_nodes", "wan_iface"),
    ),
    "generate_dae_config": ActionSpec(
        action_id="generate_dae_config",
        risk="R1",
        timeout=30,
        idempotent=True,
        requires_approval=False,
        allowed_params=("dae_version", "topology", "max_nodes", "lan_iface", "wan_iface"),
    ),
    "validate_singbox_config": ActionSpec(
        action_id="validate_singbox_config",
        risk="R1",
        timeout=20,
        idempotent=True,
        requires_approval=False,
        allowed_params=("config_path",),
    ),
    "validate_dae_config": ActionSpec(
        action_id="validate_dae_config",
        risk="R1",
        timeout=20,
        idempotent=True,
        requires_approval=False,
        allowed_params=("config_path",),
    ),
    "stage_remote_config": ActionSpec(
        action_id="stage_remote_config",
        risk="R2",
        timeout=30,
        idempotent=True,
        requires_approval=False,
        preconditions=("device_identity_verified", "config_static_validation_passed"),
        verification="verify_staged_hash_and_native_check",
        allowed_params=("staging_path", "sha256", "engine"),
    ),
    "replace_singbox_config": ActionSpec(
        action_id="replace_singbox_config",
        risk="R3",
        timeout=45,
        idempotent=False,
        requires_approval=True,
        preconditions=("device_identity_verified", "backup_verified", "config_native_validation_passed"),
        verification="verify_singbox_service_and_dns",
        rollback="restore_singbox_config",
        allowed_params=("target_path", "staging_path"),
    ),
    "replace_dae_config": ActionSpec(
        action_id="replace_dae_config",
        risk="R3",
        timeout=45,
        idempotent=False,
        requires_approval=True,
        preconditions=("device_identity_verified", "backup_verified", "config_native_validation_passed"),
        verification="verify_dae_service_and_dns",
        rollback="restore_dae_config",
        allowed_params=("target_path", "staging_path"),
    ),
    "setup_openwrt_network": ActionSpec(
        action_id="setup_openwrt_network",
        risk="R4",
        timeout=60,
        idempotent=False,
        requires_approval=True,
        preconditions=("device_identity_verified", "backup_verified", "watchdog_ready"),
        verification="verify_lan_wan_dns_and_ssh",
        rollback="revert_openwrt_network",
        allowed_params=("topology", "keep_ipv6", "no_sysctl_tuning", "dry_run"),
    ),
    "revert_openwrt_network": ActionSpec(
        action_id="revert_openwrt_network",
        risk="R4",
        timeout=60,
        idempotent=True,
        requires_approval=True,
        preconditions=("device_identity_verified",),
        verification="verify_network_baseline_restored",
        rollback="manual_console_recovery",
        allowed_params=("service",),
    ),
    "restore_singbox_config": ActionSpec(
        action_id="restore_singbox_config",
        risk="R3",
        timeout=30,
        idempotent=True,
        requires_approval=True,
        preconditions=("backup_verified",),
        verification="verify_singbox_baseline_restored",
        rollback="manual_console_recovery",
        allowed_params=("target_path", "backup_path"),
    ),
    "restore_dae_config": ActionSpec(
        action_id="restore_dae_config",
        risk="R3",
        timeout=30,
        idempotent=True,
        requires_approval=True,
        preconditions=("backup_verified",),
        verification="verify_dae_baseline_restored",
        rollback="manual_console_recovery",
        allowed_params=("target_path", "backup_path"),
    ),
}


@dataclass(frozen=True)
class RepairSpec:
    repair_id: str
    issue_id: str
    risk: str
    requires_approval: bool
    requires_human: bool
    preconditions: Tuple[str, ...]
    verification: Tuple[str, ...]
    rollback: Tuple[str, ...]
    max_retries: int = 1


REPAIR_REGISTRY: Dict[str, RepairSpec] = {
    "repair_service_stopped": RepairSpec(
        repair_id="repair_service_stopped",
        issue_id="service_stopped",
        risk="R3",
        requires_approval=True,
        requires_human=False,
        preconditions=("config_native_validation_passed", "management_channel_healthy"),
        verification=("service_process_running", "dns_query_success"),
        rollback=("restore_previous_service_state",),
        max_retries=1,
    ),
    "repair_tun_missing": RepairSpec(
        repair_id="repair_tun_missing",
        issue_id="tun_missing",
        risk="R3",
        requires_approval=True,
        requires_human=False,
        preconditions=("kmod_tun_available", "management_channel_healthy"),
        verification=("tun0_interface_up",),
        rollback=("restore_previous_service_state",),
        max_retries=1,
    ),
    "repair_fw_tun_blocked": RepairSpec(
        repair_id="repair_fw_tun_blocked",
        issue_id="fw_tun_blocked",
        risk="R4",
        requires_approval=True,
        requires_human=False,
        preconditions=("backup_verified", "lan_zone_located"),
        verification=("fw_tun_forwarding_accepted", "dns_query_success"),
        rollback=("revert_openwrt_network",),
        max_retries=1,
    ),
    "repair_dns_loop": RepairSpec(
        repair_id="repair_dns_loop",
        issue_id="dns_loop",
        risk="R3",
        requires_approval=True,
        requires_human=False,
        preconditions=("backup_verified",),
        verification=("dns_query_success",),
        rollback=("restore_dnsmasq_upstream",),
        max_retries=1,
    ),
    "repair_flow_offload": RepairSpec(
        repair_id="repair_flow_offload",
        issue_id="flow_offload_conflict",
        risk="R4",
        requires_approval=True,
        requires_human=False,
        preconditions=("backup_verified",),
        verification=("flow_offloading_disabled",),
        rollback=("revert_openwrt_network",),
        max_retries=1,
    ),
    "repair_nfqueue_missing_loop": RepairSpec(
        repair_id="repair_nfqueue_missing_loop",
        issue_id="nfqueue_missing_loop",
        risk="R3",
        requires_approval=True,
        requires_human=False,
        preconditions=("backup_verified",),
        verification=("singbox_auto_redirect_disabled", "dns_query_success"),
        rollback=("restore_singbox_config",),
        max_retries=1,
    ),
    "repair_oom_killed": RepairSpec(
        repair_id="repair_oom_killed",
        issue_id="oom_killed",
        risk="R4",
        requires_approval=True,
        requires_human=True,
        preconditions=("human_confirmed_node_cap",),
        verification=("memory_free_above_threshold", "service_process_running"),
        rollback=("restore_previous_service_state",),
        max_retries=1,
    ),
    "repair_ebpf_btf_missing": RepairSpec(
        repair_id="repair_ebpf_btf_missing",
        issue_id="ebpf_btf_missing",
        risk="R4",
        requires_approval=True,
        requires_human=True,
        preconditions=("human_confirmed_engine_switch",),
        verification=("singbox_tun_verified",),
        rollback=("restore_previous_service_state",),
        max_retries=0,
    ),
    "repair_node_auth_failed": RepairSpec(
        repair_id="repair_node_auth_failed",
        issue_id="node_auth_failed",
        risk="R3",
        requires_approval=True,
        requires_human=True,
        preconditions=("valid_subscription_credentials_supplied",),
        verification=("outbound_connectivity_ok",),
        rollback=("restore_previous_service_state",),
        max_retries=1,
    ),
    "repair_node_parse_failed": RepairSpec(
        repair_id="repair_node_parse_failed",
        issue_id="node_parse_failed",
        risk="R3",
        requires_approval=True,
        requires_human=True,
        preconditions=("valid_subscription_credentials_supplied",),
        verification=("outbound_connectivity_ok",),
        rollback=("restore_previous_service_state",),
        max_retries=1,
    ),
    "repair_fw_tun_untrusted": RepairSpec(
        repair_id="repair_fw_tun_untrusted",
        issue_id="fw_tun_untrusted",
        risk="R4",
        requires_approval=True,
        requires_human=False,
        preconditions=("backup_verified", "lan_zone_located"),
        verification=("fw_tun_forwarding_accepted", "dns_query_success"),
        rollback=("revert_openwrt_network",),
        max_retries=1,
    ),
    "repair_tls_clock_skew": RepairSpec(
        repair_id="repair_tls_clock_skew",
        issue_id="tls_clock_skew",
        risk="R2",
        requires_approval=False,
        requires_human=False,
        preconditions=("management_channel_healthy",),
        verification=("system_clock_synced", "tls_handshake_ok"),
        rollback=("restore_previous_time_config",),
        max_retries=2,
    ),
    "repair_dns_lookup_timeout": RepairSpec(
        repair_id="repair_dns_lookup_timeout",
        issue_id="dns_lookup_timeout",
        risk="R3",
        requires_approval=True,
        requires_human=False,
        preconditions=("backup_verified", "management_channel_healthy"),
        verification=("dns_query_success",),
        rollback=("restore_dnsmasq_upstream",),
        max_retries=1,
    ),
    "repair_ruleset_download_blocked": RepairSpec(
        repair_id="repair_ruleset_download_blocked",
        issue_id="ruleset_download_blocked",
        risk="R3",
        requires_approval=True,
        requires_human=False,
        preconditions=("backup_verified", "config_native_validation_passed"),
        verification=("ruleset_cached_in_tmp", "service_process_running"),
        rollback=("restore_singbox_config",),
        max_retries=1,
    ),
    "repair_port_conflict": RepairSpec(
        repair_id="repair_port_conflict",
        issue_id="port_conflict",
        risk="R4",
        requires_approval=True,
        requires_human=True,
        preconditions=("human_confirmed_stop_conflicting_service", "backup_verified"),
        verification=("port53_and_9090_conflict_free", "dns_query_success"),
        rollback=("restore_previous_service_state",),
        max_retries=1,
    ),
    "repair_config_syntax_error": RepairSpec(
        repair_id="repair_config_syntax_error",
        issue_id="config_syntax_error",
        risk="R3",
        requires_approval=True,
        requires_human=False,
        preconditions=("backup_verified", "config_native_validation_passed"),
        verification=("config_native_validation_passed", "service_process_running"),
        rollback=("restore_previous_service_state",),
        max_retries=1,
    ),
    "repair_daed_conflict": RepairSpec(
        repair_id="repair_daed_conflict",
        issue_id="daed_conflict",
        risk="R4",
        requires_approval=True,
        requires_human=True,
        preconditions=("human_confirmed_disable_daed",),
        verification=("daed_stopped", "dae_running"),
        rollback=("reenable_daed_service",),
        max_retries=1,
    ),
}


@dataclass(frozen=True)
class PlanStep:
    action_id: str
    target: str
    params: Dict[str, Any] = field(default_factory=dict)
    declared_risk: Optional[str] = None
    verification: Optional[str] = None
    rollback: Optional[str] = None


@dataclass(frozen=True)
class ExecutionPlan:
    device_id: str
    device_fingerprint: str
    steps: Tuple[PlanStep, ...]
    max_total_timeout: int = 180

    def compute_hash(self) -> str:
        """计算确定性计划哈希 (SHA-256)，绑定设备 ID、指纹、动作序列与参数。"""
        canonical = {
            "device_id": self.device_id,
            "device_fingerprint": self.device_fingerprint,
            "max_total_timeout": self.max_total_timeout,
            "steps": [
                {
                    "action_id": s.action_id,
                    "target": s.target,
                    "params": {k: s.params[k] for k in sorted(s.params.keys())},
                    "verification": s.verification,
                    "rollback": s.rollback,
                }
                for s in self.steps
            ],
        }
        payload = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def highest_risk(self) -> str:
        max_r = "R0"
        for s in self.steps:
            spec = ACTION_REGISTRY.get(s.action_id)
            if spec and RISK_ORDER[spec.risk] > RISK_ORDER[max_r]:
                max_r = spec.risk
        return max_r


@dataclass
class ApprovalToken:
    device_id: str
    device_fingerprint: str
    plan_hash: str
    approved_risk: str
    actor: str
    issued_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + 300.0)
    max_uses: int = 1
    used_count: int = 0



def _validate_safe_action_path(path_val: str, label: str, allowed_prefixes: Tuple[str, ...] = ()) -> None:
    import posixpath
    raw = str(path_val or "").strip()
    if not raw or chr(92) in raw or any(ord(c) < 32 or ord(c) == 127 for c in raw):
        raise PolicyViolationError("PATH_SECURITY_VIOLATION", f"{label} 包含非法空值、反斜杠或控制字符: {path_val!r}")
    if any(ch in raw for ch in (";", "|", "&", "`", "$", "(", ")", "<", ">")):
        raise PolicyViolationError("SHELL_INJECTION_DETECTED", f"{label} 包含危险 Shell 元字符: {path_val!r}")
    parts = [seg for seg in raw.split("/") if seg]
    if ".." in parts:
        raise PolicyViolationError("PATH_TRAVERSAL_DETECTED", f"{label} 检测到路径穿越 ('..'): {path_val!r}")
    norm = posixpath.normpath(raw)
    if allowed_prefixes and not any(norm == pfx.rstrip("/") or norm.startswith(pfx.rstrip("/") + "/") for pfx in allowed_prefixes):
        raise PolicyViolationError(
            "PATH_OUT_OF_SCOPE",
            f"{label} ({norm}) 超出允许的目录范围 {allowed_prefixes}",
        )


class PolicyEngine:
    """确定性权限与执行计划门禁引擎（禁止模型降级风险、篡改计划或无授权执行 R3/R4）。"""

    def validate_plan(self, plan: ExecutionPlan, satisfied_preconditions: Sequence[str] = ()) -> str:
        if not plan.device_id or not str(plan.device_id).strip():
            raise PolicyViolationError("INVALID_DEVICE_ID", "执行计划缺少有效的 device_id")
        if not plan.device_fingerprint or not str(plan.device_fingerprint).strip():
            raise PolicyViolationError("INVALID_DEVICE_FINGERPRINT", "执行计划缺少有效的设备身份指纹")
        if not plan.steps:
            raise PolicyViolationError("EMPTY_PLAN", "执行计划不能为空")
        if plan.max_total_timeout <= 0 or plan.max_total_timeout > 600:
            raise PolicyViolationError("TIMEOUT_OUT_OF_RANGE", f"总超时时间超出范围: {plan.max_total_timeout}")

        precond_set = set(satisfied_preconditions)
        total_step_timeout = 0
        for step in plan.steps:
            if step.action_id not in ACTION_REGISTRY:
                raise PolicyViolationError("UNREGISTERED_ACTION", f"未注册的动作: {step.action_id!r}")
            spec = ACTION_REGISTRY[step.action_id]
            total_step_timeout += spec.timeout

            # 严禁模型自行调低动作风险等级
            if step.declared_risk is not None:
                if step.declared_risk not in RISK_ORDER:
                    raise PolicyViolationError("INVALID_RISK_LEVEL", f"非法的风险级别: {step.declared_risk!r}")
                if RISK_ORDER[step.declared_risk] < RISK_ORDER[spec.risk]:
                    raise PolicyViolationError(
                        "RISK_DOWNGRADE_FORBIDDEN",
                        f"禁止将动作 {step.action_id} 的风险从 {spec.risk} 降级为 {step.declared_risk}",
                    )

            # 目标与全量字符串参数穿越/注入校验
            _validate_safe_action_path(step.target, f"{step.action_id}.target")
            for p_key, p_val in step.params.items():
                if isinstance(p_val, str):
                    _validate_safe_action_path(p_val, f"{step.action_id}.{p_key}")
            if step.action_id in ("replace_singbox_config", "restore_singbox_config"):
                _validate_safe_action_path(step.target, f"{step.action_id}.target", ("/etc/sing-box/", "/tmp/"))
                if "target_path" in step.params:
                    _validate_safe_action_path(str(step.params["target_path"]), "target_path", ("/etc/sing-box/", "/tmp/"))
            elif step.action_id in ("replace_dae_config", "restore_dae_config"):
                _validate_safe_action_path(step.target, f"{step.action_id}.target", ("/etc/dae/", "/tmp/"))
                if "target_path" in step.params:
                    _validate_safe_action_path(str(step.params["target_path"]), "target_path", ("/etc/dae/", "/tmp/"))

            if "max_nodes" in step.params:
                mn = step.params["max_nodes"]
                if isinstance(mn, bool) or not isinstance(mn, int) or not (1 <= mn <= 200):
                    raise PolicyViolationError("PARAM_OUT_OF_RANGE", f"max_nodes 超出范围 (1-200): {mn!r}")

            # 参数白名单校验
            unknown_keys = set(step.params.keys()) - set(spec.allowed_params)
            if unknown_keys:
                raise PolicyViolationError(
                    "INVALID_ACTION_PARAMS",
                    f"动作 {step.action_id} 包含未声明的参数: {sorted(unknown_keys)}",
                )

            # 前置条件检查
            missing_pre = [p for p in spec.preconditions if p not in precond_set]
            if missing_pre:
                raise PolicyViolationError(
                    "PRECONDITION_FAILED",
                    f"动作 {step.action_id} 缺少必需前置条件: {missing_pre}",
                )

            # R3/R4 生产变更必须绑定验证与回滚动作
            if RISK_ORDER[spec.risk] >= RISK_ORDER["R3"]:
                if step.verification is not None and str(step.verification).strip().lower() in ("", "none", "skip", "false"):
                    raise PolicyViolationError("MISSING_VERIFICATION", f"禁止关闭高危动作 {step.action_id} 的验证步骤")
                if step.rollback is not None and str(step.rollback).strip().lower() in ("", "none", "skip", "false"):
                    raise PolicyViolationError("MISSING_ROLLBACK", f"禁止关闭高危动作 {step.action_id} 的回滚动作")
                eff_verify = step.verification or spec.verification
                eff_rollback = step.rollback or spec.rollback
                if not eff_verify:
                    raise PolicyViolationError("MISSING_VERIFICATION", f"高危动作 {step.action_id} 缺少验证步骤")
                if not eff_rollback or (eff_rollback not in ACTION_REGISTRY and eff_rollback != "manual_console_recovery"):
                    raise PolicyViolationError("MISSING_ROLLBACK", f"高危动作 {step.action_id} 缺少已注册的回滚动作: {eff_rollback!r}")

        if total_step_timeout > plan.max_total_timeout:
            raise PolicyViolationError(
                "PLAN_TIMEOUT_EXCEEDED",
                f"步骤累计超时 ({total_step_timeout}s) 超过计划总上限 ({plan.max_total_timeout}s)",
            )
        return plan.compute_hash()

    def authorize_execution(
        self,
        plan: ExecutionPlan,
        approval: Optional[ApprovalToken],
        satisfied_preconditions: Sequence[str] = (),
        current_device_fingerprint: Optional[str] = None,
        now: Optional[float] = None,
    ) -> str:
        plan_hash = self.validate_plan(plan, satisfied_preconditions=satisfied_preconditions)
        if current_device_fingerprint is not None and current_device_fingerprint != plan.device_fingerprint:
            raise PolicyViolationError(
                "DEVICE_FINGERPRINT_MISMATCH",
                "目标设备当前指纹与计划绑定指纹不一致，立即阻断执行",
            )

        max_risk = plan.highest_risk()
        if RISK_ORDER[max_risk] >= RISK_ORDER["R3"]:
            if approval is None:
                raise PolicyViolationError(
                    "APPROVAL_REQUIRED",
                    f"计划包含 {max_risk} 级高风险动作，必须提供显式用户授权",
                )
            with _APPROVAL_LOCK:
                now_ts = time.time() if now is None else now
                if (isinstance(approval.max_uses, bool) or not isinstance(approval.max_uses, int)
                        or approval.max_uses < 1 or isinstance(approval.used_count, bool)
                        or not isinstance(approval.used_count, int) or approval.used_count < 0
                        or any(isinstance(t, bool) or not isinstance(t, (int, float)) or not math.isfinite(t)
                               for t in (now_ts, approval.issued_at, approval.expires_at))):
                    raise PolicyViolationError("INVALID_APPROVAL", "授权次数或时间必须为有效有限值")
                if now_ts < approval.issued_at:
                    raise PolicyViolationError("INVALID_APPROVAL", "授权尚未生效")
                if now_ts >= approval.expires_at:
                    raise PolicyViolationError("APPROVAL_EXPIRED", "用户授权已过期，请重新确认")
                if approval.used_count >= approval.max_uses:
                    raise PolicyViolationError("APPROVAL_EXHAUSTED", "该授权令牌已使用完毕，禁止重复复用")
                if approval.device_id != plan.device_id:
                    raise PolicyViolationError("APPROVAL_DEVICE_MISMATCH", "授权绑定的目标设备与当前计划不一致")
                if approval.device_fingerprint != plan.device_fingerprint:
                    raise PolicyViolationError("APPROVAL_FINGERPRINT_MISMATCH", "授权绑定的设备指纹与当前计划不一致")
                if approval.plan_hash != plan_hash:
                    raise PolicyViolationError("PLAN_HASH_MISMATCH", "执行计划内容或参数已变更，旧授权自动失效")
                if (
                    approval.approved_risk not in RISK_ORDER
                    or RISK_ORDER[approval.approved_risk] < RISK_ORDER[max_risk]
                ):
                    raise PolicyViolationError(
                        "INSUFFICIENT_APPROVAL_RISK",
                        f"授权风险等级 ({approval.approved_risk}) 低于计划实际最高风险 ({max_risk})",
                    )
                approval.used_count += 1
        return plan_hash

    def authorize_repair(
        self,
        repair_id: str,
        satisfied_preconditions: Sequence[str] = (),
        approved: bool = False,
        human_confirmed: bool = False,
        retry_count: int = 0,
    ) -> RepairSpec:
        if repair_id not in REPAIR_REGISTRY:
            raise PolicyViolationError("UNREGISTERED_REPAIR", f"未注册的修复动作: {repair_id!r}")
        spec = REPAIR_REGISTRY[repair_id]
        if retry_count > spec.max_retries:
            raise PolicyViolationError(
                "REPAIR_RETRY_EXCEEDED",
                f"修复动作 {repair_id} 重试次数 ({retry_count}) 超过上限 ({spec.max_retries})",
            )
        if spec.requires_human and not human_confirmed:
            raise PolicyViolationError(
                "REPAIR_REQUIRES_HUMAN",
                f"修复动作 {repair_id} 涉及高影响或外部凭据，必须人工确认",
            )
        if spec.requires_approval and not approved:
            raise PolicyViolationError(
                "REPAIR_APPROVAL_REQUIRED",
                f"修复动作 {repair_id} (风险 {spec.risk}) 必须获得显式授权",
            )
        pre_set = set(satisfied_preconditions)
        missing = [p for p in spec.preconditions if p not in pre_set]
        if missing:
            raise PolicyViolationError(
                "REPAIR_PRECONDITION_FAILED",
                f"修复动作 {repair_id} 缺少前置条件: {missing}",
            )
        return spec
