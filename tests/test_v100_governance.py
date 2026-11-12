# -*- coding: utf-8 -*-
"""v1.0.0 核心治理、Policy Engine、设备锁、15状态机、事务回滚与故障注入回归测试。"""

import json
import os
import socket
import stat
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

SINGBOX_SCRIPTS = os.path.join(REPO, "skills", "singbox-openwrt", "scripts")
if SINGBOX_SCRIPTS not in sys.path:
    sys.path.insert(0, SINGBOX_SCRIPTS)

import sub_parser
from core.security import (
    AllowedPrivateTarget,
    SSHPolicy,
    build_ssh_command,
    parse_allowed_private_targets,
    verify_known_hosts_file,
    verify_private_key_file,
)
from core.policy import (
    ACTION_REGISTRY,
    REPAIR_REGISTRY,
    ApprovalToken,
    ExecutionPlan,
    PlanStep,
    PolicyEngine,
    PolicyViolationError,
)
from core.validation import (
    ENGINE_CAPABILITY_TABLE,
    SixLayerValidator,
    ValidationReport,
)
from core.transaction import (
    AuditLogFailureError,
    AuditLogger,
    DeviceLock,
    InvalidStateTransitionError,
    LockConflictError,
    TaskStateMachine,
    TransactionManager,
)


class TestSecurityAndAllowlistV100(unittest.TestCase):
    def test_ssh_policy_strict_defaults_and_file_permission_checks(self):
        with tempfile.TemporaryDirectory() as td:
            kh = Path(td) / "known_hosts"
            key = Path(td) / "id_ed25519"
            kh.write_text("192.168.1.1 ssh-ed25519 AAAAC3Nza...\n", encoding="utf-8")
            key.write_text("PRIVATE KEY", encoding="utf-8")
            os.chmod(kh, 0o600)
            os.chmod(key, 0o600)

            pol = SSHPolicy(host="192.168.1.1", port=2222, username="root", known_hosts_file=kh, identity_file=key)
            cmd = build_ssh_command(pol, ["sing-box", "version"])
            self.assertIn("StrictHostKeyChecking=yes", cmd)
            self.assertIn(f"UserKnownHostsFile={kh}", cmd)
            self.assertIn("PasswordAuthentication=no", cmd)
            self.assertIn("IdentitiesOnly=yes", cmd)

            if os.name != "nt":
                os.chmod(key, 0o644)
                with self.assertRaises(PermissionError):
                    verify_private_key_file(key)
                os.chmod(kh, 0o666)
                with self.assertRaises(PermissionError):
                    verify_known_hosts_file(kh)

    def test_granular_private_target_allowlist_and_https_downgrade_block(self):
        # 默认拒绝 192.168.1.10:25500，但加入精确 host:port 白名单后仅允许该目标与端口
        with self.assertRaises(ValueError):
            sub_parser.validate_safe_subscription_url("http://192.168.1.10:25500/sub", allow_private=False)

        sub_parser.validate_safe_subscription_url(
            "http://192.168.1.10:25500/sub",
            allow_private=False,
            allowed_private_targets=["192.168.1.10:25500"],
        )
        # 同一 IP 的其他端口 (如 9090) 或其他私网 IP (192.168.1.1) 仍被严格拦截
        with self.assertRaises(ValueError):
            sub_parser.validate_safe_subscription_url(
                "http://192.168.1.10:9090/configs",
                allow_private=False,
                allowed_private_targets=["192.168.1.10:25500"],
            )
        with self.assertRaises(ValueError):
            sub_parser.validate_safe_subscription_url(
                "http://192.168.1.1:80/luci",
                allow_private=False,
                allowed_private_targets=["192.168.1.10:25500"],
            )
        # 严禁使用通配符 * 作为私网白名单
        with self.assertRaises(ValueError):
            parse_allowed_private_targets("*:443")

        # HTTPS -> HTTP 降级重定向默认阻断
        fake_public = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]
        handler = sub_parser._SafeRedirectHandler(allow_private=False, max_redirects=3)
        req = urllib.request.Request("https://secure.example.com/sub")
        with mock.patch("sub_parser.socket.getaddrinfo", return_value=fake_public):
            with self.assertRaises(urllib.error.URLError) as ctx:
                handler.redirect_request(req, None, 302, "Found", {}, "http://secure.example.com/sub")
            self.assertIn("拒绝从 HTTPS 降级", str(ctx.exception))


class TestPolicyEngineAndActionRegistryV100(unittest.TestCase):
    def setUp(self):
        self.engine = PolicyEngine()
        self.preconditions = (
            "device_identity_verified",
            "backup_verified",
            "config_native_validation_passed",
            "watchdog_ready",
        )

    def test_unregistered_action_and_risk_downgrade_blocked(self):
        bad_plan = ExecutionPlan(
            device_id="router-01",
            device_fingerprint="SHA256:abc123",
            steps=(PlanStep(action_id="arbitrary_shell_exec", target="/bin/sh"),),
        )
        with self.assertRaises(PolicyViolationError) as ctx:
            self.engine.validate_plan(bad_plan, self.preconditions)
        self.assertEqual(ctx.exception.reason_code, "UNREGISTERED_ACTION")

        downgraded_plan = ExecutionPlan(
            device_id="router-01",
            device_fingerprint="SHA256:abc123",
            steps=(
                PlanStep(
                    action_id="replace_singbox_config",
                    target="/etc/sing-box/config.json",
                    params={"target_path": "/etc/sing-box/config.json", "staging_path": "/tmp/sb.json"},
                    declared_risk="R1",
                ),
            ),
        )
        with self.assertRaises(PolicyViolationError) as ctx2:
            self.engine.validate_plan(downgraded_plan, self.preconditions)
        self.assertEqual(ctx2.exception.reason_code, "RISK_DOWNGRADE_FORBIDDEN")

    def test_plan_hash_binding_and_approval_invalidation_on_change(self):
        plan1 = ExecutionPlan(
            device_id="router-01",
            device_fingerprint="SHA256:fp01",
            steps=(
                PlanStep(
                    action_id="replace_singbox_config",
                    target="/etc/sing-box/config.json",
                    params={"target_path": "/etc/sing-box/config.json", "staging_path": "/tmp/sb1.json"},
                ),
            ),
        )
        h1 = self.engine.validate_plan(plan1, self.preconditions)
        # 未提供授权时 R3 动作被拒绝
        with self.assertRaises(PolicyViolationError) as no_app:
            self.engine.authorize_execution(plan1, approval=None, satisfied_preconditions=self.preconditions)
        self.assertEqual(no_app.exception.reason_code, "APPROVAL_REQUIRED")

        token = ApprovalToken(
            device_id="router-01",
            device_fingerprint="SHA256:fp01",
            plan_hash=h1,
            approved_risk="R3",
            actor="admin",
            issued_at=100.0,
            expires_at=200.0,
            max_uses=1,
        )
        # 篡改计划参数后，旧授权立即失效
        plan2 = ExecutionPlan(
            device_id="router-01",
            device_fingerprint="SHA256:fp01",
            steps=(
                PlanStep(
                    action_id="replace_singbox_config",
                    target="/etc/sing-box/config.json",
                    params={"target_path": "/etc/sing-box/config.json", "staging_path": "/tmp/sb_tampered.json"},
                ),
            ),
        )
        with self.assertRaises(PolicyViolationError) as hash_err:
            self.engine.authorize_execution(plan2, approval=token, satisfied_preconditions=self.preconditions, now=150.0)
        self.assertEqual(hash_err.exception.reason_code, "PLAN_HASH_MISMATCH")

        # 过期授权被拒绝
        with self.assertRaises(PolicyViolationError) as exp_err:
            self.engine.authorize_execution(plan1, approval=token, satisfied_preconditions=self.preconditions, now=250.0)
        self.assertEqual(exp_err.exception.reason_code, "APPROVAL_EXPIRED")

        # 正常授权通过一次后，再次复用同一单次令牌被拒绝
        self.engine.authorize_execution(plan1, approval=token, satisfied_preconditions=self.preconditions, now=150.0)
        with self.assertRaises(PolicyViolationError) as used_err:
            self.engine.authorize_execution(plan1, approval=token, satisfied_preconditions=self.preconditions, now=151.0)
        self.assertEqual(used_err.exception.reason_code, "APPROVAL_EXHAUSTED")

    def test_repair_registry_governance(self):
        # 未授权或缺少人工确认的高风险修复被拒绝
        with self.assertRaises(PolicyViolationError) as r_err:
            self.engine.authorize_repair("repair_daed_conflict", approved=True, human_confirmed=False)
        self.assertEqual(r_err.exception.reason_code, "REPAIR_REQUIRES_HUMAN")

        spec = self.engine.authorize_repair(
            "repair_daed_conflict",
            satisfied_preconditions=("human_confirmed_disable_daed",),
            approved=True,
            human_confirmed=True,
            retry_count=1,
        )
        self.assertEqual(spec.risk, "R4")


class TestDeviceLockAndTransactionRollbackV100(unittest.TestCase):
    def test_device_lock_concurrency_and_stale_recovery(self):
        with tempfile.TemporaryDirectory() as td:
            lock_dir = Path(td)
            lock1 = DeviceLock(lock_dir, device_id="router-01", task_id="t1", owner="agent-A", ttl_seconds=60)
            lock2 = DeviceLock(lock_dir, device_id="router-01", task_id="t2", owner="agent-B", ttl_seconds=60)

            lock1.acquire(now=1000.0)
            # 同一时刻第二个任务抢锁必须失败
            with self.assertRaises(LockConflictError):
                lock2.acquire(now=1010.0)
            # 非持有者释放锁必须被拒绝
            with self.assertRaises(LockConflictError):
                lock2.release()
            # 锁超时但旧进程仍存活时，不得强行回收
            with self.assertRaises(LockConflictError):
                lock2.acquire(now=2000.0, pid_checker=lambda _pid: True)
            # 锁超时且旧进程已退出时，允许安全回收并获取锁
            lock2.acquire(now=2000.0, pid_checker=lambda _pid: False)
            lock2.release()

    def test_state_machine_persistence_and_illegal_transitions(self):
        with tempfile.TemporaryDirectory() as td:
            j_path = Path(td) / "journal.jsonl"
            fsm = TaskStateMachine(j_path, task_id="task-100", device_id="router-01")
            # 未经过 BACKUP_VERIFY 直接跳 DEPLOYING 必须被拒绝
            with self.assertRaises(InvalidStateTransitionError):
                fsm.transition("DEPLOYING")

            for st in ("PROBING", "PLANNING", "POLICY_CHECK", "PREPARING", "PRECONDITION_CHECK", "BACKING_UP"):
                fsm.transition(st)

            # 模拟 Agent 重启后从持久化日志恢复状态
            recovered = TaskStateMachine(j_path, task_id="task-100", device_id="router-01")
            self.assertEqual(recovered.state, "BACKING_UP")

    def test_transaction_commit_and_rollback_to_rolled_back_vs_needs_human(self):
        with tempfile.TemporaryDirectory() as td:
            work_dir = Path(td)
            prod_cfg = work_dir / "config.json"
            prod_cfg.write_text('{"outbounds": [{"type": "direct", "tag": "direct"}]}', encoding="utf-8")
            sysctl_state = {"net.ipv4.ip_forward": "0", "net.netfilter.nf_conntrack_max": "16384"}

            txn = TransactionManager(work_dir, task_id="tx-01", device_id="router-01")
            for st in ("PROBING", "PLANNING", "POLICY_CHECK", "PREPARING", "PRECONDITION_CHECK", "BACKING_UP"):
                txn.fsm.transition(st)

            txn.backup_files_and_sysctls(
                [prod_cfg],
                {
                    "net.ipv4.ip_forward": (True, "0", "1"),
                    "net.netfilter.nf_conntrack_max": (True, "16384", "65536"),
                    "net.ipv4.tcp_congestion_control": (False, None, "bbr"),
                },
            )
            txn.verify_backups()

            # 模拟部署新配置与修改 sysctl，但 L5 业务健康检查失败触发自动回滚
            sysctl_state["net.ipv4.ip_forward"] = "1"
            sysctl_state["net.netfilter.nf_conntrack_max"] = "65536"
            sysctl_state["net.ipv4.tcp_congestion_control"] = "bbr"
            txn.stage_and_atomic_replace(
                prod_cfg,
                b'{"outbounds": [{"type": "direct", "tag": "modified"}]}',
                native_validator=lambda _p: True,
            )
            with self.assertRaises(RuntimeError):
                txn.commit_after_verification(business_verifier=lambda: False)

            final_state = txn.rollback(sysctl_state=sysctl_state, health_verifier=lambda: True)
            self.assertEqual(final_state, "ROLLED_BACK")
            self.assertIn('"tag": "direct"', prod_cfg.read_text(encoding="utf-8"))
            self.assertEqual(sysctl_state.get("net.ipv4.ip_forward"), "0")
            self.assertEqual(sysctl_state.get("net.netfilter.nf_conntrack_max"), "16384")
            self.assertNotIn("net.ipv4.tcp_congestion_control", sysctl_state)

            # 场景 2：当回滚后业务健康检查仍然失败时，严禁谎报 ROLLED_BACK，必须进入 NEEDS_HUMAN
            txn2 = TransactionManager(work_dir, task_id="tx-02", device_id="router-01")
            for st in ("PROBING", "PLANNING", "POLICY_CHECK", "PREPARING", "PRECONDITION_CHECK", "BACKING_UP"):
                txn2.fsm.transition(st)
            txn2.backup_files_and_sysctls([prod_cfg], {})
            txn2.verify_backups()
            txn2.stage_and_atomic_replace(prod_cfg, b'{"bad": 1}', native_validator=lambda _p: True)
            state2 = txn2.rollback(sysctl_state={}, health_verifier=lambda: False)
            self.assertEqual(state2, "NEEDS_HUMAN")

    def test_audit_logger_redacts_secrets_and_fails_closed_on_r3_write_error(self):
        with tempfile.TemporaryDirectory() as td:
            log_file = Path(td) / "audit.jsonl"
            logger = AuditLogger(log_file)
            ev = logger.record(
                task_id="t1",
                device_id="r1",
                action_id="fetch_sub",
                risk="R1",
                decision="auto",
                result="https://user:my_pass@sub.example.com/api?token=SECRET_TOKEN_123",
                detail="password=SUPER_SECRET_PWD",
            )
            raw_log = log_file.read_text(encoding="utf-8")
            self.assertNotIn("SECRET_TOKEN_123", raw_log)
            self.assertNotIn("my_pass", raw_log)
            self.assertNotIn("SUPER_SECRET_PWD", raw_log)
            self.assertIn("***REDACTED***", raw_log)

            # 若审计路径指向目录导致写入失败，R3/R4 必须抛出 AuditLogFailureError 阻断执行
            bad_logger = AuditLogger(Path(td))
            with self.assertRaises(AuditLogFailureError):
                bad_logger.record(
                    task_id="t2",
                    device_id="r1",
                    action_id="replace_singbox_config",
                    risk="R3",
                    decision="approved",
                    result="ok",
                )



    def test_fetch_subscription_with_allowed_private_targets_and_line_depth_limits(self):
        # 1. 验证 fetch_subscription + _pinned_getaddrinfo 对精确私网白名单目标放行，对非白名单目标阻断
        fake_priv = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.10", 25500))]
        fake_resp = mock.MagicMock()
        fake_resp.__enter__.return_value = fake_resp
        fake_resp.read.return_value = b"vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443?security=none#OK\n"
        fake_resp.headers = {}

        def _fake_open(req, timeout=15):
            # 模拟 urllib 内部调用 socket.getaddrinfo 建立连接
            socket.getaddrinfo("sub.home.arpa", 25500, 0, socket.SOCK_STREAM)
            return fake_resp

        with mock.patch("sub_parser.socket.getaddrinfo", return_value=fake_priv), \
             mock.patch("sub_parser.urllib.request.OpenerDirector.open", side_effect=_fake_open):
            body = sub_parser.fetch_subscription(
                "http://sub.home.arpa:25500/sub",
                allow_private=False,
                allowed_private_targets=["sub.home.arpa:25500"],
            )
            self.assertIn("vless://", body)
            # 未命中端口白名单 (如 9090) 在连接期同样被阻断
            with self.assertRaises(ValueError):
                sub_parser.fetch_subscription(
                    "http://sub.home.arpa:9090/sub",
                    allow_private=False,
                    allowed_private_targets=["sub.home.arpa:25500"],
                )

        # 2. 验证单行超长 (> MAX_LINE_LENGTH) 与 YAML 深度超限 (> MAX_YAML_DEPTH) 被阻断
        overlong_line = "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443#" + ("A" * (sub_parser.MAX_LINE_LENGTH + 10))
        with self.assertRaises(ValueError):
            sub_parser.parse_subscription_text(overlong_line)

        deep_flow = "{a: " * (sub_parser.MAX_YAML_DEPTH + 3) + "1" + "}" * (sub_parser.MAX_YAML_DEPTH + 3)
        with self.assertRaises(ValueError):
            sub_parser._parse_yaml_scalar_or_flow(deep_flow, {})

    def test_doctor_issues_all_registered_in_repair_registry(self):
        import re as _re
        doc_path = Path(REPO) / "skills" / "singbox-openwrt" / "scripts" / "doctor.sh"
        doc_text = doc_path.read_text(encoding="utf-8")
        issue_ids = set(_re.findall(r'add_issue\s+"([a-zA-Z0-9_]+)"', doc_text))
        self.assertGreaterEqual(len(issue_ids), 13)
        for iid in sorted(issue_ids):
            rid = f"repair_{iid}"
            self.assertIn(rid, REPAIR_REGISTRY, f"doctor.sh 诊断项 {iid} 对应的 {rid} 未在 REPAIR_REGISTRY 注册")

    def test_transaction_crash_recovery_from_manifest_and_corrupted_backup_guard(self):
        with tempfile.TemporaryDirectory() as td:
            work_dir = Path(td)
            prod_cfg = work_dir / "config.json"
            orig_text = '{"outbounds": [{"type": "direct", "tag": "orig"}]}'
            prod_cfg.write_text(orig_text, encoding="utf-8")
            sysctl_state = {"net.ipv4.ip_forward": "0"}
            service_store = {"sing-box": {"enabled": True, "running": True}}

            txn1 = TransactionManager(work_dir, task_id="tx-crash", device_id="router-01")
            for st in ("PROBING", "PLANNING", "POLICY_CHECK", "PREPARING", "PRECONDITION_CHECK", "BACKING_UP"):
                txn1.fsm.transition(st)
            txn1.backup_files_and_sysctls(
                [prod_cfg],
                {"net.ipv4.ip_forward": (True, "0", "1")},
                service_states={"sing-box": {"enabled": False, "running": False}},
            )
            txn1.verify_backups()
            txn1.stage_and_atomic_replace(prod_cfg, b'{"outbounds": [{"type": "direct", "tag": "new"}]}', lambda _p: True)
            sysctl_state["net.ipv4.ip_forward"] = "1"

            # 模拟进程崩溃重启：新建 TransactionManager 实例自动从 journal.jsonl 与 manifest.json 恢复并完成回滚
            recovered_txn = TransactionManager(work_dir, task_id="tx-crash", device_id="router-01")
            self.assertEqual(recovered_txn.fsm.state, "DEPLOYING")
            res_state = recovered_txn.rollback(
                sysctl_state=sysctl_state,
                health_verifier=lambda: True,
                service_state_store=service_store,
            )
            self.assertEqual(res_state, "ROLLED_BACK")
            self.assertEqual(prod_cfg.read_text(encoding="utf-8"), orig_text)
            self.assertEqual(sysctl_state["net.ipv4.ip_forward"], "0")
            self.assertEqual(service_store["sing-box"], {"enabled": False, "running": False})

            # 若备份文件在回滚前被损坏，回滚必须拒绝覆盖生产文件并进入 NEEDS_HUMAN
            txn_corrupt = TransactionManager(work_dir, task_id="tx-corrupt", device_id="router-01")
            for st in ("PROBING", "PLANNING", "POLICY_CHECK", "PREPARING", "PRECONDITION_CHECK", "BACKING_UP"):
                txn_corrupt.fsm.transition(st)
            txn_corrupt.backup_files_and_sysctls([prod_cfg], {})
            txn_corrupt.verify_backups()
            txn_corrupt.stage_and_atomic_replace(prod_cfg, b'{"keep": "staged"}', lambda _p: True)
            # 破坏备份文件内容
            bak_path = Path(txn_corrupt.file_backups[str(prod_cfg)].backup_path)
            bak_path.write_text("CORRUPTED_DATA", encoding="utf-8")
            corrupt_state = txn_corrupt.rollback(sysctl_state={}, health_verifier=lambda: True)
            self.assertEqual(corrupt_state, "NEEDS_HUMAN")
            self.assertEqual(prod_cfg.read_text(encoding="utf-8"), '{"keep": "staged"}')

    def test_six_layer_validator_and_quality_baseline_docs(self):
        validator = SixLayerValidator()
        # L0 输入校验拦截非法端口与超限 max_nodes
        l0_bad = validator.validate_l0_inputs("sing-box", "1.14", max_nodes=0, port=70000)
        self.assertFalse(l0_bad.passed)
        self.assertEqual(l0_bad.failure_action, "reject_input")

        l0_ok = validator.validate_l0_inputs("sing-box", "1.14", max_nodes=15, port=22)
        self.assertTrue(l0_ok.passed)

        # L1/L2 校验真实 1.14 模板通过，混入 1.13 废弃字段或未知版本被拦截
        tpl_114 = Path(REPO) / "skills" / "singbox-openwrt" / "assets" / "templates" / "openwrt-1.14-tun-fakeip.json"
        l1_ok, l2_ok = validator.validate_l1_l2_structure_and_version("sing-box", "1.14", tpl_114)
        self.assertTrue(l1_ok.passed, l1_ok.errors)
        self.assertTrue(l2_ok.passed, l2_ok.errors)

        _, l2_unknown = validator.validate_l1_l2_structure_and_version("sing-box", "1.99", tpl_114)
        self.assertFalse(l2_unknown.passed)

        # L3/L4/L5 验证与报告聚合
        l3_ok = validator.validate_l3_native_engine(tpl_114, lambda _p: (True, ""))
        l4_ok = validator.validate_l4_device_deployment(tpl_114, service_running=True, port_listening=True)
        l5_fail = validator.validate_l5_business_health(ssh_channel_ok=True, lan_wan_ok=True, dns_ok=False, proxy_egress_ok=True)
        report = ValidationReport(engine="sing-box", version="1.14", layers=[l0_ok, l1_ok, l2_ok, l3_ok, l4_ok, l5_fail])
        self.assertFalse(report.passed)
        self.assertEqual(report.failed_layer, "L5")
        self.assertEqual(report.recommended_action, "rollback_or_needs_human")

        # 验证 Section 1.2 要求的 5 个质量基线文档齐全
        q_dir = Path(REPO) / "docs" / "quality"
        for q_name in ("BASELINE.md", "KNOWN_ISSUES.md", "TEST_BASELINE.md", "DEVICE_BASELINE.md", "RELEASE_EVIDENCE.md"):
            qf = q_dir / q_name
            self.assertTrue(qf.is_file() and qf.stat().st_size > 50, f"缺少质量基线文档: {qf}")



    def test_path_traversal_shell_injection_and_wildcard_allowlist_blocked(self):
        # 1. PolicyEngine 拦截路径穿越、越界目录、Shell 注入与禁用回滚/验证
        engine = PolicyEngine()
        pre = ("device_identity_verified", "backup_verified", "config_native_validation_passed")
        for bad_target, expected_code in (
            ("/etc/sing-box/../../etc/shadow", "PATH_TRAVERSAL_DETECTED"),
            ("/etc/passwd", "PATH_OUT_OF_SCOPE"),
            ("/etc/sing-box/config.json;id", "SHELL_INJECTION_DETECTED"),
        ):
            p_bad = ExecutionPlan(
                device_id="router-01",
                device_fingerprint="SHA256:fp01",
                steps=(PlanStep(action_id="replace_singbox_config", target=bad_target),),
            )
            with self.assertRaises(PolicyViolationError) as ctx:
                engine.validate_plan(p_bad, pre)
            self.assertEqual(ctx.exception.reason_code, expected_code)

        # 显式传入 verification="none" 或未注册 rollback 必须被拦截
        p_no_ver = ExecutionPlan(
            device_id="router-01",
            device_fingerprint="SHA256:fp01",
            steps=(PlanStep(action_id="replace_singbox_config", target="/etc/sing-box/config.json", verification="none"),),
        )
        with self.assertRaises(PolicyViolationError) as ctx_v:
            engine.validate_plan(p_no_ver, pre)
        self.assertEqual(ctx_v.exception.reason_code, "MISSING_VERIFICATION")

        p_bad_rb = ExecutionPlan(
            device_id="router-01",
            device_fingerprint="SHA256:fp01",
            steps=(PlanStep(action_id="replace_singbox_config", target="/etc/sing-box/config.json", rollback="unregistered_rb"),),
        )
        with self.assertRaises(PolicyViolationError) as ctx_rb:
            engine.validate_plan(p_bad_rb, pre)
        self.assertEqual(ctx_rb.exception.reason_code, "MISSING_ROLLBACK")

        # 2. 拦截带端口的通配符白名单 (*:443 / *.lan:443 / 0.0.0.0:8080)，并支持 AllowedPrivateTarget 实例直接传入
        for bad_spec in ("*:443", "*.lan:443", "0.0.0.0:8080", "[::]:443"):
            with self.assertRaises(ValueError):
                parse_allowed_private_targets(bad_spec)
            with self.assertRaises(ValueError):
                sub_parser.validate_safe_subscription_url(
                    "http://192.168.1.10:443/sub",
                    allow_private=False,
                    allowed_private_targets=[bad_spec],
                )

        apt = AllowedPrivateTarget(host="192.168.1.10", ports=(25500,))
        sub_parser.validate_safe_subscription_url(
            "http://192.168.1.10:25500/sub",
            allow_private=False,
            allowed_private_targets=[apt],
        )

    def test_device_lock_context_manager_and_staging_cleanup_on_validator_exception(self):
        with tempfile.TemporaryDirectory() as td:
            work_dir = Path(td)
            with DeviceLock(work_dir, device_id="router-ctx", task_id="t-ctx", owner="agent-1") as lk:
                self.assertTrue(lk.lock_file.is_file())
                lock_data = json.loads(lk.lock_file.read_text(encoding="utf-8"))
                self.assertIn("expires_at", lock_data)
            self.assertFalse(lk.lock_file.exists())

            prod_cfg = work_dir / "config.json"
            prod_cfg.write_text("{}", encoding="utf-8")
            txn = TransactionManager(work_dir, task_id="tx-exc", device_id="router-ctx")
            for st in ("PROBING", "PLANNING", "POLICY_CHECK", "PREPARING", "PRECONDITION_CHECK", "BACKING_UP"):
                txn.fsm.transition(st)
            txn.backup_files_and_sysctls([prod_cfg], {})
            txn.verify_backups()

            def _raising_validator(_p: Path) -> bool:
                raise ValueError("syntax crash")

            with self.assertRaises(RuntimeError):
                txn.stage_and_atomic_replace(prod_cfg, b"bad", _raising_validator)
            # 确保临时 .staging 文件已被彻底清理
            staging_files = list(work_dir.glob("*.staging"))
            self.assertEqual(staging_files, [])



    def test_round3_deep_audit_ipv6_allowlist_ast_l2_and_terminal_rollback(self):
        # 1. 验证裸 IPv6 '::'、CIDR 网段、非法端口字符串及直接构造通配符 AllowedPrivateTarget 均被拦截
        for bad_spec in ("::", "[0:0:0:0:0:0:0:0]:443", "192.168.1.0/24", "192.168.1.10:abc", "192.168.1.10:70000"):
            with self.assertRaises(ValueError, msg=f"未能拦截非法私网白名单: {bad_spec}"):
                parse_allowed_private_targets(bad_spec)
            with self.assertRaises(ValueError, msg=f"validate_safe_subscription_url 未能拦截: {bad_spec}"):
                sub_parser.validate_safe_subscription_url(
                    "http://192.168.1.10:443/sub",
                    allow_private=False,
                    allowed_private_targets=[bad_spec],
                )
        with self.assertRaises(ValueError):
            AllowedPrivateTarget(host="*", ports=(443,))
        with self.assertRaises(ValueError):
            AllowedPrivateTarget(host="::", ports=(443,))
        with self.assertRaises(ValueError):
            AllowedPrivateTarget(host="192.168.1.10", ports=())

        # 验证非压缩 IPv6 白名单 [FE80:0000::1]:25500 能正确匹配规范化后的 [fe80::1]:25500
        ipv6_targets = parse_allowed_private_targets("[FE80:0000::1]:25500,fe80::2")
        self.assertEqual(len(ipv6_targets), 2)
        self.assertTrue(ipv6_targets[0].matches("fe80::1", 25500))
        self.assertTrue(ipv6_targets[1].matches("fe80::2", 443))

        # 2. 验证 SixLayerValidator L2 基于 JSON AST 与剥离注释校验，不因节点名 'optimistic' 或注释 '# bpf_conn_state_map_size:' 误报
        validator = SixLayerValidator()
        self.assertFalse(validator.validate_l0_inputs("sing-box", "1.14", main_router_ip="127.0.0.1").passed)
        self.assertFalse(validator.validate_l0_inputs("sing-box", "1.14", main_router_ip="0.0.0.0").passed)

        import auto_config
        import sub_to_dae
        cfg_113 = auto_config.build_config(
            version="1.13",
            dns_mode="fakeip",
            node_uris=["vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443?security=none#optimistic"],
        )
        with tempfile.TemporaryDirectory() as td:
            p_113 = Path(td) / "sb113.json"
            p_113.write_text(json.dumps(cfg_113, ensure_ascii=False), encoding="utf-8")
            l1_sb, l2_sb = validator.validate_l1_l2_structure_and_version("sing-box", "1.13", p_113)
            self.assertTrue(l1_sb.passed, l1_sb.errors)
            self.assertTrue(l2_sb.passed, l2_sb.errors)

            dae_legacy = sub_to_dae.build_full_dae_config(
                [{"type": "vless", "tag": "N1", "server": "1.2.3.4", "server_port": 443, "uuid": "11111111-1111-1111-1111-111111111111"}],
                dae_version="legacy",
            )
            dae_with_comment = "# bpf_conn_state_map_size: 65536\n" + dae_legacy
            p_dae = Path(td) / "legacy.dae"
            p_dae.write_text(dae_with_comment, encoding="utf-8")
            l1_d, l2_d = validator.validate_l1_l2_structure_and_version("dae", "legacy", p_dae)
            self.assertTrue(l1_d.passed, l1_d.errors)
            self.assertTrue(l2_d.passed, l2_d.errors)

            # 3. 验证终态 COMMITTED 调用 rollback() 立即在修改文件前抛出 InvalidStateTransitionError，且拦截非法 task_id 路径穿越
            with self.assertRaises(ValueError):
                TransactionManager(Path(td), task_id="../escape", device_id="router-01")
            with self.assertRaises(ValueError):
                DeviceLock(Path(td), device_id="..", task_id="t1", owner="agent")

            prod_f = Path(td) / "prod.json"
            prod_f.write_text("v1", encoding="utf-8")
            txn = TransactionManager(Path(td), task_id="tx-term", device_id="router-01")
            for st in ("PROBING", "PLANNING", "POLICY_CHECK", "PREPARING", "PRECONDITION_CHECK", "BACKING_UP"):
                txn.fsm.transition(st)
            txn.backup_files_and_sysctls([prod_f], {})
            txn.verify_backups()
            txn.stage_and_atomic_replace(prod_f, b"v2-committed", lambda _p: True)
            txn.commit_after_verification(lambda: True)
            self.assertEqual(txn.fsm.state, "COMMITTED")
            with self.assertRaises(InvalidStateTransitionError):
                txn.rollback(sysctl_state={}, health_verifier=lambda: True)
            # 确认已提交的生产文件未被误回滚覆写
            self.assertEqual(prod_f.read_text(encoding="utf-8"), "v2-committed")

        # 4. 验证 PolicyEngine 对非路径型字符串参数 (如 service / wan_iface) 的 Shell 元字符拦截
        engine = PolicyEngine()
        bad_step_plan = ExecutionPlan(
            device_id="router-01",
            device_fingerprint="SHA256:fp01",
            steps=(PlanStep(action_id="doctor_diagnose", target="/tmp/diag", params={"service": "sing-box; reboot"}),),
        )
        with self.assertRaises(PolicyViolationError) as ctx_s:
            engine.validate_plan(bad_step_plan)
        self.assertEqual(ctx_s.exception.reason_code, "SHELL_INJECTION_DETECTED")

        # 5. 验证 auto_config.build_config 拦截非法空 DNS 主机名 (--dns-cn "[]")
        with self.assertRaises(ValueError):
            auto_config.build_config(dns_cn="[]")


if __name__ == "__main__":
    unittest.main()
