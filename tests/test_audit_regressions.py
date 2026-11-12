# -*- coding: utf-8 -*-
"""Reproductions and regression checks for the 2026-11-12 audit.

Real loopback sockets, independent processes, and injected filesystem failures
exercise boundaries that the previous mock-only checks did not cover.
"""
import concurrent.futures
import importlib.util
import json
import multiprocessing
import os
from pathlib import Path
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

REPO = Path(os.environ.get('AUDIT_TARGET_ROOT', Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / 'skills/singbox-openwrt/scripts'))
import sub_parser
from core.policy import (ApprovalToken, ExecutionPlan, PlanStep, PolicyEngine,
                         PolicyViolationError, _validate_safe_action_path)
from core.security import SSHPolicy, build_ssh_command
from core.transaction import (AuditLogger, AuditLogFailureError, DeviceLock,
                              LockConflictError, TaskStateMachine,
                              InvalidStateTransitionError, TransactionManager,
                              _is_pid_alive)
from core.validation import SixLayerValidator


def _lock_worker(directory, ready, start, release, queue):
    lock = DeviceLock(Path(directory), 'r', str(os.getpid()), 'worker', ttl_seconds=60)
    ready.put(True)
    start.wait(15)
    try:
        lock.acquire(now=1000, pid_checker=lambda _pid: False)
    except LockConflictError:
        queue.put('conflict')
    except Exception as exc:
        queue.put('error:' + repr(exc))
    else:
        queue.put('acquired')
        release.wait(15)
        lock.release()


def _fresh_txn(directory, task='audit', audit_logger=None):
    root = Path(directory)
    target = root / 'config.json'
    target.write_bytes(b'original')
    txn = TransactionManager(root / 'txn', task, 'router', audit_logger)
    for state in ('PROBING', 'PLANNING', 'POLICY_CHECK', 'PREPARING',
                  'PRECONDITION_CHECK', 'BACKING_UP'):
        txn.fsm.transition(state)
    txn.backup_files_and_sysctls([target], {})
    txn.verify_backups()
    return txn, target


class _SubscriptionHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/redirect':
            self.send_response(302)
            self.send_header('Location', '/body')
            self.end_headers()
            return
        if self.path == '/unsafe-redirect':
            self.send_response(302)
            self.send_header('Location', 'http://169.254.169.254/latest/meta-data/')
            self.end_headers()
            return
        self.send_response(200)
        body = ('host=' + self.headers.get('Host', '')).encode()
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class TestRequestLocalDNS(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), _SubscriptionHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)

    def resolver(self, host, port, *args):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', int(port)))]

    def test_concurrent_fetches_do_not_replace_global_dns(self):
        barrier = threading.Barrier(6)
        observed = []
        calls = []

        def resolve(host, port, *args):
            calls.append((host, port))
            return self.resolver(host, port, *args)

        # Inspect the global resolver during actual socket connections.
        real_connect = socket.socket.connect
        def connect(sock, address):
            observed.append(socket.getaddrinfo is resolve)
            return real_connect(sock, address)

        def fetch(index):
            barrier.wait(5)
            host = 'sub%d.example' % index
            return sub_parser.fetch_subscription(
                'http://%s:%s/redirect' % (host, self.port), timeout=5,
                allow_private=False, allowed_private_targets=['%s:%s' % (host, self.port)])

        with mock.patch.object(socket, 'getaddrinfo', resolve), \
             mock.patch.object(socket.socket, 'connect', connect):
            with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
                results = list(pool.map(fetch, range(6)))
            self.assertIs(socket.getaddrinfo, resolve)
        self.assertTrue(observed and all(observed))
        self.assertEqual(len(calls), 6, 'same-origin redirects must reuse validated addresses')
        for index, body in enumerate(results):
            self.assertEqual(body, 'host=sub%d.example:%s' % (index, self.port))

    def test_dns_rebinding_is_pinned_at_connection(self):
        calls = []
        def rebinding(host, port, *args):
            calls.append(host)
            ip = '127.0.0.1' if len(calls) == 1 else '127.0.0.2'
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, int(port)))]
        with mock.patch.object(socket, 'getaddrinfo', rebinding):
            body = sub_parser.fetch_subscription(
                'http://sub.example:%s/redirect' % self.port, timeout=2,
                allow_private=False, allowed_private_targets=['sub.example:%s' % self.port])
        self.assertIn('sub.example', body)
        self.assertEqual(calls, ['sub.example'])

    def test_environment_proxy_does_not_bypass_pinning(self):
        with mock.patch.dict(os.environ, {'http_proxy': 'http://127.0.0.2:1',
                                         'HTTP_PROXY': 'http://127.0.0.2:1', 'no_proxy': ''}), \
             mock.patch.object(socket, 'getaddrinfo', self.resolver):
            result = sub_parser.fetch_subscription(
                'http://sub.example:%s/body' % self.port, timeout=2,
                allow_private=False, allowed_private_targets=['sub.example:%s' % self.port])
        self.assertIn('sub.example', result)

    def test_redirect_metadata_is_blocked_even_with_broad_private_opt_in(self):
        with mock.patch.object(socket, 'getaddrinfo', self.resolver):
            with self.assertRaises(ValueError):
                sub_parser.fetch_subscription(
                    'http://sub.example:%s/unsafe-redirect' % self.port, timeout=2,
                    allow_private=True, allowed_private_targets=['sub.example:%s' % self.port])

    def test_broad_private_exception_keeps_special_addresses_blocked(self):
        for host in ('127.0.0.1', '[::1]', '169.254.169.254', '[::ffff:127.0.0.1]',
                     '0.0.0.0', '[64:ff9b::127.0.0.1]', '224.0.0.1'):
            with self.subTest(host=host), self.assertRaises(ValueError):
                sub_parser.validate_safe_subscription_url('http://%s/sub' % host, allow_private=True)
        self.assertEqual(sub_parser.validate_safe_subscription_url(
            'http://192.168.1.10/sub', allow_private=True), ['192.168.1.10'])

    def test_platform_endpoints_cannot_be_whitelisted(self):
        for host in ('169.254.169.254', '100.100.100.200', '168.63.129.16', '[fd00:ec2::254]',
                     '[::ffff:169.254.169.254]'):
            with self.subTest(host=host), self.assertRaises(ValueError):
                sub_parser.validate_safe_subscription_url('http://%s/sub' % host, allow_private=True,
                                                          allowed_private_targets=[host + ':80'])

    def test_mixed_dns_answer_is_rejected_before_any_connection(self):
        infos = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 443)),
                 (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('169.254.169.254', 443))]
        with mock.patch.object(socket, 'getaddrinfo', return_value=infos), \
             mock.patch.object(socket.socket, 'connect') as connect:
            with self.assertRaises(ValueError):
                sub_parser.fetch_subscription('https://sub.example/sub', allow_private=False)
        connect.assert_not_called()

    def test_failure_does_not_expose_secrets_in_traceback(self):
        import traceback
        secret = 'TOP_' + 'SECRET'
        url = 'http://sub.example/?token=' + secret
        with mock.patch.object(socket, 'getaddrinfo', side_effect=OSError('token=' + secret)):
            try:
                sub_parser.fetch_subscription(url, allow_private=False)
            except RuntimeError:
                formatted = traceback.format_exc()
            else:
                self.fail('must fail')
        self.assertNotIn(secret, formatted)

    def test_https_keeps_certificate_verification_and_original_sni(self):
        openssl = shutil.which('openssl')
        if not openssl:
            candidate = Path(r'C:\Software\scoop\apps\git\current\usr\bin\openssl.exe')
            openssl = str(candidate) if candidate.exists() else None
        if not openssl:
            self.skipTest('openssl unavailable for ephemeral TLS certificate')
        with tempfile.TemporaryDirectory() as td:
            cert, key = str(Path(td)/'cert.pem'), str(Path(td)/'key.pem')
            config = Path(td)/'openssl.cnf'
            config.write_text('[req]\ndistinguished_name=dn\n[dn]\n', encoding='utf-8')
            subprocess.run([openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                            '-keyout', key, '-out', cert, '-days', '1', '-subj', '/CN=sub.example',
                            '-config', str(config),
                            '-addext', 'subjectAltName=DNS:sub.example'], check=True,
                           capture_output=True, timeout=15)
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.load_cert_chain(cert, key)
            names = []
            server_context.set_servername_callback(lambda sock, name, ctx: names.append(name))
            tls_server = ThreadingHTTPServer(('127.0.0.1', 0), _SubscriptionHandler)
            tls_server.socket = server_context.wrap_socket(tls_server.socket, server_side=True)
            thread = threading.Thread(target=tls_server.serve_forever, daemon=True)
            thread.start()
            port = tls_server.server_address[1]
            url = 'https://sub.example:%s/body' % port
            allowlist = ['sub.example:%s' % port]
            try:
                with mock.patch.object(socket, 'getaddrinfo', self.resolver):
                    with self.assertRaises(RuntimeError):
                        sub_parser.fetch_subscription(url, timeout=3, allow_private=False,
                                                      allowed_private_targets=allowlist)
                trusted = ssl.create_default_context(cafile=cert)
                self.assertTrue(trusted.check_hostname)
                self.assertEqual(trusted.verify_mode, ssl.CERT_REQUIRED)
                with mock.patch.object(socket, 'getaddrinfo', self.resolver), \
                     mock.patch.object(ssl, '_create_default_https_context', return_value=trusted):
                    body = sub_parser.fetch_subscription(url, timeout=3, allow_private=False,
                                                         allowed_private_targets=allowlist)
                self.assertEqual(body, 'host=sub.example:%s' % port)
                self.assertTrue(names and all(name == 'sub.example' for name in names))
            finally:
                tls_server.shutdown()
                tls_server.server_close()
                thread.join(5)


class TestLockAndJournal(unittest.TestCase):
    def test_task_identifier_cannot_reset_windows_drive(self):
        with tempfile.TemporaryDirectory() as td:
            for task in ('C:escape', 'D:escape'):
                for factory in (lambda: TransactionManager(Path(td), task, 'r'),
                                lambda: TaskStateMachine(Path(td)/'j', task, 'r'),
                                lambda: DeviceLock(Path(td), 'r', task, 'owner')):
                    with self.subTest(task=task), self.assertRaises(ValueError):
                        factory()

    def test_stale_recovery_has_one_cross_process_winner(self):
        ctx = multiprocessing.get_context('spawn')
        with tempfile.TemporaryDirectory() as td:
            old = DeviceLock(Path(td), 'r', 'old', 'old', ttl_seconds=1)
            old.acquire(now=1)
            ready, queue = ctx.Queue(), ctx.Queue()
            start, release = ctx.Event(), ctx.Event()
            processes = [ctx.Process(target=_lock_worker, args=(td, ready, start, release, queue))
                         for _ in range(8)]
            try:
                for process in processes:
                    process.start()
                for _ in processes:
                    ready.get(timeout=20)
                start.set()
                outcomes = [queue.get(timeout=20) for _ in processes]
                self.assertEqual(outcomes.count('acquired'), 1, outcomes)
                self.assertEqual(outcomes.count('conflict'), 7, outcomes)
            finally:
                release.set()
                for process in processes:
                    process.join(10)
                    if process.is_alive():
                        process.terminate()
                        process.join(5)
                ready.close()
                queue.close()

    def test_same_owner_and_task_cannot_impersonate_holder(self):
        with tempfile.TemporaryDirectory() as td:
            first = DeviceLock(Path(td), 'r', 'same', 'same')
            second = DeviceLock(Path(td), 'r', 'same', 'same')
            first.acquire()
            first.heartbeat()
            first.acquire()
            for operation in (second.acquire, second.heartbeat, second.release):
                with self.assertRaises(LockConflictError):
                    operation()
            first.release()

    def test_pid_probe_does_not_terminate_process(self):
        child = subprocess.Popen([sys.executable, '-u', '-c',
                                  "import time; print('ready', flush=True); time.sleep(20)"], stdout=subprocess.PIPE)
        try:
            self.assertEqual(child.stdout.readline().strip(), b'ready')
            for _ in range(3):
                self.assertTrue(_is_pid_alive(child.pid))
            time.sleep(0.2)  # Allow asynchronous signal effects to be observed.
            self.assertIsNone(child.poll())
        finally:
            child.terminate()
            child.wait(timeout=5)
            child.stdout.close()
        self.assertFalse(_is_pid_alive(-1))

    def test_invalid_ttl_and_corrupt_lock_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            for value in (float('nan'), float('inf'), -1, 0, True):
                with self.subTest(ttl=value), self.assertRaises(ValueError):
                    DeviceLock(Path(td), 'r', 't', 'o', value)
            lock = DeviceLock(Path(td), 'r', 't', 'o')
            lock.lock_file.write_text('{broken', encoding='utf-8')
            with self.assertRaises(LockConflictError):
                lock.acquire()

    def test_torn_journal_tail_recovers_and_can_continue(self):
        for tail in (b'{"task_id":', b'{"result":"\xe4\xb8'):
            with self.subTest(tail=tail), tempfile.TemporaryDirectory() as td:
                path = Path(td)/'journal.jsonl'
                fsm = TaskStateMachine(path, 't', 'r')
                fsm.transition('PROBING')
                with path.open('ab') as out:
                    out.write(tail)
                with self.assertWarns(RuntimeWarning):
                    recovered = TaskStateMachine(path, 't', 'r')
                self.assertEqual(recovered.state, 'PROBING')
                recovered.transition('PLANNING')
                self.assertEqual(TaskStateMachine(path, 't', 'r').state, 'PLANNING')

    def test_interior_journal_corruption_is_not_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td)/'journal.jsonl'
            path.write_text('{broken}\n', encoding='utf-8')
            with self.assertRaises(InvalidStateTransitionError):
                TaskStateMachine(path, 't', 'r')

    def test_journal_device_binding_and_latest_state(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td)/'journal.jsonl'
            a, b = TaskStateMachine(path, 't', 'r'), TaskStateMachine(path, 't', 'r')
            a.transition('PROBING')
            b.transition('PLANNING')
            self.assertEqual(b.state, 'PLANNING')
            with self.assertRaises(InvalidStateTransitionError):
                TaskStateMachine(path, 't', 'other-router')


class TestPolicyAndValidation(unittest.TestCase):
    def make_plan(self):
        plan = ExecutionPlan('r', 'fp', (PlanStep('replace_singbox_config', '/etc/sing-box/config.json'),))
        from core.policy import ACTION_REGISTRY
        pre = ACTION_REGISTRY['replace_singbox_config'].preconditions
        token = ApprovalToken('r', 'fp', plan.compute_hash(), 'R3', 'user', issued_at=1, expires_at=100)
        return plan, pre, token

    def test_single_token_concurrent_uses_across_engines(self):
        plan, pre, token = self.make_plan()
        start = threading.Barrier(20)
        def authorize(_):
            start.wait(5)
            try:
                PolicyEngine().authorize_execution(plan, token, pre, now=50)
                return True
            except PolicyViolationError as exc:
                self.assertEqual(exc.reason_code, 'APPROVAL_EXHAUSTED')
                return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
            self.assertEqual(sum(pool.map(authorize, range(20))), 1)
        self.assertEqual(token.used_count, 1)

    def test_invalid_approval_values_and_expiry_boundary(self):
        for field, value in (('max_uses', True), ('max_uses', float('nan')),
                             ('used_count', -1), ('expires_at', float('nan')),
                             ('expires_at', 50), ('issued_at', 51)):
            plan, pre, token = self.make_plan()
            setattr(token, field, value)
            with self.subTest(field=field, value=value), self.assertRaises(PolicyViolationError):
                PolicyEngine().authorize_execution(plan, token, pre, now=50)

    def test_unknown_engine_and_nonobject_json_fail_structure_validation(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td)/'config.json'
            for engine, value in (('unsupported', '{}'), ('sing-box', '[]'), ('sing-box', 'null'), ('sing-box', '1')):
                path.write_text(value, encoding='utf-8')
                with self.subTest(engine=engine, value=value):
                    l1, l2 = SixLayerValidator().validate_l1_l2_structure_and_version(engine, '1.14', path)
                    self.assertFalse(l1.passed)
                    if engine == 'unsupported':
                        self.assertFalse(l2.passed)

    def test_path_prefix_uses_directory_boundaries(self):
        for prefix in ('/etc/sing-box/', '/etc/sing-box'):
            _validate_safe_action_path('/etc/sing-box/config.json', 'path', (prefix,))
            with self.assertRaises(PolicyViolationError):
                _validate_safe_action_path('/etc/sing-box-evil/config.json', 'path', (prefix,))

    def test_ssh_remote_arguments_survive_shell_parsing(self):
        args = ['printf', '%s', 'space value', '$(touch injected)', 'x;touch injected', "quote'arg", '']
        cmd = build_ssh_command(SSHPolicy('192.168.1.1'), args, check_files=False)
        remote = cmd[cmd.index('--') + 2:]
        self.assertEqual(shlex.split(' '.join(remote)), args)

    def test_ssh_rejects_string_and_control_char_commands(self):
        for args in ('echo hi', [], ['echo', 'a\nb']):
            with self.subTest(args=args), self.assertRaises(ValueError):
                build_ssh_command(SSHPolicy('192.168.1.1'), args, check_files=False)

    def test_unimplemented_fingerprint_option_is_not_silently_ignored(self):
        with self.assertRaises(ValueError):
            build_ssh_command(SSHPolicy('192.168.1.1', expected_fingerprint='SHA256:expected'),
                              ['sing-box', 'version'], check_files=False)


class TestTransactionFailurePaths(unittest.TestCase):
    def test_service_snapshots_cannot_be_silently_omitted_during_rollback(self):
        with tempfile.TemporaryDirectory() as td:
            txn, _ = _fresh_txn(td)
            txn.service_snapshots = {'sing-box': {'running': False}}
            self.assertEqual(txn.rollback({}, lambda: True), 'NEEDS_HUMAN')
            self.assertIn('service_state_store_missing', txn.fsm.history[-1]['result'])

    def test_corrupt_manifest_never_recovers_as_empty_backup(self):
        with tempfile.TemporaryDirectory() as td:
            txn, target = _fresh_txn(td)
            txn.manifest_path.write_text('{broken', encoding='utf-8')
            with self.assertRaises(RuntimeError):
                TransactionManager(txn.work_dir, txn.task_id, txn.device_id)
            self.assertEqual(target.read_bytes(), b'original')

    def test_missing_manifest_in_deployment_state_fails_closed(self):
        for rolling_back in (False, True):
            with self.subTest(rolling_back=rolling_back), tempfile.TemporaryDirectory() as td:
                txn, _ = _fresh_txn(td)
                if rolling_back:
                    txn.fsm.transition('ROLLING_BACK')
                txn.manifest_path.unlink()
                with self.assertRaises(RuntimeError):
                    TransactionManager(txn.work_dir, txn.task_id, txn.device_id)

    def test_manifest_identity_and_backup_path_binding(self):
        for field in ('device_id', 'backup_path'):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as td:
                txn, target = _fresh_txn(td)
                data = json.loads(txn.manifest_path.read_text(encoding='utf-8'))
                if field == 'device_id':
                    data[field] = 'other'
                else:
                    data['files'][str(target)][field] = str(Path(td)/'outside.bak')
                txn.manifest_path.write_text(json.dumps(data), encoding='utf-8')
                with self.assertRaises(RuntimeError):
                    TransactionManager(txn.work_dir, txn.task_id, txn.device_id)

    def test_audit_failure_blocks_replacement_and_commit(self):
        with tempfile.TemporaryDirectory() as td:
            txn, target = _fresh_txn(td, audit_logger=AuditLogger(Path(td)))
            with self.assertRaises(AuditLogFailureError):
                txn.stage_and_atomic_replace(target, b'new', lambda _: True)
            self.assertEqual(target.read_bytes(), b'original')
            self.assertFalse(list(Path(td).glob('*.staging')))
        with tempfile.TemporaryDirectory() as td:
            txn, target = _fresh_txn(td)
            txn.stage_and_atomic_replace(target, b'new', lambda _: True)
            txn.audit = AuditLogger(Path(td))
            with self.assertRaises(AuditLogFailureError):
                txn.commit_after_verification(lambda: True)
            self.assertEqual(txn.fsm.state, 'VERIFYING')

    def test_restore_replace_and_cleanup_errors_are_both_recorded(self):
        with tempfile.TemporaryDirectory() as td:
            txn, target = _fresh_txn(td)
            target.write_bytes(b'new')
            unlink, replace = Path.unlink, os.replace
            def bad_unlink(path, *args, **kwargs):
                if str(path).endswith('.restore'):
                    raise OSError('injected cleanup failure')
                return unlink(path, *args, **kwargs)
            def bad_replace(src, dst):
                if str(src).endswith('.restore'):
                    raise OSError('injected replace failure')
                return replace(src, dst)
            with mock.patch.object(Path, 'unlink', bad_unlink), mock.patch.object(os, 'replace', bad_replace):
                self.assertEqual(txn.rollback({}, lambda: True), 'NEEDS_HUMAN')
            result = txn.fsm.history[-1]['result']
            self.assertIn('injected replace failure', result)
            self.assertIn('injected cleanup failure', result)

    def test_staging_validator_cannot_change_approved_payload(self):
        with tempfile.TemporaryDirectory() as td:
            txn, target = _fresh_txn(td)
            def mutate(path):
                path.write_bytes(b'other')
                return True
            with self.assertRaises(RuntimeError):
                txn.stage_and_atomic_replace(target, b'approved', mutate)
            self.assertEqual(target.read_bytes(), b'original')
            self.assertFalse(list(Path(td).glob('*.staging')))

    def test_unbacked_target_cannot_be_deployed(self):
        with tempfile.TemporaryDirectory() as td:
            txn, target = _fresh_txn(td)
            with self.assertRaises(RuntimeError):
                txn.stage_and_atomic_replace(Path(td)/'unbacked', b'new', lambda _: True)

    def test_audit_event_ids_are_unique_across_instances(self):
        with tempfile.TemporaryDirectory() as td, mock.patch('core.transaction.time.time', return_value=1000):
            ids = [AuditLogger(Path(td)/'audit.jsonl').record('t','r','a','R1','allow','ok')['event_id']
                   for _ in range(20)]
            self.assertEqual(len(set(ids)), 20)


class TestDaeLexerAndMock(unittest.TestCase):
    def test_mock_pipeline_does_not_deploy_when_native_validation_fails(self):
        spec = importlib.util.spec_from_file_location('audit_pipeline', REPO/'docker/run_docker_tests.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        commands = []
        state = mock.Mock()
        def execute(command, stdin_data=''):
            commands.append(command)
            if command.startswith('sing-box check'):
                return 'invalid config', 1
            if '--json' in command:
                return '{}', 0
            if command.startswith('sh'):
                return 'unsupported', 126
            return '', 0
        state.execute_command.side_effect = execute
        with mock.patch.object(module, 'is_port_open', return_value=False), \
             mock.patch.object(module, 'say'), mock.patch('builtins.print'):
            results = module.run_pipeline('127.0.0.1', 2222, mock_state=state)
        self.assertFalse(any(command.startswith('mv ') for command in commands), commands)
        self.assertIn(('Deploy & Reload', False, 'Deploy failed'), results)

    def test_escaped_quote_in_ext_reference_is_not_misclassified(self):
        sys.path.insert(0, str(REPO/'skills/dae-openwrt/scripts'))
        from check_dae_syntax import check_dae_syntax
        with tempfile.TemporaryDirectory() as td:
            path = Path(td)/'config.dae'
            path.write_text('routing {\n domain(ext:"file\\"name.dat:tag") -> direct\n fallback: direct\n}\n', encoding='utf-8')
            errors, _ = check_dae_syntax(str(path))
            self.assertFalse([e for e in errors if '单引号规范' in e], errors)

    def test_mock_never_reports_unknown_commands_or_scripts_as_success(self):
        spec = importlib.util.spec_from_file_location('audit_mock_server', REPO/'docker/mock_openwrt_server.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        state = module.OpenWrtState()
        for command, stdin in (('sha256sum /missing', ''), ('shard', ''), ('unknown', ''),
                               ('unknown sing-box version', ''),
                               ('sh -s', 'unknown\nsing-box version'),
                               ('unknown && sing-box version', ''),
                               ('sing-box check -c /missing', '')):
            with self.subTest(command=command):
                self.assertNotEqual(state.execute_command(command, stdin)[1], 0)
        self.assertEqual(state.execute_command('sing-box version')[1], 0)
        state.singbox_running = False
        output, code = state.execute_command('sh -s -- --json', 'Smart Log Doctor')
        self.assertNotEqual(code, 0)
        self.assertEqual(json.loads(output)['status'], 'unhealthy')


if __name__ == '__main__':
    unittest.main()
