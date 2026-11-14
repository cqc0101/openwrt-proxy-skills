# -*- coding: utf-8 -*-
"""POSIX guard and fork regressions; run on a real Linux kernel."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from core.transaction import DeviceLock, LockConflictError, _file_guard


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux kernel required')
class TestLinuxGuard(unittest.TestCase):
    def test_guard_released_on_process_exit_without_cleanup(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'guard'
            code = ('from pathlib import Path; import os; '
                    'from core.transaction import _file_guard; '
                    'g=_file_guard(Path(__import__("sys").argv[1])); '
                    'g.__enter__(); print("locked",flush=True); os._exit(0)')
            p = subprocess.run([sys.executable, '-c', code, str(path)],
                               capture_output=True, text=True, encoding='utf-8', timeout=20)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn('locked', p.stdout)
            with _file_guard(path):
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_threads_share_stable_guard_inode(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'guard'
            entered = threading.Event()
            finished = threading.Event()
            def worker():
                entered.set()
                with _file_guard(path):
                    finished.set()
            with _file_guard(path):
                inode = path.stat().st_ino
                t = threading.Thread(target=worker)
                t.start()
                self.assertTrue(entered.wait(10))
                self.assertFalse(finished.wait(0.1))
            t.join(10)
            self.assertFalse(t.is_alive())
            self.assertTrue(finished.is_set())
            self.assertEqual(path.stat().st_ino, inode)

    def test_guard_symlink_is_rejected_without_touching_victim(self):
        with tempfile.TemporaryDirectory() as d:
            victim = Path(d) / 'victim'
            victim.write_bytes(b'unchanged')
            guard = Path(d) / 'guard'
            guard.symlink_to(victim)
            with self.assertRaises(OSError):
                with _file_guard(guard):
                    self.fail('symlink guard accepted')
            self.assertEqual(victim.read_bytes(), b'unchanged')

    def test_forked_child_cannot_release_parent_lock(self):
        with tempfile.TemporaryDirectory() as d:
            lock = DeviceLock(Path(d), 'router', 'task', 'owner')
            lock.acquire()
            pid = os.fork()
            if pid == 0:
                try:
                    lock.release()
                except LockConflictError:
                    os._exit(0)
                except BaseException:
                    os._exit(2)
                os._exit(1)
            _, status = os.waitpid(pid, 0)
            try:
                self.assertEqual(os.waitstatus_to_exitcode(status), 0)
                lock.heartbeat()
            finally:
                lock.release()


class TestDaeNativeKeyFormat(unittest.TestCase):
    def test_export_uses_unique_safe_bare_keys_and_preserves_display_names(self):
        import re
        import urllib.parse
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills/singbox-openwrt/scripts"))
        from sub_parser import to_dae_nodes
        names = ['simple', '中文节点', 'node_2', "x}; routing { fallback: direct", '123', 'simple']
        text = to_dae_nodes([{'type': 'trojan', 'tag': name, 'server': 'proxy.example',
                              'server_port': 443, 'password': 'pw'} for name in names])
        entries = text.splitlines()[1:-1]
        keys = []
        for line in entries:
            match = re.fullmatch(r"  ([A-Za-z_][A-Za-z0-9_-]*): '([^']+)'", line)
            self.assertIsNotNone(match, line)
            keys.append(match.group(1))
            self.assertTrue(urllib.parse.urlsplit(match.group(2)).fragment)
        self.assertEqual(len(keys), len(names))
        self.assertEqual(len(keys), len(set(keys)))
        self.assertIn(urllib.parse.quote('中文节点'), text)


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux kernel required')
class TestWatchdogStartup(unittest.TestCase):
    def test_acknowledged_watchdog_survives_hangup_and_runs_recovery(self):
        import signal
        import shlex
        repo = Path(__file__).resolve().parents[1]
        for engine in ('dae-openwrt', 'singbox-openwrt'):
            text = (repo/'skills'/engine/'scripts/setup_openwrt_network.sh').read_text(encoding='utf8')
            body = text.split('arm_watchdog() {', 1)[1].split('\nkill_active_watchdog()', 1)[0].rsplit('\n}', 1)[0]
            body = body.replace('"$HOOK" enable', ':')
            body = body.replace('sleep 45', 'sleep 2')
            body = body.replace(') </dev/null >/dev/null 2>&1 &', ') </dev/null >/dev/null 2>&1 &\n    echo $! > "$STATE/watchdog.pid"')
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root/'recovery.sh').write_text('touch ' + shlex.quote(str(root/'recovered')) + '\n')
                script = ('set -e\nSTATE=' + shlex.quote(directory) + '\nSTATE_ROOT="$STATE"\nHOOK="$STATE/hook"\n'
                          'snapshot_prepare() { :; }\nsay() { :; }\nexec 9>"$STATE/lock"\nflock 9\n'
                          'arm_watchdog() {' + body + '\n}\narm_watchdog\n')
                result = subprocess.run(['sh', '-c', script], capture_output=True, text=True, encoding='utf-8', timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((root/'armed').read_text(), (root/'pending').read_text())
                os.kill(int((root/'watchdog.pid').read_text()), signal.SIGHUP)
                end = time.monotonic() + 5
                while not (root/'recovered').exists() and time.monotonic() < end:
                    time.sleep(.05)
                self.assertTrue((root/'recovered').exists())
