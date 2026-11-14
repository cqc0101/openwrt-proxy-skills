"""Behavioral diagnostics regressions using controlled command and log fixtures."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]

@unittest.skipUnless(shutil.which('sh'), 'POSIX shell required')
class TestDoctorEvidence(unittest.TestCase):
    def diagnose(self, message, service='dae'):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root/'log.txt'
            fixture.write_text(message+'\n', encoding='utf-8')
            commands = {
                'logread': 'cat "$DOCTOR_FIXTURE"',
                'pidof': '[ "$1" = dae ] && { echo 123; exit 0; }; exit 1',
                'pgrep': 'exit 1', 'ip': 'exit 1', 'uci': 'exit 1',
                'ss': "printf 'udp 0 0 127.0.0.1:53 0.0.0.0:*\\n'",
                'netstat': "printf 'udp 0 0 127.0.0.1:53 0.0.0.0:*\\n'",
                'curl': "printf '204'", 'wget': 'exit 0',
            }
            for name, body in commands.items():
                path = root/name
                path.write_text('#!/bin/sh\n'+body+'\n', encoding='utf-8', newline='\n')
                path.chmod(0o755)
            env = dict(os.environ, PATH=str(root)+os.pathsep+os.environ['PATH'], DOCTOR_FIXTURE=fixture.as_posix())
            result = subprocess.run(['sh', str(REPO/'skills/dae-openwrt/scripts/doctor.sh'),service,'--json'],
                                    env=env,capture_output=True,text=True,encoding='utf-8',timeout=15)
            return json.loads(result.stdout)

    def test_success_logs_are_not_syntax_or_download_failures(self):
        result = self.diagnose('INFO parse config success; certificate loaded; rule-set download completed')
        self.assertEqual(result['issues'], [])

    def test_rejected_node_is_not_a_schema_failure(self):
        result = self.diagnose('ERROR failed to parse node: unsupported TLS option in global configuration')
        self.assertEqual([x['id'] for x in result['issues']], ['node_parse_failed'])
        self.assertEqual(result['status'], 'warning')
        self.assertTrue(result['issues'][0]['requires_human'])

    def test_real_configuration_failure_is_detected(self):
        result = self.diagnose('ERROR failed to parse "global": unexpected key: invalid_key')
        self.assertIn('config_syntax_error', [x['id'] for x in result['issues']])
        self.assertEqual(result['status'], 'error')

    def test_real_tls_failure_is_detected(self):
        result = self.diagnose('ERROR x509: certificate signed by unknown authority')
        self.assertTrue(result['issues'])

    def test_real_rule_download_failure_is_detected(self):
        result = self.diagnose('ERROR download rule-set cn: context deadline exceeded')
        self.assertTrue(result['issues'])

    def test_runtime_fingerprint_rejection_is_not_healthy(self):
        result = self.diagnose('WARN failed to get fingerprint: unknown uTLS Client Hello ID: ; the node is dropped')
        self.assertIn('node_fingerprint_invalid', [x['id'] for x in result['issues']])
        self.assertEqual(result['status'], 'error')

    def test_empty_group_is_not_healthy(self):
        for line in ('no dialer in this group', 'Group has no dialer alive', 'no alive dialer for selection'):
            result = self.diagnose(line)
            self.assertIn('proxy_group_unavailable', [x['id'] for x in result['issues']])

    def test_clean_logs_do_not_claim_lan_forwarding(self):
        result = self.diagnose('INFO service started')
        self.assertFalse(result['lan_forwarding_verified'])
        self.assertFalse(result['dns_path_verified'])
        self.assertEqual(result['outbound_check_scope'], 'router_http_reachability_only')
