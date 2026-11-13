"""Engine prerequisites must not be reported as a verified data path."""
from pathlib import Path
import shutil
import subprocess
import unittest


@unittest.skipUnless(shutil.which('sh'), 'POSIX shell required')
class TestProbeEvidence(unittest.TestCase):
    def run_case(self, tun, dae, installed):
        root = Path(__file__).resolve().parents[1]
        for p in root.glob('skills/*/scripts/probe.sh'):
            text = p.read_text(encoding='utf-8')
            block = text.split('CAP_SINGBOX="unsupported"', 1)[1].split('LIMITS_JSON=', 1)[0]
            script = ('CAP_SINGBOX="unsupported"\n' + block +
                      '\nprintf "%s %s" "$CAP_SINGBOX" "$CAP_DAE"\n')
            import os
            env = dict(os.environ, HAS_TUN=str(tun), DAE_CAPABLE=str(dae),
                       SINGBOX_VER='v1.14.4' if installed else 'none',
                       DAE_VER='v2.1.1' if installed else 'none', DAE_GEODATA_OK='1')
            result = subprocess.run(['sh'], input=script, env=env, text=True,
                                    encoding='utf-8', capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, ('supported' if tun else 'unsupported') +
                             ' ' + ('supported' if dae else 'unsupported'), p)

    def test_installed_engines_with_prerequisites_are_not_verified(self):
        self.run_case(1, 1, True)

    def test_missing_prerequisites_remain_unsupported(self):
        self.run_case(0, 0, True)

    def test_prerequisites_without_engines_remain_supported(self):
        self.run_case(1, 1, False)
