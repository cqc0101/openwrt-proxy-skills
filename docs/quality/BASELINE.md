# v0.7.0 -> v1.0.0 Quality Baseline

- **Baseline revision**: `v0.7.0`
- **Target release**: `v1.0.0`
- **Python**: `3.11+` (zero third-party runtime dependencies)
- **Target firmware**: OpenWrt `18.06~24.10` / ImmortalWrt `23.05~25+ SNAPSHOT` / iStoreOS `22.03~24.10`
- **Target kernel**: Linux `4.14 ~ 6.6+` (`fw3`/`iptables` & `fw4`/`nftables`)
- **Engines**: `sing-box 1.13 / 1.14+`, `dae legacy (<=1.0.0) / modern (1.1+ ~ 2.1.1+)`

## Test & Verification Summary
- **Unit & Contract Tests**: `run_tests.py` (300+ automated assertions across 16 test modules)
- **Mock E2E Pipeline**: `docker/run_docker_tests.py --mode mock` (5-stage full deployment & diagnostics)
- **Fault Injection & Stress Matrix**: `docker/stress_test_matrix.py` (12-round adversarial & recovery verification)
- **Hardware Validation Evidence**: Documented in [../validation-report.md](../validation-report.md) and [../compatibility-matrix.json](../compatibility-matrix.json)
- **Device Baseline**: Documented in [DEVICE_BASELINE.md](DEVICE_BASELINE.md)
