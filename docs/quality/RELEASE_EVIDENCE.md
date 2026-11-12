# v1.0.0 Release Evidence & Gate Checklist

- **Release Version**: `1.0.0`
- **Schema Version**: `1.0`
- **Verification Scope**:
  - **Tested (Real Hardware)**: ARM64 ImmortalWrt SNAPSHOT (`apk`, `fw4`/`nftables`, Linux 6.6+, `sing-box 1.14.3` & `dae v2.1.1`) — see [../validation-report.md](../validation-report.md).
  - **Simulated (Mock / Container)**: OpenWrt `18.06~24.10` (`fw3`/`iptables` & `fw4`/`nftables`), `dae` legacy (`<=1.0.0`) & modern (`2.1.1+`).
  - **P0 Gate Status**: All Security (`SEC-001~003`), Policy (`POL-001`, `EXE-001~002`), and Transaction/Rollback (`TXN-001~006`) gates verified by automated tests.

## 2026-11-12 local audit revision

The above v1.0.0 hardware and release statements are historical input claims, not new evidence for this revision. Real Linux regression (341 passing tests), native sing-box 1.13.0/1.14.4 and dae 2.1.1 validation, code changes, and remaining device limitations are documented in [the audit review](../audit-2026-11-12.md).
