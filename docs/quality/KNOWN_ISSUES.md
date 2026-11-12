# Issue Registry & Resolution Ledger (v0.7.0 -> v1.0.0)

| Issue ID | 优先级 | 问题与风险描述 | 关联模块 | 状态 |
| :--- | :---: | :--- | :--- | :---: |
| `SEC-001` | P0 | SSH 策略统一、私钥/known_hosts 权限检查与主机密钥变更阻断 | `core/security.py`, `auto_config.py`, `sub_to_dae.py`, `setup_openwrt_network.sh` | 已闭环 |
| `SEC-002` | P0 | 私网订阅例外支持精确 `host:port` 白名单 (`AllowedPrivateTarget`)，全链路透传且拒绝通配符 | `core/security.py`, `sub_parser.py` | 已闭环 |
| `SEC-003` | P0 | 重定向逐跳 SSRF 校验、拦截 HTTPS->HTTP 降级、连接期 DNS Pinning 与单行/深度上限 | `sub_parser.py` | 已闭环 |
| `POL-001` | P0 | 独立 `PolicyEngine` 确定性权限判定（R0~R4，禁止风险降级与越权执行） | `core/policy.py` | 已闭环 |
| `EXE-001` | P0 | 集中式 `ACTION_REGISTRY` 与参数白名单校验 | `core/policy.py` | 已闭环 |
| `EXE-002` | P0 | `ExecutionPlan` SHA-256 计划哈希计算与 `ApprovalToken` 多维绑定 | `core/policy.py` | 已闭环 |
| `TXN-001` | P0 | `DeviceLock` 设备级互斥锁（绑定 owner/task_id/TTL/心跳与进程存活判定） | `core/transaction.py` | 已闭环 |
| `TXN-002` | P0 | 17 状态 `TaskStateMachine` 与 JSONL 持久化崩溃恢复 | `core/transaction.py` | 已闭环 |
| `TXN-003` | P0 | 部署前备份清单 (`manifest.json`)、崩溃重入加载与恢复前 SHA-256 完整性强校验 | `core/transaction.py` | 已闭环 |
| `TXN-004` | P0 | `sysctl` 内核参数原值与服务启停状态快照及回滚精确还原 | `core/transaction.py`, `setup_openwrt_network.sh` | 已闭环 |
| `TXN-005` | P0 | 独立 45s 内存看门狗与 `/etc/uci-defaults/99-proxy-boot-guard` 闪存自愈哨兵 | `setup_openwrt_network.sh` | 已闭环 |
| `TXN-006` | P0 | 回滚后二次业务验证与失败时诚实进入 `NEEDS_HUMAN` 终态 | `core/transaction.py`, `setup_openwrt_network.sh` | 已闭环 |
| `VAL-001` | P1 | `L0 ~ L5` 六层配置与部署验证统一接口 (`SixLayerValidator`) | `core/validation.py` | 已闭环 |
| `CAP-001` | P1 | `detected` / `supported` / `verified` 三态能力对象与证据列表 (`capability_details`) | `probe.sh` | 已闭环 |
| `REP-001` | P1 | `doctor.sh` 结构化诊断输出 (`issue_id`/`component`/`confidence`/`repair_id`/`repair_candidates`) | `doctor.sh` | 已闭环 |
| `REP-002` | P1 | 全量 13 项注册式 `REPAIR_REGISTRY`、前置条件校验、重试上限与人工确认门禁 | `core/policy.py` | 已闭环 |
| `TST-001` | P1 | 端口、Tag、URL、YAML 深度与单行长度边界属性测试 | `tests/test_v100_governance.py`, `tests/test_sub_parser.py` | 已闭环 |
| `TST-002` | P1 | Policy / SSRF / Transaction 关键门禁故障与变异断言覆盖 | `tests/test_v100_governance.py` | 已闭环 |
| `TST-003` | P0 | 网络部署、备份损坏、原生校验失败、回滚失败 `NEEDS_HUMAN` 故障注入矩阵 | `tests/test_v100_governance.py`, `docker/stress_test_matrix.py` | 已闭环 |
| `DOC-001` | P1 | 文档相对链接与废弃脚本名防呆扫描 (`test_docs.py` / `test_structure.py`) | `tests/test_docs.py`, `tests/test_structure.py` | 已闭环 |
| `DOC-002` | P1 | 质量基线与测试证据台账统一归档 (`docs/quality/`) | `docs/quality/TEST_BASELINE.md` | 已闭环 |
| `COMP-001` | P1 | 机器可读的设备与版本兼容性矩阵 (`tested`/`simulated`/`compatible`/`unsupported`) | `docs/compatibility-matrix.json`, `docs/quality/DEVICE_BASELINE.md` | 已闭环 |
| `REL-001` | P1 | 零外部依赖锁定、无密钥/无缓存打包门禁与发布证据清单 | `docs/quality/RELEASE_EVIDENCE.md` | 已闭环 |
