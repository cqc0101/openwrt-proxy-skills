# 分层测试与故障注入验收基线 (TEST_BASELINE)

## 1. 测试执行命令

```bash
# 1. 全量单元、契约、安全、策略、事务与故障注入测试
python3 run_tests.py

# 2. 本地 Mock 仿真（任意 Shell 网络接管为 SKIP，不代表真实全链路通过）
python3 docker/run_docker_tests.py --mode mock

# 3. 12 轮极限压力测试矩阵
python3 docker/stress_test_matrix.py
```

## 2. 故障注入覆盖矩阵 (Fault Injection Matrix)

| 注入场景 | 预期状态机终态 / 行为 | 验证测试 |
| :--- | :--- | :--- |
| 未注册动作或篡改参数 | 抛出 `PolicyViolationError` (`UNREGISTERED_ACTION` / `INVALID_ACTION_PARAMS`) | `test_v100_governance.py` |
| 模型试图将 R3/R4 降级为 R1 | 抛出 `PolicyViolationError` (`RISK_DOWNGRADE_FORBIDDEN`) | `test_v100_governance.py` |
| 计划参数或目标设备变更后沿用旧授权 | 抛出 `PolicyViolationError` (`PLAN_HASH_MISMATCH` / `APPROVAL_DEVICE_MISMATCH`) | `test_v100_governance.py` |
| 两个任务并发写同一台路由器 | 第二个任务抛出 `LockConflictError`，过期且旧进程退出后可安全回收 | `test_v100_governance.py` |
| 备份文件损坏或被篡改 | `verify_backups()` 抛出异常，阻止进入 `STAGING` / `DEPLOYING` | `test_v100_governance.py` |
| 原生引擎校验 (`native_validator`) 失败 | 自动清理 `.staging` 临时文件，生产配置保持原样 | `test_v100_governance.py` |
| 部署后业务健康验证失败，回滚并验证成功 | 文件与 `sysctl` 原值 100% 恢复，状态机进入 `ROLLED_BACK` | `test_v100_governance.py` |
| 回滚期间备份丢失或回滚后业务仍不可用 | 绝不伪装成功，状态机诚实进入 `NEEDS_HUMAN` 并写入审计日志 | `test_v100_governance.py` |
| R3/R4 高危操作审计日志无法写入 | 抛出 `AuditLogFailureError`，阻断生产变更 | `test_v100_governance.py` |

## 2026-11-12 审计修订

新增的并发、TLS 与事务故障注入由 `tests/test_audit_regressions.py` 覆盖，完整套件共 341 项，另含 `test_linux_regressions.py` 的 Linux 锁和 dae 裸键格式测试。
本轮运行环境和未验证项目见 [审计复核报告](../audit-2026-11-12.md)。
