# -*- coding: utf-8 -*-
"""设备级互斥锁、17 状态持久化状态机、备份校验、sysctl 快照与事务回滚管理器。"""

import datetime
import hashlib
import json
import math
import tempfile
import uuid
import warnings
from contextlib import contextmanager
import os
import re
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple


def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _validate_safe_identifier(val: str, label: str) -> str:
    s = str(val or "").strip()
    if not s or s in (".", "..") or "/" in s or "\\" in s or any(ord(c) < 32 or ord(c) == 127 for c in s):
        raise ValueError(f"[TXN-001] 非法的 {label} 标识符 (含空值、路径穿越或分隔符): {val!r}")
    if label == "task_id" and ":" in s:
        raise ValueError("[TXN-001] task_id 不允许 Windows 盘符或备用数据流分隔符")
    return s


def _redact_audit_text(text: str) -> str:
    s = str(text or "")
    s = re.sub(
        r'([?&][a-zA-Z0-9_.-]*(?:token|secret|pass|pwd|key|auth|sig|jwt|uuid|sid|pbk)[a-zA-Z0-9_.-]*=)([^&#\s\'"]+)',
        r"\1***REDACTED***",
        s,
        flags=re.IGNORECASE,
    )
    s = re.sub(r'\b([a-zA-Z][a-zA-Z0-9+.-]*://)([^/@\s\'"]+)@', r"\1***REDACTED***@", s)
    s = re.sub(
        r'((?:password|passwd|pwd|secret|token|api_key|private_key|access_token|uuid|pbk)[\s"\x27]*[:=][\s"\x27]*)([^\s"\x27,;}]+)',
        r"\1***REDACTED***",
        s,
        flags=re.IGNORECASE,
    )
    return s


class LockConflictError(RuntimeError):
    """设备已被其他写任务持有锁。"""


class InvalidStateTransitionError(RuntimeError):
    """状态机非法跳转异常。"""


class AuditLogFailureError(RuntimeError):
    """关键审计日志写入失败异常（R3/R4 必须阻断生产变更）。"""


class AuditLogger:
    """统一结构化审计日志器：强制脱敏，且在 R3/R4 审计写入失败时阻断变更。"""

    def __init__(self, log_path: Path):
        self.log_path = Path(log_path)

    def record(
        self,
        task_id: str,
        device_id: str,
        action_id: str,
        risk: str,
        decision: str,
        result: str,
        actor: str = "agent",
        plan_hash: str = "",
        evidence_ref: str = "",
        detail: str = "",
    ) -> Dict[str, Any]:
        event = {
            "event_id": f"evt-{uuid.uuid4().hex}",
            "task_id": str(task_id),
            "device_id": str(device_id),
            "action_id": str(action_id),
            "risk": str(risk),
            "decision": str(decision),
            "actor": str(actor),
            "timestamp": _utc_now_iso(),
            "plan_hash": str(plan_hash),
            "result": _redact_audit_text(result),
            "evidence_ref": str(evidence_ref),
            "detail": _redact_audit_text(detail),
        }
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            if self.log_path.is_dir():
                raise IsADirectoryError(str(self.log_path))
            with _file_guard(self.log_path.with_suffix(self.log_path.suffix + ".guard")):
                with open(self.log_path, "a", encoding="utf-8", newline="\n") as fh:
                    fh.write(json.dumps(event, ensure_ascii=False) + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
        except Exception as e:
            if risk in ("R3", "R4"):
                raise AuditLogFailureError(
                    f"[AUDIT_WRITE_FAILED] 高风险操作 ({risk}) 审计日志无法写入，已安全中止生产变更: {e}"
                )
        return event


def _is_pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        # On Windows 0 is CTRL_C_EVENT, not a POSIX-style liveness probe.
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.GetExitCodeProcess.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
        kernel32.GetExitCodeProcess.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel32.CloseHandle.restype = wintypes.BOOL
        handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            # ERROR_INVALID_PARAMETER: PID absent. Access failures must fail closed.
            return ctypes.get_last_error() != 87
        try:
            code = wintypes.DWORD()
            return not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)) or code.value == 259
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False


@contextmanager
def _file_guard(path: Path):
    """Stable sidecar inode: never unlink it, including after releasing the data lock.

    flock protects independent processes/descriptors on POSIX. Windows uses a byte
    range lock on the same persistent file. This is a local-filesystem protocol;
    all writers must use it. A process exit releases the OS lock automatically.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "r+b", buffering=0) as fh:
        if os.name == "nt":
            import msvcrt
            # Windows permits locking a byte beyond EOF; no racing initial write.
            msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            if os.name == "nt":
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


class DeviceLock:
    """Cross-process serialized metadata with PID and per-instance ownership tokens."""

    def __init__(self, lock_dir: Path, device_id: str, task_id: str, owner: str, ttl_seconds: float = 600.0):
        clean_dev = _validate_safe_identifier(device_id, "device_id")
        self.task_id = _validate_safe_identifier(task_id, "task_id")
        self.owner = str(owner or "").strip()
        if not self.owner:
            raise ValueError("[TXN-001] owner 不能为空")
        if isinstance(ttl_seconds, bool) or not math.isfinite(float(ttl_seconds)) or float(ttl_seconds) <= 0:
            raise ValueError(f"[TXN-001] ttl_seconds 必须为有限正数: {ttl_seconds!r}")
        safe_dev = re.sub(r"[^a-zA-Z0-9_.-]", "_", clean_dev)
        if not safe_dev or safe_dev in (".", ".."):
            raise ValueError("device_id 不能为空或 '.' / '..'")
        self.lock_dir = Path(lock_dir)
        self.device_id = clean_dev
        self.ttl_seconds = float(ttl_seconds)
        self.lock_file = self.lock_dir / f"device_{safe_dev}.lock.json"
        self.guard_file = self.lock_file.with_suffix(self.lock_file.suffix + ".guard")
        self.pid = os.getpid()
        self._lock_id = uuid.uuid4().hex

    def _read(self):
        try:
            data = json.loads(self.lock_file.read_text(encoding="utf-8"))
            if (not isinstance(data, dict) or data.get("device_id") != self.device_id
                    or not math.isfinite(float(data["expires_at_epoch"]))
                    or isinstance(data["pid"], bool) or not isinstance(data["pid"], int)):
                raise ValueError("invalid lock metadata")
            return data
        except Exception as exc:
            raise LockConflictError("[TXN-001] 锁元数据损坏或设备不匹配，拒绝自动抢占") from exc

    def _owned(self, existing):
        return (existing.get("owner") == self.owner and existing.get("task_id") == self.task_id
                and existing.get("pid") == os.getpid() == self.pid
                and existing.get("lock_id") == self._lock_id)

    def _write(self, payload, create=False):
        if create:
            fd = os.open(str(self.lock_file), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
                json.dump(payload, fh, ensure_ascii=False, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
        else:
            fd, name = tempfile.mkstemp(dir=self.lock_dir, prefix=".lock-", suffix=".tmp")
            tmp = Path(name)
            try:
                with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
                    json.dump(payload, fh, ensure_ascii=False, indent=2)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp, self.lock_file)
            finally:
                tmp.unlink(missing_ok=True)

    def _renew(self, existing, now_ts):
        if not self._owned(existing):
            raise LockConflictError("[TXN-001] 锁所有者/PID/令牌不匹配，拒绝续期")
        existing["heartbeat_at"] = _utc_now_iso()
        existing["expires_at"] = datetime.datetime.fromtimestamp(
            now_ts + self.ttl_seconds, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        existing["expires_at_epoch"] = now_ts + self.ttl_seconds
        self._write(existing)
        return existing

    def acquire(self, now: Optional[float] = None, pid_checker: Callable[[int], bool] = _is_pid_alive) -> Dict[str, Any]:
        now_ts = time.time() if now is None else float(now)
        if not math.isfinite(now_ts):
            raise ValueError("now 必须为有限时间")
        with _file_guard(self.guard_file):
            if self.lock_file.exists():
                existing = self._read()
                if self._owned(existing):
                    return self._renew(existing, now_ts)
                if now_ts < float(existing["expires_at_epoch"]) or pid_checker(existing["pid"]):
                    raise LockConflictError(f"[TXN-001] 设备 {self.device_id} 已被其他任务锁定")
                self.lock_file.unlink()
            self.pid = os.getpid()
            payload = {
                "device_id": self.device_id, "task_id": self.task_id, "owner": self.owner,
                "pid": self.pid, "lock_id": self._lock_id,
                "created_at": _utc_now_iso(), "heartbeat_at": _utc_now_iso(),
                "expires_at": datetime.datetime.fromtimestamp(
                    now_ts + self.ttl_seconds, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "expires_at_epoch": now_ts + self.ttl_seconds,
            }
            try:
                self._write(payload, create=True)
            except FileExistsError:
                raise LockConflictError(f"[TXN-001] 并发竞争：设备 {self.device_id} 锁已被其他进程抢占") from None
            return payload

    def heartbeat(self, now: Optional[float] = None) -> Dict[str, Any]:
        now_ts = time.time() if now is None else float(now)
        if not math.isfinite(now_ts):
            raise ValueError("now 必须为有限时间")
        with _file_guard(self.guard_file):
            if not self.lock_file.is_file():
                raise LockConflictError(f"[TXN-001] 锁文件不存在，无法续期: {self.device_id}")
            return self._renew(self._read(), now_ts)

    def release(self) -> None:
        with _file_guard(self.guard_file):
            if not self.lock_file.exists():
                return
            if not self._owned(self._read()):
                raise LockConflictError("[TXN-001] 拒绝释放非当前实例/PID/令牌持有的设备锁")
            self.lock_file.unlink()

    def __enter__(self) -> "DeviceLock":
        self.acquire()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.release()


# Section 7 统一执行状态机合法转换图
LEGAL_TRANSITIONS: Dict[str, Set[str]] = {
    "CREATED": {"PROBING", "ROLLING_BACK"},
    "PROBING": {"PLANNING", "ROLLING_BACK"},
    "PLANNING": {"POLICY_CHECK", "ROLLING_BACK"},
    "POLICY_CHECK": {"WAITING_APPROVAL", "PREPARING", "ROLLING_BACK"},
    "WAITING_APPROVAL": {"PREPARING", "ROLLING_BACK"},
    "PREPARING": {"PRECONDITION_CHECK", "ROLLING_BACK"},
    "PRECONDITION_CHECK": {"BACKING_UP", "ROLLING_BACK"},
    "BACKING_UP": {"BACKUP_VERIFY", "ROLLING_BACK"},
    "BACKUP_VERIFY": {"STAGING", "ROLLING_BACK"},
    "STAGING": {"VALIDATING", "ROLLING_BACK"},
    "VALIDATING": {"DEPLOYING", "ROLLING_BACK"},
    "DEPLOYING": {"VERIFYING", "ROLLING_BACK"},
    "VERIFYING": {"COMMITTED", "ROLLING_BACK"},
    "ROLLING_BACK": {"ROLLED_BACK", "NEEDS_HUMAN"},
    "COMMITTED": set(),
    "ROLLED_BACK": set(),
    "NEEDS_HUMAN": set(),
}


class TaskStateMachine:
    """持久化执行状态机 (TXN-002)：强制校验状态转换顺序并支持 Agent 重启恢复。"""

    def __init__(self, journal_path: Path, task_id: str, device_id: str):
        self.journal_path = Path(journal_path)
        self.task_id = _validate_safe_identifier(task_id, "task_id")
        self.device_id = _validate_safe_identifier(device_id, "device_id")
        self.state = "CREATED"
        self.history: List[Dict[str, Any]] = []
        if self.journal_path.is_file():
            self._recover()

    def _recover(self) -> None:
        with _file_guard(self.journal_path.with_suffix(".jsonl.guard")):
            self._recover_locked()

    def _recover_locked(self) -> None:
        self.state = "CREATED"
        self.history = []
        if not self.journal_path.exists():
            return
        raw = self.journal_path.read_bytes()
        offset = 0
        lines = raw.splitlines(keepends=True)
        for index, line in enumerate(lines):
            if not line.strip():
                offset += len(line)
                continue
            try:
                entry = json.loads(line.decode("utf-8"))
            except (ValueError, UnicodeError) as exc:
                # Only an incomplete final write can be discarded. Never skip an
                # interior/complete corrupt record and then trust a later COMMITTED.
                if index == len(lines) - 1 and not line.endswith(b"\n"):
                    warnings.warn("[TXN-002] 检测到日志末尾写入中断，保留最后完整状态", RuntimeWarning)
                    with open(self.journal_path, "r+b") as fh:
                        fh.truncate(offset)
                        fh.flush()
                        os.fsync(fh.fileno())
                    return
                raise InvalidStateTransitionError("[TXN-002] 日志记录损坏，拒绝继续执行") from exc
            if not isinstance(entry, dict):
                raise InvalidStateTransitionError("[TXN-002] 日志条目必须为对象")
            if entry.get("task_id") == self.task_id:
                if (entry.get("device_id") != self.device_id or entry.get("previous_state") != self.state
                        or entry.get("new_state") not in LEGAL_TRANSITIONS.get(self.state, set())):
                    raise InvalidStateTransitionError("[TXN-002] 日志设备绑定或状态链无效")
                self.state = entry["new_state"]
                self.history.append(entry)
            offset += len(line)
        if raw and not raw.endswith(b"\n"):
            with open(self.journal_path, "ab") as fh:
                fh.write(b"\n")
                fh.flush()
                os.fsync(fh.fileno())

    def transition(
        self,
        new_state: str,
        action_id: str = "",
        result: str = "ok",
        error_code: str = "",
        evidence_ref: str = "",
    ) -> Dict[str, Any]:
        with _file_guard(self.journal_path.with_suffix(".jsonl.guard")):
            self._recover_locked()
            if self.state in ("COMMITTED", "ROLLED_BACK", "NEEDS_HUMAN"):
                raise InvalidStateTransitionError(
                    f"[TXN-002] 终态 {self.state} 不可再发生状态迁移 (目标: {new_state})"
                )
            allowed = LEGAL_TRANSITIONS.get(self.state, set())
            if new_state not in allowed:
                raise InvalidStateTransitionError(
                    f"[TXN-002] 非法状态跳转: {self.state} -> {new_state} (允许: {sorted(allowed)})"
                )
            entry = {
                "task_id": self.task_id,
                "device_id": self.device_id,
                "previous_state": self.state,
                "new_state": new_state,
                "timestamp": _utc_now_iso(),
                "action_id": str(action_id),
                "result": _redact_audit_text(result),
                "error_code": str(error_code),
                "evidence_ref": str(evidence_ref),
            }
            self.journal_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.journal_path, "a", encoding="utf-8", newline="\n") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            self.state = new_state
            self.history.append(entry)
            return entry


@dataclass
class SysctlSnapshotEntry:
    key: str
    existed: bool
    original_value: Optional[str]
    planned_value: str
    apply_status: str = "pending"


@dataclass
class FileBackupEntry:
    target_path: str
    backup_path: str
    existed: bool
    sha256: str
    size: int
    mode: int


class TransactionManager:
    """完整备份、SHA256 校验、sysctl 原值快照、Staging 原子替换与二次验证回滚管理器 (TXN-003 ~ TXN-006)。"""

    def __init__(
        self,
        work_dir: Path,
        task_id: str,
        device_id: str,
        audit_logger: Optional[AuditLogger] = None,
    ):
        self.work_dir = Path(work_dir)
        self.task_id = _validate_safe_identifier(task_id, "task_id")
        self.device_id = _validate_safe_identifier(device_id, "device_id")
        self.backup_dir = self.work_dir / "backups" / self.task_id
        self.staging_dir = self.work_dir / "staging" / self.task_id
        self.manifest_path = self.backup_dir / "manifest.json"
        self.fsm = TaskStateMachine(self.work_dir / "journal.jsonl", task_id=self.task_id, device_id=self.device_id)
        self.audit = audit_logger or AuditLogger(self.work_dir / "audit.jsonl")
        self.file_backups: Dict[str, FileBackupEntry] = {}
        self.sysctl_snapshots: Dict[str, SysctlSnapshotEntry] = {}
        self.service_snapshots: Dict[str, Dict[str, Any]] = {}
        if self.manifest_path.is_file():
            self._load_manifest()
        elif (self.fsm.state in ("BACKUP_VERIFY", "STAGING", "VALIDATING", "DEPLOYING", "VERIFYING")
              or (self.fsm.state == "ROLLING_BACK"
                  and any(entry["new_state"] == "BACKUP_VERIFY" for entry in self.fsm.history))):
            raise RuntimeError("[TXN-003] 事务已进入部署阶段但备份清单缺失，拒绝继续执行")

    def _load_manifest(self) -> None:
        try:
            data = json.loads(self.manifest_path.read_text(encoding="utf-8"))
            if data.get("task_id") != self.task_id or data.get("device_id") != self.device_id:
                raise ValueError("manifest identity mismatch")
            files = {k: FileBackupEntry(**v) for k, v in data["files"].items()}
            sysctls = {k: SysctlSnapshotEntry(**v) for k, v in data["sysctls"].items()}
            services = {k: dict(v) for k, v in data["services"].items()}
            for key, entry in files.items():
                if key != entry.target_path:
                    raise ValueError("manifest target mismatch")
                if entry.existed:
                    Path(entry.backup_path).resolve().relative_to(self.backup_dir.resolve())
            self.file_backups, self.sysctl_snapshots, self.service_snapshots = files, sysctls, services
        except Exception as exc:
            raise RuntimeError("[TXN-003] 备份清单损坏或身份/路径不匹配，拒绝继续执行") from exc

    @staticmethod
    def compute_file_sha256(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    def backup_files_and_sysctls(
        self,
        file_paths: Sequence[Path],
        sysctl_plan: Dict[str, Tuple[bool, Optional[str], str]],
        service_states: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> Path:
        """执行部署前文件与 sysctl 原值快照备份并生成 manifest.json (TXN-003, TXN-004)。"""
        if self.fsm.state != "BACKING_UP":
            raise InvalidStateTransitionError(f"必须在 BACKING_UP 状态下执行备份 (当前: {self.fsm.state})")
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        for idx, fp in enumerate(file_paths):
            p = Path(fp)
            if p.is_file():
                b_path = self.backup_dir / f"file_{idx}_{p.name}.bak"
                shutil.copy2(p, b_path)
                sha = self.compute_file_sha256(b_path)
                st = p.stat()
                self.file_backups[str(p)] = FileBackupEntry(
                    target_path=str(p),
                    backup_path=str(b_path),
                    existed=True,
                    sha256=sha,
                    size=st.st_size,
                    mode=st.st_mode & 0o777,
                )
            else:
                self.file_backups[str(p)] = FileBackupEntry(
                    target_path=str(p),
                    backup_path="",
                    existed=False,
                    sha256="",
                    size=0,
                    mode=0o600,
                )

        for k, (existed, orig_val, planned_val) in sysctl_plan.items():
            self.sysctl_snapshots[k] = SysctlSnapshotEntry(
                key=k,
                existed=bool(existed),
                original_value=str(orig_val) if (existed and orig_val is not None) else None,
                planned_value=str(planned_val),
                apply_status="backed_up",
            )

        if service_states:
            for srv_name, srv_st in service_states.items():
                if isinstance(srv_st, dict):
                    self.service_snapshots[str(srv_name)] = dict(srv_st)

        manifest_data = {
            "task_id": self.task_id,
            "device_id": self.device_id,
            "created_at": _utc_now_iso(),
            "files": {k: vars(v) for k, v in self.file_backups.items()},
            "sysctls": {k: vars(v) for k, v in self.sysctl_snapshots.items()},
            "services": self.service_snapshots,
        }
        fd, name = tempfile.mkstemp(dir=self.backup_dir, prefix=".manifest-", suffix=".tmp")
        tmp_manifest = Path(name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
                json.dump(manifest_data, fh, ensure_ascii=False, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_manifest, self.manifest_path)
        finally:
            tmp_manifest.unlink(missing_ok=True)
        return self.manifest_path

    def verify_backups(self) -> bool:
        """校验所有已备份文件的存在性、大小与 SHA-256 完整性 (TXN-003)。"""
        if not self.manifest_path.is_file():
            raise RuntimeError("[TXN-003] 缺少备份元数据文件 manifest.json")
        for target, entry in self.file_backups.items():
            if not entry.existed:
                continue
            bp = Path(entry.backup_path)
            if not bp.is_file():
                raise RuntimeError(f"[TXN-003] 备份文件缺失: {bp}")
            actual_sha = self.compute_file_sha256(bp)
            if actual_sha != entry.sha256 or bp.stat().st_size != entry.size:
                raise RuntimeError(f"[TXN-003] 备份文件哈希或大小校验失败: {bp}")
        self.fsm.transition("BACKUP_VERIFY", action_id="verify_backups", result="verified")
        return True

    def stage_and_atomic_replace(
        self,
        target_path: Path,
        new_content: bytes,
        native_validator: Callable[[Path], bool],
    ) -> Path:
        """Validate a private, unpredictable same-filesystem file before replacement."""
        if self.fsm.state != "BACKUP_VERIFY":
            raise InvalidStateTransitionError(f"未完成 BACKUP_VERIFY 严禁进入 STAGING (当前: {self.fsm.state})")
        target = Path(target_path)
        if not any(Path(key).resolve() == target.resolve() for key in self.file_backups):
            raise RuntimeError("[TXN-003] 目标未纳入备份清单，拒绝替换")
        self.fsm.transition("STAGING", action_id="stage_config")
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.", suffix=".staging")
        tmp_file = Path(name)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(new_content)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp_file, 0o600)
            self.fsm.transition("VALIDATING", action_id="native_validate", evidence_ref=str(tmp_file))
            try:
                valid_ok = bool(native_validator(tmp_file))
            except Exception as exc:
                raise RuntimeError(f"[L3_VALIDATION_FAILED] 原生引擎校验异常: {_redact_audit_text(str(exc))}") from None
            if not valid_ok:
                raise RuntimeError(f"[L3_VALIDATION_FAILED] 原生引擎校验未通过: {tmp_file}")
            # A validator must not change the approved payload.
            if self.compute_file_sha256(tmp_file) != hashlib.sha256(new_content).hexdigest():
                raise RuntimeError("[TXN-003] 暂存配置在校验期间发生改变")
            self.fsm.transition("DEPLOYING", action_id="atomic_replace", evidence_ref=str(target))
            self.audit.record(task_id=self.task_id, device_id=self.device_id,
                              action_id="atomic_replace", risk="R3", decision="validated",
                              result="deploying", evidence_ref=str(target))
            os.replace(str(tmp_file), str(target))
            return target
        finally:
            tmp_file.unlink(missing_ok=True)

    def commit_after_verification(self, business_verifier: Callable[[], bool]) -> str:
        """验证和审计通过后标记 COMMITTED；失败时抛出异常，由调用方触发回滚。"""
        if self.fsm.state != "DEPLOYING":
            raise InvalidStateTransitionError(f"必须在 DEPLOYING 后进入 VERIFYING (当前: {self.fsm.state})")
        self.fsm.transition("VERIFYING", action_id="verify_business_health")
        if not business_verifier():
            raise RuntimeError("[L5_VERIFY_FAILED] 部署后业务连通性或 DNS 健康验证未通过")
        self.audit.record(
            task_id=self.task_id,
            device_id=self.device_id,
            action_id="commit_transaction",
            risk="R3",
            decision="commit_ready",
            result="verification_passed",
        )
        self.fsm.transition("COMMITTED", action_id="commit_transaction", result="committed")
        return self.fsm.state

    def rollback(
        self,
        sysctl_state: Dict[str, str],
        health_verifier: Callable[[], bool],
        service_state_store: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> str:
        """执行完整回滚并二次验证：恢复文件、恢复 sysctl 原值、校验业务恢复，失败则诚实标记 NEEDS_HUMAN (8.10/8.11)。"""
        if self.fsm.state in ("COMMITTED", "ROLLED_BACK", "NEEDS_HUMAN"):
            raise InvalidStateTransitionError(
                f"[TXN-002] 终态 {self.fsm.state} 不允许再次执行回滚"
            )
        if self.fsm.state != "ROLLING_BACK":
            self.fsm.transition("ROLLING_BACK", action_id="initiate_rollback")

        rollback_errors: List[str] = []
        # 1. 恢复文件内容与权限，并校验恢复后的 SHA256
        for target_str, entry in self.file_backups.items():
            target = Path(target_str)
            try:
                if entry.existed:
                    bp = Path(entry.backup_path)
                    if not bp.is_file():
                        rollback_errors.append(f"missing_backup:{bp}")
                        continue
                    if self.compute_file_sha256(bp) != entry.sha256:
                        rollback_errors.append(f"corrupted_backup:{bp}")
                        continue
                    fd, name = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.", suffix=".restore")
                    tmp_restore = Path(name)
                    try:
                        with os.fdopen(fd, "wb") as dst, open(bp, "rb") as src:
                            shutil.copyfileobj(src, dst)
                            dst.flush()
                            os.fsync(dst.fileno())
                        os.chmod(tmp_restore, entry.mode)
                        os.replace(str(tmp_restore), str(target))
                    finally:
                        try:
                            tmp_restore.unlink(missing_ok=True)
                        except OSError as cleanup_err:
                            rollback_errors.append(f"tmp_restore_cleanup_failed:{tmp_restore}:{cleanup_err}")
                    if self.compute_file_sha256(target) != entry.sha256:
                        rollback_errors.append(f"restore_hash_mismatch:{target}")
                else:
                    if target.exists():
                        target.unlink()
            except Exception as e:
                rollback_errors.append(f"file_restore_error:{target}:{e}")

        # 2. 恢复 sysctl 原值并二次比对
        for k, snap in self.sysctl_snapshots.items():
            try:
                if snap.existed and snap.original_value is not None:
                    sysctl_state[k] = snap.original_value
                    if sysctl_state.get(k) != snap.original_value:
                        rollback_errors.append(f"sysctl_mismatch:{k}")
                else:
                    sysctl_state.pop(k, None)
                    if k in sysctl_state:
                        rollback_errors.append(f"sysctl_not_removed:{k}")
            except Exception as e:
                rollback_errors.append(f"sysctl_restore_error:{k}:{e}")

        # 2.5 恢复服务原启停状态（若提供了 service_state_store）
        if self.service_snapshots and service_state_store is None:
            rollback_errors.append("service_state_store_missing")
        if service_state_store is not None and self.service_snapshots:
            for srv_name, orig_st in self.service_snapshots.items():
                try:
                    service_state_store[srv_name] = dict(orig_st)
                except Exception as e:
                    rollback_errors.append(f"service_restore_error:{srv_name}:{e}")

        # 3. 执行回滚后 L4/L5 业务与管理通道二次验证
        try:
            health_ok = bool(health_verifier())
        except Exception as e:
            health_ok = False
            rollback_errors.append(f"health_verify_exception:{e}")

        if not rollback_errors and health_ok:
            self.fsm.transition("ROLLED_BACK", action_id="complete_rollback", result="rolled_back_and_verified")
            self.audit.record(
                task_id=self.task_id,
                device_id=self.device_id,
                action_id="rollback",
                risk="R4",
                decision="rolled_back",
                result="ROLLED_BACK",
            )
            return "ROLLED_BACK"

        err_summary = "; ".join(rollback_errors) or "post_rollback_health_check_failed"
        self.fsm.transition(
            "NEEDS_HUMAN",
            action_id="rollback_failed",
            result=err_summary,
            error_code="ROLLBACK_VERIFICATION_FAILED",
        )
        self.audit.record(
            task_id=self.task_id,
            device_id=self.device_id,
            action_id="rollback",
            risk="R4",
            decision="needs_human",
            result="NEEDS_HUMAN",
            detail=err_summary,
        )
        return "NEEDS_HUMAN"
