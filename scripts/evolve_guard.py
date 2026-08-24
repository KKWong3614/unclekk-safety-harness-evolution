#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
unclekk-safety-harness-evolution —— 三道硬闸执行器

机械执行 SHE 进化闭环里「可程序化」的部分，确保三道硬闸不被跳过：
  闸 A  先备份：写回前必须把当前护栏快照存到带时间戳的备份文件
  闸 B  安全-效用闸门：S(候选) > S(当前) 且 U(候选) >= U(当前) 才放行
  闸 C  拒收池去重：同一补丁被拒后，后续轮不再重试

诊断 / 归因 / 补丁生成本身由 LLM（主 Agent）完成；本脚本只负责
「备份 → 闸门判定 → 拒收池去重 → 写回 → 回滚清单」的机械闭环。

用法：
  # 1) 写回前先备份当前护栏
  python evolve_guard.py backup --harness current_harness.yaml --backup-dir ./backups

  # 2) 提交候选补丁做闸门判定（不自动写回，仅判定）
  python evolve_guard.py judge \
      --candidate-patch patch.json \
      --s-current 0.60 --u-current 0.80 \
      --s-candidate 0.85 --u-candidate 0.82 \
      --reject-pool reject_pool.json

  # 3) 判定通过且已备份 → 正式写回（四工件均结构感知真合并，护栏即变硬）
  #    apply 内部强制重跑 评分+闸B 硬保险：即使调用方漏跑 judge，闸 B 也不会被绕过
  python evolve_guard.py apply \
      --harness current_harness.json \
      --candidate-patch patch.json \
      --backup-dir ./backups --reject-pool reject_pool.json \
      [--s-current 0.60 --u-current 0.80] [--llm-scorer "<cmd {patch}>"]

  # 4) 出问题时一键回滚
  python evolve_guard.py rollback --backup ./backups/harness_20260818_160500.yaml

补丁 JSON 格式（与 SKILL.md / references/architecture.md 一致）：
  {
    "target_artifact": "rule_bank",            // system_prompt|rule_bank|safety_memory|tool_policy
    "patch_type": "add_rule",                  // 见下方工件×类型映射
    "before": "<原内容或 null>",
    "after": "<新内容>",
    "supporting_trajectories": ["traj_047"]
  }

工件 × 补丁类型映射（apply 均做结构感知真合并，非记账）：
  system_prompt  → prompt_diff  （before 命中则文本替换；否则 after 追加为新段落；已存在则 skip-dup）
  rule_bank      → add_rule / modify_rule（after 作为新 rule 追加）
  safety_memory  → write_memory（after 作为对比性经验条目追加；同签名 entry 则 skip-dup）
  tool_policy    → tighten_tool（after 作为工具权限条目；含 tool 字段且已有同 tool 则覆盖收紧）
  * after 若为合法 JSON 对象，结构感知合并器直接采用该结构化条目；否则包成 {note,...} 条目。
"""

import argparse
import datetime as _dt
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time as _time

from utils import normalize_unicode as _normalize_unicode, format_ts as _format_ts

try:
    import msvcrt as _MSVCRT  # Windows 原生文件锁
except ImportError:
    _MSVCRT = None

# ── 可观测性：结构化日志 ────────────────────────────────────────────────────
logger = logging.getLogger(__name__)
if not logger.handlers:
    _handler = logging.StreamHandler(sys.stderr)
    _handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s",
                                            datefmt="%Y-%m-%dT%H:%M:%S"))
    logger.addHandler(_handler)
    logger.setLevel(logging.INFO)

# 性能：预编译正则（避免每次调用重复编译）
_PATCH_KEY_RE = re.compile(r"^[a-f0-9]{16}$")
# P1-14：精确匹配本 skill 备份文件格式（harness_<时间戳8位>_<时分秒6位>_<毫秒3位>_<pid>.ext），
# 供轮转孤儿清理使用（防误删非本 skill 的 harness_*.json）
_BACKUP_RE = re.compile(r"^harness_\d{8}_\d{6}_\d{3}_\d+\.(yaml|yml|json)$")


# ── 可观测性：metrics计数器 ───────────────────────────────────────────────────
class _Metrics:
    """轻量计数器，暴露给外部可观测系统（如Prometheus）。"""
    heuristic_runs: int = 0
    llm_runs: int = 0
    vetoes: int = 0
    applied: int = 0
    rollbacks: int = 0


METRICS = _Metrics()


def _now():
    """时间戳：毫秒级 + pid，避免同秒内备份文件名碰撞（P0-3 修复）。"""
    return _format_ts()


def _patch_key(patch: dict) -> str:
    """补丁语义指纹（P1-14）：只对 target_artifact|patch_type|归一化 after 哈希。

    before / supporting_trajectories / source_event 等元字段不参与——同一语义补丁
    无论大小写、空白、附加字段怎么变都归一到同 key，防攻击者靠「改大小写/加空格/
    换轨迹 ID」攻破拒收池去重后重试；after 实质内容变化（措辞不同）则 key 不同，
    改进版补丁可正常重新进入进化环。
    """
    t = str(patch.get("target_artifact") or "").strip().lower()
    pt = str(patch.get("patch_type") or "").strip().lower()
    after = patch.get("after")
    if isinstance(after, (dict, list)):
        blob = json.dumps(after, sort_keys=True, ensure_ascii=False)
    else:
        blob = str(after or "")
    blob_n = _normalize_unicode(blob).lower()
    blob_n = re.sub(r"\s+", "", blob_n)  # 去全部空白（含换行/制表/全角空格）
    return hashlib.sha256(f"{t}|{pt}|{blob_n}".encode("utf-8")).hexdigest()[:16]


def _load(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ── 路径沙箱化（P0-1 修复：消除 rollback/apply/backup 的任意路径写原语）────────
# 所有用户可控的输出路径（--harness / --backup）都必须收敛到 allow_root 之内，
# 且必须是受支持的护栏扩展名；拒绝 .. 穿越与跨盘绝对路径。
_ALLOWED_EXT = (".json", ".yaml", ".yml")


class _PathEscapeError(ValueError):
    """路径越出允许根（疑似穿越或非受信目录）。"""


def _sandbox_path(path: str, allow_root: str, *, require_ext=_ALLOWED_EXT,
                  label: str = "目标路径") -> str:
    """把用户提供的 path 收敛到 allow_root 内并返回绝对路径；越界即抛错。

    allow_root 是 CLI 路径（main 已注入默认）；若为 None（如单测直接调 cmd_* 函数），
    则回退为「path 自身所在目录」作为沙箱根——此时约束退化为「扩展名校验」，
    既不阻断既有测试，CLI 又始终受目录沙箱约束。
    """
    raw = os.path.realpath(os.path.abspath(path))
    if not raw.lower().endswith(require_ext):
        raise _PathEscapeError(
            f"[路径沙箱] {label} {raw} 扩展名不在 {require_ext} 之内，拒绝（防覆盖任意文件）。")
    if not allow_root:
        # 单测/内部调用：以 path 自身目录为根，仅做强扩展名校验
        return raw
    root_abs = os.path.realpath(allow_root)
    try:
        common = os.path.commonpath([root_abs, raw])
    except ValueError:
        # 不同盘符（Windows）必然越界
        raise _PathEscapeError(
            f"[路径沙箱] {label} {raw} 与允许根 {root_abs} 不在同一盘符/卷，越界拒绝。")
    if common != root_abs:
        raise _PathEscapeError(
            f"[路径沙箱] {label} {raw} 越出允许根 {root_abs}（疑似 ../ 穿越或非受信目录），拒绝写入。")
    return raw


def _load_reject_pool(path, fail_open: bool = False):
    """读拒收池。

    P1-9 修复：
      * fail_open=False（默认，写回链路）：损坏时抛 RuntimeError → 调用方拒绝写回，
        绝不静默回退空池（否则攻破一次即抹掉闸C 记忆）。
      * fail_open=True（judge 只读判定）：损坏时归档 + 回退空池（不阻塞进化闭环）。
      * 类型校验：顶层必须是 list，否则按损坏处理。
    """
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            pool = json.load(f)
        if not isinstance(pool, list):
            raise ValueError(f"拒收池顶层必须是 list，实际 {type(pool).__name__}")
        return pool
    except (json.JSONDecodeError, ValueError, OSError) as e:
        if fail_open:
            print(f"[拒收池] 文件损坏（{e}），回退空池，原文件归档为 {path}.corrupt。", file=sys.stderr)
            corrupt = path + ".corrupt"
            if os.path.exists(corrupt):
                corrupt += f"_{_time.time():.6f}"
            try:
                shutil.move(path, corrupt)
            except OSError:
                pass
            return []
        raise RuntimeError(f"[拒收池] 文件损坏或格式非法（{e}），按 fail-closed 拒绝继续（防抹掉拒收记忆）。") from e


class _RejectPoolLock:
    """跨进程持久化读写锁（Windows 用 msvcrt 字节级排他锁；非 Windows 回退 fcntl）。

    设计要点（P0-D 修复）：
      * 用 OS 原生文件锁做互斥，依赖「加锁」而非「删除 lock 文件」来表达持有状态，
        彻底规避 Windows 下 os.remove(some.lock) 偶发 WinError 5 / FileNotFoundError
        导致锁无法回收、并发时仅 1 个进程能成功的缺陷。
      * 死进程：OS 在进程结束时自动释放其持有的锁，不会永久占锁（不再依赖 _lockfile_stale 删文件）。
      * 锁文件长期存在无害（仅作为锁对象），pool 数据写在 pool_path 本身。
    """

    def __init__(self, pool_path, timeout_sec=60):
        self.pool_path = pool_path
        self.lock_path = pool_path + ".lock"
        self.timeout_sec = timeout_sec
        self._fd = None

    def __enter__(self):
        self._acquire()
        return self

    def __exit__(self, *exc):
        self._release()
        return False

    def _try_open(self):
        try:
            return os.open(self.lock_path, os.O_CREAT | os.O_RDWR)
        except OSError:
            return None

    def _try_lock(self, fd):
        """对锁文件首字节加非阻塞排他锁；已被占用则立即失败（不阻塞）。"""
        if _MSVCRT is not None:
            try:
                _MSVCRT.locking(fd, _MSVCRT.LK_NBLCK, 1)
                return True
            except OSError:
                return False
        # 非 Windows：fcntl 排他非阻塞锁
        try:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except (ImportError, OSError):
            return False

    def _acquire(self):
        # 单次超时即 fail-closed（正常竞争下持锁为毫秒级，60s 远超所需）
        deadline = _time.time() + self.timeout_sec
        while True:
            fd = self._try_open()
            if fd is not None and self._try_lock(fd):
                self._fd = fd
                return
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
            if _time.time() > deadline:
                raise RuntimeError(
                    f"[拒收池锁] 等待锁 {self.lock_path} 超时 {self.timeout_sec}s，"
                    "判定为并发争用超过上限，中止写入（防写丢）")
            _time.sleep(0.02)

    def _release(self):
        fd = getattr(self, "_fd", None)
        if fd is None:
            return
        self._fd = None
        if _MSVCRT is not None:
            try:
                _MSVCRT.locking(fd, _MSVCRT.LK_UNLCK, 1)
            except OSError:
                pass
        else:
            try:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_UN)
            except (ImportError, OSError):
                pass
        try:
            os.close(fd)
        except OSError:
            pass

    def read(self, fail_open: bool = False):
        return _load_reject_pool(self.pool_path, fail_open=fail_open)

    def write(self, obj):
        _save(self.pool_path, obj)


def _open_write_no_follow(path: str):
    """L3-14（P1-19）：以「不跟随 symlink」语义打开文件用于写入。

    - 先 islink 预检（跨平台）：Windows 的 os.O_NOFOLLOW 语义是「打开 reparse point
      本身」而非「拒绝」，故预检是主防线
    - 再 O_NOFOLLOW（Unix）：open 层原子拒绝 symlink 目标，防预检与 open 之间
      TOCTOU 竞态（攻击者把 .tmp 预置为指向目标文件的 symlink，写入即覆盖目标）
    返回 file object（调用方负责 close）。
    """
    if os.path.islink(path):
        raise OSError(f"[O_NOFOLLOW] 目标 {path} 是 symlink，拒绝写入（防劫持）")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is not None:
        fd = os.open(path, flags | nofollow)
    else:
        fd = os.open(path, flags)
    return os.fdopen(fd, "w", encoding="utf-8")


def _save(path, obj):
    """原子写：先写 .tmp 再 os.replace，杜绝并发写半截 / 文件损坏（L3-14 防 symlink 劫持）。"""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = path + ".tmp"
    with _open_write_no_follow(tmp) as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def _pool_has(pool: list, key: str) -> bool:
    """拒收池成员判断（P1-14）：兼容旧 str 条目与新 dict 条目 {key, reason, ts}。"""
    return any(item == key or (isinstance(item, dict) and item.get("key") == key)
               for item in pool)


def _reject_key(pool_path, key, reason=None):
    """原子地把 key 写进拒收池（跨进程锁保护）。已存在则跳过。返回写入后池大小。

    P0-D 修复核心：原先 cmd_apply 用裸 _load_reject_pool + _save，并发 apply 时
    『读旧池→append→写』非原子，两进程同时读到空池各 append 后互相覆盖，导致
    拒收池大量丢数据。统一走 _RejectPoolLock 后，读→改→写 三段整体加锁。
    P1-14：条目升级为 {key, reason, ts}，拒收原因可审计；读取侧兼容旧 str 条目。
    """
    entry = {"key": key, "reason": reason, "ts": _now()}
    with _RejectPoolLock(pool_path) as lock:
        pool = lock.read()
        if not _pool_has(pool, key):
            pool.append(entry)
            lock.write(pool)
        return len(pool)


def _load_harness(path):
    """读护栏快照，支持 .json / .yaml。yaml 缺库时尝试按 JSON 降级读取（M-01 修复）。"""
    if path.endswith(".json"):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    if path.endswith((".yaml", ".yml")):
        try:
            import yaml
        except ImportError:
            # P1 修复：缺 pyyaml 时尝试按 JSON 解析（很多 .yaml 护栏实为合法 JSON）
            with open(path, "r", encoding="utf-8") as f:
                try:
                    return json.load(f)
                except json.JSONDecodeError:
                    print("[错误] 检测到 yaml 护栏但未安装 pyyaml，且文件非合法 JSON。"
                          "请 pip install pyyaml，或将护栏另存为 .json 后重试。",
                          file=sys.stderr)
                    raise
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    raise ValueError(f"不支持的护栏格式：{path}（仅支持 .json / .yaml）")


def _looks_like_harness(obj) -> bool:
    """粗略结构校验（P1-17）：解析后是 dict，且 artifacts 键若存在必须是 dict。

    防「删 manifest + 篡改备份为任意合法 JSON」的降级绕过（PoC 实证：备份被改成
    {"hacked": true, "artifacts": null} 后回滚成功写坏护栏）。注意区分「键不存在」
    （旧格式护栏，合并器会补）与「键存在但非 dict」（含 null——篡改特征）。
    """
    if not isinstance(obj, dict):
        return False
    if "artifacts" in obj and not isinstance(obj["artifacts"], dict):
        return False
    return True


def _run_p0_regression(timeout_sec: int = 120) -> int:
    """P0-3 修复：写回后强制跑同目录下的 P0 回归测试，确保护栏未被改弱。

    返回子进程 returncode；任何异常（找不到测试、超时）一律视为失败（fail-closed）。
    防递归：若当前进程已是回归测试派生的子进程（环境变量标记），直接视为通过，
    避免 test_p0_regression → cmd_apply → 回归 → … 无限嵌套。
    """
    if os.environ.get("SHE_P0_REGRESSION_RUNNING") == "1":
        return 0
    here = os.path.dirname(os.path.abspath(__file__))
    test_py = os.path.join(here, "test_p0_regression.py")
    if not os.path.exists(test_py):
        print(f"[P0 回归] 未找到回归测试 {test_py}，按 fail-closed 视为未通过。", file=sys.stderr)
        return 1
    env = dict(os.environ)
    env["SHE_P0_REGRESSION_RUNNING"] = "1"
    try:
        r = subprocess.run([sys.executable, test_py],
                           capture_output=True, text=True, timeout=timeout_sec,
                           cwd=here, env=env)
    except Exception as e:  # noqa: BLE001
        print(f"[P0 回归] 执行异常（{e}），按 fail-closed 视为未通过。", file=sys.stderr)
        return 1
    if r.returncode != 0:
        sys.stderr.write(r.stdout)
        sys.stderr.write(r.stderr)
    return r.returncode


def _save_harness(path, obj):
    """写回护栏快照，格式跟随扩展名，使用原子写防并发损坏（L3-14 防 symlink 劫持）。"""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp_path = path + ".tmp"
    try:
        if path.endswith(".json"):
            with _open_write_no_follow(tmp_path) as f:
                json.dump(obj, f, ensure_ascii=False, indent=2)
        elif path.endswith((".yaml", ".yml")):
            import yaml
            with _open_write_no_follow(tmp_path) as f:
                yaml.safe_dump(obj, f, allow_unicode=True, sort_keys=False)
        else:
            raise ValueError(f"不支持的护栏格式：{path}（仅支持 .json / .yaml）")
        os.replace(tmp_path, path)
    except Exception:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise


# ── 闸 A：备份 ────────────────────────────────────────────────────────────
_MANIFEST_NAME = "manifest.json"
_MAX_BACKUPS_DEFAULT = 20


def _manifest_path(backup_root: str) -> str:
    return os.path.join(backup_root, _MANIFEST_NAME)


def _load_manifest(backup_root: str) -> list:
    """读 backups/manifest.json；缺失/损坏返回空列表（清单仅作完整性校验，非硬闸）。"""
    mp = _manifest_path(backup_root)
    if not os.path.exists(mp):
        return []
    try:
        with open(mp, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and isinstance(data.get("backups"), list):
            return data["backups"]
    except (json.JSONDecodeError, OSError, AttributeError):
        pass
    return []


def _save_manifest(backup_root: str, entries: list):
    """原子写 manifest.json（P1-14）。"""
    _save(_manifest_path(backup_root), {"version": 1, "backups": entries})


# ── L2-7 审计日志（P1-15）：写回/判定全程可追溯 ────────────────────────────
_AUDIT_MAX_BYTES = 10 * 1024 * 1024  # P1-17：审计轮转阈值 10MB


def _append_audit(log_path: str, entry: dict):
    """JSONL append 一条审计记录（ts/action/patch_key/diagnosis/scores/gate/backup…）。

    审计是非硬闸的增强层：失败不阻断主流程，但正常路径必须写（供合规审查与问题回溯）。
    P1-17：超过 10MB 归档为 audit.log.1（保留 1 份旧档），防无限膨胀。
    """
    if not log_path:
        return
    try:
        os.makedirs(os.path.dirname(os.path.abspath(log_path)), exist_ok=True)
        if os.path.exists(log_path) and os.path.getsize(log_path) > _AUDIT_MAX_BYTES:
            old = log_path + ".1"
            if os.path.exists(old):
                os.remove(old)
            os.rename(log_path, old)
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            f.flush()
    except OSError:
        pass


def _rotate_backups(backup_root: str, entries: list, max_backups: int) -> list:
    """轮转保留（P1-14）：entries 按 created_at 升序，超过 max_backups 删除最旧文件与记录；
    随后兜底扫描目录，把不在保留名单内的受管格式备份（孤儿，如 manifest 重建前的残留）
    一并删除，防目录无限堆积。"""
    if max_backups <= 0:
        return entries
    if len(entries) > max_backups:
        keep = entries[-max_backups:]
        for e in entries[:-max_backups]:
            fp = os.path.join(backup_root, e.get("file", ""))
            if os.path.exists(fp):
                try:
                    os.remove(fp)
                except OSError:
                    pass
        entries = keep
    keep_files = {e.get("file") for e in entries}
    for f in os.listdir(backup_root):
        if _BACKUP_RE.match(f) and f not in keep_files:
            fp = os.path.join(backup_root, f)
            try:
                os.remove(fp)
            except OSError:
                pass
    return entries


def cmd_backup(args):
    _allow_root = getattr(args, "allow_root", None) or os.path.dirname(
        os.path.realpath(args.harness))
    harness_abs = _sandbox_path(args.harness, _allow_root,
                                require_ext=_ALLOWED_EXT, label="--harness")
    with open(harness_abs, "r", encoding="utf-8") as f:
        content = f.read()
    backup_root = _sandbox_path(args.backup_dir, _allow_root,
                                require_ext=("",), label="--backup-dir")
    os.makedirs(backup_root, exist_ok=True)
    # P1-4 修复：备份扩展名跟随源文件，而非硬编码 .yaml
    ext = os.path.splitext(harness_abs)[1] or ".yaml"
    dest = os.path.join(backup_root, f"harness_{_now()}{ext}")
    with open(dest, "w", encoding="utf-8") as f:
        f.write(content)
    # P1-14 修复：备份写入 sha256 清单（manifest.json），回滚前校验哈希防篡改/磁盘坏块
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    entries = _load_manifest(backup_root)
    entries.append({
        "file": os.path.basename(dest),
        "sha256": digest,
        "size": len(content.encode("utf-8")),
        "created_at": _now(),
        "harness": harness_abs,
    })
    max_backups = getattr(args, "max_backups", _MAX_BACKUPS_DEFAULT)
    entries = _rotate_backups(backup_root, entries, max_backups)
    _save_manifest(backup_root, entries)
    print(f"[闸A 备份] 已保存当前护栏快照 -> {dest}（sha256 {digest[:12]}…）")
    print(f"[闸A 备份] 后续写回前请确认此备份存在，否则中止。")
    return 0


# ── 闸 B + 闸 C：判定 ─────────────────────────────────────────────────────
def cmd_judge(args):
    patch = _load(args.candidate_patch)
    key = _patch_key(patch)

    # P1-17（安全专家审计）：judge 也做 ValidEdit + 一票否决校验——
    # 原实现 judge 只比数值，对减安补丁（allow all）直接 ACCEPT（PoC 实证 rc=0），
    # 会误导自动化链路并产生错误审计记录。现在非法/减安补丁 judge 直接 REJECT。
    if not all(k in patch for k in ("target_artifact", "patch_type", "after")):
        print("[ValidEdit] 补丁格式非法（缺 target_artifact/patch_type/after），judge 拒绝。", file=sys.stderr)
        _append_audit(getattr(args, "audit_log", None)
                      or os.path.join(os.path.dirname(os.path.abspath(args.reject_pool)), "audit.log"), {
            "ts": _now(), "action": "judge-reject", "patch_key": key,
            "gate": "VALIDEDIT-FAIL", "reason": "missing target_artifact/patch_type/after",
            "operator": getattr(args, "operator", "manual"),
        })
        return 2
    _sp = _load_score_module()
    if _sp is not None:
        veto = _sp._hard_veto_after(str(patch.get("after") or ""))
        if veto:
            print(f"[一票否决] {veto}，judge 拒绝（PoC 修复）。", file=sys.stderr)
            n = _reject_key(args.reject_pool, key, reason="Veto: " + veto)
            _append_audit(getattr(args, "audit_log", None)
                          or os.path.join(os.path.dirname(os.path.abspath(args.reject_pool)), "audit.log"), {
                "ts": _now(), "action": "judge-reject", "patch_key": key,
                "gate": "VETO", "reason": veto, "operator": getattr(args, "operator", "manual"),
            })
            print(f"[闸C 拒收池] 已写入拒收池（共 {n} 条）。")
            return 2

    # 检查进化轮次上限
    reject_pool = _load_reject_pool(args.reject_pool, fail_open=True)
    if len(reject_pool) >= args.max_rounds:
        logger.warning(f"[闸C 拒收池] 已达 K 轮上限（{args.max_rounds} 轮），中止进化并建议人工审核。")
        print(f"[闸C 拒收池] 已达 K 轮上限（{args.max_rounds} 轮），中止进化并建议人工审核。", file=sys.stderr)
        print(f"[判定] HALT —— 已拒绝 {len(reject_pool)} 个补丁，超过上限。", file=sys.stderr)
        return 3

    # 闸 C：拒收池去重
    with _RejectPoolLock(args.reject_pool) as lock:
        reject_pool = lock.read()
        if _pool_has(reject_pool, key):
            print(f"[闸C 拒收池] 命中已拒补丁 {key}，自动跳过（不再重试）。")
            return 2  # 拒收

    # 闸 B：安全-效用闸门
    s_ok = args.s_candidate > args.s_current
    u_ok = args.u_candidate >= args.u_current
    if s_ok and u_ok:
        print(f"[闸B 安全-效用] 通过 | S {args.s_current}->{args.s_candidate} (+{args.s_candidate-args.s_current:.3f}), "
              f"U {args.u_current}->{args.u_candidate} ({'=' if args.u_candidate==args.u_current else '+'}{abs(args.u_candidate-args.u_current):.3f})")
        print(f"[判定] ACCEPT —— 可进入写回（apply）。")
        _append_audit(getattr(args, "audit_log", None)
                      or os.path.join(os.path.dirname(os.path.abspath(args.reject_pool)), "audit.log"), {
            "ts": _now(), "action": "judge-accept", "patch_key": key,
            "scores": {"s_current": args.s_current, "s_candidate": args.s_candidate,
                       "u_current": args.u_current, "u_candidate": args.u_candidate},
            "gate": "ACCEPT", "operator": getattr(args, "operator", "manual"),
        })
        return 0
    else:
        why = []
        if not s_ok:
            why.append(f"安全分未提升 ({args.s_current}->{args.s_candidate})")
        if not u_ok:
            why.append(f"效用分下降 ({args.u_current}->{args.u_candidate})")
        print(f"[闸B 安全-效用] 未通过：{'；'.join(why)}")
        print(f"[判定] REJECT —— 补丁指纹 {key} 记入拒收池。")
        n = _reject_key(args.reject_pool, key, reason="GateB: " + "；".join(why))
        _append_audit(getattr(args, "audit_log", None)
                      or os.path.join(os.path.dirname(os.path.abspath(args.reject_pool)), "audit.log"), {
            "ts": _now(), "action": "judge-reject", "patch_key": key,
            "scores": {"s_current": args.s_current, "s_candidate": args.s_candidate,
                       "u_current": args.u_current, "u_candidate": args.u_candidate},
            "gate": "REJECT", "reason": "；".join(why), "operator": getattr(args, "operator", "manual"),
        })
        print(f"[闸C 拒收池] 已写入拒收池（共 {n} 条）。")
        return 2


# ── 写回（依赖闸 A 已备份；内部强制重跑 闸 B + 闸 C 硬保险）─────────────────
def _load_score_module():
    """导入同目录 score_patch 作为评分器（硬保险依赖）。失败返回 None。"""
    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.insert(0, here)
    try:
        import score_patch  # noqa: F401
        return score_patch
    except Exception as e:
        sys.stderr.write(f"[apply 硬保险] 无法导入 score_patch.py：{e}\n")
        return None


def _resolve_current_scores(args, harness):
    """解析当前基线分：优先 CLI --s-current/--u-current，其次护栏 _scores，否则告警用启发式基线。
    P1-23（第二轮审计 W-R2）：拒绝极端基线——s<0.3 / u<0.5 视为疑似篡改/误传
    （零基线会让任何补丁「提升」且 U 恒过，放大过严写回攻击），回落护栏 _scores 或默认。"""
    s_cur = args.s_current
    u_cur = args.u_current
    if s_cur is not None and s_cur < 0.3:
        print("[硬保险 警告] --s-current 低于 0.3（疑似篡改/误传），回落护栏 _scores 或默认 0.5。", file=sys.stderr)
        s_cur = None
    if u_cur is not None and u_cur < 0.5:
        print("[硬保险 警告] --u-current 低于 0.5（疑似篡改/误传），回落护栏 _scores 或默认 0.8。", file=sys.stderr)
        u_cur = None
    if s_cur is None or u_cur is None:
        base = (harness.get("_scores") or {}) if isinstance(harness, dict) else {}
        if s_cur is None:
            s_cur = base.get("s")
        if u_cur is None:
            u_cur = base.get("u")
    if s_cur is None:
        print("[硬保险 警告] 未给 --s-current 且护栏无 _scores.s，退回启发式基线 0.5（保险力下降）。", file=sys.stderr)
        s_cur = 0.5
    if u_cur is None:
        print("[硬保险 警告] 未给 --u-current 且护栏无 _scores.u，退回启发式基线 0.8（保险力下降）。", file=sys.stderr)
        u_cur = 0.8
    return s_cur, u_cur


def _score_candidate(score_mod, patch, llm_scorer=None):
    """重算候选分：默认启发式，可选 --llm-scorer 接外部小模型。返回 (s,u,hits)。

    P0-B 修复（防外部评分器绕闸）：
      1) 任意 LLM 返回的 (s,u) 先夹取至 [0,1]（防脏数据 / 异常高分）。
      2) 最终分取 启发式 与 LLM 的【更小值】（保守合并）——外部评分只能
         「收紧 / 否决」，不能单边「抬高」来让坏补丁过闸 B。即使恶意评分器
         返回 s=99，也会变成 min(启发式, 1.0)=启发式值，无法绕闸写回坏补丁。
    """
    s_h, u_h, hits_h = score_mod.heuristic_score(patch)
    if not llm_scorer:
        return s_h, u_h, hits_h
    import tempfile
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8")
    json.dump(patch, tmp)
    tmp.close()
    try:
        res = score_mod.call_llm_scorer(llm_scorer, tmp.name)
    finally:
        os.remove(tmp.name)
    if not res:
        return s_h, u_h, hits_h + ["外部 LLM scorer 调用失败/无合法输出，回退启发式"]
    s_l = max(0.0, min(1.0, float(res[0])))
    u_l = max(0.0, min(1.0, float(res[1])))
    s_final = min(s_h, s_l)
    u_final = min(u_h, u_l)
    return s_final, u_final, [
        f"外部 LLM scorer 采纳但已保守合并(min)：启发式 S={s_h}/U={u_h}，"
        f"LLM S={s_l}/U={u_l} → 采用 S={s_final}/U={u_final}（外部评分仅作收紧）"
    ]


def cmd_apply(args):
    _allow_root = getattr(args, "allow_root", None) or os.path.dirname(
        os.path.realpath(args.harness))
    # 闸 A 证明：写回前必须已备份，且备份须【非空、可解析】（P0-A 修复）
    if not os.path.exists(args.backup_dir):
        print("[闸A 备份] 未找到备份目录，按规则中止写回（防止无回滚能力改坏线上护栏）。", file=sys.stderr)
        return 3
    # 仅统计「有内容且可解析」的备份；空/损坏备份视为无有效回滚能力
    backups = []
    for f in os.listdir(args.backup_dir):
        if not _BACKUP_RE.match(f):
            continue
        fp = os.path.join(args.backup_dir, f)
        if os.path.getsize(fp) == 0:
            continue  # 空备份不计入有效证明（防空备份骗过闸A后回滚清空护栏）
        try:
            _load_harness(fp)  # 内容可解析性校验（防损坏备份在回滚时覆盖坏）
        except Exception:
            continue
        backups.append(f)
    if not backups:
        print("[闸A 备份] 备份目录为空或无有效（非空且可解析）备份，按规则中止写回（防回滚时把护栏覆盖成空/损坏）。", file=sys.stderr)
        return 3
    logger.info(f"[闸A 备份] 确认存在最新有效备份：{backups[-1]}")
    print(f"[闸A 备份] 确认存在最新有效备份：{backups[-1]}")

    patch = _load(args.candidate_patch)
    key = _patch_key(patch)

    # ValidEdit：格式非法直接进拒收池（不写回）；用锁原子写（P0-D）
    if not all(k in patch for k in ("target_artifact", "patch_type", "after")):
        logger.warning(f"[ValidEdit] 补丁格式非法，进拒收池（key={key}）。")
        print("[ValidEdit] 补丁格式非法（缺 target_artifact/patch_type/after），进拒收池。", file=sys.stderr)
        n = _reject_key(args.reject_pool, key, reason="ValidEdit: missing target_artifact/patch_type/after")
        print(f"[闸C 拒收池] 已写入拒收池（共 {n} 条）。")
        return 2

    # L2-6（P1-15）：诊断 schema 校验——补丁带 diagnosis 字段则必须合法（机器可校验）。
    # 注意：诊断非法是「元数据问题」非内容问题，只拒绝本次写回（rc=7），不进拒收池——
    # 否则同 after 的合法补丁会被语义 key 连累（诊断不参与 key）。
    diag = patch.get("diagnosis")
    if diag is not None:
        diag_errors = _validate_diagnosis(diag)
        if diag_errors:
            logger.warning(f"[ValidEdit] diagnosis schema 非法（key={key}）：{'；'.join(diag_errors)}")
            print(f"[ValidEdit] diagnosis schema 非法：{'；'.join(diag_errors)}，拒绝写回（rc=7，修复诊断后可重试）。",
                  file=sys.stderr)
            _append_audit(getattr(args, "audit_log", None)
                          or os.path.join(args.backup_dir, "audit.log"), {
                "ts": _now(), "action": "apply-rejected", "patch_key": key,
                "target_artifact": patch.get("target_artifact"),
                "gate": "DIAG-SCHEMA-FAIL", "reason": "；".join(diag_errors[:2]),
                "operator": getattr(args, "operator", "manual"),
            })
            return 7

    # 闸 C：拒收池去重（已拒过的补丁不再写回）；用锁读，防 TOCTOU 并发竞态（P0-D）
    # P1-9 修复：apply 也做 K 轮熔断（与 judge 一致），且池损坏时 fail-closed 拒绝写回。
    max_rounds = getattr(args, "max_rounds", 20)
    with _RejectPoolLock(args.reject_pool) as lock:
        try:
            reject_pool = lock.read(fail_open=False)
        except RuntimeError as e:
            print(str(e), file=sys.stderr)
            return 5
    if len(reject_pool) >= max_rounds:
        print(f"[闸C 拒收池] 已达 K 轮上限（{max_rounds} 轮），中止进化并建议人工审核。", file=sys.stderr)
        return 3
    if _pool_has(reject_pool, key):
        print(f"[闸C 拒收池] 命中已拒补丁 {key}，中止写回。")
        return 2

    # ── 护栏写回：加锁保证 读→改→写 原子（P0-D 修复：防并发 apply 互相覆盖护栏）──
    score_mod = _load_score_module()
    if score_mod is None:
        logger.error("[apply 硬保险] 缺少 score_patch.py，无法重跑闸 B；为防绕闸，中止写回。")
        print("[硬保险 错误] 缺少 score_patch.py，无法重跑闸 B；为防绕闸，中止写回。", file=sys.stderr)
        return 5

    with _RejectPoolLock(args.harness) as _hlock:
        # 锁内重读最新护栏，避免用进入函数时可能已过期的快照
        harness_abs = _sandbox_path(args.harness, _allow_root,
                                    require_ext=_ALLOWED_EXT, label="--harness")
        harness = _load_harness(harness_abs)
        # ── 硬保险：强制重跑 评分 + 闸 B（不依赖调用方先 judge，杜绝绕闸）──
        logger.info(f"[硬保险] 开始重跑评分 + 闸 B（patch key={key}）")
        s_cur, u_cur = _resolve_current_scores(args, harness)
        s_can, u_can, hits = _score_candidate(score_mod, patch, getattr(args, "llm_scorer", None))
        s_ok = s_can > s_cur
        u_ok = u_can >= u_cur
        if not (s_ok and u_ok):
            why = []
            if not s_ok:
                why.append(f"安全分未提升 ({s_cur}->{s_can})")
            if not u_ok:
                why.append(f"效用分下降 ({u_cur}->{u_can})")
            verdict_accept = False
            _why = why
            _hits = hits
            _reject_count = _reject_key(args.reject_pool, key,
                                        reason="GateB(hard): " + "；".join(why))  # 原子写拒收池（P0-D）
        else:
            verdict_accept = True
            _hits = hits
            _why = []
            # 应用补丁到护栏快照：先记账，再结构感知真合并进对应工件
            merged_into = _merge_artifact(harness, patch, key)
            _merged_into = merged_into
            # P0-2 修复：棘轮偏序校验驳回（放宽护栏）→ 阻断写回，不入 applied_patches，
            # 但记入拒收池（同 key 后续轮不再重试），并显式 WARN 不谎报"已变硬"。
            if "ratchet-reject" in merged_into:
                verdict_accept = False
                _why = [merged_into]
                _hits = hits
                _reject_count = _reject_key(args.reject_pool, key, reason=merged_into)
            else:
                harness.setdefault("applied_patches", []).append({
                    "key": key,
                    "applied_at": _now(),
                    "target_artifact": patch["target_artifact"],
                    "patch_type": patch["patch_type"],
                    "after": patch["after"],
                    "merged_into": merged_into,
                    "backup": backups[-1],
                    "rollback_cmd": f"python evolve_guard.py rollback --backup {os.path.join(args.backup_dir, backups[-1])} --harness {harness_abs}",
                })
                # L3-15（P1-19）：写回 tool_policy 时同步编译 enforcement spec——
                # 护栏与运行时执行器解耦校验：改了工具策略必须让执行器跟着改
                if patch.get("target_artifact") == "tool_policy":
                    harness["_enforcement"] = compile_enforcement(
                        harness.get("artifacts", {}).get("tool_policy"))
                    print("[写回] tool_policy 已更新，enforcement spec 已同步编译——"
                          "运行时执行器需重新加载 harness 才会生效。")
            _save_harness(harness_abs, harness)
            _merged_into = merged_into
            # P0-3 修复：写回后强制跑 P0 回归闸门；失败自动回滚到最新备份并中止写回。
            # 允许 --skip-p0-regression（回归测试自身嵌套调用 apply 时避免指数放大）。
            if not getattr(args, "skip_p0_regression", False):
                rc = _run_p0_regression()
                if rc != 0:
                    print(f"[P0 回归] 回归测试未通过（rc={rc}），护栏可能被改弱，自动回滚到 {backups[-1]}。",
                          file=sys.stderr)
                    _append_audit(getattr(args, "audit_log", None)
                                  or os.path.join(args.backup_dir, "audit.log"), {
                        "ts": _now(), "action": "rollback-auto", "patch_key": key,
                        "target_artifact": patch.get("target_artifact"),
                        "gate": "P0-REGRESSION-FAIL", "reason": f"regression rc={rc}",
                        "backup": backups[-1], "operator": getattr(args, "operator", "manual"),
                    })
                    try:
                        rollback_args = argparse.Namespace(
                            backup=os.path.join(args.backup_dir, backups[-1]),
                            harness=harness_abs,
                            allow_root=getattr(args, "allow_root", None))
                        cmd_rollback(rollback_args)
                    except Exception as e:  # noqa: BLE001
                        print(f"[P0 回归] 自动回滚失败：{e}，请人工介入。", file=sys.stderr)
                    return 6

    # ── 锁外打印结果（缩短持锁时间）──
    if not verdict_accept:
        if _why and any("ratchet-reject" in w for w in _why):
            print(f"[棘轮 安全-效用] 阻断：{'；'.join(_why)}（命中信号：{', '.join(_hits) or '无'}）")
            print(f"[棘轮] 补丁 {key} 试图放宽护栏，已被棘轮偏序校验拒绝写回并记入拒收池。")
            print(f"[闸C 拒收池] 已写入拒收池（共 {_reject_count} 条）。")
        else:
            print(f"[硬保险 闸B 安全-效用] 未通过：{'；'.join(_why)}（命中信号：{', '.join(_hits) or '无'}）")
            print(f"[硬保险] 补丁 {key} 未过闸 B，拒绝写回并记入拒收池。")
            print(f"[闸C 拒收池] 已写入拒收池（共 {_reject_count} 条）。")
        return 2
    print(f"[硬保险 闸B 安全-效用] 通过 | S {s_cur}->{s_can} (+{s_can-s_cur:.3f}), "
          f"U {u_cur}->{u_can} ({'=' if u_can==u_cur else '+'}{abs(u_can-u_cur):.3f})（命中信号：{', '.join(_hits) or '无'}）")
    logger.info(f"[写回] 补丁 {key} 已应用（target={patch['target_artifact']}，合并位置={_merged_into}）。")
    print(f"[写回] 补丁 {key} 已应用（target={patch['target_artifact']}，合并位置={_merged_into}）。")
    # L2-7（P1-15）：写回审计记录（含诊断引用与评分，供合规审查与回溯）
    _append_audit(getattr(args, "audit_log", None) or os.path.join(args.backup_dir, "audit.log"), {
        "ts": _now(), "action": "apply", "patch_key": key,
        "target_artifact": patch.get("target_artifact"),
        "patch_type": patch.get("patch_type"),
        "after_preview": str(patch.get("after") or "")[:80],
        "diagnosis": patch.get("diagnosis"),
        "scores": {"s_current": s_cur, "s_candidate": s_can,
                   "u_current": u_cur, "u_candidate": u_can},
        "gate": "ACCEPT", "merged_into": _merged_into,
        "backup": backups[-1], "operator": getattr(args, "operator", "manual"),
    })
    # P1-10 修复：仅当真正合并进工件（非记账/非 skip-dup/非未知工件）才报"已变硬"
    if _merged_into and "skip-dup" not in _merged_into and "(未知工件" not in _merged_into \
            and "early-write-blocked" not in _merged_into:
        logger.info(f"[写回] 护栏对应工件已变硬（{_merged_into}）。")
        print(f"[写回] 护栏对应工件已变硬（{_merged_into}）。")
    elif _merged_into and "skip-dup" in _merged_into:
        logger.info(f"[写回] 该补丁内容已在工件中，跳过重复硬化（{_merged_into}）。")
        print(f"[写回] 该补丁内容已在工件中，跳过重复硬化（{_merged_into}）。")
    elif _merged_into and "(未知工件" in _merged_into:
        logger.info(f"[写回] 未知工件仅记账，未改动护栏结构（{_merged_into}）。")
        print(f"[写回] 未知工件仅记账，未改动护栏结构（{_merged_into}）。")
    elif _merged_into and "early-write-blocked" in _merged_into:
        logger.info(f"[写回] 冷启动保护触发，未写入（{_merged_into}）。")
        print(f"[写回] 冷启动保护触发，未写入（{_merged_into}）。")
    rollback_cmd = (f"python evolve_guard.py rollback --backup {os.path.join(args.backup_dir, backups[-1])}"
                    f" --harness {harness_abs}")
    print(f"[写回] 回滚命令：{rollback_cmd}")
    return 0


# ── 结构感知工件合并器（四工件均真合并，非记账）─────────────────────────
def _parse_structured(after: str):
    """若 after 是 JSON 对象，返回 dict；否则返回 None。"""
    try:
        parsed = json.loads(after)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        return None
    return None


# P1-20：条目判重忽略演化元字段（applied_at/from_patch/key）——同语义内容条目
# 无论何时合入、来自哪个补丁，签名一致（防 push→pull 往返重复合入）
_ENTRY_META_FIELDS = ("applied_at", "from_patch", "key")


def _entry_sig(entry) -> str:
    """条目的语义指纹：剔除演化元字段后的稳定序列化。"""
    if isinstance(entry, dict):
        core = {k: v for k, v in entry.items() if k not in _ENTRY_META_FIELDS}
    else:
        core = entry
    return json.dumps(core, sort_keys=True, ensure_ascii=False)


def _dup_entry(items, entry) -> bool:
    """判定 entry 是否已存在于条目列表（按语义指纹，忽略元字段——P1-20 往返幂等）。"""
    sig = _entry_sig(entry)
    return any(_entry_sig(m) == sig for m in items if isinstance(m, dict))


def _merge_system_prompt(art, patch, key):
    """system_prompt 是全局行为契约文本（prompt_diff）。

    - before 给出 → 仅当 before 与某个【整段落】完全一致时替换该段落（P0-4：防误替换）
    - before 为空/未命中，且 after 尚未作为独立段落存在 → 追加为末尾新段落
    - after 已作为独立段落存在 → skip-dup
    """
    sp = art.get("system_prompt", "")
    if not isinstance(sp, str):
        sp = str(sp)
    after = patch.get("after") or ""
    before = patch.get("before") or ""
    # 段落级判定：按空行切分
    _paras = [p for p in re.split(r"\n\s*\n", sp)]
    _after_stripped = after.strip()
    if _after_stripped and any(p.strip() == _after_stripped for p in _paras):
        return "artifacts.system_prompt(skip-dup)"
    if before:
        before_stripped = before.strip()
        for i, p in enumerate(_paras):
            if p.strip() == before_stripped:
                _paras[i] = _after_stripped
                sp = "\n\n".join(_paras).strip()
                art["system_prompt"] = sp
                return "artifacts.system_prompt(replaced-para)"
        # before 未作为独立段落命中 → 拒绝修改，避免误替换
        art["system_prompt"] = sp
        return "artifacts.system_prompt(skipped-no-para-match)"
    sp = (sp + "\n\n" + after).strip()
    art["system_prompt"] = sp
    return "artifacts.system_prompt(appended)"


def _merge_safety_memory(art, patch, key, min_rounds=2):
    """safety_memory 是对比性经验条目列表（write_memory）。

    - after 本身是 JSON 对象 → 直接用；否则包成 {note, applied_at, from_patch}
    - 同签名条目已存在 → skip-dup
    - P2-5 修复：冷启动保护 — 若 patch 含 failed_attempts 且 < min_rounds，
      拒绝写入并返回 'artifacts.safety_memory(early-write-blocked)'
    """
    sm = art.get("safety_memory")
    if not isinstance(sm, list):
        sm = []
        art["safety_memory"] = sm
    after = patch.get("after") or ""
    entry = _parse_structured(after)
    if entry is None:
        entry = {"note": after, "applied_at": _now(), "from_patch": key}
    else:
        entry.setdefault("applied_at", _now())
        entry.setdefault("from_patch", key)

    # 冷启动保护：检查 failed_attempts
    failed_attempts = patch.get("failed_attempts", 0)
    if failed_attempts < min_rounds:
        return f"artifacts.safety_memory(early-write-blocked, failed_attempts={failed_attempts}<{min_rounds})"

    if _dup_entry(sm, entry):
        return "artifacts.safety_memory(skip-dup)"
    sm.append(entry)
    return "artifacts.safety_memory"


def _ratchet_check_tool_policy(existing: dict, incoming: dict) -> list:
    """棘轮偏序校验（P0-2 修复核心）：新条目相对旧条目只能「收紧」，不得放宽。

    规则：
      * allow：只能收缩（如 read-only → read-only；* → read-only 是收紧；read-only → * 是放宽）
              用权限集大小近似比较（* 视为最小约束=最宽）。
      * deny：只能扩张（新增禁止项，不得删除已有禁止项）。
      * require / confirm / before_use：只能增加关键词，不得减少。
    返回违例说明列表（空=通过）。
    """
    violations = []
    if not isinstance(existing, dict) or not isinstance(incoming, dict):
        return violations

    def _allow_breadth(v):
        # P1-16：all/everything/any 与 * 同属最宽（宽度 0）——修复 read-only → all 被误判等宽放行
        if v in (None, "", "*", "all", "everything", "any"):
            return 0
        return 1 + len(str(v).split())

    e_allow, i_allow = existing.get("allow"), incoming.get("allow")
    if e_allow is not None and i_allow is not None:
        e_b, i_b = _allow_breadth(e_allow), _allow_breadth(i_allow)
        # 收紧：e_b>=1 且 i_b < e_b（或 i_allow 为 * 即 i_b=0 也是放宽）
        if i_b < e_b:
            violations.append(f"tool_policy.allow 被放宽：{e_allow!r} → {i_allow!r}（棘轮禁止）")

    e_deny, i_deny = existing.get("deny"), incoming.get("deny")
    if e_deny is not None:
        e_set, i_set = set(_as_list(e_deny)), set(_as_list(i_deny or []))
        dropped = e_set - i_set
        if dropped:
            violations.append(f"tool_policy.deny 被删减：移除 {sorted(dropped)}（棘轮禁止）")

    for fld in ("require", "confirm", "before_use", "note_restrict"):
        e_v, i_v = existing.get(fld), incoming.get(fld)
        if e_v is not None:
            # 关键词类字段：按空白分词比较（"verify" ⊆ "verify before use" 视为收紧，不误杀）
            e_set, i_set = _token_set(e_v), _token_set(i_v or "")
            dropped = e_set - i_set
            if dropped:
                violations.append(f"tool_policy.{fld} 被删减：移除 {sorted(dropped)}（棘轮禁止）")
    return violations


def _token_set(v):
    """把 require/confirm 等关键词字段按空白分词成集合；列表则逐项分词。"""
    items = v if isinstance(v, list) else str(v).split()
    out = set()
    for it in items:
        for tok in str(it).split():
            if tok:
                out.add(tok)
    return out


def _as_list(v):
    if v is None:
        return []
    if isinstance(v, (list, tuple, set)):
        return list(v)
    return [v]


def _merge_tool_policy(art, patch, key):
    """tool_policy 是工具权限列表（tighten_tool）。

    - after 本身是 JSON 对象 → 直接用；否则包成 {note, applied_at, from_patch}
    - 含 tool 字段且已存在同 tool 条目 → 覆盖合并（收紧）
    - 同签名条目已存在 → skip-dup
    - P0-2 修复：合并前做棘轮偏序校验，放宽即 REJECT（不写回、不入池，返回拒绝标记）
    """
    tp = art.get("tool_policy")
    if not isinstance(tp, list):
        tp = []
        art["tool_policy"] = tp
    after = patch.get("after") or ""
    entry = _parse_structured(after)
    if entry is None:
        entry = {"note": after, "applied_at": _now(), "from_patch": key}
    else:
        entry.setdefault("applied_at", _now())
        entry.setdefault("from_patch", key)
    tool = entry.get("tool")
    if tool:
        for i, m in enumerate(tp):
            if isinstance(m, dict) and m.get("tool") == tool:
                violations = _ratchet_check_tool_policy(m, entry)
                if violations:
                    return "artifacts.tool_policy(ratchet-reject:" + "; ".join(violations) + ")"
                tp[i] = entry
                return "artifacts.tool_policy(merged)"
    if _dup_entry(tp, entry):
        return "artifacts.tool_policy(skip-dup)"
    tp.append(entry)
    return "artifacts.tool_policy"


# ── L2-6 诊断 schema（P1-15）：让进化环步骤③（诊断/归因）机器可校验 ────────────
_DIAG_FAILURE_TYPES = ("injection", "privilege_escalation", "data_exfil", "logic_bypass", "composite")
_DIAG_HAZARDS = ("data_leak", "privilege_escalation", "logic_bypass", "other")
_DIAG_ATTACK_SURFACES = ("system_prompt", "rule_bank", "safety_memory", "tool_policy")
_DIAG_FAILURE_MODES = ("canary_bypass", "zero_width_injection", "semantic_paraphrase",
                       "tool_tampering", "composite", "other")
_DIAG_ARTIFACTS = ("system_prompt", "rule_bank", "safety_memory", "tool_policy")
_DIAG_CONFIDENCE = ("high", "medium", "low")


def _validate_diagnosis(diag) -> list:
    """校验诊断 schema（P1-15）。返回错误列表（空 = 合法）。

    schema：{failure_type, zi:{hazard, attack_surface, failure_mode},
             routing:{artifact, confidence, reason}, trajectory_refs?}
    全部为受控枚举；LLM 输出诊断必须按此格式，写回前机器校验，审计可复核。
    """
    errors = []
    if not isinstance(diag, dict):
        return ["diagnosis 必须是对象"]
    if diag.get("failure_type") not in _DIAG_FAILURE_TYPES:
        errors.append(f"failure_type 非法 {diag.get('failure_type')!r}（应为 {_DIAG_FAILURE_TYPES}）")
    zi = diag.get("zi")
    if not isinstance(zi, dict):
        errors.append("zi 缺失或非对象")
    else:
        if zi.get("hazard") not in _DIAG_HAZARDS:
            errors.append(f"zi.hazard 非法 {zi.get('hazard')!r}（应为 {_DIAG_HAZARDS}）")
        if zi.get("attack_surface") not in _DIAG_ATTACK_SURFACES:
            errors.append(f"zi.attack_surface 非法 {zi.get('attack_surface')!r}（应为 {_DIAG_ATTACK_SURFACES}）")
        if zi.get("failure_mode") not in _DIAG_FAILURE_MODES:
            errors.append(f"zi.failure_mode 非法 {zi.get('failure_mode')!r}（应为 {_DIAG_FAILURE_MODES}）")
    rt = diag.get("routing")
    if not isinstance(rt, dict):
        errors.append("routing 缺失或非对象")
    else:
        if rt.get("artifact") not in _DIAG_ARTIFACTS:
            errors.append(f"routing.artifact 非法 {rt.get('artifact')!r}（应为 {_DIAG_ARTIFACTS}）")
        if rt.get("confidence") not in _DIAG_CONFIDENCE:
            errors.append(f"routing.confidence 非法 {rt.get('confidence')!r}（应为 {_DIAG_CONFIDENCE}）")
        if not rt.get("reason"):
            errors.append("routing.reason 缺失")
    return errors


def compile_enforcement(tool_policy) -> dict:
    """L3-15（P1-19）：把 tool_policy 编译为机器可读的 enforcement spec
    （工具→决策 三元组），供运行时执行器（harness_hooks.enforce_tool）消费——
    「护栏改了，执行器跟着改」：apply 写回 tool_policy 时自动更新 _enforcement。"""
    spec = {"version": 1, "rules": []}
    for tp in tool_policy or []:
        if not isinstance(tp, dict) or not tp.get("tool"):
            continue
        decision = "block" if tp.get("deny") else ("warn" if (tp.get("require") or tp.get("confirm")) else "allow")
        spec["rules"].append({
            "tool": tp["tool"],
            "decision": decision,
            "allow": tp.get("allow"),
            "deny": tp.get("deny"),
            "require": tp.get("require"),
            "confirm": tp.get("confirm"),
            "note": tp.get("note"),
        })
    return spec


def _merge_artifact(harness, patch, key, min_rounds=2):
    """按 target_artifact + patch_type 路由到对应结构感知合并器。"""
    art = harness.setdefault("artifacts", {})
    t = patch.get("target_artifact")
    pt = patch.get("patch_type")
    if t == "rule_bank" and pt in ("add_rule", "modify_rule"):
        rb = art.get("rule_bank")
        if not isinstance(rb, list):
            rb = []
            art["rule_bank"] = rb
        # P0-3 修复：modify_rule 真合并（按整条目匹配替换），不再等同于 add_rule
        entry = _make_rule_entry(patch.get("after"), key)
        # P1-20：rule_bank 追加前语义去重（防 push→pull 往返重复合入）
        if _dup_entry(rb, entry):
            return "artifacts.rule_bank(skip-dup)"
        if pt == "modify_rule":
            before = patch.get("before")
            if isinstance(before, str):
                for i, m in enumerate(rb):
                    if isinstance(m, dict) and m.get("rule") == before:
                        rb[i] = entry
                        return "artifacts.rule_bank(modified)"
                # 未命中既有 rule → 退化为追加（显式告知）
                rb.append(entry)
                return "artifacts.rule_bank(add-fallback-no-match)"
        rb.append(entry)
        return "artifacts.rule_bank"
    if t == "system_prompt" and pt in ("prompt_diff", "add_rule"):
        return _merge_system_prompt(art, patch, key)
    if t == "safety_memory" and pt in ("write_memory", "add_rule"):
        # P2-5: 冷启动保护 — 检查 failed_attempts 是否 >= min_rounds
        failed_attempts = patch.get("failed_attempts", 0)
        return _merge_safety_memory(art, patch, key, min_rounds=min_rounds)
    if t == "tool_policy" and pt in ("tighten_tool", "add_rule", "modify_rule"):
        return _merge_tool_policy(art, patch, key)
    # 未知工件/类型：仍只记账，绝不盲改结构
    return f"(未知工件, 仅记账) {t}/{pt}"


def _make_rule_entry(after, key):
    """构造 rule_bank 条目。after 若为合法 JSON 对象则保留结构化；否则包 {rule:...}。"""
    parsed = _parse_structured(str(after)) if after else None
    if parsed is not None:
        parsed.setdefault("from_patch", key)
        parsed.setdefault("applied_at", _now())
        return parsed
    return {"rule": after, "from_patch": key, "applied_at": _now()}


# ── 回滚 ──────────────────────────────────────────────────────────────────
def cmd_rollback(args):
    _allow_root = getattr(args, "allow_root", None) or os.path.dirname(
        os.path.realpath(args.backup))
    backup_abs = _sandbox_path(args.backup, _allow_root,
                               require_ext=_ALLOWED_EXT, label="--backup")
    if not os.path.exists(backup_abs):
        print(f"[回滚] 备份不存在：{backup_abs}", file=sys.stderr)
        return 4

    # P0-A 修复：空 / 损坏备份拒绝覆盖线上护栏（fail-safe：宁可不动，也不把护栏清空/写坏）
    if os.path.getsize(backup_abs) == 0:
        print(f"[回滚] 备份为空（0 字节），拒绝用空备份覆盖线上护栏（防清空）。", file=sys.stderr)
        return 4
    try:
        _load_harness(backup_abs)
    except Exception as e:
        print(f"[回滚] 备份内容无法解析（{e}），拒绝覆盖线上护栏（防写坏）。", file=sys.stderr)
        return 4

    with open(backup_abs, "r", encoding="utf-8") as f:
        content = f.read()

    # P1-14 修复：manifest 哈希校验（存在记录时）——防备份被篡改 / 磁盘坏块导致回滚成坏护栏
    backup_root = os.path.dirname(backup_abs)
    digest_cur = hashlib.sha256(content.encode("utf-8")).hexdigest()
    entries = _load_manifest(backup_root)
    rec = next((e for e in entries if e.get("file") == os.path.basename(backup_abs)), None)
    if rec:
        if rec.get("sha256") != digest_cur:
            print(f"[回滚] 备份哈希校验失败：manifest 记录 {str(rec.get('sha256',''))[:12]}… "
                  f"≠ 实际 {digest_cur[:12]}…（备份可能被篡改或损坏），拒绝覆盖线上护栏。",
                  file=sys.stderr)
            return 4
    else:
        print(f"[回滚] 警告：备份 {os.path.basename(backup_abs)} 无 manifest 哈希记录，"
              f"跳过完整性校验（降级，仅做内容可解析校验）。", file=sys.stderr)
        # P1-17（安全专家审计）：降级路径加结构校验——防「删 manifest + 篡改备份为
        # 任意合法 JSON」的回滚绕过（PoC 实证曾把护栏写坏成 {"hacked": true}）
        try:
            obj = _load_harness(backup_abs)
        except Exception:
            obj = None
        if not _looks_like_harness(obj):
            print(f"[回滚] 降级路径结构校验失败：备份不是有效护栏结构（缺 dict 结构或 "
                  f"artifacts 非 dict），拒绝覆盖线上护栏（防篡改备份回滚）。", file=sys.stderr)
            return 4

    # P0-2 修复：真正执行文件复制，不再只打印
    if not args.harness:
        print("[回滚] 缺少 --harness 目标路径，仅打印备份（兼容旧行为）：")
        print(f"        备份路径：{backup_abs}")
        print(f"        内容预览（前 400 字符）：\n{content[:400]}")
        return 0

    # P0-1 修复：目标护栏也必须落在 allow_root 内，且为受支持扩展名；不再 makedirs 造目录
    try:
        dest_abs = _sandbox_path(args.harness, _allow_root,
                                 require_ext=_ALLOWED_EXT, label="--harness")
    except _PathEscapeError as e:
        print(f"[回滚] {e}", file=sys.stderr)
        return 4
    if os.path.dirname(dest_abs) and not os.path.isdir(os.path.dirname(dest_abs)):
        print(f"[回滚] 目标目录不存在：{os.path.dirname(dest_abs)}，拒绝自动创建（防越界造目录）。",
              file=sys.stderr)
        return 4
    with open(dest_abs, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"[回滚] 已将备份 {backup_abs} 恢复到当前护栏：{dest_abs}")
    print(f"[回滚] 回滚后护栏行数：{content.count(chr(10))+1}")
    return 0


def main():
    p = argparse.ArgumentParser(description="unclekk-safety-harness-evolution 三道硬闸执行器")
    p.add_argument("--version", action="version", version="%(prog)s 1.1.1")
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("backup", help="闸A：写回前备份当前护栏")
    b.add_argument("--harness", required=True, help="当前护栏文件路径（yaml/json）")
    b.add_argument("--backup-dir", required=True, help="备份目录")
    b.add_argument("--max-backups", type=int, default=_MAX_BACKUPS_DEFAULT,
                   help="P1-14 备份轮转保留上限（默认20），超过删除最旧备份及其 manifest 记录")
    b.add_argument("--allow-root", default=None,
                   help="P0-1 路径沙箱根：--harness/--backup-dir 必须落在其内；"
                        "缺省自动取 --harness 与 --backup-dir 的共同父目录")
    b.set_defaults(func=cmd_backup)

    j = sub.add_parser("judge", help="闸B+闸C：判定候选补丁是否放行")
    j.add_argument("--candidate-patch", required=True, help="候选补丁 JSON")
    j.add_argument("--s-current", type=float, required=True, help="当前安全分")
    j.add_argument("--u-current", type=float, required=True, help="当前效用分")
    j.add_argument("--s-candidate", type=float, required=True, help="候选安全分")
    j.add_argument("--u-candidate", type=float, required=True, help="候选效用分")
    j.add_argument("--reject-pool", required=True, help="拒收池 JSON 路径")
    j.add_argument("--max-rounds", type=int, default=20,
                   help="进化轮次上限（默认20），超出后返回 rc=3 中止进化")
    j.add_argument("--audit-log", default=None,
                   help="P1-15 审计日志路径（JSONL，判定记录；缺省取 reject-pool 同目录 audit.log）")
    j.add_argument("--operator", default="manual",
                   help="P1-15 操作者标识（manual/auto_hook/agent名），写入审计记录")
    j.set_defaults(func=cmd_judge)

    a = sub.add_parser("apply", help="写回（闸A已备份 + 内部强制重跑闸B/闸C硬保险）")
    a.add_argument("--harness", required=True, help="当前护栏文件路径（yaml/json）")
    a.add_argument("--candidate-patch", required=True, help="候选补丁 JSON")
    a.add_argument("--backup-dir", required=True, help="备份目录（闸A证明）")
    a.add_argument("--reject-pool", required=True, help="拒收池 JSON 路径")
    a.add_argument("--s-current", type=float, default=None,
                   help="当前基线安全分(可选；缺则读护栏 _scores.s，再缺用启发式 0.5)")
    a.add_argument("--u-current", type=float, default=None,
                   help="当前基线效用分(可选；缺则读护栏 _scores.u，再缺用启发式 0.8)")
    a.add_argument("--llm-scorer", help="外部评分命令模板，{patch} 替换为补丁路径(可选)；缺则走启发式打分")
    a.add_argument("--allow-root", default=None,
                   help="P0-1 路径沙箱根：--harness/--reject-pool 必须落在其内；"
                        "缺省自动取 --harness 所在目录")
    a.add_argument("--skip-p0-regression", action="store_true",
                   help="P0-3 跳过写回后的 P0 回归测试（仅供回归测试自身嵌套调用，生产不建议）")
    a.add_argument("--max-rounds", type=int, default=20,
                   help="进化轮次上限（默认20），拒收池超过则 rc=3 中止（P1-9：apply 与 judge 一致）")
    a.add_argument("--audit-log", default=None,
                   help="P1-15 审计日志路径（JSONL，写回/自动回滚记录；缺省取 backup-dir 下 audit.log）")
    a.add_argument("--operator", default="manual",
                   help="P1-15 操作者标识（manual/auto_hook/agent名），写入审计记录")
    a.set_defaults(func=cmd_apply)

    r = sub.add_parser("rollback", help="一键回滚到指定备份")
    r.add_argument("--backup", required=True, help="备份文件路径")
    r.add_argument("--harness", help="当前护栏文件路径（P0-2：指定此参数自动复制备份回原位置）")
    r.add_argument("--allow-root", default=None,
                   help="P0-1 路径沙箱根：--backup/--harness 必须落在其内；"
                        "缺省自动取 --backup 与 --harness 的共同父目录")
    r.set_defaults(func=cmd_rollback)

    args = p.parse_args()
    # P0-1 修复：自动推导 allow_root 默认（用户未显式给出时，取受信目录，绝不默认全盘）
    if getattr(args, "allow_root", None) is None:
        candidates = []
        for attr in ("harness", "backup_dir", "backup", "reject_pool"):
            v = getattr(args, attr, None)
            if v:
                candidates.append(os.path.dirname(os.path.realpath(v)) or os.path.realpath(v))
        # 取共同父目录；若只有一个来源则用其目录；多来源取 commonpath
        if candidates:
            try:
                args.allow_root = os.path.commonpath(candidates)
            except ValueError:
                # 跨盘：退而取第一个来源的目录（仍受 _sandbox_path 的 commonpath 二次校验约束）
                args.allow_root = candidates[0]
        else:
            args.allow_root = os.path.realpath(".")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
