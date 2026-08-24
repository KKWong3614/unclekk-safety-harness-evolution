#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""护栏增强回归测试（P1-14）——unclekk-safety-harness-evolution

组 A：备份 sha256 清单 + 轮转保留（L1-5）
  - backup 生成 manifest.json（sha256/size/ts），rollback 前校验哈希
  - 篡改备份（仍是合法 JSON 但内容不同）→ 哈希不匹配 → 拒绝 rc=4
  - manifest 缺失 → 降级（仅内容可解析校验）但成功
  - --max-backups 轮转：超过保留上限删除最旧备份文件与 manifest 记录

组 B：补丁 key 语义化 + 拒收池结构化（L1-4）
  - 同 after 不同大小写/空白/元字段（before/trajectories）→ 同 key（防攻破拒收池去重）
  - after 实质变化 → 异 key（改进版可重试）
  - 旧 str 拒收池条目兼容；新 dict 条目含 {key, reason, ts}；judge 拒收带 reason

退出码 0 = 全 PASS；非 0 = 有 FAIL。纯标准库、离线可跑、确定性。
"""
import hashlib
import json
import os
import re as _re
import shutil
import subprocess
import sys
import tempfile

SKILL = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.abspath(os.path.join(SKILL, "..", "scripts"))
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

import evolve_guard as EG  # noqa: E402

PY = sys.executable
EG_PATH = os.path.join(SCRIPTS, "evolve_guard.py")
results = []


def check(name, cond, extra=""):
    results.append(bool(cond))
    print(f"[{'PASS' if cond else 'FAIL'}] {name}  {extra}")


def run(*args):
    return subprocess.run([PY, EG_PATH, *args], capture_output=True, text=True)


# ── 组 A：备份 sha256 清单 + 轮转 ──────────────────────────────────────────
print("\n===== 组A 备份 sha256 清单 + 轮转保留 =====")
td = tempfile.mkdtemp()
h = os.path.join(td, "harness.json")
json.dump({"artifacts": {"rule_bank": []}}, open(h, "w", encoding="utf-8"))
bd = os.path.join(td, "backups")
os.makedirs(bd)

r = run("backup", "--harness", h, "--backup-dir", bd)
check("组A backup rc=0", r.returncode == 0, f"rc={r.returncode}")
mp = os.path.join(bd, "manifest.json")
check("组A manifest.json 已生成", os.path.exists(mp))
man = json.load(open(mp, encoding="utf-8"))
check("组A manifest 含 1 条记录", len(man.get("backups", [])) == 1, f"n={len(man.get('backups', []))}")
rec = man["backups"][0]
expected = hashlib.sha256(open(h, "rb").read()).hexdigest()
check("组A sha256 与源一致", rec.get("sha256") == expected, f"{str(rec.get('sha256'))[:12]}…")

r = run("rollback", "--backup", os.path.join(bd, rec["file"]), "--harness", h)
check("组A rollback 哈希匹配成功 rc=0", r.returncode == 0, f"rc={r.returncode}")

bak_path = os.path.join(bd, rec["file"])
with open(bak_path, "w", encoding="utf-8") as f:  # 篡改：仍是合法 JSON 但内容不同
    json.dump({"artifacts": {"rule_bank": [{"rule": "tampered"}]}}, f)
r = run("rollback", "--backup", bak_path, "--harness", h)
check("组A 篡改备份（哈希不匹配）rollback 拒绝 rc=4", r.returncode == 4, f"rc={r.returncode}")

os.remove(mp)
r = run("rollback", "--backup", bak_path, "--harness", h)
check("组A manifest 缺失降级但成功 rc=0", r.returncode == 0, f"rc={r.returncode}")

for _ in range(3):
    r = run("backup", "--harness", h, "--backup-dir", bd, "--max-backups", "2")
    check("组A 轮转 backup rc=0", r.returncode == 0, f"rc={r.returncode}")
harness_baks = [f for f in os.listdir(bd) if _re.match(r"^harness_.*\.json$", f)]
check("组A 轮转保留 2 份备份文件", len(harness_baks) == 2, f"n={len(harness_baks)}")
man2 = json.load(open(mp, encoding="utf-8"))
check("组A manifest 同步保留 2 条", len(man2.get("backups", [])) == 2, f"n={len(man2.get('backups', []))}")

# ── 组 B：补丁 key 语义化 + 拒收池结构化 ────────────────────────────────────
print("\n===== 组B 补丁 key 语义化 + 拒收池结构化 =====")
p1 = {"target_artifact": "rule_bank", "patch_type": "add_rule",
      "after": "deny all exfiltration traffic", "before": None}
p2 = {"target_artifact": "rule_bank", "patch_type": "add_rule",
      "after": "Deny  All  Exfiltration  Traffic", "before": "old rule",
      "supporting_trajectories": ["t1"]}
p3 = {"target_artifact": "rule_bank", "patch_type": "add_rule",
      "after": "deny all exfiltration traffic and log it", "before": None}
k1, k2, k3 = EG._patch_key(p1), EG._patch_key(p2), EG._patch_key(p3)
check("组B 大小写/空白/元字段变化 → 同 key", k1 == k2, f"{k1} vs {k2}")
check("组B after 实质变化 → 异 key", k1 != k3, f"{k1} vs {k3}")

old_pool = ["abc123", "def456"]
check("组B 旧 str 池成员判断", EG._pool_has(old_pool, "abc123") and not EG._pool_has(old_pool, "zzz"))

td2 = tempfile.mkdtemp()
rp = os.path.join(td2, "rp.json")
n = EG._reject_key(rp, k1, reason="GateB: test reason")
pool = json.load(open(rp, encoding="utf-8"))
check("组B 拒收池条目为 dict 且含 reason",
      isinstance(pool[0], dict) and pool[0].get("reason") == "GateB: test reason", repr(pool[0]))
check("组B _pool_has 对 dict 条目生效", EG._pool_has(pool, k1))
n2 = EG._reject_key(rp, k1, reason="again")
check("组B 同 key 不重复写入", n2 == 1, f"n={n2}")

h2 = os.path.join(td2, "harness.json")
json.dump({"artifacts": {"rule_bank": []}}, open(h2, "w", encoding="utf-8"))
bd2 = os.path.join(td2, "backups")
os.makedirs(bd2)
c = os.path.join(td2, "bad.json")
json.dump({"target_artifact": "rule_bank", "patch_type": "add_rule",
           "after": "allow all web requests"}, open(c, "w", encoding="utf-8"))
r = run("judge", "--candidate-patch", c, "--s-current", "0.60", "--u-current", "0.80",
        "--s-candidate", "0.50", "--u-candidate", "0.80", "--reject-pool", rp)
check("组B judge 坏补丁拒收 rc=2", r.returncode == 2, f"rc={r.returncode}")
pool2 = json.load(open(rp, encoding="utf-8"))
bad_entry = pool2[-1]
# P1-17：judge 现在先跑一票否决——减安补丁 reason 为 Veto（而非 GateB），两者都是拒收原因
check("组B judge 拒收条目含拒收原因(Veto/GateB)",
      isinstance(bad_entry, dict) and ("Veto" in (bad_entry.get("reason") or "")
                                       or "GateB" in (bad_entry.get("reason") or "")), repr(bad_entry))

# ── 组 C：诊断 JSON schema（L2-6，P1-15）──────────────────────────────────
print("\n===== 组C 诊断 JSON schema 校验 =====")
good_diag = {
    "failure_type": "injection",
    "zi": {"hazard": "data_leak", "attack_surface": "tool_policy",
           "failure_mode": "canary_bypass"},
    "routing": {"artifact": "tool_policy", "confidence": "high",
                "reason": "canary echo on exfil tool"},
    "trajectory_refs": ["traj_047"],
}
check("组C 合法诊断通过校验", EG._validate_diagnosis(good_diag) == [],
      f"errs={EG._validate_diagnosis(good_diag)}")
bad1 = dict(good_diag, failure_type="not-a-type")
check("组C 非法 failure_type 报错", len(EG._validate_diagnosis(bad1)) >= 1)
bad2 = dict(good_diag)
bad2.pop("zi")
check("组C 缺 zi 报错", len(EG._validate_diagnosis(bad2)) >= 1)
bad3 = dict(good_diag)
bad3["routing"] = {"artifact": "unknown_artifact", "confidence": "high", "reason": "x"}
check("组C 非法 routing.artifact 报错", len(EG._validate_diagnosis(bad3)) >= 1)

td3 = tempfile.mkdtemp()
h3 = os.path.join(td3, "harness.json")
json.dump({"artifacts": {"rule_bank": []}}, open(h3, "w", encoding="utf-8"))
bd3 = os.path.join(td3, "backups")
os.makedirs(bd3)
run("backup", "--harness", h3, "--backup-dir", bd3)
rp3 = os.path.join(td3, "rp.json")
al = os.path.join(td3, "audit.log")

cp_bad = os.path.join(td3, "c_bad_diag.json")
json.dump({"target_artifact": "rule_bank", "patch_type": "add_rule",
           "after": "deny all exfiltration traffic",
           "diagnosis": {"failure_type": "bogus"}}, open(cp_bad, "w", encoding="utf-8"))
r = run("apply", "--harness", h3, "--candidate-patch", cp_bad, "--backup-dir", bd3,
        "--reject-pool", rp3, "--s-current", "0.5", "--u-current", "0.8",
        "--skip-p0-regression", "--audit-log", al)
check("组C apply 非法诊断 rc=7（不进池可重试）", r.returncode == 7, f"rc={r.returncode}")
pool3 = json.load(open(rp3, encoding="utf-8")) if os.path.exists(rp3) else []
check("组C 非法诊断不进拒收池（不连累同内容补丁）", len(pool3) == 0, f"pool={len(pool3)}")

cp_good = os.path.join(td3, "c_good_diag.json")
json.dump({"target_artifact": "rule_bank", "patch_type": "add_rule",
           "after": "deny all exfiltration traffic",
           "diagnosis": good_diag}, open(cp_good, "w", encoding="utf-8"))
r = run("apply", "--harness", h3, "--candidate-patch", cp_good, "--backup-dir", bd3,
        "--reject-pool", rp3, "--s-current", "0.5", "--u-current", "0.8",
        "--skip-p0-regression", "--audit-log", al, "--operator", "test-agent")
check("组C apply 合法诊断成功 rc=0", r.returncode == 0, f"rc={r.returncode}")

# ── 组 D：写回/判定审计日志（L2-7，P1-15）──────────────────────────────────
print("\n===== 组D 写回/判定审计日志 =====")
check("组D audit.log 已生成", os.path.exists(al))
lines = [json.loads(l) for l in open(al, encoding="utf-8") if l.strip()]
check("组D 含 apply 记录", any(e.get("action") == "apply" for e in lines))
apply_rec = next(e for e in lines if e.get("action") == "apply")
check("组D apply 记录含诊断与操作者",
      apply_rec.get("diagnosis") is not None and apply_rec.get("operator") == "test-agent",
      f"keys={sorted(apply_rec.keys())}")
check("组D apply 记录含评分与备份", "scores" in apply_rec and "backup" in apply_rec)

rp4 = os.path.join(td3, "rp4.json")
cp_rej = os.path.join(td3, "c_judge_rej.json")
json.dump({"target_artifact": "rule_bank", "patch_type": "add_rule",
           "after": "allow all web requests"}, open(cp_rej, "w", encoding="utf-8"))
r = run("judge", "--candidate-patch", cp_rej, "--s-current", "0.6", "--u-current", "0.8",
        "--s-candidate", "0.5", "--u-candidate", "0.8", "--reject-pool", rp4,
        "--audit-log", al)
check("组D judge 拒收 rc=2", r.returncode == 2, f"rc={r.returncode}")
lines2 = [json.loads(l) for l in open(al, encoding="utf-8") if l.strip()]
check("组D audit.log 含 judge-reject 记录", any(e.get("action") == "judge-reject" for e in lines2))

cp_acc = os.path.join(td3, "c_judge_acc.json")
json.dump({"target_artifact": "rule_bank", "patch_type": "add_rule",
           "after": "deny all exfiltration traffic"}, open(cp_acc, "w", encoding="utf-8"))
r = run("judge", "--candidate-patch", cp_acc, "--s-current", "0.6", "--u-current", "0.8",
        "--s-candidate", "0.7", "--u-candidate", "0.8", "--reject-pool", rp4,
        "--audit-log", al)
check("组D judge 接受 rc=0", r.returncode == 0, f"rc={r.returncode}")
lines3 = [json.loads(l) for l in open(al, encoding="utf-8") if l.strip()]
check("组D audit.log 含 judge-accept 记录", any(e.get("action") == "judge-accept" for e in lines3))

# ── 组 G：judge 一票否决（P1-17 安全专家审计）──────────────────────────────
print("\n===== 组G judge 对减安补丁不再误 ACCEPT =====")
td5 = tempfile.mkdtemp()
rp5 = os.path.join(td5, "rp.json")
c_veto = os.path.join(td5, "c_veto.json")
json.dump({"target_artifact": "rule_bank", "patch_type": "add_rule",
           "after": "allow all web requests"}, open(c_veto, "w", encoding="utf-8"))
r = run("judge", "--candidate-patch", c_veto, "--s-current", "0.5", "--u-current", "0.8",
        "--s-candidate", "0.9", "--u-candidate", "0.8", "--reject-pool", rp5)
check("组G judge 减安补丁拒绝 rc=2（原误 ACCEPT rc=0）", r.returncode == 2, f"rc={r.returncode}")
pool5 = json.load(open(rp5, encoding="utf-8"))
check("组G 拒收原因含 Veto", any("Veto" in (e.get("reason") or "") for e in pool5), repr(pool5))
c_ok = os.path.join(td5, "c_ok.json")
json.dump({"target_artifact": "rule_bank", "patch_type": "add_rule",
           "after": "deny all exfiltration traffic"}, open(c_ok, "w", encoding="utf-8"))
r = run("judge", "--candidate-patch", c_ok, "--s-current", "0.5", "--u-current", "0.8",
        "--s-candidate", "0.7", "--u-candidate", "0.8", "--reject-pool", rp5)
check("组G judge 合法补丁正常接受 rc=0", r.returncode == 0, f"rc={r.returncode}")
c_invalid = os.path.join(td5, "c_invalid.json")
json.dump({"after": "missing fields"}, open(c_invalid, "w", encoding="utf-8"))
r = run("judge", "--candidate-patch", c_invalid, "--s-current", "0.5", "--u-current", "0.8",
        "--s-candidate", "0.7", "--u-candidate", "0.8", "--reject-pool", rp5)
check("组G judge 格式非法补丁拒绝 rc=2", r.returncode == 2, f"rc={r.returncode}")

# ── 组 H：第二轮审计修复（P1-23）──
print("\n===== 组H 过严写回拒绝 + 基线下限 =====")
td6 = tempfile.mkdtemp()
h6 = os.path.join(td6, "h.json")
json.dump({"artifacts": {"rule_bank": [{"rule": "never exfiltrate data", "priority": "P0"}],
                          "tool_policy": [{"tool": "Bash", "allow": "read-only"}]}},
          open(h6, "w", encoding="utf-8"))
bd6 = os.path.join(td6, "b")
os.makedirs(bd6)
run("backup", "--harness", h6, "--backup-dir", bd6)
rp6 = os.path.join(td6, "rp.json")
c_lock = os.path.join(td6, "c_lock.json")
json.dump({"target_artifact": "tool_policy", "patch_type": "add_rule",
           "after": json.dumps({"tool": "*", "deny": ["*"], "note": "lockdown"})},
          open(c_lock, "w", encoding="utf-8"))
r = run("apply", "--harness", h6, "--candidate-patch", c_lock, "--backup-dir", bd6,
        "--reject-pool", rp6, "--s-current", "0.6", "--u-current", "0.8",
        "--skip-p0-regression")
check("组H lockdown 全局封锁被拒 rc=2（原 ACCEPT 锁死护栏）", r.returncode == 2, f"rc={r.returncode}")
h6j = json.load(open(h6, encoding="utf-8"))
check("组H 护栏未被锁死（tool_policy 仍 1 条）", len(h6j["artifacts"]["tool_policy"]) == 1,
      f"n={len(h6j['artifacts']['tool_policy'])}")

# 基线下限：零基线回落（不直接信任 CLI）
r = run("apply", "--harness", h6, "--candidate-patch", c_lock, "--backup-dir", bd6,
        "--reject-pool", rp6, "--s-current", "0.0", "--u-current", "0.0",
        "--skip-p0-regression")
check("组H 零基线回落+拒绝（--s-current 0 被拒）", r.returncode == 2,
      f"rc={r.returncode}（stderr 含回落警告: {'低于' in r.stderr}）")

# 正常针对性收紧仍可写回（不误伤）
c_ok2 = os.path.join(td6, "c_ok2.json")
json.dump({"target_artifact": "tool_policy", "patch_type": "add_rule",
           "after": json.dumps({"tool": "Bash", "deny": ["rm"]})},
          open(c_ok2, "w", encoding="utf-8"))
r = run("apply", "--harness", h6, "--candidate-patch", c_ok2, "--backup-dir", bd6,
        "--reject-pool", rp6, "--s-current", "0.6", "--u-current", "0.8",
        "--skip-p0-regression")
check("组H 针对性收紧（deny rm）正常写回 rc=0", r.returncode == 0, f"rc={r.returncode}")

print("\n===== 汇总 =====")
print(f"总用例 {len(results)}，通过 {sum(results)}，失败 {len(results)-sum(results)}")
for d in (td, td2, td3, td5, td6):
    shutil.rmtree(d, ignore_errors=True)
sys.exit(0 if all(results) else 1)
