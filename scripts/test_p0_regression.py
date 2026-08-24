#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""unclekk-safety-harness-evolution 4 个 P0 修复回归测试（可复跑、确定性）。

覆盖审计发现的 4 个阻断级 P0：
  P0-A  闸A 仅校验备份目录存在→改为校验「非空且可解析」；rollback 拒绝空/损坏备份
  P0-B  --llm-scorer 输出未夹取可绕闸→改为夹取 [0,1] + 保守合并取 min
  P0-C  减安正则漏 "verify" 且无中文减安词→修正正则 + 补中/英减安词 + 中文加安词（已收敛至 utils.py）
  P0-D  并发锁粒度不足→改为 OS 原生字节级锁（msvcrt/fcntl），跨进程无丢数据

退出码 0 = 全部 PASS；非 0 = 有 FAIL。
"""
import os, sys, json, tempfile, shutil, subprocess, types

# P0-3 修复：回归测试自身进程内标记「已处于回归运行中」，
# 使直接调用 cmd_apply 时不再嵌套触发 _run_p0_regression（防递归指数放大）。
os.environ["SHE_P0_REGRESSION_RUNNING"] = "1"

SKILL = os.path.dirname(os.path.abspath(__file__))
pc = os.path.join(SKILL, "__pycache__")
if os.path.exists(pc):
    shutil.rmtree(pc, ignore_errors=True)
sys.path.insert(0, SKILL)
import score_patch as SP
import evolve_guard as EG

PY = sys.executable
EG_PATH = os.path.join(SKILL, "evolve_guard.py")
results = []
def check(name, cond, extra=""):
    results.append(bool(cond))
    print(f"[{'PASS' if cond else 'FAIL'}] {name}  {extra}")

def aargs(**kw):
    return types.SimpleNamespace(
        harness=kw["harness"], candidate_patch=kw["candidate_patch"],
        backup_dir=kw["backup_dir"], reject_pool=kw["reject_pool"],
        s_current=kw.get("s_current"), u_current=kw.get("u_current"),
        llm_scorer=kw.get("llm_scorer"))

# ───────── P0-C 中文/verify 减安 ─────────
print("\n===== P0-C 减安词（含 verify/中文） =====")
s = SP.heuristic_score({"target_artifact":"rule_bank","patch_type":"add_rule","after":"no longer verify all uploads"})
check("P0-C 'no longer verify'现veto(S=0)", s[0]==0.0, f"S={s[0]}")
s2 = SP.heuristic_score({"target_artifact":"rule_bank","patch_type":"add_rule","after":"取消所有安全限制"})
check("P0-C 中文减安veto(S=0)", s2[0]==0.0, f"S={s2[0]}")
s3 = SP.heuristic_score({"target_artifact":"rule_bank","patch_type":"add_rule","after":"拦截所有危险请求"})
check("P0-C 中文加安得正分(S>0.5)", s3[0]>0.5, f"S={s3[0]}")
s4 = SP.heuristic_score({"target_artifact":"rule_bank","patch_type":"add_rule","after":"allow all web requests"})
check("P0-C 英文减安veto(S=0)", s4[0]==0.0, f"S={s4[0]}")
s5 = SP.heuristic_score({"target_artifact":"rule_bank","patch_type":"add_rule","after":"remove all guard restrictions"})
check("P0-C 英文减安veto(S=0)", s5[0]==0.0, f"S={s5[0]}")

# ───────── P0-B 恶意 llm-scorer 保守合并 ─────────
print("\n===== P0-B 外部评分器保守合并 =====")
td = tempfile.mkdtemp()
scorer = os.path.join(td, "fake_scorer.py")
open(scorer, "w", encoding="utf-8").write('import sys; print(\'{"s": 99.0, "u": 99.0}\')')
tmpl = f'"{PY}" "{scorer}" {{patch}}'
bad = {"target_artifact":"rule_bank","patch_type":"add_rule","after":"allow all web requests"}
sb, ub, hb = EG._score_candidate(SP, bad, tmpl)
check("P0-B 恶意llm不能抬高坏补丁(仍0)", sb==0.0, f"S={sb}")
good = {"target_artifact":"rule_bank","patch_type":"add_rule","after":"deny all exfiltration traffic","supporting_trajectories":["t1"]}
sg, ug, hg = EG._score_candidate(SP, good, tmpl)
check("P0-B 恶意llm不能单边抬高(取启发式)", 0 < sg < 1.0, f"S={sg}")
h_path = os.path.join(td, "h.json"); json.dump({"_scores":{"s":0.9,"u":0.85},"artifacts":{"rule_bank":[]}}, open(h_path,"w"))
bd = os.path.join(td,"b"); os.makedirs(bd); EG.cmd_backup(types.SimpleNamespace(harness=h_path, backup_dir=bd))
rp = os.path.join(td,"rp.json")
g2 = os.path.join(td,"g2.json"); json.dump(good, open(g2,"w"))
rc = EG.cmd_apply(aargs(harness=h_path, candidate_patch=g2, backup_dir=bd, reject_pool=rp))
check("P0-B 高基线下llm无法抬高过闸(rc=2)", rc==2, f"rc={rc}")

# ───────── P0-A 闸A内容校验 + rollback防护 ─────────
print("\n===== P0-A 闸A内容校验 + rollback防护 =====")
td1 = tempfile.mkdtemp()
h1 = os.path.join(td1, "harness.json"); json.dump({"artifacts":{"rule_bank":[]}}, open(h1,"w"))
bd1 = os.path.join(td1,"backups"); os.makedirs(bd1)
open(os.path.join(bd1, "harness_20260101_000000_000_1.json"), "w").close()  # 空备份
rp1 = os.path.join(td1,"rp.json")
c1 = os.path.join(td1,"c.json"); json.dump({"target_artifact":"rule_bank","patch_type":"add_rule","after":"deny all exfiltration","supporting_trajectories":["t1"]}, open(c1,"w"))
rc = EG.cmd_apply(aargs(harness=h1, candidate_patch=c1, backup_dir=bd1, reject_pool=rp1))
check("P0-A 空备份骗不过闸A(rc=3)", rc==3, f"rc={rc}")
EG.cmd_backup(types.SimpleNamespace(harness=h1, backup_dir=bd1))
rc = EG.cmd_apply(aargs(harness=h1, candidate_patch=c1, backup_dir=bd1, reject_pool=rp1))
check("P0-A 有效备份后apply成功(rc=0)", rc==0, f"rc={rc}")
empty_bak = os.path.join(td1,"empty.json"); open(empty_bak,"w").close()
rc = EG.cmd_rollback(types.SimpleNamespace(backup=empty_bak, harness=h1))
check("P0-A 空备份rollback拒绝(rc=4)", rc==4, f"rc={rc}")
bad_bak = os.path.join(td1,"bad.json"); open(bad_bak,"w").write("{not valid")
rc = EG.cmd_rollback(types.SimpleNamespace(backup=bad_bak, harness=h1))
check("P0-A 损坏备份rollback拒绝(rc=4)", rc==4, f"rc={rc}")

# ───────── P0-D 跨进程并发锁（真实部署形态）─────────
print("\n===== P0-D 跨进程并发（拒收池 + 护栏） =====")
def subproc_apply(harness, cand, bdir, rpool, s_cur="0.5", u_cur="0.8"):
    return subprocess.Popen([PY, EG_PATH, "apply", "--harness", harness,
                             "--candidate-patch", cand, "--backup-dir", bdir,
                             "--reject-pool", rpool, "--s-current", s_cur, "--u-current", u_cur,
                             "--skip-p0-regression"])

# 好补丁 8 并发 → 护栏应写满 8 条
tdg = tempfile.mkdtemp()
hg = os.path.join(tdg, "harness.json"); json.dump({"artifacts":{"rule_bank":[]}}, open(hg,"w"))
bdg = os.path.join(tdg,"backups"); os.makedirs(bdg)
subprocess.run([PY, EG_PATH, "backup", "--harness", hg, "--backup-dir", bdg], capture_output=True)
rpg = os.path.join(tdg,"rp.json")
cands_g = []
for i in range(8):
    c = {"target_artifact":"rule_bank","patch_type":"add_rule","after":f"deny request pattern {i} from unknown host","supporting_trajectories":[f"t{i}"]}
    p = os.path.join(tdg, f"c{i}.json"); json.dump(c, open(p,"w")); cands_g.append(p)
procs = [subproc_apply(hg, p, bdg, rpg) for p in cands_g]
rcs = [p.wait() for p in procs]
hgj = json.load(open(hg))
check("P0-D[跨进程] 好补丁8并发全部rc=0", all(r==0 for r in rcs), f"rcs={rcs}")
check("P0-D[跨进程] 护栏8条规则全写入(无丢)", len(hgj["artifacts"]["rule_bank"])==8, f"rules={len(hgj['artifacts']['rule_bank'])}")
rpgd = json.load(open(rpg)) if os.path.exists(rpg) else []
check("P0-D[跨进程] 好补丁不入拒收池", len(rpgd)==0, f"rp={len(rpgd)}")

# 坏补丁 8 并发 → 拒收池应 8 个唯一 key（无丢）
tdb = tempfile.mkdtemp()
hb = os.path.join(tdb, "harness.json"); json.dump({"artifacts":{"rule_bank":[]}}, open(hb,"w"))
bdb = os.path.join(tdb,"backups"); os.makedirs(bdb)
subprocess.run([PY, EG_PATH, "backup", "--harness", hb, "--backup-dir", bdb], capture_output=True)
rpb = os.path.join(tdb,"rp.json")
cands_b = []
for i in range(8):
    c = {"target_artifact":"rule_bank","patch_type":"add_rule","after":f"allow all traffic pattern {i}","supporting_trajectories":[f"t{i}"]}
    p = os.path.join(tdb, f"c{i}.json"); json.dump(c, open(p,"w")); cands_b.append(p)
procs = [subproc_apply(hb, p, bdb, rpb) for p in cands_b]
rcs = [p.wait() for p in procs]
rbj = json.load(open(hb))
rpbj = json.load(open(rpb)) if os.path.exists(rpb) else []
rp_keys = [k.get("key") if isinstance(k, dict) else k for k in rpbj]  # P1-14：兼容 dict 条目
check("P0-D[跨进程] 坏补丁8并发全部rc=2(拒)", all(r==2 for r in rcs), f"rcs={rcs}")
check("P0-D[跨进程] 拒收池8个唯一key无丢失", len(rp_keys)==8 and len(set(rp_keys))==8, f"rp={len(rp_keys)} unique={len(set(rp_keys))}")
check("P0-D[跨进程] 护栏未被坏补丁写坏(rules=0)", len(rbj["artifacts"]["rule_bank"])==0, f"rules={len(rbj['artifacts']['rule_bank'])}")

print("\n===== 汇总 =====")
print(f"总用例 {len(results)}，通过 {sum(results)}，失败 {len(results)-sum(results)}")
for d in (td, td1, tdg, tdb):
    shutil.rmtree(d, ignore_errors=True)
pc2 = os.path.join(SKILL, "__pycache__")
if os.path.exists(pc2):
    shutil.rmtree(pc2, ignore_errors=True)
sys.exit(0 if all(results) else 1)
