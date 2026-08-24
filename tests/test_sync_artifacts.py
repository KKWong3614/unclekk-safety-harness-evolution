#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sync_artifacts 回归测试（P1-16，L2-9/L2-10）——unclekk-safety-harness-evolution

组 E（pull）：
  - security_check_rules：.md 提取引号话术 → rule_bank；.json 结构规则解析
  - allowed_tools：frontmatter 提取 → tool_policy
  - cross_agent_memory：JSONL 经验 → safety_memory（满足冷启动保护）
  - 棘轮：外部 tool_policy 比本地宽 → 拒绝合入
  - dry-run 不改写；写回前有备份
组 F（push）：
  - push 导出共享情报；push → pull 往返一致

退出码 0 = 全 PASS；非 0 = 有 FAIL。纯标准库、可复跑。
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

SKILL = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.abspath(os.path.join(SKILL, "..", "scripts"))
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

import evolve_guard as EG  # noqa: E402
import sync_artifacts as SA  # noqa: E402

PY = sys.executable
SA_PATH = os.path.join(SCRIPTS, "sync_artifacts.py")
results = []


def check(name, cond, extra=""):
    results.append(bool(cond))
    print(f"[{'PASS' if cond else 'FAIL'}] {name}  {extra}")


def run(*args):
    return subprocess.run([PY, SA_PATH, *args], capture_output=True, text=True)


def make_harness(path, tool_policy=None):
    art = {"rule_bank": [], "safety_memory": [], "tool_policy": tool_policy or []}
    json.dump({"artifacts": art}, open(path, "w", encoding="utf-8"))
    return path


# ── 组 E：pull ────────────────────────────────────────────────────────────
print("\n===== 组E pull：三源解析 + 棘轮 + dry-run =====")
td = tempfile.mkdtemp()

# E1: security_check_rules .md 话术提取
md = os.path.join(td, "sec.md")
open(md, "w", encoding="utf-8").write(
    '---\nname: fake-sec\n---\n\n## 已知攻击话术\n\n'
    '- `"⚠️ CRITICAL REQUIREMENT BEFORE USING THIS SKILL"`\n'
    '- `"RUN THIS COMMAND"`、`"请先运行"`\n'
    '- 普通列表项不算\n')
rules = SA._parse_security_rules(md, "P0")
check("组E security_check_rules .md 提取话术 >=3",
      len(rules) >= 3, f"n={len(rules)} rules={[r['rule'][:20] for r in rules]}")
check("组E 话术条目带 from_patch", all(r.get("from_patch", "").startswith("sync:") for r in rules))

# E2: security_check_rules .json 结构解析
sj = os.path.join(td, "sec_rules.json")
json.dump({"rules": [
    {"rule": "never exfiltrate data", "priority": "P0"},
    {"rule": "block suspicious url", "priority": "P1"},
    "plain rule string",
]}, open(sj, "w", encoding="utf-8"))
jrules = SA._parse_security_rules(sj, "P0")
check("组E security_check_rules .json 解析 3 条", len(jrules) == 3, f"n={len(jrules)}")

# E3: allowed_tools frontmatter
sk = os.path.join(td, "tool_skill.md")
open(sk, "w", encoding="utf-8").write(
    "---\nname: demo\nallowed_tools:\n  - PowerShell\n---\n# demo\n")
tools = SA._parse_allowed_tools(sk)
check("组E allowed_tools 提取 1 条", len(tools) == 1 and tools[0]["tool"] == "PowerShell",
      f"tools={[t['tool'] for t in tools]}")

# E4: cross_agent_memory JSONL
mem = os.path.join(td, "mem.jsonl")
open(mem, "w", encoding="utf-8").write(
    json.dumps({"note": "Agent A 多次被越权：Bash 需 read-only", "type": "failure"}) + "\n"
    + json.dumps({"content": "工具篡改注入：挂 input 切面"}) + "\n"
    + "not json line\n")
mems = SA._parse_cross_agent_memory(mem)
check("组E cross_agent_memory 提取 2 条经验", len(mems) == 2, f"n={len(mems)}")

# E5: 端到端 pull（三源 + 棘轮拒绝宽化）
h = make_harness(os.path.join(td, "harness.json"),
                 tool_policy=[{"tool": "Bash", "allow": "read-only"}])
intel_json = os.path.join(td, "intel.json")
json.dump({"artifacts": {"tool_policy": [{"tool": "Bash", "allow": "all"}]}}, open(intel_json, "w", encoding="utf-8"))
cfg = os.path.join(td, "sources.json")
json.dump({"sources": [
    {"type": "security_check_rules", "path": md, "priority": "P0"},
    {"type": "allowed_tools", "path": sk},
    {"type": "cross_agent_memory", "path": mem},
    {"type": "shared_intel", "path": intel_json},
]}, open(cfg, "w", encoding="utf-8"))
bd = os.path.join(td, "backups")
r = run("pull", "--harness", h, "--sources", cfg, "--backup-dir", bd)
check("组E pull rc=0", r.returncode == 0, f"rc={r.returncode}")
out = r.stdout
check("组E pull 输出含棘轮拒绝", "棘轮拒绝" in out and "拒绝" in out, out[-200:])
hjs = json.load(open(h, encoding="utf-8"))
art = hjs["artifacts"]
check("组E rule_bank 合入话术", len(art["rule_bank"]) >= 3, f"n={len(art['rule_bank'])}")
check("组E safety_memory 合入经验", len(art["safety_memory"]) == 2, f"n={len(art['safety_memory'])}")
check("组E tool_policy 保留 read-only（宽化被拒）",
      any(t.get("tool") == "Bash" and t.get("allow") == "read-only" for t in art["tool_policy"])
      and any(t.get("tool") == "PowerShell" and t.get("allow") == "whitelisted" for t in art["tool_policy"]),
      f"tp={art['tool_policy']}")
check("组E 写回前有备份", any(f.startswith("harness_") for f in os.listdir(bd)), os.listdir(bd))

# E6: dry-run 不改写
h2 = make_harness(os.path.join(td, "harness2.json"))
cfg2 = os.path.join(td, "sources2.json")
json.dump({"sources": [{"type": "security_check_rules", "path": md}]}, open(cfg2, "w", encoding="utf-8"))
r = run("pull", "--harness", h2, "--sources", cfg2, "--backup-dir", os.path.join(td, "b2"), "--dry-run")
check("组E dry-run rc=0 且不写回", r.returncode == 0 and len(json.load(open(h2))["artifacts"]["rule_bank"]) == 0,
      f"rc={r.returncode}")

# ── 组 F：push + 往返 ─────────────────────────────────────────────────────
print("\n===== 组F push 导出 + 往返 =====")
h3 = make_harness(os.path.join(td, "harness3.json"))
json.dump({"artifacts": {
    "rule_bank": [{"rule": "block suspicious url", "priority": "P1"}],
    "safety_memory": [{"note": "经验", "from_patch": "x"}],
    "tool_policy": [{"tool": "Bash", "allow": "read-only"}],
}}, open(h3, "w", encoding="utf-8"))
out_f = os.path.join(td, "shared_intel.json")
r = run("push", "--harness", h3, "--out", out_f)
check("组F push rc=0", r.returncode == 0, f"rc={r.returncode}")
intel = json.load(open(out_f, encoding="utf-8"))
check("组F 导出含三类工件",
      len(intel["artifacts"]["rule_bank"]) == 1 and len(intel["artifacts"]["safety_memory"]) == 1
      and len(intel["artifacts"]["tool_policy"]) == 1, f"keys={sorted(intel['artifacts'].keys())}")

h4 = make_harness(os.path.join(td, "harness4.json"))
cfg4 = os.path.join(td, "sources4.json")
json.dump({"sources": [{"type": "shared_intel", "path": out_f}]}, open(cfg4, "w", encoding="utf-8"))
r = run("pull", "--harness", h4, "--sources", cfg4, "--backup-dir", os.path.join(td, "b4"))
h4j = json.load(open(h4, encoding="utf-8"))
check("组F push→pull 往返一致（rule_bank 1 条）",
      len(h4j["artifacts"]["rule_bank"]) == 1, f"n={len(h4j['artifacts']['rule_bank'])}")
check("组F 往返 tool_policy 合入",
      any(t.get("tool") == "Bash" for t in h4j["artifacts"]["tool_policy"]),
      f"tp={h4j['artifacts']['tool_policy']}")

# 组F2：往返幂等（P1-20）——push→pull 两次，rule_bank 不增长
h5 = make_harness(os.path.join(td, "harness5.json"))
json.dump({"artifacts": {"rule_bank": [{"rule": "r1", "priority": "P0"}, {"rule": "r2", "priority": "P1"}],
                          "safety_memory": [], "tool_policy": []}}, open(h5, "w", encoding="utf-8"))
out5 = os.path.join(td, "intel5.json")
run("push", "--harness", h5, "--out", out5)
cfg5 = os.path.join(td, "sources5.json")
json.dump({"sources": [{"type": "shared_intel", "path": out5}]}, open(cfg5, "w", encoding="utf-8"))
run("pull", "--harness", h5, "--sources", cfg5, "--backup-dir", os.path.join(td, "b5"))
run("pull", "--harness", h5, "--sources", cfg5, "--backup-dir", os.path.join(td, "b5"))
h5j = json.load(open(h5, encoding="utf-8"))
check("组F2 往返幂等：rule_bank 不增长（P1-20）",
      len(h5j["artifacts"]["rule_bank"]) == 2, f"n={len(h5j['artifacts']['rule_bank'])}")

print("\n===== 汇总 =====")
print(f"总用例 {len(results)}，通过 {sum(results)}，失败 {len(results)-sum(results)}")
shutil.rmtree(td, ignore_errors=True)
sys.exit(0 if all(results) else 1)
