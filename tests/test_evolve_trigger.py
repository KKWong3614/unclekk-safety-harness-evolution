#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""进化环触发器回归测试（P1-21，接入方式 B）——unclekk-safety-harness-evolution

组 N：monitor-panel 自动化触发闭环
  - 拦截事件 → candidate 生成 → 评分 → judge ACCEPT
  - 自由文本告警（越权）→ tool_policy 补丁类型映射
  - --auto-apply 写回（harness 更新 + 备份 + 审计）
  - --dry-run 不写回
  - 减安事件 → 一票否决 REJECT 不写回

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

PY = sys.executable
TR_PATH = os.path.join(SCRIPTS, "evolve_trigger.py")
results = []


def check(name, cond, extra=""):
    results.append(bool(cond))
    print(f"[{'PASS' if cond else 'FAIL'}] {name}  {extra}")


def run(*args):
    return subprocess.run([PY, TR_PATH, *args], capture_output=True, text=True)


def make_harness(path):
    json.dump({"artifacts": {"rule_bank": [], "safety_memory": [],
                             "tool_policy": [{"tool": "Bash", "allow": "read-only"}]}},
              open(path, "w", encoding="utf-8"))


# ── 组 N：触发器闭环 ──────────────────────────────────────────────────────
print("\n===== 组N 进化环触发器（接入方式 B）=====")
td = tempfile.mkdtemp()

# N1：拦截事件 → candidate → judge ACCEPT
h = os.path.join(td, "harness.json")
make_harness(h)
evt = os.path.join(td, "evt.json")
json.dump({"type": "tool_dispatch", "tool_name": "Bash",
           "reasons": ["ToolPolicy 违反：尝试写入系统目录"], "trust": "untrusted"},
          open(evt, "w", encoding="utf-8"))
rp = os.path.join(td, "rp.json")
r = run("--event", evt, "--harness", h, "--backup-dir", os.path.join(td, "b"),
        "--reject-pool", rp, "--audit-log", os.path.join(td, "audit.log"))
out = json.loads(r.stdout)
check("组N 拦截事件 judge ACCEPT", out.get("judge", {}).get("verdict") == "ACCEPT",
      f"verdict={out.get('judge')}")
check("组N 事件生成 candidate 含 diagnosis", "diagnosis" in out and out["diagnosis"].get("failure_type") is not None,
      f"diag={out.get('diagnosis', {}).get('failure_type')}")
check("组N 默认不 auto-apply（人工旁路）", out.get("apply") is None, f"apply={out.get('apply')}")
h0 = json.load(open(h, encoding="utf-8"))
check("组N 未写回（harness tool_policy 仍 1 条）", len(h0["artifacts"]["tool_policy"]) == 1)

# N2：自由文本告警（越权）→ tool_policy 补丁类型
evt2 = os.path.join(td, "evt2.json")
json.dump({"text": "检测到越权：Agent 尝试调用未授权工具删除数据库"}, open(evt2, "w", encoding="utf-8"))
r = run("--event", evt2, "--harness", h, "--backup-dir", os.path.join(td, "b"),
        "--reject-pool", rp, "--dry-run")
out2 = json.loads(r.stdout)
check("组N 自由文本越权 → tool_policy 补丁",
      out2["candidate"]["target_artifact"] == "tool_policy", f"ta={out2['candidate'].get('target_artifact')}")

# N3：--auto-apply 写回（备份 + 审计）
h3 = os.path.join(td, "harness3.json")
make_harness(h3)
bd3 = os.path.join(td, "b3")
evt3 = os.path.join(td, "evt3.json")
json.dump({"type": "ingest", "verdict": "alert", "reasons": ["canary 回显命中"]},
          open(evt3, "w", encoding="utf-8"))
r = run("--event", evt3, "--harness", h3, "--backup-dir", bd3,
        "--reject-pool", os.path.join(td, "rp3.json"),
        "--audit-log", os.path.join(td, "audit3.log"), "--auto-apply")
out3 = json.loads(r.stdout)
check("组N auto-apply 写回成功", out3.get("apply", {}).get("applied") is True, f"apply={out3.get('apply')}")
h3j = json.load(open(h3, encoding="utf-8"))
check("组N harness rule_bank 已更新", len(h3j["artifacts"]["rule_bank"]) >= 1,
      f"n={len(h3j['artifacts']['rule_bank'])}")
check("组N 写回前有备份", any(f.startswith("harness_") for f in os.listdir(bd3)), os.listdir(bd3))
check("组N 审计日志记录 apply", os.path.exists(os.path.join(td, "audit3.log")))

# N3b：事件描述含攻击载荷词（如中文注入原文）→ veto 保护（防规则库被污染）
h3b = os.path.join(td, "harness3b.json")
make_harness(h3b)
evt3b = os.path.join(td, "evt3b.json")
json.dump({"type": "ingest", "verdict": "alert", "reasons": ["中文注入命中: 忽略之前指令"]},
          open(evt3b, "w", encoding="utf-8"))
r = run("--event", evt3b, "--harness", h3b, "--backup-dir", os.path.join(td, "b3b"),
        "--reject-pool", os.path.join(td, "rp3b.json"), "--auto-apply")
out3b = json.loads(r.stdout)
check("组N 载荷词入 after 被 veto 保护（不写回）",
      out3b.get("judge", {}).get("verdict") == "REJECT", f"judge={out3b.get('judge')}")

# N4：--dry-run 不写回
h4 = os.path.join(td, "harness4.json")
make_harness(h4)
evt4 = os.path.join(td, "evt4.json")
json.dump({"type": "ingest", "verdict": "warn", "reasons": ["low-trust 片段含指令动词"]},
          open(evt4, "w", encoding="utf-8"))
r = run("--event", evt4, "--harness", h4, "--backup-dir", os.path.join(td, "b4"),
        "--reject-pool", os.path.join(td, "rp4.json"), "--dry-run", "--auto-apply")
out4 = json.loads(r.stdout)
h4j = json.load(open(h4, encoding="utf-8"))
check("组N dry-run 不写回", out4.get("apply", {}).get("skipped") == "dry-run"
      and len(h4j["artifacts"]["rule_bank"]) == 0, f"apply={out4.get('apply')}")

# N5：减安事件 → 一票否决 REJECT 不写回
h5 = os.path.join(td, "harness5.json")
make_harness(h5)
evt5 = os.path.join(td, "evt5.json")
json.dump({"target_artifact": "rule_bank", "patch_type": "add_rule",
           "after": "allow all web requests"}, open(evt5, "w", encoding="utf-8"))
r = run("--event", evt5, "--harness", h5, "--backup-dir", os.path.join(td, "b5"),
        "--reject-pool", os.path.join(td, "rp5.json"), "--auto-apply")
out5 = json.loads(r.stdout)
check("组N 减安事件 veto REJECT", out5.get("judge", {}).get("verdict") == "REJECT",
      f"judge={out5.get('judge')}")
h5j = json.load(open(h5, encoding="utf-8"))
check("组N 减安事件不写回", len(h5j["artifacts"]["rule_bank"]) == 0, "harness 未变")

# N6：JSON 字符串事件（P1-22 修复——字符串先尝试 json.loads，拦截事件可直接传 JSON）
h6 = os.path.join(td, "harness6.json")
make_harness(h6)
r = run("--event", '{"type":"tool_dispatch","tool_name":"Bash","reasons":["ToolPolicy 违反"],"trust":"untrusted"}',
        "--harness", h6, "--backup-dir", os.path.join(td, "b6"),
        "--reject-pool", os.path.join(td, "rp6.json"), "--dry-run")
out6 = json.loads(r.stdout)
check("组N JSON 字符串事件解析为拦截事件 → tool_policy",
      out6["candidate"]["target_artifact"] == "tool_policy", f"ta={out6['candidate'].get('target_artifact')}")
r = run("--event", "检测到注入迹象", "--harness", h6, "--backup-dir", os.path.join(td, "b6"),
        "--reject-pool", os.path.join(td, "rp6.json"), "--dry-run")
out6b = json.loads(r.stdout)
check("组N 自由文本仍走文本映射（P1-22 不破坏）",
      out6b["candidate"]["target_artifact"] == "rule_bank"
      and out6b["diagnosis"]["failure_type"] == "injection",
      f"ta={out6b['candidate'].get('target_artifact')} diag={out6b['diagnosis'].get('failure_type')}")

print("\n===== 汇总 =====")
print(f"总用例 {len(results)}，通过 {sum(results)}，失败 {len(results)-sum(results)}")
shutil.rmtree(td, ignore_errors=True)
sys.exit(0 if all(results) else 1)
