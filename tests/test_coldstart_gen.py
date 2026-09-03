#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_coldstart_gen.py —— gen_coldstart_samples 确定性自检（纯标准库，无需 pytest）

运行：python tests/test_coldstart_gen.py
断言全绿即通过；任何失败抛 AssertionError 使进程非零退出。
"""
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(SKILL, "scripts"))

import gen_coldstart_samples as G  # noqa: E402


def _load(name):
    with open(os.path.join(SKILL, "tests", name), "r", encoding="utf-8") as f:
        return json.load(f)


def run():
    bench = _load("attack_bench.json")
    benign = _load("benign_bench.json")
    traj, cand, bp, summ = G.generate(bench, benign)

    # 1) 数量自洽
    assert len(cand) == summ["attack_samples"], "候选数应等于对抗样本数"
    assert len(traj) == summ["attack_samples"], "轨迹数应等于对抗样本数"
    assert len(bp) == summ["benign_samples"], "良性提示数应等于良性样本数"

    # 2) 候选结构合法（含受控枚举 diagnosis）
    arts = ("system_prompt", "rule_bank", "safety_memory", "tool_policy")
    for c in cand:
        assert c["target_artifact"] in arts, f"非法 target_artifact: {c['target_artifact']}"
        d = c["diagnosis"]
        assert d["zi"]["attack_surface"] in arts
        assert d["routing"]["artifact"] in arts
        assert d["routing"]["confidence"] in ("high", "medium", "low")
        assert d["routing"]["reason"]

    # 3) honeytoken 样本 → tool_policy 收紧候选（含 deny）
    ht = [c for c in cand if c.get("source_sample", "").lower().startswith("honeytoken")
          or "honeytoken" in (c.get("diagnosis", {}).get("zi", {}).get("attack_surface", ""))]
    # 注意：attack_bench 的 honeytoken 样本 id 形如 honeytoken-*；至少应存在且映射为 tool_policy
    ht_ids = [c for c in cand if str(c.get("source_sample", "")).lower().startswith("honey")]
    for c in ht_ids:
        assert c["target_artifact"] == "tool_policy", "honeytoken 样本应映射为 tool_policy"
        after = json.loads(c["after"]) if c["after"].strip().startswith("{") else {}
        assert after.get("deny"), "honeytoken 候选应包含 deny"

    # 4) 良性样本保留 payload 文本
    for b in bp:
        assert b["text"], "良性提示文本不应为空"

    # 5) 写盘 + 回读一致性
    with tempfile.TemporaryDirectory() as td:
        G.write_outputs(td, traj, cand, bp, summ)
        tl = sum(1 for _ in open(os.path.join(td, "attack_trajectories.jsonl"), encoding="utf-8"))
        cl = sum(1 for _ in open(os.path.join(td, "attack_candidates.jsonl"), encoding="utf-8"))
        bl = sum(1 for _ in open(os.path.join(td, "benign_prompts.jsonl"), encoding="utf-8"))
        assert tl == len(traj) and cl == len(cand) and bl == len(bp), "写盘行数应与内存一致"

    print(f"[coldstart] PASS: attack={summ['attack_samples']} benign={summ['benign_samples']} "
          f"candidates={summ['candidates']} honeytoken_mapped={len(ht_ids)}")
    return True


if __name__ == "__main__":
    run()
    print("ALL GOOD")
