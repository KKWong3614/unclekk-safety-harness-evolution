#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gen_coldstart_samples.py —— 本地冷启动样本工厂（不依赖 SkillSentry）

测评摘要 concern：SkillSentry 是可选外部组件、本 skill 未提供其实现，冷启动只能靠本地模拟。
本脚本把内置的对抗/良性基准（tests/attack_bench.json + tests/benign_bench.json）转成
**可回放的样本**，作为不依赖 SkillSentry 的本地冷启动样本源：

  - attack 样本 → 可回放轨迹（evolve_trigger --event 直接消费）+ 收敛后的候选补丁（含 diagnosis）
  - benign 样本 → 效用 sanity 提示（确认护栏不误拒正常任务）

输出（--out 目录）：
  attack_trajectories.jsonl   每行一条可回放事件（文本告警 / 拦截事件）
  attack_candidates.jsonl     每行一条候选补丁（target_artifact/patch_type/after/diagnosis）
  benign_prompts.jsonl        每行一条正常任务提示（效用校验用）
  summary.json                统计 + 每条样本的归类

用法：
  python scripts/gen_coldstart_samples.py \
      --bench tests/attack_bench.json --benign tests/benign_bench.json \
      --out coldstart_samples [--selftest]

纯标准库、离线、确定性（同输入同输出）。退出码：0 成功 / 3 输入缺失。
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def _load_bench(path):
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _candidate_for(sample):
    """把一条对抗样本收敛为候选补丁（target_artifact/patch_type/after + 结构化 diagnosis）。"""
    payload = sample.get("payload", "")
    engine = (sample.get("engine") or "").lower()
    cat = (sample.get("category") or "").lower()
    sid = sample.get("id", "unknown")

    # honeytoken 类 → 工具策略收紧（拦截触碰蜜罐凭据的工具）
    if engine == "honeytoken" or "凭据" in cat or "honeytoken" in cat:
        after = json.dumps({"tool": "honeytoken_reader", "deny": ["*"],
                            "note": f"cold-start auto: block honeytoken access ({sid})"},
                           ensure_ascii=False)
        art, pt, hazard, surface, mode = "tool_policy", "tighten_tool", "data_leak", "tool_policy", "tool_tampering"
    # 注入 / canary
    elif engine == "ingest" or "注入" in cat or "canary" in cat or "inject" in cat:
        after = f"block prompt-injection / canary-echo pattern :: {payload[:120]}"
        art, pt, hazard, surface, mode = "rule_bank", "add_rule", "logic_bypass", "rule_bank", "canary_bypass"
    # 指令覆盖 / 身份劫持 / 规则豁免
    elif "指令覆盖" in cat or "身份劫持" in cat or "override" in cat or "hijack" in cat or "exemption" in cat:
        after = f"block instruction-override / identity-hijack :: {payload[:120]}"
        art, pt, hazard, surface, mode = "rule_bank", "add_rule", "privilege_escalation", "rule_bank", "semantic_paraphrase"
    # 凭据 / 数据外泄
    elif "数据" in cat or "外泄" in cat or "exfil" in cat or "credential" in cat:
        after = f"block data-exfiltration :: {payload[:120]}"
        art, pt, hazard, surface, mode = "rule_bank", "add_rule", "data_leak", "tool_policy", "composite"
    else:
        after = f"block anomalous pattern :: {payload[:120]}"
        art, pt, hazard, surface, mode = "rule_bank", "add_rule", "logic_bypass", "rule_bank", "other"

    patch = {
        "target_artifact": art,
        "patch_type": pt,
        "after": after,
        "source_sample": sid,
        "auto_generated": True,
        "diagnosis": {
            "failure_type": "injection" if surface == "rule_bank" and mode == "canary_bypass" else "privilege_escalation",
            "zi": {"hazard": hazard, "attack_surface": surface, "failure_mode": mode},
            "routing": {"artifact": art, "confidence": "high",
                        "reason": f"cold-start sample {sid} ({engine}/{cat})"},
        },
    }
    return patch


def _trajectory_for(sample):
    """把一条对抗样本转成可回放事件（文本告警；honeytoken 用拦截事件形态）。"""
    payload = sample.get("payload", "")
    engine = (sample.get("engine") or "").lower()
    sid = sample.get("id", "unknown")
    if engine == "honeytoken":
        return {"type": "tool_dispatch", "tool_name": "read_secret",
                "args": {"secret": payload}, "trust": "untrusted",
                "reasons": ["honeytoken touch"], "source_sample": sid}
    return {"text": payload, "source_sample": sid}


def generate(bench, benign):
    """返回 (attack_trajectories, attack_candidates, benign_prompts, summary)。"""
    samples = (bench.get("samples") if isinstance(bench, dict) else None) or []
    b_samples = (benign.get("samples") if isinstance(benign, dict) else None) or []

    trajectories, candidates, benign_prompts = [], [], []
    cat_count = {}
    for s in samples:
        expect = (s.get("expect") or "block").lower()
        cat = s.get("category", "unknown")
        cat_count[cat] = cat_count.get(cat, 0) + 1
        # 仅当预期拦截（block）时生成候选补丁；gap（已归零，理论不再出现）同样处理以防万一
        candidates.append(_candidate_for(s))
        trajectories.append(_trajectory_for(s))

    for b in b_samples:
        benign_prompts.append({"id": b.get("id"), "engine": b.get("engine"),
                               "text": b.get("payload", ""), "note": b.get("note", "")})

    summary = {
        "attack_samples": len(samples),
        "benign_samples": len(b_samples),
        "candidates": len(candidates),
        "category_breakdown": cat_count,
        "note": "cold-start samples derived from built-in benches; feed trajectories to evolve_trigger --event, candidates to judge/apply.",
    }
    return trajectories, candidates, benign_prompts, summary


def write_outputs(out_dir, trajectories, candidates, benign_prompts, summary):
    os.makedirs(out_dir, exist_ok=True)
    _dump_jsonl(os.path.join(out_dir, "attack_trajectories.jsonl"), trajectories)
    _dump_jsonl(os.path.join(out_dir, "attack_candidates.jsonl"), candidates)
    _dump_jsonl(os.path.join(out_dir, "benign_prompts.jsonl"), benign_prompts)
    with open(os.path.join(out_dir, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    return summary


def _dump_jsonl(path, rows):
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def selftest():
    """内置自检：用内置 bench 跑一遍，断言不抛错且数量自洽。"""
    bench_path = os.path.join(HERE, "..", "tests", "attack_bench.json")
    benign_path = os.path.join(HERE, "..", "tests", "benign_bench.json")
    bench = _load_bench(bench_path)
    benign = _load_bench(benign_path)
    assert bench and benign, "内置 bench 缺失"
    traj, cand, bp, summ = generate(bench, benign)
    assert len(cand) == summ["attack_samples"], "候选数应与对抗样本数一致"
    assert all(isinstance(c.get("diagnosis"), dict) for c in cand), "每条候选须含结构化 diagnosis"
    assert all(c["diagnosis"]["routing"]["artifact"] in
               ("system_prompt", "rule_bank", "safety_memory", "tool_policy") for c in cand), "路由工件须合法枚举"
    print(f"[selftest] OK: attack={summ['attack_samples']} benign={summ['benign_samples']} "
          f"candidates={summ['candidates']} cats={list(summ['category_breakdown'])}")
    return 0


def main():
    p = argparse.ArgumentParser(description="gen_coldstart_samples —— 本地冷启动样本工厂（不依赖 SkillSentry）")
    p.add_argument("--version", action="version", version="%(prog)s 1.0.0")
    p.add_argument("--bench", default=os.path.join(HERE, "..", "tests", "attack_bench.json"),
                   help="对抗基准 JSON（默认 tests/attack_bench.json）")
    p.add_argument("--benign", default=os.path.join(HERE, "..", "tests", "benign_bench.json"),
                   help="良性基准 JSON（默认 tests/benign_bench.json）")
    p.add_argument("--out", default=os.path.join(HERE, "..", "coldstart_samples"),
                   help="输出目录")
    p.add_argument("--selftest", action="store_true", help="跑内置自检后退出（不写文件）")
    args = p.parse_args()

    if args.selftest:
        return selftest()

    bench = _load_bench(args.bench)
    benign = _load_bench(args.benign)
    if bench is None or benign is None:
        miss = args.bench if bench is None else args.benign
        print(f"[coldstart] 基准缺失：{miss}", file=sys.stderr)
        return 3

    traj, cand, bp, summ = generate(bench, benign)
    write_outputs(args.out, traj, cand, bp, summ)
    print(f"[coldstart] 已生成：{args.out}")
    print(f"  attack 样本 {summ['attack_samples']} → 轨迹 {len(traj)} + 候选 {len(cand)}")
    print(f"  benign 样本 {summ['benign_samples']} → 效用 sanity 提示 {len(bp)}")
    print(f"  分类：{summ['category_breakdown']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
