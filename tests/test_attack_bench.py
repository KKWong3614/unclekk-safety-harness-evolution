#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""attack-bench 对抗样本测试运行器（unclekk-safety-harness-evolution）

加载 tests/attack_bench.json，按 engine 路由到对应检测器：
  veto       → score_patch.heuristic_score    断言 S == 0.0（一票否决命中）
  ingest     → harness_hooks.ingest_probe     断言 verdict == "alert"
  honeytoken → harness_hooks._scan_honeytoken 断言命中

expect == "gap" 的样本为「语义等价绕过已知盲区」：仅统计基线、不断言——
  known-gap        = 当前引擎确实漏检（暴露短板，供后续强化瞄准）
  unexpected-block = 当前引擎已拦截（防御增强的好信号，仅报告）

退出码：0 = block 类全部拦截；非 0 = 存在漏检（含样本 id 明细）。
纯标准库、离线可跑、确定性可复现。CI 直接调用本脚本。
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.abspath(os.path.join(HERE, "..", "scripts"))
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

import score_patch as SP  # noqa: E402
import harness_hooks as HH  # noqa: E402


def load_bench():
    with open(os.path.join(HERE, "attack_bench.json"), encoding="utf-8") as f:
        return json.load(f)


def main():
    bench = load_bench()
    samples = bench["samples"]
    results = []          # block 类判定结果（仅 expect=block）
    block_samples = []    # block 类样本（与 results 对齐）
    blocked = 0
    blocked_total = 0
    gap_known = 0
    gap_unexpected = []

    print(f"attack-bench v{bench['meta']['version']} ｜ 共 {len(samples)} 条样本")
    for s in samples:
        sid = s["id"]
        engine = s["engine"]
        payload = s["payload"]
        expect = s["expect"]
        intercepted = False
        detail = ""
        if engine == "veto":
            sc, _uc, hits = SP.heuristic_score({
                "target_artifact": "rule_bank", "patch_type": "add_rule",
                "after": payload})
            intercepted = sc == 0.0
            detail = f"S={sc}" + (f" (veto: {hits[0][:40]})" if hits and intercepted else "")
        elif engine == "ingest":
            r = HH.ingest_probe(payload)
            intercepted = r["verdict"] == "alert"
            detail = f"verdict={r['verdict']}"
            if intercepted and r["reasons"]:
                detail += f" ({r['reasons'][0][:40]})"
        elif engine == "honeytoken":
            hits = HH._scan_honeytoken(payload)
            intercepted = bool(hits)
            detail = f"hits={len(hits)}" + (f" ({hits[0][:40]})" if hits else "")
        else:
            detail = f"未知 engine: {engine}"

        if expect == "block":
            blocked_total += 1
            block_samples.append(s)
            results.append(intercepted)
            if intercepted:
                blocked += 1
            print(f"[{'PASS' if intercepted else 'FAIL'}] {sid} [{engine}] {payload[:46]!r} -> {detail}")
        else:
            if intercepted:
                gap_unexpected.append(sid)
                print(f"[GAP!] {sid} [{engine}] {payload[:46]!r} -> 意外被拦（防御增强信号）{detail}")
            else:
                gap_known += 1
                print(f"[GAP ] {sid} [{engine}] {payload[:46]!r} -> 已知盲区（漏检基线）{detail}")

    # 汇总
    print("\n===== 汇总 =====")
    rate = (blocked / blocked_total * 100.0) if blocked_total else 0.0
    print(f"block 类：{blocked}/{blocked_total} 拦截，拦截率 {rate:.1f}%")
    print(f"gap 类：known-gap {gap_known}（盲区基线）/ unexpected-block {len(gap_unexpected)}")
    if gap_unexpected:
        print(f"  意外被拦（防御增强，建议日后转为 block 断言）：{', '.join(gap_unexpected)}")

    all_ok = all(results)
    if not all_ok:
        fails = [s["id"] for s, ok in zip(block_samples, results) if not ok]
        print(f"\n[FAIL] 存在 {len(fails)} 条漏检样本：{', '.join(fails)}")
        print("处理建议：漏检分两类——① 模板应覆盖但正则缺失 → 补正则/样本校准；② 语义等价绕过 → 移入 gap 类作盲区基线，待语义评分（L3）补齐")
    else:
        print(f"\n[PASS] block 类全部拦截（{blocked_total}/{blocked_total}），gap 盲区 {gap_known} 条已如实暴露")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
