#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""benign-bench 良性基准集测试运行器（unclekk-safety-harness-evolution）

加载 tests/benign_bench.json，断言护栏不误杀正常任务指令（防过拒 over-refusal）：
  veto       → score_patch.heuristic_score    断言 S > 0（不被一票否决误杀）
  ingest     → harness_hooks.ingest_probe     断言 verdict != "alert"（warn 标黄属设计行为，容忍）
  honeytoken → harness_hooks._scan_honeytoken 断言不命中

输出「良性放行率」——效用 U 分的实证锚点；CI 断言 >= meta.min_pass_rate（默认 0.95）。
退出码：0 = 放行率达标；非 0 = 存在误杀。
纯标准库、离线可跑、确定性可复现。
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


def main():
    with open(os.path.join(HERE, "benign_bench.json"), encoding="utf-8") as f:
        bench = json.load(f)
    samples = bench["samples"]
    min_rate = float(bench["meta"].get("min_pass_rate", 0.95))
    passed = 0
    total = len(samples)
    failures = []

    print(f"benign-bench v{bench['meta']['version']} ｜ 共 {total} 条良性样本（门槛放行率 >= {min_rate:.0%}）")
    for s in samples:
        sid = s["id"]
        engine = s["engine"]
        payload = s["payload"]
        ok = False
        detail = ""
        if engine == "veto":
            sc, _uc, hits = SP.heuristic_score({
                "target_artifact": "rule_bank", "patch_type": "add_rule",
                "after": payload})
            ok = sc > 0
            detail = f"S={sc}"
        elif engine == "ingest":
            r = HH.ingest_probe(payload)
            ok = r["verdict"] != "alert"
            detail = f"verdict={r['verdict']}"
            if r["reasons"]:
                detail += f" ({r['reasons'][0][:40]})"
        elif engine == "honeytoken":
            hits = HH._scan_honeytoken(payload)
            ok = not hits
            detail = f"hits={len(hits)}"
        else:
            detail = f"未知 engine: {engine}"

        if ok:
            passed += 1
            print(f"[PASS] {sid} [{engine}] {payload[:44]!r} -> {detail}")
        else:
            failures.append((sid, payload, detail))
            print(f"[FAIL] {sid} [{engine}] {payload[:44]!r} -> {detail}")

    rate = (passed / total * 100.0) if total else 0.0
    print("\n===== 汇总 =====")
    print(f"良性放行率 {passed}/{total} = {rate:.1f}% （门槛 {min_rate:.0%}）")
    ok_all = rate >= min_rate * 100.0 and not failures
    if failures:
        print(f"[FAIL] 误杀样本 {len(failures)} 条：{', '.join(sid for sid, _, _ in failures)}")
        for sid, payload, detail in failures:
            print(f"  {sid}: {payload!r} -> {detail}")
        print("处理建议：误杀分两类——① 正常指令被减安词误判 → 校准减安正则/样本；② 正常指令撞上注入模板 → 补白名单豁免")
    elif rate < min_rate * 100.0:
        print(f"[FAIL] 放行率 {rate:.1f}% 低于门槛 {min_rate:.0%}")
    else:
        print(f"[PASS] 放行率达标，无误杀（U 分实证锚点：{rate:.1f}%）")
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
