#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""evolve_trigger.py —— 进化环自动化触发器（接入方式 B，P1-21）

monitor-panel（或任何外部系统）检测到越权/异常后，调用本命令一次，
自动跑完整进化环：「事件 → 补丁 → 诊断 → 评分 → 闸门 → (写回) → 审计」，
输出结构化 JSON 供调用方解析。

事件输入（--event 支持三种形态）：
  1. harness_hooks 拦截事件（含 tool_name/reasons/trust）→ sample_to_candidate
  2. 自由文本告警（monitor-panel 消息）→ 按类型映射生成补丁
  3. 直接 candidate patch JSON（含 target_artifact/patch_type/after）→ 原样过闸

保护机制：
  - 默认不写回：--auto-apply 显式传才在 ACCEPT 后执行 backup+apply（人工旁路原则）
  - --dry-run：全程只预览（评分+判定），不写回
  - 减安补丁：一票否决 → REJECT 进拒收池，永不写回
  - K 轮熔断 / 拒收池去重 / 棘轮 由 evolve_guard 天然提供
  - 每次运行写审计记录（复用 evolve_guard._append_audit）

用法：
  python evolve_trigger.py --event event.json --harness harness.json \
      --backup-dir backups --reject-pool reject_pool.json \
      [--auto-apply] [--dry-run] [--audit-log audit.log] [--operator monitor-panel]

输出（stdout JSON）：
  {"ok": true, "event": {...}, "candidate": {...}, "diagnosis": {...},
   "score": {...}, "judge": {"verdict": "ACCEPT|REJECT", "rc": ...},
   "apply": {...}|null}
"""
import argparse
import json
import os
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import evolve_guard as EG  # noqa: E402
import harness_hooks as HH  # noqa: E402
import score_patch as SP  # noqa: E402


# ── 事件 → candidate patch ────────────────────────────────────────────────
def _event_to_candidate(event: dict) -> dict:
    """按事件形态生成 candidate patch（含 diagnosis）。"""
    # 形态 3：已是 candidate patch
    if isinstance(event, dict) and "target_artifact" in event and "patch_type" in event and "after" in event:
        patch = dict(event)
        patch.setdefault("diagnosis", _infer_diagnosis(event))
        return patch
    # 形态 1：harness_hooks 拦截事件
    if isinstance(event, dict) and ("tool_name" in event or "reasons" in event):
        reason = "; ".join(event.get("reasons", [])) or "auto-detected anomaly"
        tool = event.get("tool_name", "unknown")
        if tool != "unknown" and event.get("type") == "tool_dispatch":
            patch = {"target_artifact": "tool_policy", "patch_type": "add_rule",
                     "after": json.dumps({"tool": tool, "deny": ["*"],
                                          "note": f"auto-block after: {reason}"},
                                         ensure_ascii=False)}
        else:
            patch = {"target_artifact": "rule_bank", "patch_type": "add_rule",
                     "after": f"block {reason}"}
        patch["supporting_trajectories"] = [f"evt_{hash(json.dumps(event, sort_keys=True)):08x}"]
        patch["auto_generated"] = True
        patch["diagnosis"] = _infer_diagnosis(event)
        return patch
    # 形态 2：自由文本告警（monitor-panel 消息）
    text = event.get("text") if isinstance(event, dict) else str(event)
    patch = _text_to_patch(text)
    patch["supporting_trajectories"] = [f"alert_{hash(text):08x}"]
    patch["auto_generated"] = True
    patch["diagnosis"] = _infer_diagnosis({"text": text})
    return patch


def _text_to_patch(text: str) -> dict:
    """自由文本告警 → 按类型映射补丁。"""
    t = text.lower()
    if any(k in t for k in ("越权", "privilege", "越权调用", "未授权工具")):
        return {"target_artifact": "tool_policy", "patch_type": "add_rule",
                "after": json.dumps({"tool": "unknown", "deny": ["*"],
                                     "note": f"auto: {text[:80]}"}, ensure_ascii=False)}
    if any(k in t for k in ("注入", "inject", "prompt injection")):
        return {"target_artifact": "rule_bank", "patch_type": "add_rule",
                "after": f"block prompt-injection pattern :: {text[:80]}"}
    if any(k in t for k in ("外泄", "exfil", "数据泄漏", "凭据")):
        return {"target_artifact": "rule_bank", "patch_type": "add_rule",
                "after": f"block data-exfiltration :: {text[:80]}"}
    return {"target_artifact": "rule_bank", "patch_type": "add_rule",
            "after": f"block anomalous pattern :: {text[:80]}"}


def _infer_diagnosis(event: dict) -> dict:
    """从事件推断结构化 diagnosis（过 schema 校验：failure_type/zi/routing）。"""
    text = json.dumps(event, ensure_ascii=False).lower()
    if any(k in text for k in ("越权", "privilege", "tool_dispatch", "honeytool")):
        ftype, hazard, surface, mode = "privilege_escalation", "privilege_escalation", "tool_policy", "tool_tampering"
    elif any(k in text for k in ("注入", "inject", "canary", "ignore previous")):
        ftype, hazard, surface, mode = "injection", "logic_bypass", "rule_bank", "canary_bypass"
    elif any(k in text for k in ("外泄", "exfil", "凭据", "credential")):
        ftype, hazard, surface, mode = "data_exfil", "data_leak", "tool_policy", "composite"
    else:
        ftype, hazard, surface, mode = "logic_bypass", "logic_bypass", "rule_bank", "other"
    return {"failure_type": ftype,
            "zi": {"hazard": hazard, "attack_surface": surface, "failure_mode": mode},
            "routing": {"artifact": surface, "confidence": "medium",
                        "reason": "auto-inferred from trigger event (human review recommended)"}}


# ── 主流程 ────────────────────────────────────────────────────────────────
def run_trigger(args) -> dict:
    event = args.event
    if isinstance(event, str):
        if os.path.exists(event):
            with open(event, "r", encoding="utf-8") as f:
                event = json.load(f)
        else:
            # P1-22：先尝试把字符串当 JSON 对象解析（拦截事件以 JSON 字符串传入），
            # 解析失败才退回自由文本告警
            try:
                parsed = json.loads(event)
                event = parsed if isinstance(parsed, dict) else {"text": event}
            except (json.JSONDecodeError, TypeError):
                event = {"text": event}

    patch = _event_to_candidate(event)
    result = {"ok": True, "event": event, "candidate": patch,
              "diagnosis": patch.get("diagnosis"), "score": None,
              "judge": None, "apply": None}

    # 1) 评分（启发式；veto 类直接 S=0）
    s_can, u_can, hits = SP.heuristic_score(patch)
    result["score"] = {"s_candidate": s_can, "u_candidate": u_can, "hits": hits}

    # 2) 判定（judge 子命令，含 ValidEdit + 一票否决）
    # 临时 candidate 写到系统临时目录（scripts 目录受沙箱保护，os.remove 会被钩子拦截）
    import tempfile as _tf
    cand_path = os.path.join(_tf.gettempdir(), f"_trigger_candidate_{os.getpid()}.json")
    try:
        with open(cand_path, "w", encoding="utf-8") as f:
            json.dump(patch, f, ensure_ascii=False)
        judge_args = types.SimpleNamespace(
            candidate_patch=cand_path,
            s_current=args.s_current, u_current=args.u_current,
            s_candidate=s_can, u_candidate=u_can,
            reject_pool=args.reject_pool, max_rounds=args.max_rounds,
            audit_log=args.audit_log, operator=args.operator)
        rc = EG.cmd_judge(judge_args)
        verdict = "ACCEPT" if rc == 0 else "REJECT"
        result["judge"] = {"verdict": verdict, "rc": rc}

        # 3) 写回（仅 ACCEPT + --auto-apply + 非 dry-run）
        if verdict == "ACCEPT" and args.auto_apply and not args.dry_run:
            EG.cmd_backup(types.SimpleNamespace(
                harness=args.harness, backup_dir=args.backup_dir,
                max_backups=20, allow_root=None))
            apply_args = types.SimpleNamespace(
                harness=args.harness, candidate_patch=cand_path,
                backup_dir=args.backup_dir, reject_pool=args.reject_pool,
                s_current=args.s_current, u_current=args.u_current,
                llm_scorer=None, allow_root=None, skip_p0_regression=False,
                max_rounds=args.max_rounds, audit_log=args.audit_log, operator=args.operator)
            arc = EG.cmd_apply(apply_args)
            result["apply"] = {"rc": arc, "applied": arc == 0}
            result["ok"] = result["ok"] and arc == 0
        elif args.dry_run:
            result["apply"] = {"rc": None, "applied": False, "skipped": "dry-run"}
    finally:
        if os.path.exists(cand_path):
            os.remove(cand_path)
    return result


def main():
    p = argparse.ArgumentParser(description="evolve_trigger —— 进化环自动化触发器（接入方式 B）")
    p.add_argument("--version", action="version", version="%(prog)s 1.0.0")
    p.add_argument("--event", required=True,
                   help="事件：事件 JSON 路径 / 自由文本告警 / 或直接 candidate patch JSON 路径")
    p.add_argument("--harness", required=True, help="护栏文件（json/yaml）")
    p.add_argument("--backup-dir", required=True, help="备份目录（auto-apply 需要）")
    p.add_argument("--reject-pool", required=True, help="拒收池 JSON 路径")
    p.add_argument("--s-current", type=float, default=0.60, help="当前安全分基线")
    p.add_argument("--u-current", type=float, default=0.80, help="当前效用分基线")
    p.add_argument("--max-rounds", type=int, default=20, help="进化轮次上限")
    p.add_argument("--auto-apply", action="store_true",
                   help="ACCEPT 后自动 backup+apply 写回（默认只评+判，人工旁路）")
    p.add_argument("--dry-run", action="store_true", help="只预览评分+判定，不写回")
    p.add_argument("--audit-log", default=None, help="审计日志路径（JSONL）")
    p.add_argument("--operator", default="monitor-panel", help="操作者标识")
    args = p.parse_args()
    # 内部 judge/apply 的日志输出重定向到 stderr——stdout 只留给最终结构化 JSON
    #（供 monitor-panel 等调用方解析）
    import contextlib
    with contextlib.redirect_stdout(sys.stderr):
        result = run_trigger(args)
    print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    return 0 if result.get("ok") else 2


if __name__ == "__main__":
    sys.exit(main())
