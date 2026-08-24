#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sync_artifacts.py —— 跨 Agent 威胁情报同步 + 与 KK 现有资产接线（L2-9/L2-10, P1-16）

把护栏工件（rule_bank / safety_memory / tool_policy）与外部来源打通：

  pull --harness <path> --sources <intel_sources.json> [--dry-run] [--backup-dir <dir>]
      从 intel_sources.json 配置的来源拉取工件，合并进本地 harness（只增不减，棘轮把关）。
  push --harness <path> --out <shared_intel.json>
      把本地 harness 的工件导出为共享情报 JSON，供其他 Agent/共享库消费。

来源类型（intel_sources.json 的 sources[]）：
  security_check_rules   skills-security-check 的规则/话术 → rule_bank
                         .md：提取「已知攻击话术模板」（反引号/双引号包裹的短语）
                         .json：结构化规则数组 [{rule|text, priority?, condition?}]
  cross_agent_memory     跨 Agent 共享记忆 JSONL 的经验 → safety_memory
  allowed_tools          SKILL.md frontmatter 的 allowed_tools / allowed-tools → tool_policy
  shared_intel           本脚本 push 导出的共享情报文件（rule_bank/safety_memory/tool_policy）

合并语义：
  rule_bank / safety_memory 追加去重（safety_memory 注入 failed_attempts=2，满足冷启动保护——
  共享记忆里的经验本身就是「反复失败后沉淀」的，语义上等于已过 2 轮）。
  tool_policy 棘轮偏序：allow 只缩不扩，宽化拒绝（复用 evolve_guard._ratchet_check_tool_policy）。
写回前强制备份（复用 evolve_guard.cmd_backup，含 manifest + 轮转）。

纯标准库、离线可跑、确定性。集成映射总表见 references/architecture.md。
"""
import argparse
import copy
import json
import os
import re
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import evolve_guard as EG  # noqa: E402

_ALLOWED_EXT = (".json", ".yaml", ".yml")
_SYNC_TAG = "sync:"  # from_patch 前缀，标识来源


# ── 来源解析器 ────────────────────────────────────────────────────────────
def _parse_frontmatter_tools(text: str) -> list:
    """轻量解析 YAML frontmatter 的 allowed_tools / allowed-tools 字段（不依赖 pyyaml）。"""
    m = re.match(r"^---\n(.*?)\n---", text, re.S)
    if not m:
        return []
    fm = m.group(1)
    for key in ("allowed_tools", "allowed-tools"):
        km = re.search(rf"^{key}:\s*(.*)$", fm, re.M)
        if not km:
            continue
        val = km.group(1).strip()
        if val in ("null", "", "None", "[]"):
            return []
        items = re.findall(r"^\s*-\s*(.+?)\s*$", fm[km.start():], re.M)
        if items:
            return [it.strip().strip('"\'') for it in items if it.strip()]
        m2 = re.match(r"\[(.*)\]", val)
        if m2:
            return [x.strip().strip('"\'') for x in m2.group(1).split(",") if x.strip()]
        return [val]
    return []


def _extract_quoted_terms(text: str) -> list:
    """提取被反引号或双引号包裹的短语（安全话术/规则），去 http(s) 链接。"""
    terms = []
    for m in re.finditer(r'`([^`]+)`|"([^"]+)"', text):
        t = (m.group(1) or m.group(2)).strip().strip('"')
        if len(t) >= 3 and not t.startswith(("http://", "https://")):
            terms.append(t)
    return terms


def _parse_security_rules(path: str, default_priority: str = "P0") -> list:
    """skills-security-check 规则 → rule_bank 条目列表。
    .json：结构数组 [{rule|text, priority?, condition?}]；.md：提取引号包裹的话术。"""
    if not os.path.exists(path):
        return []
    if path.endswith(".json"):
        try:
            data = _load_json(path)
        except (json.JSONDecodeError, OSError):
            return []
        entries = data.get("rules") if isinstance(data, dict) else data
        if not isinstance(entries, list):
            return []
        out = []
        for it in entries:
            if isinstance(it, str):
                out.append({"rule": it, "priority": default_priority,
                            "from_patch": _SYNC_TAG + "security-check"})
            elif isinstance(it, dict):
                rule = it.get("rule") or it.get("text") or it.get("condition")
                if rule:
                    out.append({"rule": rule, "priority": it.get("priority", default_priority),
                                "condition": it.get("condition"),
                                "from_patch": _SYNC_TAG + "security-check"})
        return out
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    return [{"rule": t, "priority": default_priority, "from_patch": _SYNC_TAG + "security-check"}
            for t in _extract_quoted_terms(text)]


def _parse_cross_agent_memory(path: str) -> list:
    """cross-agent-memory JSONL 经验 → safety_memory 条目列表。
    每行取 note/content/text 字段；无文本字段的行跳过。"""
    if not os.path.exists(path):
        return []
    out = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(rec, dict):
                    continue
                note = rec.get("note") or rec.get("content") or rec.get("text") or rec.get("memory")
                if note and isinstance(note, str):
                    out.append({"note": note[:500], "source": "cross-agent-memory",
                                "from_patch": _SYNC_TAG + "cross-agent-memory"})
    except OSError:
        return []
    return out


def _parse_allowed_tools(path: str, explicit_tools: list = None) -> list:
    """SKILL.md allowed_tools → tool_policy 条目列表（allow=whitelisted）。"""
    tools = list(explicit_tools or [])
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            tools += _parse_frontmatter_tools(f.read())
    seen = set()
    out = []
    for t in tools:
        t = t.strip()
        if not t or t in seen:
            continue
        seen.add(t)
        out.append({"tool": t, "allow": "whitelisted", "note": "sync from allowed_tools",
                    "from_patch": _SYNC_TAG + "allowed-tools"})
    return out


def _parse_shared_intel(path: str) -> dict:
    """push 导出的共享情报 → {rule_bank:[], safety_memory:[], tool_policy:[]}。"""
    if not os.path.exists(path):
        return {}
    try:
        data = _load_json(path)
    except (json.JSONDecodeError, OSError):
        return {}
    art = data.get("artifacts") if isinstance(data, dict) else None
    if not isinstance(art, dict):
        return {}
    return {
        "rule_bank": art.get("rule_bank") if isinstance(art.get("rule_bank"), list) else [],
        "safety_memory": art.get("safety_memory") if isinstance(art.get("safety_memory"), list) else [],
        "tool_policy": art.get("tool_policy") if isinstance(art.get("tool_policy"), list) else [],
    }


def _load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ── 合并（复用 evolve_guard 结构感知合并器）─────────────────────────────────
def _merge_entry(harness, target_artifact, entry, failed_attempts=None):
    """把一条结构化 entry 合入 harness 工件。返回 (合并位置描述, patch_key)。"""
    patch = {"target_artifact": target_artifact,
             "patch_type": "add_rule", "after": json.dumps(entry, ensure_ascii=False)}
    if failed_attempts is not None:
        patch["failed_attempts"] = failed_attempts
    key = EG._patch_key(patch)
    return EG._merge_artifact(harness, patch, key), key


def _merge_intel(harness, intel: dict, stats: dict):
    """把解析出的 intel 合入 harness（内存内）。stats 收集新增/跳过/棘轮拒绝。"""
    for rule in intel.get("rule_bank", []):
        pos, _k = _merge_entry(harness, "rule_bank", rule)
        _tally(pos, stats, "rule_bank")
    for mem in intel.get("safety_memory", []):
        pos, _k = _merge_entry(harness, "safety_memory", mem, failed_attempts=2)
        _tally(pos, stats, "safety_memory")
    for tp in intel.get("tool_policy", []):
        pos, _k = _merge_entry(harness, "tool_policy", tp)
        _tally(pos, stats, "tool_policy")


def _tally(pos: str, stats: dict, kind: str):
    if "skip-dup" in pos:
        stats["skipped"] += 1
    elif "ratchet-reject" in pos:
        stats["rejected"].append(pos)
    elif "early-write-blocked" in pos:
        stats["skipped"] += 1
    else:
        stats["added"][kind] = stats["added"].get(kind, 0) + 1


# ── 子命令 ────────────────────────────────────────────────────────────────
def cmd_pull(args):
    if not os.path.exists(args.harness):
        print(f"[sync] 护栏不存在：{args.harness}", file=sys.stderr)
        return 4
    if not args.harness.lower().endswith(_ALLOWED_EXT):
        print(f"[sync] 护栏扩展名不受支持：{args.harness}", file=sys.stderr)
        return 4
    if not os.path.exists(args.sources):
        print(f"[sync] 来源配置不存在：{args.sources}", file=sys.stderr)
        return 4

    harness = EG._load_harness(args.harness)
    working = copy.deepcopy(harness) if args.dry_run else harness
    stats = {"added": {}, "skipped": 0, "rejected": []}

    cfg = _load_json(args.sources)
    sources = cfg.get("sources") if isinstance(cfg, dict) else None
    if not isinstance(sources, list):
        print("[sync] 来源配置缺 sources[] 列表", file=sys.stderr)
        return 4

    for src in sources:
        stype = src.get("type")
        path = os.path.expanduser(src.get("path", ""))
        if stype == "security_check_rules":
            intel = {"rule_bank": _parse_security_rules(path, src.get("priority", "P0"))}
            label = "security_check_rules"
        elif stype == "cross_agent_memory":
            intel = {"safety_memory": _parse_cross_agent_memory(path)}
            label = "cross_agent_memory"
        elif stype == "allowed_tools":
            intel = {"tool_policy": _parse_allowed_tools(path, src.get("tools"))}
            label = f"allowed_tools({os.path.basename(path) or 'inline'})"
        elif stype == "shared_intel":
            intel = _parse_shared_intel(path)
            label = f"shared_intel({os.path.basename(path)})"
        else:
            print(f"[sync] 未知来源类型 {stype!r}，跳过", file=sys.stderr)
            continue
        before = dict(stats["added"])
        _merge_intel(working, intel, stats)
        after = dict(stats["added"])
        added_now = {k: after.get(k, 0) - before.get(k, 0) for k in after if after.get(k, 0) > before.get(k, 0)}
        print(f"[sync] {label}: 新增 {added_now or '0'}，累计跳过 {stats['skipped']}，棘轮拒绝 {len(stats['rejected'])}")

    print("\n===== 合并汇总 =====")
    print(f"新增：{stats['added'] or '无'} ｜ 跳过(重复/冷启动)：{stats['skipped']} ｜ 棘轮拒绝：{len(stats['rejected'])}")
    for r in stats["rejected"]:
        print(f"  [棘轮拒绝] {r}")

    if args.dry_run:
        print("\n[dry-run] 未写回（以上为将合并内容预览）")
        return 0

    # 写回前强制备份（复用 evolve_guard：manifest + 轮转）
    ns = types.SimpleNamespace(harness=args.harness, backup_dir=args.backup_dir,
                               max_backups=20, allow_root=None)
    EG.cmd_backup(ns)
    # P1-20：合入 tool_policy 后同步编译 enforcement spec（护栏与执行器解耦一致性）
    if stats["added"].get("tool_policy"):
        working["_enforcement"] = EG.compile_enforcement(
            working.get("artifacts", {}).get("tool_policy"))
        print("[sync] tool_policy 已合入，enforcement spec 已同步编译——执行器需重新加载 harness。")
    EG._save_harness(args.harness, working)
    print(f"[sync] 已写回：{args.harness}（备份见 {args.backup_dir}）")
    return 0


def cmd_push(args):
    if not os.path.exists(args.harness):
        print(f"[sync] 护栏不存在：{args.harness}", file=sys.stderr)
        return 4
    harness = EG._load_harness(args.harness)
    art = harness.get("artifacts") or {}
    _META = ("applied_at", "from_patch", "key")

    def _clean(items):
        """剥离演化元字段——共享情报只含语义内容（P1-20 往返幂等）。"""
        out = []
        for it in items or []:
            if isinstance(it, dict):
                it = {k: v for k, v in it.items() if k not in _META}
            if it not in out:
                out.append(it)
        return out

    out = {
        "intel_version": 1,
        "exported_at": EG._now(),
        "source_harness": os.path.abspath(args.harness),
        "artifacts": {
            "rule_bank": _clean(art.get("rule_bank") if isinstance(art.get("rule_bank"), list) else []),
            "safety_memory": _clean(art.get("safety_memory") if isinstance(art.get("safety_memory"), list) else []),
            "tool_policy": _clean(art.get("tool_policy") if isinstance(art.get("tool_policy"), list) else []),
        },
    }
    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(f"[sync] 已导出共享情报：{args.out}（rule_bank {len(out['artifacts']['rule_bank'])} / "
          f"safety_memory {len(out['artifacts']['safety_memory'])} / "
          f"tool_policy {len(out['artifacts']['tool_policy'])}）")
    return 0


def main():
    p = argparse.ArgumentParser(description="sync_artifacts —— 跨 Agent 威胁情报同步 / 与现有资产接线")
    p.add_argument("--version", action="version", version="%(prog)s 1.0.0")
    sub = p.add_subparsers(dest="cmd", required=True)

    pl = sub.add_parser("pull", help="从来源配置拉取工件合并进 harness（只增不减）")
    pl.add_argument("--harness", required=True, help="护栏文件（json/yaml）")
    pl.add_argument("--sources", required=True, help="来源配置 intel_sources.json")
    pl.add_argument("--backup-dir", default=None,
                    help="写回前备份目录（默认 harness 同目录 backups/）")
    pl.add_argument("--dry-run", action="store_true", help="只预览将合并内容，不写回")
    pl.set_defaults(func=cmd_pull)

    ps = sub.add_parser("push", help="导出护栏工件为共享情报 JSON")
    ps.add_argument("--harness", required=True, help="护栏文件（json/yaml）")
    ps.add_argument("--out", required=True, help="共享情报输出路径")
    ps.set_defaults(func=cmd_push)

    args = p.parse_args()
    if getattr(args, "backup_dir", None) is None:
        args.backup_dir = os.path.join(os.path.dirname(os.path.abspath(args.harness)), "backups")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
