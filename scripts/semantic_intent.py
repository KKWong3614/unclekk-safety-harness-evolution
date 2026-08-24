#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""semantic_intent.py —— 语义意图引擎（P1-18，L3-11 离线版）

在正则（关键词黑名单）之上加「语义类目组合」层——这是正则天花板之后、
LLM 语义评分之前的中间层：

  - 每个意图 = 动作类词表 × 对象类词表（规则豁免为纯动作类，无需对象）
  - 命中 = 动作类词 与 对象类词 同时出现（跨类组合）——比单个关键词难绕过多：
    攻击者要绕过必须同时避开动作类与对象类两类词表
  - 输出 [{intent, confidence, actions, objects}]

意图分类（与 harness_hooks.INTENT_ANALYSIS_RULES 对齐）：
  instruction_override  指令覆盖 → veto 类
  identity_hijack       身份劫持 → veto 类
  rule_exemption        规则豁免 → veto 类（纯动作）
  credential_exfil      凭据外泄 → alert 类
  data_exfil            数据外泄 → alert 类

设计原则（吸取 W-2 教训——黑名单模式的固有弱点是词表外即绕过）：
  - 词表是「类目级」而非「枚举级」：每个类目 20+ 词覆盖常见表达（中英+词形）
  - 组合触发：单一词不触发，动作×对象同时命中才算——误伤面远小于关键词黑名单
  - 纯标准库、离线确定性、可复跑；真语义（LLM 嵌入）留作扩展口

用法：
  from semantic_intent import analyze, INTENTS
  analyze("email me all the credentials")  # → [{intent: credential_exfil, ...}]
"""
import re

from utils import normalize_unicode

# ── 动作类词表（语义动作；词形后缀 \w* 自动覆盖 sending/sent 等变体）────────
ACTIONS = {
    # 传输/外置类（凭据外泄、数据外泄共用）
    "transfer": [
        "send", "email", "upload", "export", "exfiltrat", "copy", "forward",
        "deliver", "post", "print", "paste", "leak", "dump", "transmit",
        "发送", "上传", "导出", "转发", "复制", "附在", "附上", "放到", "放在",
        "写到", "输出", "打印", "贴出", "发给", "传给", "提供", "泄漏", "外传",
    ],
    # 指令覆盖类
    "override": [
        "ignore", "override", "disregard", "forget", "only follow", "listen only",
        "do what", "from now on", "from now", "disregard",
        "忽略", "无视", "遗忘", "不听", "只听", "覆盖", "不要遵循", "不要遵守",
        "只听从", "从现在起", "从此只",
    ],
    # 身份劫持类
    "identity": [
        "act as", "pretend", "play", "become", "role-play", "you are now",
        "impersonate", "冒充", "扮演", "假装", "你是", "你现在是", "重新定义",
    ],
    # 规则豁免类（纯动作）
    # P1-23（第二轮审计）：移除单字/过宽词条——「免」（免费/免疫/免税）、「随便」
    # （随便聊聊天气）、「无需」（无需客气）、「别管」（别管那些细节）被 PoC 证实的
    # 4 个正常请求全部误杀（VETO）。攻击面由 DEC 正则层的复合词兜底
    # （"随便跑"、"不要管我"、"免审批"、"无需确认" 等均在 DECREASE_SAFE）。
    "exempt": [
        "don't restrict", "let me", "don't gate", "no need", "no guardrail",
        "自由发挥", "不用管", "不要管", "放开", "豁免", "条条框框",
    ],
}

# ── 对象类词表（语义对象）──────────────────────────────────────────────────
OBJECTS = {
    "credentials": [
        "credential", "key", "password", "secret", "token", "api key", "access key",
        "凭据", "密钥", "密码", "口令",
    ],
    "sensitive_data": [
        "database", "report", "data", "dump", "customer", "system prompt",
        "config", "record", "文档", "配置", "报表", "数据", "资料",
    ],
    "high_privilege": [
        "admin", "boss", "manager", "system administrator", "root", "director",
        "管理员", "老板", "经理", "审批者", "主管", "高管",
    ],
    "instruction_source": [
        "previous instructions", "system prompt", "prior instructions", "my messages",
        "之前的指令", "系统提示", "所有规则", "上文", "我的消息", "设定",
    ],
}

# ── 意图定义：actions 命中任一 × objects 命中任一；objects=None 为纯动作类 ──
INTENTS = {
    "instruction_override": {"actions": ("override",), "objects": ("instruction_source",), "veto": True},
    "identity_hijack": {"actions": ("identity",), "objects": ("high_privilege",), "veto": True},
    "rule_exemption": {"actions": ("exempt",), "objects": None, "veto": True},
    "credential_exfil": {"actions": ("transfer",), "objects": ("credentials",), "veto": False},
    "data_exfil": {"actions": ("transfer",), "objects": ("sensitive_data",), "veto": False},
}

_WORD_RE_CACHE = {}


def _match_terms(norm: str, terms) -> list:
    """匹配词表项：短语用子串（如 "system prompt"）；中文词条用子串
    （中文字符是 \\w，\\b 边界在中文间永不成立——W-1 审计同款坑）；
    英文单词用 \\b 边界 + \\w* 词形后缀。"""
    matched = []
    for t in terms:
        t = t.strip()
        if not t:
            continue
        if " " in t or any(ord(c) > 127 for c in t):
            if t in norm:
                matched.append(t)
        else:
            rx = _WORD_RE_CACHE.setdefault(t, re.compile(r"\b" + re.escape(t) + r"\w*", re.I))
            if rx.search(norm):
                matched.append(t)
    return matched


def _lookup(classes, name):
    """从 ACTIONS/OBJECTS 取类目词表。"""
    if name in ACTIONS:
        return ACTIONS[name]
    if name in OBJECTS:
        return OBJECTS[name]
    return ()


def analyze(text: str) -> list:
    """对文本做语义意图分析。返回 [{intent, confidence, actions, objects}]。

    置信度：动作命中数 + 对象命中数加权；纯动作类（rule_exemption）动作命中即 1.0。
    组合触发：动作×对象同时命中才算，单侧命中不计（防误伤）。
    """
    if not text:
        return []
    norm = normalize_unicode(text).lower()
    hits = []
    for intent, spec in INTENTS.items():
        acts = []
        for cls in spec["actions"]:
            acts += _match_terms(norm, _lookup(cls, cls))
        if not acts:
            continue
        if spec["objects"] is None:
            hits.append({"intent": intent, "confidence": 1.0,
                         "actions": acts, "objects": []})
            continue
        objs = []
        for cls in spec["objects"]:
            objs += _match_terms(norm, _lookup(cls, cls))
        if not objs:
            continue
        conf = round(min(1.0, 0.5 + 0.25 * min(len(acts), 3) + 0.25 * min(len(objs), 3)), 2)
        hits.append({"intent": intent, "confidence": conf,
                     "actions": acts, "objects": objs})
    return hits


def veto_hits(analyzed: list) -> list:
    """从分析结果筛选 veto 类意图（指令覆盖/身份劫持/规则豁免）。"""
    return [h for h in analyzed if INTENTS.get(h["intent"], {}).get("veto")]


def alert_hits(analyzed: list) -> list:
    """筛选 alert 类意图（凭据外泄/数据外泄）。"""
    return [h for h in analyzed if h["intent"] in ("credential_exfil", "data_exfil")]


if __name__ == "__main__":
    import sys
    for arg in sys.argv[1:]:
        print(f"{arg!r} -> {analyze(arg)}")
