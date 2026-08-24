#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
公共工具模块 —— unclekk-safety-harness-evolution v1.1.0

提供三个脚本共享的基础功能：
  - normalize_unicode: 零宽字符去除 + NFKC 归一化（防 canary/减安词绕过）
  - normalize_for_scan: 输入切面归一化（去零宽 + 下划线/点号替换空格）
  - compile_regex: 预编译正则列表

依赖：仅 Python 标准库。
"""
import re
import unicodedata as _unicodedata


# ── Unicode 归一化（防零宽/全角注入绕过）────────────────────────────────────
_ZW_CHARACTERS = ("\u200b", "\u200c", "\u200d", "\ufeff", "\u00a0", "\u2028", "\u2029")


def normalize_unicode(text: str) -> str:
    """去除零宽空格、BOM、NFKC 归一化（防 canary/减安词绕过）。"""
    try:
        text = _unicodedata.normalize("NFKC", text)
    except Exception:
        pass
    for ch in _ZW_CHARACTERS:
        text = text.replace(ch, "")
    return text


def normalize_for_scan(text: str) -> str:
    """输入切面归一化：去零宽 + 下划线/点号替换回空格，捕获变体注入。"""
    t = normalize_unicode(text)
    t = t.replace("_", " ").replace(".", " ")
    t = re.sub(r"\s+", " ", t)
    return t


def compile_regex(patterns: list[str], flags: int = re.I) -> list[tuple[str, re.Pattern]]:
    """预编译正则列表，返回 (pattern_str, compiled_pattern) 元组列表。"""
    return [(p, re.compile(p, flags)) for p in patterns]


def format_ts() -> str:
    """时间戳：毫秒级 + pid，避免同秒内备份文件名碰撞。"""
    import datetime as _dt
    import os
    now = _dt.datetime.now()
    ts = now.strftime("%Y%m%d_%H%M%S")
    ms = now.microsecond // 1000
    return f"{ts}_{ms:03d}_{os.getpid()}"
