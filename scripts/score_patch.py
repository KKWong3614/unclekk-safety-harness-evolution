#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
score_patch.py —— 安全护栏进化闭环的「评分器」(Scorer)

职责：给一个候选补丁(candidate patch)打 安全分 S / 效用分 U，
      供 evolve_guard.py 的 judge 闸门使用，把"打分"从人工/模型口头报数
      机械化成可复跑的代码。

设计（诚实声明）：
  * 默认走 启发式正则打分（纯标准库，离线可跑，确定性可复现）。
  * 若装了小模型/LLM，可用 --llm-scorer 注入外部评分命令（如一个调用本地
    小模型的脚本），其 stdout 需输出 JSON {"s":0.x,"u":0.x}；本脚本解析后
    采纳。这样既不强行依赖我没有的 API，又保留了"小模型评分"扩展口。
  * 本评分器不保证 100% 对齐论文的 LLM scorer，但作为闭环第一道自动闸门足够。

输入：
  --candidate-patch  候选补丁 JSON（必填）
  --harness          当前护栏文件(yaml/json，可选，用于约束面对比)
  --s-current / --u-current   基线分(可选，用于输出 delta)
  --llm-scorer       外部评分命令模板，{patch} 会被替换为补丁路径(可选)
输出：JSON {"s_candidate":f,"u_candidate":f,"s_current":f,"u_current":f,
            "delta_s":f,"delta_u":f,"heuristic_hits":[...],"verdict_hint":str,
            "metrics":{...}}
"""
import argparse, json, logging, os, re, statistics, subprocess, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils import normalize_unicode

# ── 可观测性：结构化日志 ────────────────────────────────────────────────────

logger = logging.getLogger(__name__)
if not logger.handlers:
    _handler = logging.StreamHandler(sys.stderr)
    _handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S"))
    logger.addHandler(_handler)
    logger.setLevel(logging.INFO)


# ── 可观测性：metrics 计数器 ────────────────────────────────────────────────
class Metrics:
    """简单计数器暴露，供外部监控或测试查询。"""
    def __init__(self):
        self.veto_count = 0        # 一票否决命中次数
        self.heuristic_runs = 0    # 启发式打分总次数
        self.llm_runs = 0          # 外部 LLM 评分调用次数
        self.llm_failures = 0      # 外部评分失败次数
        self.regex_matches = 0     # 正则命中总次数
        self.norm_calls = 0        # 归一化调用次数

    def to_dict(self):
        return {
            "veto_count": self.veto_count,
            "heuristic_runs": self.heuristic_runs,
            "llm_runs": self.llm_runs,
            "llm_failures": self.llm_failures,
            "regex_matches": self.regex_matches,
            "norm_calls": self.norm_calls,
        }


_METRICS = Metrics()


# ── 正则编译缓存统计 ───────────────────────────────────────────────────────
class RegexCache:
    """记录每个正则的使用次数，供性能分析。"""
    def __init__(self):
        self._cache: dict[str, re.Pattern] = {}
        self._hits: dict[str, int] = {}

    def compile(self, pattern: str, flags: int = 0) -> re.Pattern:
        if pattern not in self._cache:
            self._cache[pattern] = re.compile(pattern, flags)
            self._hits[pattern] = 0
        return self._cache[pattern]

    def record_hit(self, pattern: str):
        self._hits[pattern] = self._hits.get(pattern, 0) + 1

    def stats(self) -> dict:
        total_hits = sum(self._hits.values())
        return {
            "compiled_count": len(self._cache),
            "total_hits": total_hits,
            "per_pattern": dict(self._hits),
        }


_RE_CACHE = RegexCache()


def _compile(patterns):
    return [(p, _RE_CACHE.compile(p, re.I)) for p in patterns]


# ---- 权重依据注释：每个权重值基于"最小必要"原则 + 攻防博弈经验 ----
#   - 减安词权重 -0.25：减安词是"最高优先级负面信号"，1条减安词
#     相当于多条加安词的抵消量（攻防非对称性）。
#   - 加安词权重 +0.12：加安词是"次要正面信号"，多条加安词只能
#     部分抵消减安词（不是完全等权，符合安全优先原则）。
#   - patch_type 权重 ±0.08/0.10：加规则类通常提高安全分，
#     放松类通常降低安全分，幅度适中避免单一字段主导。
#   - 过度限制权重 -0.35：过度限制是"最高优先级效用负面信号"，
#     1条过度限制 = 3条最小补丁信号的抵消量（效用保护优先）。
#   - 最小补丁信号 +0.05：局部改写 + 轨迹支撑 → 效用提升。
#   - 宽泛改写惩罚 -0.10：无 before 且 after 过长 → 疑似一刀切。

# P0-5 修复：补齐 delete/drop/nullify/unset/revoke/clear 变体
DECREASE_SAFE = [
    # 一级：高危害减安词（权重 -0.25）
    r"\ballow\s+all\b",           # 允许一切
    r"\bturn\s+off\b",           # 关闭安全
    r"\bbypass\b",                # 绕过检查
    r"\bskip\s+(the\s+)?(safety|check|verif)",  # 跳过验证
    r"\bignore\s+(all\s+)?(safety|rule|instruction|previous)",  # 忽略安全指令
    r"\bno\s+(longer\s+)?(verif|check)\w*",  # 不再验证（\w* 兼容 verify/verification/checking 等完整词，原 (verif)\b 因边界问题漏判 "verify"）
    r"\bremove\s+(the\s+|all\s+)?(guard|restriction|limit)",  # 移除限制（含 the/all 插入词）
    r"\bdisable\s+(all\s+)?(safety|guard|check|restriction|limit)",  # 禁用安全（含 restriction/limit）
    r"\bdisable\W+(\w+\W+){0,3}(safety|guard|check|restriction|limit)",  # P1-6：兼容 "disable the safety check" 式插入词
    r"\bstop\s+(all\s+)?(checking|check\w*|verif\w*|validat\w*|safety)",  # P1-13：stop checking safety 类
    r"\bopen\s+(everything|all)\b",  # 放开一切
    r"\ballow\s+(everything|all)\b",  # P1-6：允许一切（原 allow all 只匹配紧跟 all）
    r"\bno\s+need\s+(for\s+|to\s+)?(confirm\w*|approv\w*|verif\w*|check\w*)",  # P1-6/P1-17：无需确认/审批（approv\w* 兼容 approval——approve 与 approval 非前缀关系，词干是 approv）
    r"(免审批|无需确认|免确认|无需验证)",  # P1-6/P1-13：中文免审批/免确认（去 \b，防中文字符边界失效）
    # 二级：补充式减安词（同权重 -0.25，补齐常见变体）
    r"\bdelete\s+(all\s+)?(rule|guard|restriction|check|safety)",
    r"\bdrop\s+(all\s+)?(rule|guard|restriction|check|safety)",
    r"\bunset\s+(all\s+)?(rule|guard|restriction|check|safety)",
    r"\bnullify\s+(all\s+)?(rule|guard|restriction|check|safety)",
    r"\brevoke\s+(all\s+)?(rule|guard|restriction|check|safety)",
    r"\bclear\s+(all\s+)?(rule|guard|restriction|check|safety)",
    r"\bwhitelist\s+(everything|all)",
    # 中文减安词（P0-C 修复：原正则仅覆盖英文，中文减安补丁如「取消所有安全限制」
    #   可绕过一票否决写回护栏。补齐后触发 veto → S=0 → 闸B 拒绝）
    r"取消.{0,4}(安全|防护|限制|检查|验证|校验|审核)",
    r"取消.{0,12}(安全|防护|限制|检查|验证|校验|审核)",  # P1-6：中文间隔放宽（"取消对所有工具调用的安全校验"）
    r"关闭.{0,4}(安全|防护|检查|验证|校验)",
    r"关闭.{0,12}(安全|防护|检查|验证|校验)",  # P1-6
    r"移除.{0,4}(安全|防护|限制|检查|验证)",
    r"忽略.{0,6}(安全|指令|规则|限制)",  # P1-13：间隔放宽（"忽略之前的所有规则"）
    r"解除.{0,4}(限制|防护|锁定|安全)",
    r"停用.{0,4}(安全|防护|检查|验证)",
    r"放开.{0,4}(一切|所有|全部)",
    r"不再.{0,4}(验证|检查|校验|核实|审查)",
    r"禁用.{0,4}(安全|防护|检查|验证)",
    r"绕过.{0,4}(检查|验证|安全|防护)",
    # P1-17：词表外同义减安（PoC 实证漏检，安全专家审计修复）
    r"(全|完全|全部|都)\s*放开",      # 全放开
    r"(全|完全|全部|都)\s*放行",      # 全放行
    r"随便\s*跑",                     # 随便跑
    r"不要\s*管\s*我",                # 不要管我
    r"let\s+everything\s+through",   # let everything through
    r"don'?t\s+gate\s+me",           # don't gate me
    r"no\s+guardrail",               # no guardrail
]
# ---- 粘连/分隔符变形检测（P1-13 升级为模式集，P1-17 替换手动词表）----
# 攻击者插入零宽字符/下划线/连字符，使归一化后单词粘连（allow\u200ball → allowall）、
# 或直接写 disable_the_safety_check 式变体，\s+ 正则匹配不到。
# 方案：把 DEC 的每个分隔符（\s+/\s*/\W+/\W*）替换为宽松分隔符集 [\s_\-.\u200b\u200c\u200d]*，
# 对「去分隔符」文本匹配——自动继承全部 DEC 模式，加新 DEC 模式即自动获得变形覆盖，
# 不再依赖手动词表（手动词表被 PoC 证实的 8 种同义减安绕过击穿）。
_DEFORM_SEP_RX = re.compile(r"\\s\+|\\s\*|\\W\+|\\W\*")
_DEFORM_SEP = r"[\s_\-\.\u200b\u200c\u200d]*"


def _make_deform(patterns):
    """把模式中的分隔符替换为宽松分隔符集（* 匹配 0+），并去掉 \\b 词边界，生成变形检测模式。

    - 用 lambda 替换（re.sub 的 repl 字符串会把 \\s 当转义解释，PatternError）。
    - 去掉 \\b：DEFORM 匹配「分隔符折叠文本」（分隔符→单空格），粘连词（allowall）中
      词边界失效（all 后接 web 时 \\b 不成立），故去边界做子串匹配（fail-closed 偏向拦截；
      "disallow all" 式罕见误伤可接受，benign bench 兜底）。
    """
    out = []
    for p in patterns:
        p2 = _DEFORM_SEP_RX.sub(lambda _m: _DEFORM_SEP, p)
        p2 = p2.replace(r"\b", "")
        out.append(p2)
    return out


DECREASE_SAFE_DEFORM = _make_deform(DECREASE_SAFE)
_DEC_DEFORM = _compile(DECREASE_SAFE_DEFORM)
# ---- 加安信号（命中即提升安全分，权重 +0.12）----
INCREASE_SAFE = [
    r"\bblock\b", r"\bdeny\b", r"\brequire\b", r"\bverif", r"\bquarantine\b",
    r"\bmonitor\b", r"\breject\b", r"\bforbid\b", r"\bsandbox\b", r"\bconfirm\b",
    # 中文加安词（P0-C 配套：让中文好补丁如「拦截所有危险请求」得正分，
    #   避免被基线压低而难以过闸；与上方中文减安词互不冲突，veto 优先）
    r"拦截", r"隔离", r"核验", r"校验", r"防护", r"管控", r"收紧", r"锁定",
]
# ---- 过度限制（命中即拉低效用分，权重 -0.35）----
OVER_RESTRICT = [
    r"\bban\s+all\b", r"\bdisable\s+all\b", r"\bblock\s+(everything|all)\b",
    r"\bforbid\s+(all|every)\b", r"\bno\s+tool\b", r"\bstop\s+all\s+(action|tool)",
]
# ---- 最小补丁信号（命中即提升效用分，权重 +0.05）----
MINIMAL_SIGNAL = [
    r"supporting_trajectories", r"\bbefore\b", r"\bafter\b", r"\bonly\b", r"\bspecific\b",
]

DEC = _compile(DECREASE_SAFE)
INC = _compile(INCREASE_SAFE)
OVR = _compile(OVER_RESTRICT)
MIN = _compile(MINIMAL_SIGNAL)


def _count(text, compiled):
    """统计命中次数，同时更新 metrics 和 regex cache。"""
    n = 0
    for p, rx in compiled:
        if rx.search(text):
            n += 1
            _RE_CACHE.record_hit(p)
    _METRICS.regex_matches += n
    return n


def _hard_veto_after(after: str) -> str | None:
    """一票否决（P0-1 + P1-13 + P1-17）。after 中若含减安词，不管加安词多少直接给 0.0。

    理由：闸 B 的安全判定必须以"补丁没有降低安全"为前置条件，
    不能被字符串构造绕过。P1-13/P1-17：正则 \\s+ 漏网的粘连/分隔符变形
    （allow\\u200ball → allowall、disable_the_safety_check）在去分隔符后，
    用 DEC 的 DEFORM 模式集（分隔符 → 宽松集 *）做匹配——自动覆盖全部减安模式的
    粘连/变形变体，不再依赖手动词表（词表被同义减安绕过击穿）。
    """
    if not after:
        return None
    after_norm = after.lower()
    after_norm = normalize_unicode(after_norm)
    for _, rx in DEC:
        if rx.search(after_norm):
            _METRICS.veto_count += 1
            return f"一票否决：after 含减安词（{rx.pattern[:40]}）"
    # P1-17：DEFORM 模式集 —— 分隔符折叠文本（分隔符→单空格）后匹配
    #（覆盖 allow all / allow_all / allow\u200ball / allow-all-web-requests 等全部 DEC 变形）
    folded = re.sub(r"[\s_\-\.]+", " ", after_norm)
    for p, rx in _DEC_DEFORM:
        if rx.search(folded):
            _METRICS.veto_count += 1
            return f"一票否决：after 含粘连减安词（{p[:40]}）"
    # P1-18（L3-11 语义层）：语义意图引擎——指令覆盖/身份劫持/规则豁免类意图命中即 veto
    #（动作×对象组合触发，抓正则/模式集都漏的语义等价绕过，如 "email me all the credentials"）
    try:
        from semantic_intent import analyze as _sem_analyze, veto_hits as _sem_veto_hits
        _sem = _sem_veto_hits(_sem_analyze(after_norm))
        if _sem:
            _METRICS.veto_count += 1
            h = _sem[0]
            return f"一票否决：语义意图命中 {h['intent']}（动作 {h['actions']}×对象 {h['objects']}）"
    except Exception:
        pass  # 语义引擎缺失/异常时降级（不阻断主流程，正则层仍在）
    # 过度限制词在 after 中是合理的（比如 "block all"），不算一票否决
    return None


def _after_is_safe(after: str) -> bool:
    """after 字段自身是否通过安全自检（无减安词命中，含 DEFORM 变形 + 语义意图检测）。"""
    if not after:
        return True
    after_norm = normalize_unicode(after.lower())
    for _, rx in DEC:
        if rx.search(after_norm):
            return False
    folded = re.sub(r"[\s_\-\.]+", " ", after_norm)
    if any(rx.search(folded) for _, rx in _DEC_DEFORM):
        return False
    try:
        from semantic_intent import analyze as _sem_analyze, veto_hits as _sem_veto_hits
        if _sem_veto_hits(_sem_analyze(after_norm)):
            return False
    except Exception:
        pass
    return True


def heuristic_score(patch: dict) -> tuple[float, float, list]:
    """返回 (s, u, 命中说明)。纯启发式。

    P1 修复：打分 blob 仅包含 after/before/patch_type 三个语义字段，
    排除 supporting_trajectories / source_event 等元字段对分数的污染（M-09）。
    """
    _METRICS.heuristic_runs += 1
    logger.info(f"[score_patch] 开始评分")
    after = str(patch.get("after") or "")
    before = str(patch.get("before") or "")
    ptype = str(patch.get("patch_type") or "").lower()
    # 计分 blob 只由 after+before+ptype 拼接，避免元字段污染
    blob = f"{after}\n{before}\n{ptype}"

    hits = []

    # P0-1 一票否决：after 含任何减安词，直接 S=0.0
    veto = _hard_veto_after(after)
    if veto:
        return 0.0, 0.0, [veto]

    # ── 安全分 S：基线 0.5，区间 [0.0, 1.0] ──
    # 权重依据：减安词 -0.25/条（高危害，线性递减）
    #           加安词 +0.12/条（低危害，上限封顶防过度放大）
    s = 0.5
    n_dec = _count(blob, DEC)
    n_inc = _count(blob, INC)
    if n_dec:
        s -= 0.25 * n_dec
        hits.append(f"减安词×{n_dec}（安全分-，权重-0.25/条）")
    if n_inc:
        s += 0.12 * n_inc
        hits.append(f"加安词×{n_inc}（安全分+，权重+0.12/条）")
    # 补丁类型权重（add/tighten +0.08；relax/remove -0.10）
    if ptype in ("add_rule", "add_policy", "tighten"):
        s += 0.08
        hits.append("add/tighten 类（安全分+0.08）")
    elif ptype in ("relax", "remove_rule", "loosen"):
        s -= 0.10
        hits.append("relax/remove 类（安全分-0.10，需看内容）")

    # ── 效用分 U：基线 0.8（默认补丁为针对性收敛，不降低效用）──
    # 权重依据：过度限制 -0.35/条（高危害，效用保护优先）
    #           最小补丁 +0.05（局部改写提高效用）
    #           宽泛改写 -0.10（疑似一刀切）
    u = 0.8
    n_ovr = _count(blob, OVR)
    if n_ovr:
        u -= 0.35 * n_ovr
        hits.append(f"过度限制词×{n_ovr}（效用分-，权重-0.35/条）")
    # P1-23（第二轮审计 W-R1）：结构化 tool_policy 的全局封锁检测——
    # after 是 JSON（{"tool":"*","deny":["*"]}）时文本模式 "deny all" 匹配不到，
    # 导致 lockdown 补丁 S 提升而 U 不变、正常基线也过闸写回（护栏可被锁死）。
    # 解析 JSON 后检查 tool/deny 通配符 → 过度限制惩罚。
    try:
        obj = json.loads(after)
        if isinstance(obj, dict):
            t = obj.get("tool")
            d = obj.get("deny")
            # 全局封锁：tool=="*"（封锁所有工具）或 tool 缺失且 deny 含 "*"；
            # {"tool":"Bash","deny":["*"]} 是针对性收紧（Bash 全拒），不算全局封锁
            locked = (t == "*") or ((not t) and isinstance(d, list) and "*" in d)
            if locked:
                u -= 0.35
                hits.append("结构化全局封锁（tool/deny 通配符，效用分-0.35）")
    except (json.JSONDecodeError, TypeError):
        pass
    # 最小补丁度：有 before/after 局部 + 轨迹支撑 → 效用更高
    n_min = _count(blob, MIN)
    if n_min >= 2:
        u += 0.05
        hits.append(f"最小补丁信号×{n_min}（效用分+0.05）")
    # 副作用面：before 为空且 after 很长 → 可能一刀切
    if (not before.strip()) and len(after) > 120:
        u -= 0.10
        hits.append("无 before 且 after 冗长（疑似宽泛改写，效用分-0.10）")

    s = max(0.0, min(1.0, round(s, 3)))
    u = max(0.0, min(1.0, round(u, 3)))
    return s, u, hits


def call_llm_scorer(cmd_template: str, patch_path: str) -> tuple[float, float] | None:
    """调用外部评分命令（小模型）。stdout 需为单行/单块 JSON {s,u}。失败返回 None。
    P1 修复：禁止 shell=True（防命令注入）；JSON 解析用严格模式并校验顶层字段。
    P1-17 加固：命令可执行文件必须存在（防拼写错误/路径被删导致执行意外命令）；
              每次调用打印强警告——llm-scorer 会执行任意命令，信任边界在调用方。
    """
    _METRICS.llm_runs += 1
    t0 = time.time()
    # shell=True 移除：把模板按空白切分为 argv（不支持子 shell）
    try:
        import shlex
        argv = shlex.split(cmd_template.replace("{patch}", patch_path))
    except ValueError:
        sys.stderr.write("[score_patch] llm-scorer 模板含未闭合引号，忽略。\n")
        _METRICS.llm_failures += 1
        return None
    if not argv:
        sys.stderr.write("[score_patch] llm-scorer 模板为空，忽略。\n")
        _METRICS.llm_failures += 1
        return None
    if not os.path.exists(argv[0]):
        sys.stderr.write(f"[score_patch] llm-scorer 可执行文件不存在：{argv[0]}，忽略。\n")
        _METRICS.llm_failures += 1
        return None
    sys.stderr.write("[score_patch] 警告：llm-scorer 将执行外部命令 "
                     f"{argv[0]} —— 该命令可执行任意操作，请确保来自可信来源。\n")
    try:
        out = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    except Exception as e:
        sys.stderr.write(f"[score_patch] llm-scorer 执行失败，回退启发式: {e}\n")
        _METRICS.llm_failures += 1
        return None
    elapsed = round(time.time() - t0, 3)
    # 严格解析：逐行找单行 JSON，避免贪婪匹配多花括号块
    for line in out.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(j, dict) or "s" not in j or "u" not in j:
            continue
        try:
            s, u = float(j["s"]), float(j["u"])
            logger.info(f"[score_patch] llm-scorer 完成，耗时 {elapsed}s，返回 s={s}, u={u}")
            return s, u
        except (TypeError, ValueError):
            continue
    sys.stderr.write("[score_patch] llm-scorer stdout 无合法 {s,u} 行，回退启发式。\n")
    _METRICS.llm_failures += 1
    return None


def get_memory_usage_mb() -> float:
    """返回当前进程的内存占用（MB，近似值）。"""
    try:
        import resource
        usage = resource.getrusage(resource.RUSAGE_SELF)
        # ru_maxrss 在 Linux 是 KB，macOS 也是 KB；Windows 不可用
        return round(usage.ru_maxrss / 1024, 2)
    except Exception:
        try:
            import psutil
            return round(psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024, 2)
        except Exception:
            return 0.0


def main():
    ap = argparse.ArgumentParser(description="安全护栏补丁评分器")
    ap.add_argument("--version", action="version", version="%(prog)s 1.1.0")
    ap.add_argument("--candidate-patch", required=True, help="候选补丁 JSON 路径")
    ap.add_argument("--harness", help="当前护栏文件(yaml/json)，可选")
    ap.add_argument("--s-current", type=float, help="基线安全分(可选)")
    ap.add_argument("--u-current", type=float, help="基线效用分(可选)")
    ap.add_argument("--llm-scorer", help="外部评分命令模板，{patch} 替换为补丁路径(可选)")
    ap.add_argument("--show-metrics", action="store_true", help="输出 metrics 统计后退出")
    args = ap.parse_args()

    if args.show_metrics:
        print(json.dumps({
            "metrics": _METRICS.to_dict(),
            "regex_cache": _RE_CACHE.stats(),
            "memory_mb": get_memory_usage_mb(),
        }, indent=2, ensure_ascii=False))
        return

    patch = json.load(open(args.candidate_patch, encoding="utf-8"))

    s_cur = args.s_current
    u_cur = args.u_current

    if args.llm_scorer:
        llm = call_llm_scorer(args.llm_scorer, args.candidate_patch)
        if llm:
            s_can, u_can = llm
            heuristic_hits = ["外部 LLM scorer 采纳"]
        else:
            s_can, u_can, heuristic_hits = heuristic_score(patch)
    else:
        s_can, u_can, heuristic_hits = heuristic_score(patch)

    out = {
        "s_candidate": s_can,
        "u_candidate": u_can,
        "s_current": s_cur,
        "u_current": u_cur,
        "delta_s": round(s_can - s_cur, 3) if s_cur is not None else None,
        "delta_u": round(u_can - u_cur, 3) if u_cur is not None else None,
        "heuristic_hits": heuristic_hits,
        "verdict_hint": ("ACCEPT 倾向" if (s_can > (s_cur or 0)) and (u_can >= (u_cur or 0))
                         else "REJECT 倾向"),
        "metrics": _METRICS.to_dict(),
        "regex_cache": _RE_CACHE.stats(),
        "memory_mb": get_memory_usage_mb(),
    }
    print(json.dumps(out, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()