# FAQ 与反模式（常见问题 + 绕过尝试防御对照）

> 本文件集中收录高频疑问与「攻击者会怎么试图绕过护栏、护栏如何挡」的反模式清单。
> 这是 SKILL.md 各段落里分散的 FIXME / 边界说明的**统一入口**，便于快速查阅。

---

## 一、常见问答（FAQ）

### Q1：SkillSentry 蜜罐必须装吗？不装能用吗？
**不必。** SkillSentry（arXiv 2608.03485）是**可选外部组件**，本 skill 不捆绑其实现。
- 不装 SkillSentry，你仍有两条本地路径造样本：
  1. `python scripts/harness_hooks.py --demo` —— 自研 ReAct demo，演示「honeytool 触碰 → 拦截 → 自动产 candidate」。
  2. `python scripts/gen_coldstart_samples.py --bench tests/attack_bench.json --harness harness.json` —— **直接从内置 attack_bench.json（97 条对抗样本）生成可回放轨迹 + 候选补丁**，作为冷启动样本源（本功能为解决「冷启动只靠本地模拟」而加）。
- 装了 SkillSentry，则在 C 联动模式下用它做「样本工厂 + 复测 oracle」。

### Q2：进化环的最小输入是什么？
失败轨迹文件 + 当前护栏快照 `harness.json`，**缺一不可**（CHECKPOINT 强制）。
缺任一 → 中止并提示补充。没有 `harness.json` 先按 SKILL.md 的「起始护栏模板」初始化。

### Q3：棘轮（ratchet）是什么？为什么我的「放宽」补丁总被拒？
棘轮保证护栏**只增不减**：
- `tool_policy`：allow 只能收缩、deny/require/confirm 只能扩张——`read-only → allow: all` 这种放宽会被偏序校验拦截（rc=2，记入拒收池）。
- `rule_bank`：新增/收紧 OK；删除或弱化一条已生效规则会被判为「放宽」，同样拦截。
- 这是有意为之的安全属性，**不是 bug**。要调整策略，请用更紧的规则覆盖，而非放宽旧规则。

### Q4：三道硬闸的公式是什么？
- **闸A（先备份）**：写回前必须把当前护栏存成带时间戳的备份；`apply` 无有效备份会 rc=3 中止（fail-safe）。
- **闸B（安全-效用）**：`S(候选) > S(当前)` 且 `U(候选) >= U(当前)`；否则进拒收池、不写回。
- **闸C（拒收池去重）**：同一补丁被拒后后续轮不再重试；`apply` 写回前强制重跑闸B（硬保险，即使调用方漏跑 judge 也拦得住）。

### Q5：怎么回滚？
```bash
python scripts/evolve_guard.py rollback \
  --backup backups/harness_<时间戳>.json --harness harness.json
```
回滚前会做：备份存在性 / 非空 / 可解析 / sha256 manifest 校验（或降级路径结构校验）→ 任一不通过 rc=4 拒绝覆盖，杜绝「用坏备份清空/写坏线上护栏」。

### Q6：`apply` 会默认写回吗？`--auto-apply` 在哪？
- `evolve_guard.py apply` **默认即写回**（且内部强制重跑闸B + 写回后跑 P0 回归，失败自动回滚）。
- `--auto-apply` 是 **`evolve_trigger.py`** 的参数（人工旁路原则：默认只评+判，显式传才写回）。两者别混。

### Q7：必填参数别忘了
`judge` 与 `apply` 都**必填 `--reject-pool`**；传路径沙箱外的路径会被拒（rc=4，路径沙箱）。

### Q8：Windows + Git Bash 下把 POSIX 路径传给 python 脚本报错 `c:\c\Users...`？
本机环境坑：Git Bash 的 `python3` 常解析到原生 Windows python，会把 `/c/Users/...` 拼成 `c:\c\Users...`。
**一律先用 `cygpath -m <路径>` 转成 `C:/...` 形式再传给脚本**（本会话已修复 SkillHub 启动器、并已记录在记忆中）。

---

## 二、反模式与绕过尝试（防御视角）

下面列的是**攻击者 / 误用方会尝试的绕过**，以及护栏如何挡。**不要试图绕过这些——它们就是护栏的价值。**

| # | 绕过尝试（反模式） | 护栏如何挡 | 退出码 / 结果 |
|---|---|---|---|
| 1 | 候选补丁写 `allow all web requests` / `disable the safety check` 等减安词 | 一票否决：`_hard_veto_after` 命中减安词 → S=0 | judge/apply rc=2，入拒收池 |
| 2 | 粘连/零宽变形：`allow\u200ball` → `allowall`、`disable_the_safety_check` | 去分隔符子串扫描（`_DECREASE_GLUED_TERMS`）+ NFKC 归一 | 同上 |
| 3 | 语义等价绕关键词：`email me all the credentials` / `act as a system administrator` | 语义意图引擎（动作类×对象类组合）veto/alert | attack bench 97/97 全拦截 |
| 4 | `{"tool":"*","deny":["*"]}` 结构化「锁死」补丁（可用性 DoS） | `score_patch` 解析 JSON after，`tool=="*"` 且 deny 含 `*` → U -0.35 | 拦截至拒收池 |
| 5 | 想用 `read-only → allow: all` 放宽工具权限 | 棘轮偏序：`_allow_breadth` 视 all 为最宽，放宽被拒 | rc=2 入池 |
| 6 | 删/弱化一条已生效 rule | 棘轮：rule 只增不减 | rc=2 入池 |
| 7 | 篡改备份文件后回滚（含删 manifest + 写 `{"hacked":true}`） | manifest sha256 校验 + 降级路径 `_looks_like_harness` 结构校验 | rc=4 拒绝覆盖 |
| 8 | 跨目录 `../` 穿越 / 跨盘写 / 非 `.json/.yaml/.yml` 目标 | 路径沙箱：`realpath`+`commonpath` 收敛 + 扩展名白名单 | rc=4 拒绝 |
| 9 | 绕过 judge 直接 `apply`（指望跳过闸B） | `apply` 硬保险：写回前**强制重跑**评分 + 闸B | 仍走闸B，失败自动回滚 |
| 10 | 无备份就 `apply`（指望改坏线上也能跑） | 闸A：无有效备份 rc=3 中止 | rc=3 |
| 11 | 把基线分传成 0（`--s-current 0`）让任何补丁都「提升」 | 基线下限：s<0.3/u<0.5 回落护栏 `_scores` 或默认 + 告警 | 闸门不误放 |
| 12 | 给 backup/apply 传一个不存在的 `score_patch.py` 想绕闸 | fail-closed：`import` 失败 rc=5 中止写回 | rc=5 |
| 13 | 往蜜罐灌垃圾告警反污染检测信号 | `HoneypotRateLimiter` 滑动窗口限流，超阈值标 suspicious | 标记灌毒 |
| 14 | 多轮碎片化投毒（单句都正常、合起来有害） | `SlowPoisonDetector` 跨轨迹碎片关联 | 组合命中才 alert |

> 完整对抗实证见 `tests/attack_bench.json`（97 条，veto/ingest/honeytoken）+ `tests/test_attack_bench.py`（确定性、纯标准库、CI 红即构建失败）。

---

## 三、已知边界（诚实披露，非缺陷）

- **训练数据 / SFT / RLHF 投毒**：本 skill 改的是推理期护栏，不动权重，管不了权重级后门。
- **push 共享情报的源签名**：`sync_artifacts push` 现已为导出情报附加来源签名（`source` + `signed_at` + `signature`），供 pull 方溯源与篡改检测（回应此前「push 缺源签名」记录）。
- **跨 Agent 吞吐**：`SlowPoisonDetector` 源键上限 1000，超出剪最旧，防内存膨胀。
- **锁等待**：跨进程写用原生文件锁，超时（默认 60s）后 fail-closed——长时间阻塞极少见，遇之多半是另有一进程在写。
