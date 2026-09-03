# 速查卡（一页纸 + 概念图）

> 测评反馈：核心概念多、SKILL.md 偏长，初次上手成本偏高。本卡把「四工件 / 三道闸 / 7 步闭环 /
> 常用命令 / 退出码」压成一页，配一张概念图，先读这张再深入 SKILL.md。

---

## 概念图

```
                        失败轨迹 / SkillSentry 对抗样本
                                  │
                                  ▼
        ┌─────────────────── 测 → 诊 → 改 → 验 自愈闭环 ───────────────────┐
        │                                                                   │
        │   ① 收集轨迹+护栏快照        ② RiskRelevant 过滤(只留安全失败)      │
        │            │                            │                          │
        │            ▼                            ▼                          │
        │   ③ 结构化诊断 zi + 路由 ri ──► 定位责任工件                        │
        │            │                                                          │
        │            ▼                                                          │
        │   ④ 生成补丁(针对路由到的工件)  ⑤ ValidEdit 格式校验 ──fail──► 拒收池 │
        │            │                                                          │
        │            ▼                                                          │
        │   ⑥ 安全-效用闸门 S↑ 且 U≥ ──fail──► 拒收池(闸B)                    │
        │            │                                                          │
        │            ▼                                                          │
        │   ⑦ 写回: 先备份(闸A) → 合并工件 → 写回后重跑 P0 回归 (失败自动回滚)  │
        └───────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
                    护栏四工件(独立演化, 哪里坏修哪里)
        ┌──────────────┬──────────────┬────────────────┬─────────────────┐
        │ 系统提示      │ 规则库        │ 安全记忆        │ 工具策略         │
        │ System Prompt│ Rule Bank    │ Safety Memory  │ Tool Policy     │
        │ 全局行为契约  │ 显式安全规则  │ 反复失败后的    │ 工具权限+运行时  │
        │              │ (首攻切入点)  │ 对比性边界      │ 强制             │
        └──────────────┴──────────────┴────────────────┴─────────────────┘
                                  │
                                  ▼
                    三道硬闸(不可跳过, 只增不减/棘轮)
        ┌──────────────┬──────────────────────┬────────────────┐
        │ 闸A 先备份    │ 闸B 安全-效用         │ 闸C 拒收池去重   │
        │ 无备份不写回   │ S候选>S当前 且 U≥      │ 同补丁不再重试   │
        │ rc=3 中止     │ 否则入池(硬保险重跑)   │ 上限 K 轮熔断     │
        └──────────────┴──────────────────────┴────────────────┘
```

---

## 四工件 vs 典型补丁

| 工件 | 管什么 | 补丁类型 |
|---|---|---|
| System Prompt | 全局行为契约（来源层级/能力边界/信任承诺） | `prompt_diff` |
| Rule Bank | 显式规则（危害标签/触发/干预动作/豁免/优先级） | `add_rule` / `modify_rule` |
| Safety Memory | 反复未解的对比性边界（冷启动保护：2 轮未解才写） | `write_memory` |
| Tool Policy | 工具权限与运行时强制（收紧/加 detector） | `tighten_tool` |

---

## 常用命令（记忆法：备→评→判→写→回）

```bash
# 1) 监控切面截到越权 → 自动产 candidate
python scripts/harness_hooks.py --demo

# 2) 评分（启发式正则，可选 --llm-scorer）
python scripts/score_patch.py --candidate-patch patch.json --s-current 0.60 --u-current 0.80

# 3) 闸门判定（ValidEdit + 一票否决）
python scripts/evolve_guard.py judge --candidate-patch patch.json \
  --s-current 0.60 --u-current 0.80 --s-candidate 0.70 --u-candidate 0.85 \
  --reject-pool reject_pool.json

# 4) 写回前先备份（闸A；缺此步 apply rc=3 中止）
python scripts/evolve_guard.py backup --harness harness.json --backup-dir backups

# 5) 写回（内部强制重跑闸B + 写回后跑 P0 回归，失败自动回滚）
python scripts/evolve_guard.py apply --harness harness.json \
  --candidate-patch patch.json --backup-dir backups --reject-pool reject_pool.json

# 回滚
python scripts/evolve_guard.py rollback --backup backups/harness_<ts>.json --harness harness.json
```

---

## 退出码速查（rc）

| rc | 含义 | 你该做什么 |
|---|---|---|
| 0 | 成功 | 无需处理 |
| 1 | 一般性错误（如 P0 回归测试文件缺失） | 看 stderr 具体报错 |
| 2 | 闸B/格式拒绝：补丁被拒收池收录 | 看 reason；这是**预期的安全拦截**，不是坏结果 |
| 3 | 中止：无有效备份 / 拒收池达上限 | 先 `backup` 再 `apply`；上限则人工审核 |
| 4 | 路径沙箱/回滚拒绝：越界、扩展名非法、备份损坏/被篡改 | 检查路径是否越界、备份是否完好 |
| 5 | 缺 `score_patch.py` 无法重跑闸B（fail-closed） | 确认脚本同在 scripts/ 目录 |
| 6 | 写回后 P0 回归未过，已自动回滚 | 护栏未被改弱，检查补丁质量 |
| 7 | 诊断 schema 非法（元数据问题，不进池） | 修正 diagnosis 后重试，同内容可重试 |

---

## 一句话心智模型

> **护栏 = 四工件；进化 = 测诊改验；安全 = 三道闸 + 棘轮（只增不减）。**
> 任何想「放宽」护栏的补丁都会被棘轮或一票否决拦下——这是设计目标，不是 bug。
