# 完整架构规格（unclekk-safety-harness-evolution）

> 本文是 SKILL.md 的渐进式披露补充：四工件映射、进化环伪码、三闸判定、SkillSentry 冷启动、Rule Bank schema、集成映射、局限风险。
> 基于 SHE 方法论四工件分解 + 归因引导进化环；与 SkillSentry（arXiv 2608.03485）组成「预防 + 检测」双层框架。SHE 方法论参考 ARIS 论文（arXiv 2608.09885）。

---

## 元信息

| 字段 | 值 |
|------|-----|
| Skill 名称 | `unclekk-safety-harness-evolution` |
| 别名 | `she-hardener` |
| 触发场景 | 多 Agent 运行出现越权/失败案例；或 SkillSentry 蜜罐测出风险后自动进入硬化流程 |
| 输入 | Agent 运行轨迹日志（含失败/越权样本）+ 当前四工件快照 |
| 输出 | 进化后的护栏工件补丁 + 验证报告 + 写回确认（含备份路径） |
| 依赖 | `skills-security-check`（P0/P1/P2 分级）、`cross-agent-memory`（共享记忆）、可选 `skill-skillsentry-safety`（蜜罐复测） |

---

## 四工件 × KK 现有资产映射

| 工件 | 管什么 | KK 现有资产映射 | 补丁类型 |
|------|--------|-----------------|----------|
| 系统提示 System Prompt | 全局行为契约：来源层级、能力边界、信任边界承诺 | SOUL.md / IDENTITY.md / 各 Agent 系统提示 | prompt diff（文本替换） |
| 规则库 Rule Bank | 显式安全规则：风险标签、触发条件、干预动作(allow/warn/block/sanitize/judge)、良性豁免、优先级 | `skills-security-check` P0/P1/P2 规则集 | 新增/修改一条 rule 记录 |
| 安全记忆 Safety Memory | 失败反复未解后的对比性边界：{有害/良性行为}{已阻断/已放行}+源轨迹+置信度+状态 | cross-agent-memory 共享记忆、MEMORY.md | 写入一条对比性经验条目 |
| 工具策略 Tool Policy | 工具权限与运行时强制：检查位置、覆盖工具、触发条件、决策、恢复动作 | 各 skill 的 allowed_tools 白名单 | 收紧权限 / 加 detector 记录 |

### 安全记忆写入硬约束
- 失败模式经过 **2 轮进化仍未解决**；或
- 改完工件后 **同一失败模式复发**。
> 否则不写，避免污染 Safety Memory（论文原文确认的冷启动保护机制）。

---

## 进化环主流程（事件驱动，非轮询）

```
触发：收到失败/越权轨迹 traj_fail
       或 SkillSentry 蜜罐产出对抗样本
  │
  ① 收集轨迹与快照：正常轨迹 traj_norm（效用基线）+ 当前护栏快照
  ② RiskRelevant 筛选：只筛「安全相关失败」，正常轨迹不进诊断 → 第 k 轮失败集
  ③ 结构化诊断 zi + 工件路由 ri：三维度（危害域 × 攻击面 × 失败模式）→ 定位责任工件（或小工件集）
  ④ Edit 生成补丁：针对路由到的工件做 prompt diff / 加 rule / 写 memory / 收紧 tool 权限
  ⑤ ValidEdit 合法校验：补丁格式是否合法？ 否→拒收池
  ⑥ 安全-效用闸门（公式9）：S(候选) > S(当前) 且 U(候选) >= U(当前)？ 否→拒收池
  ⑦ 写回 + 备份：保存当前最优护栏 + 补丁，留回滚快照
```

---

## 三道硬闸（不可跳过）

| # | 闸门 | 判定标准 | 不通过处理 |
|---|------|----------|-----------|
| A | 先备份 | 写回前必须保存当前护栏到带时间戳的备份文件 | 未备份则中止 |
| B | 安全-效用验证 | S(候选) > S(当前) 且 U(候选) >= U(当前) | 进拒收池，不写回 |
| C | 拒收池去重 | 同一补丁被拒后后续轮不再重试（拒收池缓冲） | 自动跳过 |

> 三道闸与现有 `skills-security-check` 的 P0/P1/P2 分级 + 可回滚原则天然吻合。做 SKILL 时必须原样保留。

> **硬保险**：`evolve_guard.py apply` 内部**强制重跑 评分 + 闸 B**，不依赖调用方先跑 `judge`。即使某条链路漏跑 judge，`apply` 也会独立复判安全-效用闸门，杜绝绕闸直接改坏护栏。当前基线分读取优先级：CLI `--s-current/--u-current` → 护栏内 `_scores` → 启发式基线（0.5/0.8，会告警降级）；若 `score_patch.py` 缺失则 fail-closed 返回 5 中止写回。

---

## 冷启动方案（破「无失败不转」死锁）

SHE 论文从轻量种子起步（1 条 safety-memory），但**无失败样本则进化环不转**。

### K 轮上限编码

为防止进化震荡（反复改来改去），`evolve_guard.py judge` 支持 `--max-rounds` 参数。
超过上限后直接返回 rc=3，中止进化并建议人工审核。默认上限 20 轮。

```bash
# 限制进化轮次
python evolve_guard.py judge --candidate-patch patch.json \
    --s-current 0.60 --u-current 0.80 \
    --s-candidate 0.85 --u-candidate 0.82 \
    --reject-pool reject_pool.json --max-rounds 20
```

### 用 SkillSentry 蜜罐主动造对抗样本（可选）

> ⚠️ **边界声明**：SkillSentry 是**可选外部组件**，本 skill 未实现其集成。
> 以下指标来自 arXiv 2608.03485 论文，仅作为设计参考。本 skill 的冷启动通过
> `run_react_demo()` 本地模拟事件，而非真实 SkillSentry 集成。

蜜罐不是拍脑袋补丁，而是有学术依据：SkillSentry（Adaptive Honeypot Worlds for Dynamic Agent Skill Safety）用「自适应蜜罐世界 + 受控诱饵资源 + 行为归因（启用 vs 无技能执行对比）」在技能接入前动态探边界，标准基准达 **99.50% Recall / 96.26% F1**。它和 SHE 共享「行为归因」底座，正好构成「预防（SHE）+ 检测（SkillSentry）」双层。

**SkillSentry 身兼两职**：
1. **SHE 的样本工厂**——破冷启动，主动造对抗样本喂进化环
2. **SHE 的复测 oracle**——硬化完成后用蜜罐重新测试，确认改好了

### 本地替代方案：run_react_demo

本 skill 提供 `run_react_demo()` 作为本地模拟方案，展示「honeytool 触碰 → 拦截 → 自动产 candidate」流程。

```
SkillSentry 蜜罐世界
  ├── 推断技能能力边界
  ├── 维护行为状态图
  ├── 针对未探/风险状态迭代生成任务逼边界
  │
  ├── 开启技能轨迹 vs 无技能轨迹 对比
  │     └─ 锚定越界行为 + 源码定位
  │
  └── 产出：(任务, 环境, 越界轨迹) 对抗样本
          │
          当作 SHE 的失败轨迹输入 → 打通冷启动
```

**SkillSentry 身兼两职**：
1. **SHE 的样本工厂**——破冷启动，主动造对抗样本喂进化环
2. **SHE 的复测 oracle**——硬化完成后用蜜罐重新测试，确认改好了

---

## Rule Bank 首攻策略（推荐切入点）

| 理由 | 说明 |
|------|------|
| 粒度最细 | 每条规则独立，增删改不影响其他规则 |
| 可枚举 | P0/P1/P2 已有现成分级体系，直接映射 |
| 副作用最小 | 改一条 rule ≠ 改 system prompt 全文 |
| 可审计 | 每条 rule 有优先级+支撑轨迹，变更可追溯 |

### Rule Bank 记录 Schema（从论文附录 C 提取）

```yaml
rule_record:
  risk_labels: [data_exfiltration, privacy]          # 危害标签
  condition: "agent attempts to install packages"      # 触发条件
  intervention: block                                  # 干预动作: allow/warn/block/sanitize/judge
  rationale: "device-level execution beyond scope"     # 理由
  benign_exemption: "official store recommendations"   # 良性豁免
  priority: P1                                         # 优先级
  supporting_trajectories: [traj_047, traj_089]        # 支撑轨迹 ID
```

---

## 事件驱动接入点设计

### 接入方式 A：手动触发
用户提供失败轨迹文件 → 调用本 SKILL → 输出诊断报告 + 补丁建议

### 接入方式 B：自动化钩子（推荐）
```
monitor-panel 检测到越权/异常
   → 触发 unclekk-safety-harness-evolution
   → 自动诊断 + 生成补丁 + 验证
   → 通过三道闸后自动写回
   → 回报结果给 monitor-panel
```

### 接入方式 C：SkillSentry 联动闭环（可选）

> **注意**：SkillSentry 是外部组件，需单独部署。

```
SkillSentry 蜜罐测出风险
   → 产出对抗样本
   → 喂给 unclekk-safety-harness-evolution
   → 进化环生成补丁 → 验证 → 写回
   → 回传 SkillSentry 复测
   → 复测通过 → 闭环完成
   → 复测未过 → 回到进化环再跑一轮
```

### 本地替代方案：run_react_demo

本 skill 提供 `run_react_demo()` 作为本地模拟方案，展示「honeytool 触碰 → 拦截 → 自动产 candidate」流程。

### 监控自动喂样本（harness_hooks.py）
运行期把 `harness_hooks.py` 的 `ingest_probe` / `wrap_tool_dispatch` 挂到 Agent 的 input 与 tool_dispatch 切面：
- 命中（canary 回显 / 注入模板 / honeytool 触碰 / honeytoken 外发 / ToolPolicy 违反）→ 事件进 RingBus（内存 ring + 可选落盘 jsonl）
- `sample_to_candidate(event)` 把命中事件自动落成 candidate patch JSON（target_artifact 默认 rule_bank）
- 该 candidate 直接喂 `score_patch.py` + `evolve_guard.py judge`，无需人工从日志挖样本
- 对 LangGraph 用 `langgraph_adapters(registry, bus, canaries)` 拿 on_input / tool_dispatch 回调即可挂载，无需 import langgraph
- 自研 ReAct 框架：`run_react_demo()` 即为可跑示例，展示「honeytool 触碰 → 拦截 → 自动产 candidate」
```

---

## 输出产物规范

每次进化运行产出：

| 产物 | 格式 | 内容 |
|------|------|------|
| 诊断报告 | Markdown | {失败摘要, 三维度诊断 zi, 工件路由 ri, 置信度} |
| 候选补丁 | YAML/JSON | {target_artifact, patch_type, before, after} |
| 验证结果 | 表格 | {S_before, S_after, U_before, U_after, pass/fail} |
| 写回记录 | 日志条目 | {timestamp, artifact, action, backup_path, rollback_cmd} |
| 拒收池快照 | JSON | 拒收池当前内容（供审计） |

---

## 局限与已知风险

| 风险 | 缓解措施 |
|------|----------|
| 归因可能不准（多工件耦合故障） | 允许路由到「小工件集」而非单一工件；人工审核高风险补丁 |
| 进化震荡（反复改来改去） | 拒收池去重 + 安全-效用双向闸门；K 轮上限（建议 20） |
| 过拒（over-refusal）— 把正常活儿也拦了 | 效用指标 U 必须不降才通过；Clean UBR 监控 |
| 自动改坏线上 harness | 三道闸 + 本地备份 + 回滚命令一键可用 |
| 论文未披露精确切分边界案例 | 从 AgentHarm/SafetyBench 基准补充更多 case study |
| 训练/SFT/RLHF 数据投毒 | SHE 改推理期护栏、不动权重，管不了权重级后门；须另走数据溯源/签名/隔离训练 |
| 慢毒/历史投毒 | 多轮把恶意指令拆成无害碎片写进记忆，单轮不触蜜罐；靠 Safety Memory 边界 + 蜜罐凭据监控缓解，非绝对 |
| 语义等价绕过 | ✅ P1-18 缓解：语义意图引擎（动作×对象组合）封掉已知 paraphrase 盲区（attack bench 97/97、gap 归零）；LLM 嵌入语义评分留作扩展口。残留：组合模式库之外的极罕见表达仍需人工/未来 LLM 层 |
| 蜜罐被识别 | 攻击者先「列出你的工具」避开假工具，或往蜜罐灌垃圾 telemetry 反污染告警；需工具名随机化+定期轮换 |
| detection-only 定位 | 多数 Agent 蜜罐方案只告警不阻断，若主 Agent 有权限且异步执行，告警到动作已发出；需阻断器 + human-in-the-loop |

---

## 与现有体系的集成映射总表

| SHE 概念 | KK 现有对应 | 集成动作 |
|----------|------------|----------|
| 规则库 Rule Bank | `skills-security-check` P0/P1/P2 | 升级为动态进化规则库；✅ 已代码化 `scripts/sync_artifacts.py pull --type security_check_rules`（从 SKILL.md 提取话术或 .json 规则 → rule_bank） |
| 安全记忆 Safety Memory | `cross-agent-memory` | 失败轨迹自动入库成安全经验；✅ 已代码化 `pull --type cross_agent_memory`（JSONL 经验 → safety_memory，注入 failed_attempts=2 过冷启动保护） |
| 工具策略 Tool Policy | skill `allowed_tools` | 越权调用自动触发收紧；✅ 已代码化 `pull --type allowed_tools`（frontmatter → tool_policy，棘轮只增不减） |
| 系统提示 System Prompt | SOUL.md / IDENTITY.md | 行为契约版本化管理（补丁走 `evolve_guard.py apply`，版本治理见 history 规划） |
| 进化环 Algorithm 1 | monitor-panel 安全审计 | 形成「测 → 诊 → 改 → 验」闭环；✅ 诊断 schema 校验（P1-15）+ 审计日志（P1-15）+ `--dry-run` 预览 |
| 拒收池 | 无现有对应 | 新建（轻量 JSON 文件即可）；✅ 结构化 `{key, reason, ts}`（P1-14） |
| 跨 Agent 情报 | 共享记忆库 / 多 Agent | ✅ `sync_artifacts.py push` 导出共享情报 JSON，其他 Agent `pull --type shared_intel` 合并（棘轮把关） |
| SkillSentry 蜜罐 | 可选外部组件 | 提供集成接口，不提供实现；冷启动可用 `run_react_demo` 本地模拟 |
