# 自动化钩子接线示例（接入方式 B）

> 测评反馈：自动化触发的「实际使用场景」说明偏少。本文件给出**可直接照抄**的接线模板，
> 把 monitor-panel / 定时任务 / 任意外部系统检测到的异常事件接入 `evolve_trigger.py`，跑完整进化环。

---

## 1. 最小可跑（命令行一次触发）

```bash
python scripts/evolve_trigger.py \
  --event '{"type":"tool_dispatch","tool_name":"Bash","reasons":["honeytool touch","canary echo"],"trust":"untrusted"}' \
  --harness harness.json \
  --backup-dir backups \
  --reject-pool reject_pool.json \
  --dry-run            # 先只评+判，不写回
```

确认输出 `judge.verdict == "ACCEPT"` 且 `apply` 建议正确后，去掉 `--dry-run` 并加 `--auto-apply` 才真正写回：

```bash
python scripts/evolve_trigger.py \
  --event event.json \
  --harness harness.json --backup-dir backups --reject-pool reject_pool.json \
  --auto-apply --operator monitor-panel
```

---

## 2. 事件三形态（--event 取值）

| 形态 | 传什么 | 触发后行为 |
|---|---|---|
| 拦截事件 | JSON（含 `tool_name`/`reasons` 或 `type:tool_dispatch`）或 JSON **字符串** | 映射为 tool_policy / rule_bank 补丁 |
| 自由文本告警 | 普通字符串，如 `"Agent 越权调用了未授权工具"` | 按关键词（越权/注入/外泄…）映射补丁 |
| 直接 candidate | 含 `target_artifact`+`patch_type`+`after` 的 JSON | 原样过闸 |

> `--event` 的字符串参数：先尝试 `json.loads`，失败才当自由文本——所以「拦截事件 JSON 字符串」能正确识别，不会被误送到文本映射器。

---

## 3. monitor-panel 联动（推荐）

monitor-panel 检测到以下信号时，调用本 skill（见 monitor-panel SKILL.md 的「安全护栏联动」章节）：

- 自愈反复失败（同一失败模式 2 轮未解）
- agent 日志出现越权 / 注入迹象
- 用户上报 Agent 行为异常

**接线模板**（monitor-panel 侧）：

```yaml
on_security_event:
  - match: [privilege_escalation, injection, data_exfil, anomaly]
    action:
      - run: "python scripts/evolve_trigger.py
              --event '{{event_json}}'
              --harness harness.json
              --backup-dir backups
              --reject-pool reject_pool.json
              --dry-run"
        capture: stdout            # 解析 judge.verdict
      - if: "verdict == 'ACCEPT'"
        run: "... --auto-apply --operator monitor-panel"
      - else:
        notify: "护栏拒绝自动修复，转人工审核（见 reject_pool.json）"
```

---

## 4. 定时巡检（cron / 任务计划）

把「收集到的失败轨迹」攒成事件文件，定时跑：

```bash
# Linux crontab：每 10 分钟巡检一次待处理异常事件
*/10 * * * *  cd /path/to/skill && python scripts/evolve_trigger.py \
  --event ./inbox/latest_event.json \
  --harness harness.json --backup-dir backups --reject-pool reject_pool.json \
  --auto-apply --operator cron >> ./logs/heal.log 2>&1
```

> ⚠️ 自动 `--auto-apply` 前，建议先用 `--dry-run` 观察若干轮，确认判定符合预期再放开写回。

---

## 5. 接你自己的 Agent 框架（wrap_tool_dispatch / on_input）

`harness_hooks.py` 暴露可直接挂载的回调，无需本 skill 自己起服务：

```python
from harness_hooks import HoneytoolRegistry, RingBus, ingest_probe, wrap_tool_dispatch, make_honeytoken
import evolve_guard as EG, evolve_trigger as ET

registry = HoneytoolRegistry()
registry.register("send_email_exfil", "decoy exfil tool")   # 注册 honeytool
bus = RingBus(log_path="./logs/hook.jsonl")

# 挂到你的 Agent 的「用户输入」切面
def on_input(text):
    r = ingest_probe(text, trust="untrusted", canaries=[make_honeytoken()])
    bus.emit({"type":"ingest","verdict":r["verdict"],"reasons":r["reasons"]})
    return r

# 挂到「工具调度」切面；命中即落成 candidate 并触发进化环
def tool_dispatch(tool_name, args, trust="untrusted"):
    evt = wrap_tool_dispatch(tool_name, args, registry, trust=trust)
    bus.emit(evt)
    if not evt["allowed"]:
        ET.run_trigger(EG.types.SimpleNamespace(
            event=evt, harness="harness.json", backup_dir="backups",
            reject_pool="reject_pool.json", dry_run=True, operator="my-agent"))
    return evt
```

命中事件经 `sample_to_candidate` 自动落成 candidate → 走评分/判定/写回全流程。

---

## 6. 输出怎么解析（stdout JSON）

`evolve_trigger.py` 的 stdout 是**结构化 JSON**（内部 judge/apply 日志已重定向到 stderr）：

```json
{
  "ok": true,
  "event": {...},
  "candidate": {"target_artifact":"tool_policy","patch_type":"add_rule","after":"{...}"},
  "diagnosis": {"failure_type":"...","zi":{...},"routing":{...}},
  "score": {"s_candidate":0.9,"u_candidate":0.85,"hits":[...]},
  "judge": {"verdict":"ACCEPT","rc":0},
  "apply": {"rc":0,"applied":true} | {"skipped":"dry-run"} | null
}
```

调用方读 `judge.verdict` 决定后续，读 `apply.applied` 确认是否写回。
