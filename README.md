---
name: unclekk-safety-harness-evolution
description: Self-evolving Safety Harness (SHE) workflow for multi-agent systems. When agents experience privilege escalation, failures, or indirect injection/poisoning, diagnose the responsible artifact, generate minimal patches, pass through three hard gates (backup / safety-utility gate / reject pool dedup), and write back to form a self-healing loop. Integrates with SkillSentry honeypot for proactive sample generation.
---

# Self-Evolving Safety Harness (SHE)

A production-ready framework for autonomous agent security hardening. Transforms static "big prompt" security constraints into a **four-artifact system** that evolves independently where failures occur.

## Core Concepts

### Four Artifacts System

| Artifact | Purpose | Patch Type |
|----------|---------|------------|
| System Prompt | Global behavior contract: source hierarchy, capability boundaries, trust commitments | `prompt_diff` |
| Rule Bank | Explicit security rules: hazard tags, trigger conditions, intervention actions | `add_rule` / `modify_rule` |
| Safety Memory | Comparative boundaries after repeated failures: {harmful/benign}{blocked/allowed} + source trajectory + confidence | `write_memory` |
| Tool Policy | Tool permissions and runtime enforcement: check location, override tools, trigger conditions | `tighten_tool` |

### Three Hard Gates (Non-skippable)

| Gate | Standard | Failure Handling |
|------|----------|------------------|
| A: Backup | Must save current harness to timestamped backup before writeback | Abort if no backup |
| B: Safety-Utility Gate | S(candidate) > S(current) AND U(candidate) >= U(current) | Reject pool, no writeback |
| C: Reject Pool Dedup | Same patch rejected → skip in future rounds | Auto-skip |

### Evolution Loop (7 Steps)

```
Trigger: Receive failure trajectory OR SkillSentry honeypot sample
  │
  ├─ ① Collect trajectory + current harness snapshot
  ├─ ② RiskRelevant filter: Only safety-related failures
  ├─ ③ Structured diagnosis + artifact routing (3D: hazard × attack surface × failure mode)
  ├─ ④ Edit: Generate patch for target artifact
  ├─ ⑤ ValidEdit: Format validation → reject pool if invalid
  ├─ ⑥ Safety-Utility gate: Score check → reject pool if fails
  └─ ⑦ Writeback + backup: Backup first, then merge into artifact
```

## Quick Start

```bash
# 1. Run monitoring hooks (canary scan + honeypot interception)
python scripts/harness_hooks.py --demo

# 2. Score candidate patch
python scripts/score_patch.py --candidate-patch patch.json \
    --s-current 0.60 --u-current 0.80

# 3. Gate judgment
python scripts/evolve_guard.py judge --candidate-patch patch.json \
    --s-current 0.60 --u-current 0.80 \
    --s-candidate 0.70 --u-candidate 0.85 \
    --reject-pool reject_pool.json

# 4. Back up current harness first (Gate A; `apply` aborts with rc=3 without it)
python scripts/evolve_guard.py backup --harness harness.json --backup-dir backups/

# 5. Writeback (auto re-runs Gate B + P0 regression after writeback; auto-rollback on failure)
python scripts/evolve_guard.py apply --harness harness.json \
    --candidate-patch patch.json --backup-dir backups/ \
    --reject-pool reject_pool.json \
    --s-current 0.60 --u-current 0.80   # optional but recommended baseline scores

# 6. Rollback if needed
python scripts/evolve_guard.py rollback --backup backups/harness_<timestamp>.json \
    --harness harness.json
```

## Architecture

See `references/architecture.md` for complete specification with pseudocode.

### Core Scripts

| Script | Purpose |
|--------|---------|
| `evolve_guard.py` | Three hard gates executor (backup / gate B / reject pool / rollback / friendly rc hints) |
| `score_patch.py` | Candidate patch scorer (heuristic regex + optional LLM) |
| `harness_hooks.py` | Runtime monitoring hooks (canary / honeypot / ToolPolicy enforcement) |
| `sync_artifacts.py` | Cross-Agent intel sync (pull/push) — push now carries a source `signature` (W-R5 fixed) |
| `gen_coldstart_samples.py` | **Local cold-start sample factory** — turns built-in benches into replayable trajectories + candidate patches, no SkillSentry required |
| `semantic_intent.py` | Semantic intent engine (action×object composition: veto / alert intents) |
| `utils.py` | Shared utilities (unicode normalization, regex compilation) |

### Docs

- `references/cheatsheet.md` — one-page concept map + quick reference (start here)
- `references/faq.md` — FAQ + anti-pattern / bypass-attempt defense table
- `references/architecture.md` — full spec (pseudocode, gate tables, integration matrix)
- `examples/automation_hook.md` — copy-paste wiring templates (monitor-panel / cron / your own framework)

### Test Coverage

- **18/18 P0 tests passing** (100% coverage)
- **97/97 attack-bench samples blocked** (100% interception rate; adversarial veto/ingest/honeytoken samples)
- **30/30 benign-bench samples passed** (100% utility pass rate; over-refusal guard — incl. 5 second-audit FP regressions: 免费/免疫/随便/无需 no longer vetoed)
- **43/43 guard-enhancement tests passing** (backup sha256 manifest + rotation; patch-key semantic dedup; structured reject pool; diagnosis JSON schema; writeback audit log; structured-lockdown U-penalty; baseline floor)
- **16/16 sync-artifacts tests passing** (cross-Agent intel pull/push, three source parsers, ratchet on external loosenings)
- **24/24 semantic-intent tests passing** (action×object intent engine; all 9 former paraphrase blind-spots now blocked; benign zero-FP)
- **21/21 L3-hardening tests passing** (rotated honeytokens, obfuscated honeytools, anti-flood limiter, slow-poison detection, O_NOFOLLOW writes, runtime-enforcement spec)
- **15/15 evolve-trigger tests passing** (access-mode-B automation loop: event→patch→diagnosis→gate→auto-apply, load-payload veto protection)
- **cold-start sample factory**: `python scripts/gen_coldstart_samples.py --selftest` (deterministic; `tests/test_coldstart_gen.py` 1 file, CI-friendly) — derives replayable trajectories + candidate patches from built-in benches (no SkillSentry needed)
- **0 known blind-spot (gap) samples remain** — the semantic intent layer closed the last paraphrase blind-spot; attack bench is 97/97
- Run: `python scripts/test_p0_regression.py` (cross-platform; no `PYTHONHOME` hack needed)
- Run: `python tests/test_attack_bench.py` (cross-platform; deterministic; no pytest needed)
- Run: `python tests/test_benign_bench.py` (cross-platform; deterministic; no pytest needed)
- Run: `python tests/test_guard_enhancements.py` (cross-platform; deterministic; no pytest needed)
- Run: `python tests/test_coldstart_gen.py` (cross-platform; deterministic; no pytest needed)

## Integration with SkillSentry

**SkillSentry** (arXiv 2608.03485) is an **optional external component** for proactive sample generation.

- **Sample factory**: Breaks cold-start by generating adversarial samples
- **Re-test oracle**: Verifies hardening with honeypot re-testing

Local alternatives (no SkillSentry required):
- `scripts/gen_coldstart_samples.py` — derives replayable trajectories + candidate patches from the built-in benches (`tests/attack_bench.json` 97 + `tests/benign_bench.json` 30); feeds directly into `evolve_trigger --event` / `judge` / `apply`.
- `run_react_demo()` in `harness_hooks.py` — single-shot "honeytool touch → intercept → candidate" demo.

## Security Features

- ✅ One-vote veto: Plaintext / zero-width / NFKC bypass detection (incl. "disable the safety check" variants, glued/deformed terms like `allow_all` / `allow\u200ball` → `allowall`)
- ✅ Attack bench: 97-sample adversarial test suite in CI — any regression in veto/ingest/honeytoken interception fails the build
- ✅ Benign bench: 25-sample utility test suite in CI — over-refusal (false-positive blocking) regression fails the build; pass rate anchors the U-score
- ✅ Backup manifest (P1-14): backups carry sha256 hashes verified on rollback (tamper/corruption → rc=4); `--max-backups` rotation keeps only the newest N
- ✅ Semantic patch-key dedup (P1-14): reject pool keys ignore case/whitespace/metadata — same semantic patch can't bypass dedup by reformatting; structured entries carry `{key, reason, ts}`
- ✅ Diagnosis schema (P1-15): LLM diagnosis must satisfy a controlled-enum JSON schema (`failure_type`/`zi`/`routing`) — machine-verifiable before writeback (invalid → rc=7, retry-able)
- ✅ Writeback audit log (P1-15): JSONL audit of every apply/judge/auto-rollback with scores, diagnosis, gate, operator (`--audit-log`, `--operator`)
- ✅ Cross-Agent intel sync (P1-16): `sync_artifacts.py` pulls rules/experience/tool-allowlists from `skills-security-check` / `cross-agent-memory` / skill `allowed_tools` / shared-intel JSONs — merging is ratchet-guarded (external loosenings like `allow: all` are rejected); `push` exports shared intel for other Agents
- ✅ Push source signature (W-R5 fixed, v1.1.15): `sync_artifacts push` now attaches a `signature` block (source + `signed_at` + sha256 digest); `sync_artifacts verify` re-checks integrity so tampered/forged shared intel is detectable — closes the previously "documented-not-fixed" gap
- ✅ Local cold-start sample factory (v1.1.15): `gen_coldstart_samples.py` turns the built-in attack/benign benches into replayable trajectories + candidate patches — the evolution loop gets real local samples without depending on the external SkillSentry component
- ✅ Semantic intent engine (P1-18): action×object class-composition (`email me all the credentials` → exfil alert, `act as a system administrator` → hijack veto) — closes the paraphrase blind-spot that regex/keyword blacklists could not; veto-class intents block patches, exfil-class intents raise non-downgradable alerts
- ✅ L3 hardening (P1-19): rotated/obfuscated honeypots (`make_honeytoken`, `register_honeytool`, anti-flood `HoneypotRateLimiter`); `SlowPoisonDetector` for multi-turn fragment injection; O_NOFOLLOW atomic writes; `compile_enforcement` + `enforce_tool` runtime-enforcement decoupling (harness↔executor consistency)
- ✅ Automation trigger (P1-21): `evolve_trigger.py` runs the full loop on a single anomaly event (intercept event / free-text alert / direct candidate) → diagnosis → score → judge → optional auto-apply with backup + audit; machine-parseable JSON output for monitor-panel integration
- ✅ Ratchet monotonicity: tool_policy/rule merges only tighten, never loosen (allow shrinks, deny/require grow)
- ✅ Path sandboxing: backup/apply/rollback reject `../` traversal, cross-drive, and non-`.json/.yaml/.yml` targets
- ✅ Hard insurance: Gate B re-run before writeback (even if caller skips judge)
- ✅ P0 regression gate: `apply` runs regression after writeback and auto-rolls-back on failure
- ✅ Whitelist cannot downgrade canary/injection alerts (hard alert)
- ✅ Reject pool dedup: Cross-process safe with file locking; fail-closed on corruption
- ✅ Rollback support: One-click restore from backup
- ✅ Metrics exposure: `--show-metrics` for observability

## License

MIT License

## Author

unclekk (Sapiens AI)

## Citation

If used in research, cite:
```bibtex
@misc{safety_harness_evolution,
  title={Self-Evolving Safety Harness for Multi-Agent Systems},
  author={unclekk},
  year={2026},
  url={https://github.com/unclekk/safety-harness-evolution}
}
```
