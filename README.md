# Anzen 

A simple observation and audit tool for AI agents. Point any
**OpenInference-instrumented** agent (LangChain, LlamaIndex, CrewAI, or the
OpenAI/Anthropic SDK instrumentations) at Anzen and it records every action
the agent takes into a local SQLite log
you can inspect at any time. A compliance rule pack (OWASP LLM Top 10 mapped)
runs automatically as actions arrive, so findings are always current.

## Install

```bash
pip install -e ".[dev]"     # dev extra pulls in the OTel SDK for tests
```

## Quick start

```bash
# 1. Start the collector (OTLP/HTTP on :4318) — leave this terminal running
anzen serve

# 2. In another terminal: capture your Claude Code sessions automatically
anzen install-hook          # ... then use Claude Code normally ...

# 3. One glance: collector health, agents seen, findings, hooks
anzen status

# 4. Observe what the agent did — findings are already there (auto-scan)
anzen list
anzen show <id>
```

The database lives in `~/.anzen/` — no flags needed anywhere. Override the
location with `ANZEN_HOME`.

Point a real agent at it by setting its OTel exporter endpoint:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
```

Frameworks auto-instrumented with `openinference-instrumentation-*` packages
emit the right span format out of the box.

## Audit your own Claude Code

Anzen can capture every tool call your real Claude Code sessions make with no
instrumentation or API key:

```bash
anzen serve                 # collector running in another terminal
anzen install-hook          # adds a PostToolUse hook to ./.claude/settings.json
# ... use Claude Code normally (new sessions pick up the hook) ...
anzen list                  # a "claude-code" session appears
anzen show <id>             # every command/file/edit it actually ran
anzen report <id>           # audit report — findings were recorded live
```

The hook is fail-safe: if the collector isn't running it exits silently in
milliseconds and Claude Code is unaffected. Remove with `anzen uninstall-hook`.
Use `--user` to install for all projects, `--endpoint` for a non-default
collector address.

## Commands

| Command | Description |
|---|---|
| `anzen serve` | Run the collector (leave it running in a terminal). |
| `anzen status` | Collector health, captured activity, findings, hook state. |
| `anzen list` | List recorded sessions. |
| `anzen show <id>` | The action timeline for a session — what the agent actually did. |
| `anzen report <id> [-o file] [--llm] [--rules dir]` | The audit report; `--llm` adds the Claude pass, `--rules` re-scans with an extra pack. |

## How it works

```
OpenInference agent ──OTLP/HTTP──▶ collector ──▶ normalize ──▶ SQLite (~/.anzen/anzen.db)
                                                    │
                                          auto-scan (rule pack)
                                                    │
                       anzen status/list/show (observe) · anzen report (audit)
```

- **Observe (the core):** the collector normalizes OpenInference spans
  (`openinference.span.kind`, `tool.name`, `input.value`, `output.value`) into
  a uniform action log. Unrecognized spans are kept raw — nothing is dropped.
- **Audit (continuous):** every stored action is immediately checked against
  the YAML rule pack (secrets, destructive commands, exfiltration, PII, prompt
  injection); every finding carries an explanation and a remediation, and shows
  up live in `anzen status` / `anzen list`. `anzen report --rules <dir>`
  re-scans with an extra pack and `--llm` adds a Claude contextual pass. See
  `anzen/rules_builtin.yaml` for the rule format.
