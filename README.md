# Anzen 

A simple observation and audit tool for AI agents. Point any
**OpenInference-instrumented** agent (LangChain, LlamaIndex, CrewAI, or the
OpenAI/Anthropic SDK instrumentations) at Anzen and it records every action
the agent takes into a local SQLite log
you can inspect at any time. A compliance rule pack (OWASP LLM Top 10 mapped)
can be run over any recorded session on demand.

## Install

```bash
pip install -e ".[dev]"     # dev extra pulls in the OTel SDK for demo/tests
```

## Quick start

```bash
# 1. Start the collector in the background (OTLP/HTTP on :4318)
anzen up

# 2. Emit a synthetic agent session (or connect a real agent — see below)
anzen demo

# 3. One-glance health: collector, activity, findings, hooks
anzen status

# 4. Observe what the agent did
anzen list
anzen show demo-XXXX

# 5. Stop the background collector
anzen down
```

Everything lives in `~/.anzen/` (db, collector log, pidfile) — no flags needed
anywhere. Override the location with `ANZEN_HOME`. `anzen serve` still runs the
collector in the foreground for development.

Point a real agent at it by setting its OTel exporter endpoint:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
```

Frameworks auto-instrumented with `openinference-instrumentation-*` packages
emit the right span format out of the box.

## Audit your own Claude Code

Anzen can capture every tool call your real Claude Code sessions make — no
instrumentation, no API key:

```bash
anzen up                    # collector running in the background
anzen install-hook          # adds a PostToolUse hook to ./.claude/settings.json
# ... use Claude Code normally (new sessions pick up the hook) ...
anzen list                  # a "claude-code" session appears
anzen show <id>             # every command/file/edit it actually ran
anzen scan <id>             # compliance check over the session
```

The hook is fail-safe: if the collector isn't running it exits silently in
milliseconds and Claude Code is unaffected. Remove with `anzen uninstall-hook`.
Use `--user` to install for all projects, `--endpoint` for a non-default
collector address.

## Commands

| Command | Description |
|---|---|
| `anzen up` / `anzen down` | Start/stop the collector in the background. |
| `anzen status` | Collector health, captured activity, findings, hook state. |
| `anzen serve` | Run the collector in the foreground (dev). |
| `anzen list` | List recorded sessions. |
| `anzen show <id>` | The action timeline for a session — what the agent actually did. |
| `anzen scan <id> [--llm]` | Run the compliance rules over a session (on demand). |
| `anzen report <id> [-o file]` | Render the audit report for a scanned session. |
| `anzen demo` | Emit a synthetic risky session to a running collector. |

## How it works

```
OpenInference agent ──OTLP/HTTP──▶ anzen serve ──▶ SQLite (anzen.db)
                                                       │
                                anzen show (observe) · anzen scan/report (audit)
```

- **Observe (the core):** the collector normalizes OpenInference spans
  (`openinference.span.kind`, `tool.name`, `input.value`, `output.value`) into
  a uniform action log. Unrecognized spans are kept raw — nothing is dropped.
- **Audit (on demand):** `anzen scan` checks a session against YAML rules
  (secrets, destructive commands, exfiltration, PII, prompt injection); every
  finding carries an explanation and a remediation. `--llm` adds a Claude
  contextual pass. See `anzen/rules_builtin.yaml` for the format; drop extra
  rules in a directory and pass `--rules`.
