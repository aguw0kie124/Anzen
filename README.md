# Anzen 安全

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
# 1. Start the collector (OTLP/HTTP on :4318)
anzen serve

# 2. In another terminal, emit a synthetic agent session
anzen demo

# 3. Observe what the agent did
anzen list
anzen show demo-XXXX
```

Point a real agent at it by setting its OTel exporter endpoint:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
```

Frameworks auto-instrumented with `openinference-instrumentation-*` packages
emit the right span format out of the box.

## Commands

| Command | Description |
|---|---|
| `anzen serve` | Start the collector; records every span an agent sends. |
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
