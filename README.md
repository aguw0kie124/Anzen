# Anzen

An observation and audit layer for AI agents. Anzen ingests **OpenTelemetry**
telemetry from agents into a local SQLite log and scans every action as it
arrives against a compliance rule pack (OWASP LLM Top 10 mapped), so findings
are always current.

Agents don't need custom instrumentation — anything that emits OTel spans with
**OpenInference** attributes (LangChain, LlamaIndex, CrewAI, the
OpenAI/Anthropic SDK instrumentations) works with one environment variable.
Native ingestion of Claude Code's built-in telemetry (OTLP logs/metrics) is in
progress — see the roadmap note below.

## How it works

1. **The collector** (`anzen serve`) — an OTLP/HTTP endpoint that receives
   activity, stores it, and scans it against the rule pack.
2. **Your agent's OTel exporter** — pointed at the collector:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
```

Everything is stored locally in `~/.anzen/anzen.db`. Nothing leaves your
machine. Override the location with `ANZEN_HOME`.

## Install

```bash
pip install -e ".[dev]"
```

## Quick start

```bash
# 1. Start the collector — leave this running in its own terminal
anzen serve

# 2. Point any OpenInference/OTel-instrumented agent at it
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318

# (or run the bundled real-agent example: python examples/real_agent.py)

# 3. See what was captured
anzen status
anzen list
anzen show <id>
```

## Commands

| Command | What it does |
|---|---|
| `anzen serve` | Run the collector. Must stay running to capture anything. |
| `anzen status` | One glance: collector health, agents seen, findings. |
| `anzen list` | List recorded sessions. |
| `anzen show <id>` | Full action timeline for one session. |
| `anzen report <id> [-o file] [--llm] [--rules dir]` | Audit report; `--llm` adds a Claude review pass, `--rules` re-scans with an extra rule pack. |

## How auditing works

Every action is checked the moment it arrives against a YAML rule pack —
secrets, destructive commands, exfiltration, PII, prompt injection — mapped
to the OWASP LLM Top 10. Every finding explains what happened and how to fix
it. See `anzen/rules_builtin.yaml` for the rule format, or point
`anzen report --rules <dir>` at your own.

## Roadmap

Anzen is pivoting from a single-developer CLI to a self-hosted
discovery/observability/security server for fleets of coding agents,
ingesting Claude Code's **native** OpenTelemetry export (tool calls,
permission decisions, MCP server connections, plugin inventory, cost) with a
web dashboard — no per-machine install. The custom Claude Code hook that
previously lived here has been removed in favor of that native telemetry.
