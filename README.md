# Anzen

Discovery, observability, and security for fleets of AI coding agents.

Anzen is a self-hosted server that ingests **Claude Code's native
OpenTelemetry export** containing tool calls, permission decisions, prompts, MCP server
connections, plugin inventory, and cost and then scans every action against a
compliance rule pack (OWASP LLM Top 10), giving security teams an
inventory of what's actually running.

## Setup

**1. Run the server**

```bash
pip install -e ".[dev]"
ANZEN_API_KEYS=your-secret-key anzen server --host 0.0.0.0
```

**2. Point Claude Code at it** — in managed settings (MDM) or
`~/.claude/settings.json`:

```json
{ "env": {
    "CLAUDE_CODE_ENABLE_TELEMETRY": "1",
    "OTEL_LOGS_EXPORTER": "otlp",
    "OTEL_EXPORTER_OTLP_PROTOCOL": "http/protobuf",
    "OTEL_EXPORTER_OTLP_ENDPOINT": "http://anzen.internal:4318",
    "OTEL_EXPORTER_OTLP_HEADERS": "Authorization=Bearer your-secret-key",
    "OTEL_LOG_TOOL_DETAILS": "1" } }
```

Managed settings take precedence over user settings — engineers cannot
disable reporting. See the
[Claude Code monitoring docs](https://code.claude.com/docs/en/monitoring-usage).

### Privacy tiers

Claude Code redacts content by default. Choose how much Anzen sees:

| Setting | What Anzen receives |
|---|---|
| *(default)* | Metadata only — tool names, decisions, timings, cost, identity |
| `OTEL_LOG_TOOL_DETAILS=1` | Tool parameters and inputs, bash commands, MCP server names |
| `OTEL_LOG_USER_PROMPTS=1` | Prompt and response text |

Most rules need `OTEL_LOG_TOOL_DETAILS=1` to match on command content.

## API

| Route | What it does |
|---|---|
| `POST /v1/logs` | OTLP ingest (protobuf + JSON). Rules run on arrival. |
| `POST /v1/metrics` | Accepted for exporter compatibility. |
| `GET /api/inventory` | Discovered MCP servers, plugins, skills, hooks. |
| `PATCH /api/inventory/{id}` | Mark an item approved / unreviewed. |
| `GET /api/endpoints` | Who is running agents, where, on what version. |
| `GET /api/sessions` · `/api/sessions/{id}` | Sessions and full action timelines. |
| `GET /api/findings?severity=&since=` | Cross-session findings feed. |
| `GET /api/sessions/{id}/report.md` | Markdown audit report. |
| `GET /healthz` | Liveness (never requires auth). |

All other routes require `Authorization: Bearer <key>` when `ANZEN_API_KEYS`
is set. Unset = open, for local development only.

## Commands

| Command | What it does |
|---|---|
| `anzen server [--host --port]` | Run the server (OTLP ingest + read API). |
| `anzen status` | One glance: server health, agents seen, findings. |
| `anzen list` | List recorded sessions. |
| `anzen show <id>` | Full action timeline for one session. |
| `anzen report <id> [-o file] [--llm] [--rules dir]` | Audit report; `--llm` adds a Claude review pass, `--rules` re-scans with an extra rule pack. |

## Known gaps

- **Tool *output* content is not available** on the events path — Claude Code
  sends result sizes, not bodies. Rules matching on output (e.g. `INJ-001`
  prompt-injection detection) have reduced coverage.
- **Subprocess activity is invisible** — `OTEL_*` is not propagated to shells
  or MCP servers Claude Code spawns.
- Rule precision needs work (e.g. `SEC-002` matches `.env.example`), and
  matched secrets are currently stored unredacted.

## How auditing works

Every action is checked the moment it arrives against a YAML rule pack —
secrets, destructive commands, exfiltration, PII, prompt injection — mapped
to the OWASP LLM Top 10. Every finding explains what happened and how to fix
it. See `anzen/rules_builtin.yaml` for the rule format, or point
`anzen report --rules <dir>` at your own.
