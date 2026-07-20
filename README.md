# Anzen

A simple observation and audit tool for AI agents that captures every action
from **Claude Code automatically** (no instrumentation, no API key), or from
any **OpenTelemetry/OpenInference-instrumented** agent (LangChain, LlamaIndex, CrewAI, the
OpenAI/Anthropic SDK instrumentations), into a local SQLite log you can
inspect at any time. A compliance rule scan (OWASP LLM Top 10 mapped) runs
automatically as actions arrive, so findings are always current.

## How it works

Anzen is two pieces that talk to each other over `localhost:4318`:

1. **The collector** (`anzen serve`) — receives activity, stores it, and
   scans it against the rule pack. It must be running or nothing is
   captured. Leave it running in its own terminal.
2. **A sender in your agent** — pushes activity to the collector as it
   happens. For Claude Code this is a hook you install once per project.
   For other agents, it's one environment variable.

Everything is stored locally in `~/.anzen/anzen.db`. Nothing leaves your
machine. Override the location with `ANZEN_HOME`.

## Install

```bash
pip install -e ".[dev]"
```

This puts the `anzen` command in your current Python environment. If a new
terminal can't find `anzen`, either activate that same environment
(`source .venv/bin/activate`) or link it onto your PATH once:

```bash
ln -s "$(pwd)/.venv/bin/anzen" ~/.local/bin/anzen
```

## Quick start: audit Claude Code

```bash
# 1. Start the collector — leave this running in its own terminal
anzen serve

# 2. In the project you want to monitor, install the hook
anzen install-hook

# 3. Use Claude Code normally in that project — new sessions are captured

# 4. See what was captured
anzen status
anzen list
anzen show <id>
```

**The hook only applies to where you install it:**
- `anzen install-hook` — captures Claude Code only in *this* project.
- `anzen install-hook --user` — captures Claude Code in *every* project on
  this machine.

Use `--user` if you want it always on everywhere. Otherwise, run
`anzen install-hook` inside each project you want monitored.

**The hook fails silently.** If the collector isn't running, Claude Code
works normally but nothing gets captured — no error, no warning. If
`anzen status` isn't showing new activity, check that `anzen serve` is
still running.

## Connect any other agent

Point your agent's OTel exporter at the collector:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
```

Frameworks auto-instrumented with `openinference-instrumentation-*` packages
emit the right span format out of the box.

## Commands

| Command | What it does |
|---|---|
| `anzen serve` | Run the collector. Must stay running to capture anything. |
| `anzen install-hook [--user]` | Add the Claude Code hook — this project, or every project with `--user`. |
| `anzen uninstall-hook [--user]` | Remove the hook. |
| `anzen status` | One glance: collector health, agents seen, findings, hook state. |
| `anzen list` | List recorded sessions. |
| `anzen show <id>` | Full action timeline for one session. |
| `anzen report <id> [-o file] [--llm] [--rules dir]` | Audit report; `--llm` adds a Claude review pass, `--rules` re-scans with an extra rule pack. |

## How auditing works

Every action is checked the moment it arrives against a YAML rule pack —
secrets, destructive commands, exfiltration, PII, prompt injection — mapped
to the OWASP LLM Top 10. Every finding explains what happened and how to fix
it, and shows up immediately in `anzen status` / `anzen list`, with no
manual scan step. See `anzen/rules_builtin.yaml` for the rule format, or
point `anzen report --rules <dir>` at your own.
