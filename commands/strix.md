---
description: Run a Strix-style penetration test as a Claude Code agent team against a URL, a local folder, or a git repo
argument-hint: <target...> [--mode quick|standard|deep] [--instruction "text"] [--authorized] [--static-only] [--run-code] [--max-agents N]
allowed-tools: Bash, Read, Write, Edit, Glob, Grep, Agent, AskUserQuestion, TodoWrite
---

You are the **lead** of a Strix security team. Arguments: `$ARGUMENTS`

Security testing sends hostile traffic and can run untrusted code. Follow every step below in order. Do not skip the authorization gate.

## 1. Parse arguments

- Targets: every token that is not a flag or a flag value. Each is a website URL (`http(s)://...`), a local folder path, or a git repo URL (`github.com/...`, `*.git`, `git@...`). At least one is required; if none, show the usage line above and stop.
- `--mode quick|standard|deep` (default `standard`).
- `--instruction "text"`: operator guidance (focus areas, credentials supplied by the user, tenancy model). Treat as the user's own instruction.
- `--authorized`: the user states they are authorized to test every listed non-local target. Skips the question in step 2 only.
- `--static-only`: read code and run offline scanners only; send no traffic and run no target code.
- `--run-code`: allow running code from a cloned repo (default: cloned repos are static-only).
- `--max-agents N`: maximum parallel Agent calls in one message (default: the mode cap in the strix-team skill).

## 2. Authorization gate

Classify each target:

- **Local**: host is `localhost`, `127.0.0.1`, `[::1]`, `*.localhost`, `*.test`, or the target is a local folder path.
- **Remote**: any other host, or a repo URL.

If any target is Remote and `--authorized` was not given, call AskUserQuestion once, naming each remote host and asking: "Do you own these targets or have written authorization to test them?" Options: "Yes, I am authorized", "No, test local targets only". On "No", drop the remote targets (stop if none remain). Never test a target the user has not confirmed.

Dynamic-testing rules, applied after the gate:
- Repo URL: clone it into the run dir later only as a read-only checkout; static-only unless `--run-code` was given.
- Local folder: dynamic testing only against a localhost instance the user names; otherwise static-only.
- Website: dynamic, authorized hosts only; no third-party hosts discovered via redirects or links.
- If any target ends up static-only, pass `--static-only` to init.

## 3. Initialize the run

Resolve the plugin root: `${CLAUDE_PLUGIN_ROOT}`. If that is empty, use `git rev-parse --show-toplevel` or locate `skills/strix-team/scripts/strix_team.py`. Then run, with Bash:

```bash
python3 "<plugin-root>/skills/strix-team/scripts/strix_team.py" init <target...> --mode <mode> --instruction "<text>" [--static-only] --json
python3 "<plugin-root>/skills/strix-team/scripts/strix_team.py" preflight --json
```

`init` prints the run dir (`strix_runs/<run-name>/`) and writes `scope.md`. `preflight` reports which scanners exist on PATH. If `init` exits non-zero, show the error and stop.

Optional `init` flags: `--out-dir DIR` (where run dirs live, default `./strix_runs`), `--run-name NAME`, and `--source-root PATH` (repeatable). `strix_team.py verify` checks that every finding's `code_locations` path exists under a source root. A folder target counts as one automatically. For a **repo URL**, clone it first (`git clone --depth 1 <url> <RUN>/workspace/<name>`, delegated to a subagent or run by you before init if the clone is trusted-read-only) and pass the clone path as `--source-root`; otherwise `verify` fails on its `code_locations` paths.

Append a `## Operator options` section to `scope.md` (Edit tool) recording: authorized hosts the user confirmed, `--run-code` yes/no, `--max-agents`, and which targets are static-only.

## 4. Hand off to the playbook

Follow the **strix-team** skill (`skills/strix-team/SKILL.md`) wave by wave: mapping, threat model, hunt, validate, report, reconcile, finalize. Pass it the run dir, mode, plugin root, and options above. You orchestrate only: you never send requests to the target, run scanners, or read target code yourself. Every such action goes to a subagent.

When finished, give the user: run dir path, number of findings by severity, the one-paragraph posture summary, and a list of `needs_follow_up` / unreviewed areas.
