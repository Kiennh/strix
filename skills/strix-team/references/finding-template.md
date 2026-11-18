# Finding template (`vulnerabilities/<id>.md`)

Flat YAML frontmatter, then a markdown body. `strix_team.py verify` checks every key below. Compute the score with `python3 <plugin-root>/skills/strix-team/scripts/strix_team.py cvss <AV> <AC> <PR> <UI> <S> <C> <I> <A>` and copy `score` and `severity` from its output. Do not estimate them.

```yaml
---
id: idor-users-7f3a
title: "IDOR on GET /api/users/{id}"
severity: high              # derived from cvss; must match the cvss command output
cvss:
  AV: N                     # N | A | L | P
  AC: L                     # L | H
  PR: L                     # N | L | H
  UI: N                     # N | R
  S: U                      # U | C
  C: H                      # N | L | H
  I: N                      # N | L | H
  A: N                      # N | L | H
cvss_score: 6.5             # cvss command output
cwe: CWE-639                # ^CWE-\d+$
target: "https://localhost:8080"
endpoint: "/api/users/{id}"   # optional; null for code-only
method: GET                   # optional
confidence: high            # high | medium | low
confidence_rationale: ""    # required when confidence is not high
fix_effort: low             # trivial | low | medium | high
status: reported            # reported | withdrawn
code_locations:             # optional; required to carry a fix
  - file: app/api/users.py
    start_line: 42
    end_line: 48            # >= start_line
    snippet: "..."
    fix_before: "..."       # verbatim current code; both fix_ keys or neither
    fix_after: "..."        # verbatim replacement
assumptions: "..."          # exploitability prerequisites, non-empty
counterevidence: "..."      # strongest case against, non-empty
severity_change_conditions: "..."   # one fact that would raise or lower severity, non-empty
http_evidence:              # optional; paths relative to the run dir
  - evidence/idor-users-7f3a/trigger.http
fix_verification: "..."     # REQUIRED when any code_location has fix_after
discovered_by: strix-hunter-3
validated_by: strix-validator-1
---
```

## Body

```markdown
## Description
What the flaw is, in two or three sentences. Name the affected component.

## Impact
Concrete consequence for a real attacker and victim. No worst-case chains you did not prove.

## Technical Analysis
Source -> control -> sink trace, with file:line, or the observed request/response behavior.

## PoC
Numbered, copy-pasteable steps. Include the exact requests and expected output. Put script code in a fenced block and save it to `evidence/<id>/poc.<ext>`.

## Remediation
Root-cause fix first (shared helper, not one route), then defense in depth.
```

## Rules

- Rate severity after counterevidence, per `analysis/severity_calibration`. Prefer the lower rating when unsure and say what would raise it in `severity_change_conditions`.
- `fix_before` must match the source byte for byte. If you cannot verify the fix (see `analysis/fix_verification`), omit `fix_before`, `fix_after` and `fix_verification` and describe the fix in Remediation.
- Redact secrets in every file: keep the first 4 characters.
- One file per reachable instance. Do not merge instances because they share a root cause.
