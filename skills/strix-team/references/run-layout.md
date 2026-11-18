# Run directory layout

Every run writes to `strix_runs/<run-name>/`. State lives in files, not in transcripts. The lead reads files; subagents write files and return at most 200 words.

```
strix_runs/<run-name>/
  run.json                 metadata: targets, mode, started, status, tool availability
  scope.md                 targets, classification, in/out of scope, ROE, operator options
  plan.md                  architect: hunter assignments, priorities, budget
  threat_model.md          architect: overview, trust boundaries, attack surface, severity calibration + mermaid
  amendments/<agent>-<n>.md   append-only corrections to the threat model
  notes/<agent>--<slug>.md    per-agent notes (never edit another agent's file)
  coverage/<agent>.jsonl      one JSON object per line
  candidates/<id>.md       hunter output
  validated/<id>.md        validator output
  vulnerabilities/<id>.md  reporter output (full finding)
  evidence/<id>/...        raw HTTP, screenshots, PoC scripts, tool output
  # built by strix_team.py assemble:
  vulnerabilities.json  vulnerabilities.csv  findings.sarif  coverage.json
  penetration_test_report.md
```

## IDs

`<id>` = `<vuln-slug>-<4hex>`, for example `idor-users-7f3a`. The hunter picks it; it stays the same in `candidates/`, `validated/`, `vulnerabilities/` and `evidence/`. Slug: lowercase letters, digits and hyphens.

## File ownership (write races)

Each agent writes only files whose name contains its own agent name, or the id it was assigned. Exceptions: `validated/<id>.md` is written by the validator assigned that id; `vulnerabilities/<id>.md` by the reporter assigned that id. The lead edits `scope.md` (operator options) and nothing else, except `coverage/<agent>.jsonl` rows it rewrites during reconcile.

## Candidate frontmatter (`candidates/<id>.md`)

```yaml
id: idor-users-7f3a
title: "IDOR on GET /api/users/{id}"
suspected_cwe: CWE-639
target: "https://localhost:8080"
endpoint: "/api/users/{id}"     # null for code-only
method: GET                     # null for code-only
hypothesis: "Handler loads the user by id without checking the caller owns it."
source_refs:                    # file:line or url
  - app/api/users.py:42
suggested_severity: high        # critical|high|medium|low|info
priority: 1                     # 1 = validate first
discovered_by: strix-hunter-3
```

Body: `## Why suspected` and `## How to validate`.

## Validated frontmatter (`validated/<id>.md`)

```yaml
id: idor-users-7f3a
closure: confirmed              # confirmed | ruled_out | open_proof_gap
validator: strix-validator-1
evidence:                       # relative paths under the run dir
  - evidence/idor-users-7f3a/trigger.http
counterevidence: "Strongest case against the finding, and why it fails."
ruled_out_reason: ""            # required when closure is ruled_out: the named control, file:line, why it runs on every path
proof_gap: ""                   # required when closure is open_proof_gap: what is missing
```

Only `confirmed` proceeds to a reporter.

## Coverage rows (`coverage/<agent>.jsonl`)

One JSON object per line:

```json
{"surface":"GET /api/users/{id}","risk_area":"IDOR","outcome":"reported","evidence":"validated/idor-users-7f3a.md","agent":"strix-hunter-3"}
```

`outcome` is one of `reported`, `no_issue_found`, `ruled_out`, `not_applicable`, `needs_follow_up`. The last three require non-empty `evidence`. One row per `(surface, risk_area)`; to change an outcome, rewrite the existing line rather than adding a second.

## threat_model.md

Headings must contain (case-insensitive): `overview`, `trust boundaries`, `attack surface`, `severity calibration`. At least one fenced mermaid block: components as nodes, one `subgraph` per trust zone, edges labelled with what crosses (credential, token, untrusted input). Boundaries and severity calibration are tables, one short row per item.

## plan.md

A table with columns `hunter | vuln classes | component/surface | knowledge packs (<=5) | priority | budget(turns)`, then a short rationale and a "Deferred / out of scope" list.

## amendments/<agent>-<n>.md

Plain markdown: which boundary or fact in `threat_model.md` is wrong, what was observed, and the evidence path. Folded into the model by the architect in Wave 6, then removed.
