# Report template (`penetration_test_report.md`)

`strix_team.py assemble` builds the report from `vulnerabilities/*.md`, `coverage/*.jsonl` and `threat_model.md`. The lead checks the result against this structure and writes the executive summary the user sees. If a section is missing from the assembled file, tell the user rather than inventing content.

## Structure

1. **Title block**: run name, date, targets, mode, tools available (from `run.json`).
2. **Executive summary** (max 10 lines): overall posture, counts by severity, the three issues that matter most, and the first fix to make.
3. **Scope and method**: in-scope targets, static-only or dynamic, waves run, what was not tested and why.
4. **Findings table**: `id | severity | title | endpoint or file | confidence | status`, sorted by CVSS score descending.
5. **Findings**: one section per finding, in the same order, taken from the finding file body (Description, Impact, Technical Analysis, PoC, Remediation) plus `counterevidence` and `severity_change_conditions`.
6. **Threat model**: the final `threat_model.md` (diagram and tables).
7. **Coverage**: counts per outcome, then the list of `needs_follow_up` and `open_proof_gap` items. A clean result covers only what is listed here.
8. **Ruled out**: candidates closed as `ruled_out`, each with its named control.
9. **Limits**: budget and turn caps hit, tools missing, areas unreviewed, assumptions about deployment.

## Tone

State what was proven and what was not. Do not call the target "secure" or "clean": say "no exploitable issue found in the areas covered". Do not include raw secrets.
