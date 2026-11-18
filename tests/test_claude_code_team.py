"""Tests for the Strix Claude Code team plugin: helper script, agents, manifests, cross-refs."""

from __future__ import annotations

import argparse
import csv
import importlib.util
import itertools
import json
import re
import shutil
import ssl
import subprocess
import sys
import urllib.error
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from cvss import CVSS3


if TYPE_CHECKING:
    from collections.abc import Callable
    from types import ModuleType


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "skills" / "strix-team" / "scripts" / "strix_team.py"


def _load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("strix_team", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["strix_team"] = module
    spec.loader.exec_module(module)
    return module


st = _load_script()

FINDING_1 = "idor-users-7f3a"
FINDING_2 = "sqli-search-1b2c"
RUN_COMMANDS = ("init", "preflight", "cvss", "verify", "status", "assemble")


# --------------------------------------------------------------------------- helpers


def run_cli(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, dict[str, Any]]:
    """Run ``strix_team.main`` and return ``(exit code, parsed stdout JSON)``."""
    capsys.readouterr()
    code = st.main(list(argv))
    out = capsys.readouterr().out
    return code, json.loads(out)


def _lib_expected(vector: str) -> dict[str, Any]:
    lib = CVSS3(vector)
    severity = lib.severities()[0].lower()
    return {
        "vector": vector,
        "score": lib.scores()[0],
        "severity": "info" if severity == "none" else severity,
    }


def _metrics(vector: str) -> list[str]:
    return [part.split(":")[1] for part in vector.split("/")[1:]]


def _finding_text(
    fid: str,
    vector: str,
    *,
    title: str,
    cwe: str,
    confidence: str = "high",
    endpoint: str = "/api/users/{id}",
    method: str = "GET",
    code: bool = False,
) -> str:
    expected = _lib_expected(vector)
    metrics = dict(part.split(":") for part in vector.split("/")[1:])
    lines = [
        "---",
        f"id: {fid}",
        f'title: "{title}"',
        f"severity: {expected['severity']}",
        "cvss:",
        *[f"  {key}: {value}" for key, value in metrics.items()],
        f"cvss_score: {expected['score']}",
        f"cwe: {cwe}",
        'target: "https://localhost:8080"',
        f'endpoint: "{endpoint}"',
        f"method: {method}",
        f"confidence: {confidence}",
    ]
    if confidence != "high":
        lines.append('confidence_rationale: "Reproduced once; response varies under load."')
    lines.append("fix_effort: low")
    lines.append("status: reported")
    if code:
        lines += [
            "code_locations:",
            "  - file: app/api/users.py",
            "    start_line: 42",
            "    end_line: 48",
            '    snippet: "user = db.get(id)"',
            '    fix_before: "user = db.get(id)"',
            '    fix_after: "user = db.get(id, owner=caller)"',
        ]
    lines += [
        'assumptions: "Attacker holds any valid low-privilege account."',
        'counterevidence: "A gateway rule could scope the id; none was observed."',
        'severity_change_conditions: "Raise if the id space is guessable across tenants."',
        "http_evidence:",
        f"  - evidence/{fid}/trigger.http",
    ]
    if code:
        lines.append(f"  - evidence/{fid}/victim.http")
        lines.append('fix_verification: "Re-run trigger.http as another user; expect 403."')
    lines += [
        "discovered_by: strix-hunter-3",
        "validated_by: strix-validator-1",
        "---",
        "",
        "## Description",
        "",
        f"{title} lets one caller read another caller's records.",
        "",
        "## Impact",
        "",
        "Cross-tenant data disclosure.",
        "",
        "## Technical Analysis",
        "",
        "The handler loads by id without an owner check.",
        "",
        "## PoC",
        "",
        "Send the trigger request as the second user.",
        "",
        "## Remediation",
        "",
        "Scope the query to the caller.",
        "",
    ]
    return "\n".join(lines)


PLAN_MD = """# Plan

| hunter | vuln classes | component/surface | knowledge packs (<=5) | priority | budget(turns) |
| --- | --- | --- | --- | --- | --- |
| strix-hunter-3 | IDOR | /api/users | vulnerabilities/idor.md | 1 | 30 |

## Rationale

Users API is the largest authorization surface.

## Deferred / out of scope

- Admin console.
"""

THREAT_MODEL_MD = """# Threat model

## Overview

A small web API in front of a database.

```mermaid
flowchart LR
  subgraph Internet
    C[Client]
  end
  subgraph App
    A[API]
  end
  C -->|bearer token| A
```

## Trust boundaries

| boundary | crosses |
| --- | --- |
| Internet to API | bearer token, untrusted input |

## Attack surface

| surface | note |
| --- | --- |
| GET /api/users/{id} | object reference in path |

## Severity calibration

| class | typical severity |
| --- | --- |
| IDOR | high |
"""

CANDIDATE_MD = """---
id: {fid}
title: "{title}"
suspected_cwe: {cwe}
target: "https://localhost:8080"
endpoint: "{endpoint}"
method: GET
hypothesis: "Handler skips an ownership check."
source_refs:
  - app/api/users.py:42
suggested_severity: high
priority: 1
discovered_by: strix-hunter-3
---

## Why suspected

Id comes straight from the path.

## How to validate

Replay as another user.
"""

VALIDATED_MD = """---
id: {fid}
closure: confirmed
validator: strix-validator-1
evidence:
  - evidence/{fid}/trigger.http
counterevidence: "No gateway scoping observed."
ruled_out_reason: ""
proof_gap: ""
---

Confirmed.
"""

COVERAGE_HUNTER_3 = [
    {
        "surface": "GET /api/users/{id}",
        "risk_area": "IDOR",
        "outcome": "reported",
        "evidence": f"validated/{FINDING_1}.md",
        "agent": "strix-hunter-3",
    },
    {
        "surface": "POST /search",
        "risk_area": "SQL injection",
        "outcome": "reported",
        "evidence": f"validated/{FINDING_2}.md",
        "agent": "strix-hunter-3",
    },
    {
        "surface": "GET /health",
        "risk_area": "Information disclosure",
        "outcome": "no_issue_found",
        "evidence": "",
        "agent": "strix-hunter-3",
    },
    {
        "surface": "GET /admin",
        "risk_area": "Broken access control",
        "outcome": "ruled_out",
        "evidence": "notes/strix-hunter-3--admin.md",
        "agent": "strix-hunter-3",
    },
]
COVERAGE_HUNTER_4 = [
    {
        "surface": "POST /upload",
        "risk_area": "File upload",
        "outcome": "needs_follow_up",
        "evidence": "notes/strix-hunter-4--upload.md",
        "agent": "strix-hunter-4",
    },
]


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def edit(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    assert old in text, f"{old!r} not in {path}"
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


@pytest.fixture
def golden(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Path:
    """A valid run directory built through ``init`` plus hand-written artifacts."""
    src = tmp_path / "src"
    (src / "app" / "api").mkdir(parents=True)
    (src / "app" / "api" / "users.py").write_text("def get(id): ...\n", encoding="utf-8")
    code, data = run_cli(
        capsys,
        "init",
        str(src),
        "https://localhost:8080",
        "--out-dir",
        str(tmp_path / "runs"),
        "--run-name",
        "golden",
        "--json",
    )
    assert code == 0
    run_dir = Path(data["run_dir"])
    (run_dir / "plan.md").write_text(PLAN_MD, encoding="utf-8")
    (run_dir / "threat_model.md").write_text(THREAT_MODEL_MD, encoding="utf-8")
    specs = (
        (
            FINDING_1,
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
            "IDOR on GET /api/users/{id}",
            "CWE-639",
            {"code": True},
        ),
        (
            FINDING_2,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "SQL injection in POST /search",
            "CWE-89",
            {"confidence": "medium", "endpoint": "/search", "method": "POST"},
        ),
    )
    for fid, vector, title, cwe, extra in specs:
        endpoint = extra.get("endpoint", "/api/users/{id}")
        fields = {"fid": fid, "title": title, "cwe": cwe, "endpoint": endpoint}
        (run_dir / "candidates" / f"{fid}.md").write_text(
            CANDIDATE_MD.format(**fields), encoding="utf-8"
        )
        (run_dir / "validated" / f"{fid}.md").write_text(
            VALIDATED_MD.format(fid=fid), encoding="utf-8"
        )
        (run_dir / "vulnerabilities" / f"{fid}.md").write_text(
            _finding_text(fid, vector, title=title, cwe=cwe, **extra), encoding="utf-8"
        )
        evidence = run_dir / "evidence" / fid
        evidence.mkdir(parents=True)
        (evidence / "trigger.http").write_text("GET /x HTTP/1.1\n", encoding="utf-8")
        if extra.get("code"):
            (evidence / "victim.http").write_text("GET /y HTTP/1.1\n", encoding="utf-8")
    write_jsonl(run_dir / "coverage" / "strix-hunter-3.jsonl", COVERAGE_HUNTER_3)
    write_jsonl(run_dir / "coverage" / "strix-hunter-4.jsonl", COVERAGE_HUNTER_4)
    return run_dir


def failed_checks(result: dict[str, Any]) -> set[str]:
    return {row["name"] for row in result["checks"] if row["status"] == "fail"}


# --------------------------------------------------------------------------- CVSS parity

PARITY_VECTORS = [
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
    "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",
    "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
    "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:C/C:N/I:N/A:N",
    "CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:H",
    "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H",
    "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:C/C:L/I:L/A:L",
    "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H",
    "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N",
    "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",
    "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:L",
    "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
    "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H",
    "CVSS:3.1/AV:A/AC:H/PR:H/UI:N/S:U/C:L/I:L/A:N",
    "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L",
    "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:L",
    "CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H",
    "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:N",
    "CVSS:3.1/AV:A/AC:L/PR:H/UI:R/S:C/C:L/I:H/A:L",
]


@pytest.mark.parametrize("vector", PARITY_VECTORS)
def test_cvss_matches_library(vector: str) -> None:
    assert st.cvss(*_metrics(vector)) == _lib_expected(vector)


def test_cvss_parity_vector_count() -> None:
    assert len(set(PARITY_VECTORS)) >= 20


def test_cvss_all_2592_vectors_match_library() -> None:
    """Exhaustive sweep covers every roundup boundary and scope-changed edge."""
    mismatches = []
    count = 0
    for combo in itertools.product(*st.CVSS_ENUMS.values()):
        vector = "CVSS:3.1/" + "/".join(
            f"{k}:{v}" for k, v in zip(st.CVSS_KEYS, combo, strict=True)
        )
        count += 1
        if st.cvss(*combo) != _lib_expected(vector):
            mismatches.append(vector)
    assert count == 2592
    assert mismatches == []


@pytest.mark.parametrize(
    ("vector", "score", "severity"),
    [
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"),
        ("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "critical"),
        ("AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5, "medium"),
        ("AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "medium"),
        ("AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8, "high"),
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "info"),
        ("AV:P/AC:H/PR:H/UI:R/S:C/C:N/I:N/A:N", 0.0, "info"),
        ("AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6, "low"),
    ],
)
def test_cvss_known_scores(vector: str, score: float, severity: str) -> None:
    result = st.cvss(*_metrics(f"CVSS:3.1/{vector}"))
    assert result == {"vector": f"CVSS:3.1/{vector}", "score": score, "severity": severity}


def test_cvss_accepts_lowercase_and_rejects_bad_metric() -> None:
    assert st.cvss(*"nllnuhnn")["score"] == 6.5
    with pytest.raises(ValueError, match="invalid CVSS metric AV:X"):
        st.cvss("X", "L", "L", "N", "U", "H", "N", "N")


def test_cvss_cli_json_and_exit_codes(capsys: pytest.CaptureFixture[str]) -> None:
    code, data = run_cli(capsys, "cvss", *"NLLNUHNN", "--json")
    assert code == 0
    assert data == {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "score": 6.5,
        "severity": "medium",
    }
    code, data = run_cli(capsys, "cvss", *"NLLNUHNZ")
    assert code == 1
    assert "invalid CVSS metric A:Z" in data["error"]
    with pytest.raises(SystemExit) as excinfo:
        st.main(["cvss", "N", "L"])
    assert excinfo.value.code == 2


# --------------------------------------------------------------------------- cve-search


def _nvd_payload(*items: tuple[str, float | None, str]) -> dict[str, Any]:
    """Build a minimal NVD CVE API 2.0 response for ``(id, cvss_score, published)`` rows."""
    vulns = []
    for cve_id, score, published in items:
        metrics = (
            {"cvssMetricV31": [{"baseSeverity": "HIGH", "cvssData": {"baseScore": score}}]}
            if score is not None
            else {}
        )
        vulns.append(
            {
                "cve": {
                    "id": cve_id,
                    "published": published,
                    "descriptions": [{"lang": "en", "value": f"{cve_id} summary"}],
                    "metrics": metrics,
                    "references": [{"url": f"https://example.test/{cve_id}"}],
                }
            }
        )
    return {"totalResults": len(vulns), "vulnerabilities": vulns}


def test_cve_search_queries_nvd_and_ranks_by_score_then_recency(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_urls = []

    def fake_get(url: str, *, timeout: float) -> dict[str, Any]:
        captured_urls.append(url)
        assert timeout > 0
        return _nvd_payload(
            ("CVE-2020-0001", 5.0, "2020-01-01T00:00:00.000"),
            ("CVE-2026-9999", 9.8, "2026-01-01T00:00:00.000"),
            ("CVE-2021-0002", 9.8, "2021-01-01T00:00:00.000"),
        )

    monkeypatch.setattr(st, "_http_get_json", fake_get)
    data, code = st.cmd_cve_search(argparse.Namespace(product="cPanel WHM", version="11.140"))

    assert code == 0
    assert data["product"] == "cPanel WHM"
    assert data["version"] == "11.140"
    assert data["query"] == "cPanel WHM 11.140"
    normalized_url = captured_urls[0].replace("+", " ")
    assert "keywordSearch=cPanel" in normalized_url
    ranked_ids = [row["id"] for row in data["results"]]
    # Highest CVSS first; ties broken by most recent publish date first.
    assert ranked_ids == ["CVE-2026-9999", "CVE-2021-0002", "CVE-2020-0001"]
    assert data["results"][0]["severity"] == "high"
    assert data["results"][0]["references"] == ["https://example.test/CVE-2026-9999"]


def test_cve_search_no_version_omits_it_from_query(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_get(_url: str, *, timeout: float) -> dict[str, Any]:
        assert timeout > 0
        return _nvd_payload()

    monkeypatch.setattr(st, "_http_get_json", fake_get)
    data, code = st.cmd_cve_search(argparse.Namespace(product="Jenkins", version=""))
    assert code == 0
    assert data["query"] == "Jenkins"
    assert data["version"] is None
    assert data["results"] == []
    assert data["total_results"] == 0


def test_cve_search_caps_results_and_handles_missing_score(monkeypatch: pytest.MonkeyPatch) -> None:
    published = "2026-06-01T00:00:00.000"
    items = [(f"CVE-2026-{1000 + n}", None if n == 0 else float(n), published) for n in range(20)]

    def fake_get(_url: str, *, timeout: float) -> dict[str, Any]:
        assert timeout > 0
        return _nvd_payload(*items)

    monkeypatch.setattr(st, "_http_get_json", fake_get)
    data, _code = st.cmd_cve_search(argparse.Namespace(product="Widget", version=""))
    assert len(data["results"]) == st._CVE_SEARCH_MAX_RESULTS
    ranked_ids = {row["id"] for row in data["results"]}
    assert "CVE-2026-1000" not in ranked_ids, "zero-score item should rank last and get cut"


def test_cve_search_rejects_non_https_urls() -> None:
    with pytest.raises(ValueError, match="non-https"):
        st._http_get_json("http://example.test/cves", timeout=5)


def _ssl_url_error() -> Any:
    return urllib.error.URLError(ssl.SSLCertVerificationError("CERTIFICATE_VERIFY_FAILED"))


def test_http_get_json_falls_back_to_curl_on_ssl_trust_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def broken_urllib(_url: str, *, timeout: float) -> dict[str, Any]:
        assert timeout > 0
        raise _ssl_url_error()

    captured_cmd: list[str] = []

    def fake_run(cmd: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        captured_cmd.extend(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout='{"ok": true}', stderr="")

    monkeypatch.setattr(st, "_http_get_json_urllib", broken_urllib)
    monkeypatch.setattr(st.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(st.subprocess, "run", fake_run)

    result = st._http_get_json("https://example.test/cves", timeout=15)
    assert result == {"ok": True}
    assert captured_cmd[0] == "/usr/bin/curl"
    assert "https://example.test/cves" in captured_cmd


def test_http_get_json_non_ssl_error_does_not_fall_back_to_curl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def broken_urllib(_url: str, *, timeout: float) -> dict[str, Any]:
        assert timeout > 0
        raise urllib.error.URLError("connection refused")

    def must_not_run(*_args: Any, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        msg = "curl should not be invoked for a non-SSL error"
        raise AssertionError(msg)

    monkeypatch.setattr(st, "_http_get_json_urllib", broken_urllib)
    monkeypatch.setattr(st.subprocess, "run", must_not_run)

    with pytest.raises(urllib.error.URLError, match="connection refused"):
        st._http_get_json("https://example.test/cves", timeout=15)


def test_http_get_json_curl_fallback_missing_curl_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken_urllib(_url: str, *, timeout: float) -> dict[str, Any]:
        assert timeout > 0
        raise _ssl_url_error()

    monkeypatch.setattr(st, "_http_get_json_urllib", broken_urllib)
    monkeypatch.setattr(st.shutil, "which", lambda _name: None)

    with pytest.raises(OSError, match="curl is not on PATH"):
        st._http_get_json("https://example.test/cves", timeout=15)


def test_http_get_json_curl_fallback_nonzero_exit_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken_urllib(_url: str, *, timeout: float) -> dict[str, Any]:
        assert timeout > 0
        raise _ssl_url_error()

    def failing_run(cmd: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(cmd, 22, stdout="", stderr="curl: (22) HTTP 404")

    monkeypatch.setattr(st, "_http_get_json_urllib", broken_urllib)
    monkeypatch.setattr(st.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(st.subprocess, "run", failing_run)

    with pytest.raises(OSError, match="curl exited 22"):
        st._http_get_json("https://example.test/cves", timeout=15)


def test_cve_search_network_error_surfaces_as_exit_1(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(_url: str, *, timeout: float) -> dict[str, Any]:
        assert timeout > 0
        msg = "simulated network failure"
        raise OSError(msg)

    monkeypatch.setattr(st, "_http_get_json", boom)
    code, data = run_cli(capsys, "cve-search", "cPanel WHM", "--version", "11.140", "--json")
    assert code == 1
    assert "simulated network failure" in data["error"]


def test_cve_search_cli_registers_in_parser() -> None:
    parser = st.build_parser()
    args = parser.parse_args(["cve-search", "Grafana", "--version", "8.3.0"])
    assert args.command == "cve-search"
    assert args.product == "Grafana"
    assert args.version == "8.3.0"
    args_no_version = parser.parse_args(["cve-search", "Jenkins"])
    assert args_no_version.version == ""


# --------------------------------------------------------------------------- mini YAML


def test_frontmatter_parser_handles_the_finding_subset() -> None:
    text = (
        "---\n"
        "id: x-1  # comment\n"
        'title: "a: b, c"\n'
        "score: 6.5\n"
        "count: 3\n"
        "flag: true\n"
        "nothing: ~\n"
        'empty: ""\n'
        "cvss:\n"
        "  AV: N   # [N,A,L,P]\n"
        "list:\n"
        "- one\n"
        "- two\n"
        "flow: [a, 'b, c']\n"
        "locs:\n"
        "  - file: a.py\n"
        "    start_line: 4\n"
        "    snippet: 'it''s'\n"
        "  - file: b.py\n"
        "text: |\n"
        "  line1\n"
        "  # not a comment\n"
        "last: end\n"
        "---\n"
        "\n"
        "## Body\n"
    )
    raw, body = st.split_frontmatter(text)
    assert st.parse_yaml(raw) == {
        "id": "x-1",
        "title": "a: b, c",
        "score": 6.5,
        "count": 3,
        "flag": True,
        "nothing": None,
        "empty": "",
        "cvss": {"AV": "N"},
        "list": ["one", "two"],
        "flow": ["a", "b, c"],
        "locs": [{"file": "a.py", "start_line": 4, "snippet": "it's"}, {"file": "b.py"}],
        "text": "line1\n# not a comment\n",
        "last": "end",
    }
    assert body.strip() == "## Body"


def test_frontmatter_errors() -> None:
    with pytest.raises(st.FrontmatterError):
        st.split_frontmatter("no frontmatter")
    with pytest.raises(st.FrontmatterError):
        st.split_frontmatter("---\nid: x\n")


# --------------------------------------------------------------------------- init / preflight


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("https://example.com", "website"),
        ("http://localhost:8080/app", "website"),
        ("example.org", "website"),
        ("10.0.0.5:8443", "website"),
        ("https://github.com/acme/app", "repo-url"),
        ("https://github.com/acme/app.git", "repo-url"),
        ("git@github.com:acme/app.git", "repo-url"),
        ("https://example.com/team/app.git", "repo-url"),
        ("github.com/acme/app", "repo-url"),
        ("./some/dir", "folder"),
        ("/abs/path/that/does/not/exist", "folder"),
        ("~/code/app", "folder"),
    ],
)
def test_classify_target(target: str, expected: str) -> None:
    assert st.classify_target(target) == expected


def test_classify_existing_folder(tmp_path: Path) -> None:
    assert st.classify_target(str(tmp_path)) == "folder"


def test_init_classifies_targets_and_writes_scope(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    folder = tmp_path / "code"
    folder.mkdir()
    code, data = run_cli(
        capsys,
        "init",
        "https://example.com",
        str(folder),
        "https://github.com/acme/app.git",
        "--mode",
        "deep",
        "--instruction",
        "focus on authz",
        "--static-only",
        "--out-dir",
        str(tmp_path / "runs"),
        "--run-name",
        "r1",
    )
    assert code == 0
    assert data["mode"] == "deep"
    assert data["run_name"] == "r1"
    assert data["targets"] == [
        {"value": "https://example.com", "class": "website"},
        {"value": str(folder), "class": "folder"},
        {"value": "https://github.com/acme/app.git", "class": "repo-url"},
    ]
    run_dir = Path(data["run_dir"])
    assert run_dir == (tmp_path / "runs" / "r1").resolve()
    scope = (run_dir / "scope.md").read_text(encoding="utf-8")
    assert "https://example.com | website" in scope
    assert "| repo-url |" in scope
    assert "focus on authz" in scope
    assert "static_only: true" in scope
    meta = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    assert meta["mode"] == "deep"
    assert meta["static_only"] is True
    assert meta["status"] == "initialized"
    assert [t["class"] for t in meta["targets"]] == ["website", "folder", "repo-url"]
    for sub in ("amendments", "notes", "coverage", "candidates", "validated", "vulnerabilities"):
        assert (run_dir / sub).is_dir()


def test_init_defaults_and_generated_name(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, data = run_cli(capsys, "init", "https://example.com", "--out-dir", str(tmp_path))
    assert code == 0
    assert data["mode"] == "standard"
    assert re.fullmatch(r"example-com-[0-9a-f]{4}", data["run_name"])
    meta = json.loads((Path(data["run_dir"]) / "run.json").read_text(encoding="utf-8"))
    assert meta["static_only"] is False


def test_init_refuses_existing_run_dir(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    args = ["init", "https://example.com", "--out-dir", str(tmp_path), "--run-name", "dup"]
    assert run_cli(capsys, *args)[0] == 0
    code, data = run_cli(capsys, *args)
    assert code == 1
    assert "already exists" in data["error"]


def test_preflight_probes_exactly_the_fifteen_tools(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code, data = run_cli(capsys, "preflight")
    assert code == 0
    assert list(data["tools"]) == [
        "nmap",
        "httpx",
        "subfinder",
        "ffuf",
        "nuclei",
        "katana",
        "sqlmap",
        "opengrep",
        "sg",
        "gitleaks",
        "trufflehog",
        "trivy",
        "curl",
        "python3",
        "docker",
    ]
    assert len(data["tools"]) == 15
    assert all(isinstance(value, bool) for value in data["tools"].values())
    assert data["python3"] is True
    assert data["docker"] is data["tools"]["docker"]


def test_preflight_uses_path_and_records_tool_env(
    golden: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(st.shutil, "which", lambda name: "/bin/x" if name == "nmap" else None)
    code, data = run_cli(capsys, "preflight", "--run-dir", str(golden))
    assert code == 0
    assert data["tools"]["nmap"] is True
    assert data["tools"]["curl"] is False
    meta = json.loads((golden / "run.json").read_text(encoding="utf-8"))
    assert meta["tool_env"] == data["tools"]


# --------------------------------------------------------------------------- verify: positive


def test_verify_golden_passes(golden: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, result = run_cli(capsys, "verify", str(golden))
    assert code == 0
    assert result["ok"] is True
    assert [row["name"] for row in result["checks"]] == list(st.CHECK_NAMES)
    assert len(result["checks"]) == 9
    assert all(row["status"] == "pass" for row in result["checks"])
    assert [item["surface"] for item in result["needs_follow_up"]] == ["POST /upload"]


def test_verify_human_output_when_tty(
    golden: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(st.sys.stdout, "isatty", lambda: True, raising=False)
    capsys.readouterr()
    assert st.main(["verify", str(golden)]) == 0
    out = capsys.readouterr().out
    assert "PASS required_files" in out
    assert out.strip().endswith("OK")


def test_verify_note_naming_confirmed_id_counts_as_reason(
    golden: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (golden / "vulnerabilities" / f"{FINDING_2}.md").unlink()
    (golden / "notes" / "strix-reporter-1--skipped.md").write_text(
        f"{FINDING_2}: not filed, duplicate of {FINDING_1}.\n", encoding="utf-8"
    )
    code, result = run_cli(capsys, "verify", str(golden))
    assert code == 0
    assert result["ok"] is True


def test_verify_missing_run_dir_is_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, data = run_cli(capsys, "verify", str(tmp_path / "nope"))
    assert code == 1
    assert "not found" in data["error"]


# --------------------------------------------------------------------------- verify: negative

F1 = f"vulnerabilities/{FINDING_1}.md"


def _unlink(rel: str) -> Callable[[Path], None]:
    return lambda run_dir: (run_dir / rel).unlink()


def _edit(rel: str, old: str, new: str) -> Callable[[Path], None]:
    return lambda run_dir: edit(run_dir / rel, old, new)


def _coverage_rows(rows: list[dict[str, Any]]) -> Callable[[Path], None]:
    return lambda run_dir: write_jsonl(run_dir / "coverage" / "strix-hunter-3.jsonl", rows)


def _row(**overrides: str) -> dict[str, Any]:
    return {**COVERAGE_HUNTER_3[0], **overrides}


NEGATIVE_CASES: dict[str, tuple[Callable[[Path], None], str]] = {
    "missing_threat_model": (_unlink("threat_model.md"), "required_files"),
    "missing_plan": (_unlink("plan.md"), "required_files"),
    "missing_scope": (_unlink("scope.md"), "required_files"),
    "no_severity_calibration": (
        _edit("threat_model.md", "## Severity calibration", "## Misc"),
        "threat_model",
    ),
    "no_trust_boundaries": (
        _edit("threat_model.md", "## Trust boundaries", "## Boundaries"),
        "threat_model",
    ),
    "no_mermaid": (_edit("threat_model.md", "```mermaid", "```text"), "threat_model"),
    "bad_cvss_enum": (_edit(F1, "  AV: N\n", "  AV: X\n"), "finding_schema"),
    "missing_cvss_metric": (_edit(F1, "  AC: L\n", ""), "finding_schema"),
    "bad_cwe": (_edit(F1, "cwe: CWE-639", "cwe: CWE-abc"), "finding_schema"),
    "bad_confidence": (_edit(F1, "confidence: high", "confidence: certain"), "finding_schema"),
    "bad_fix_effort": (_edit(F1, "fix_effort: low", "fix_effort: huge"), "finding_schema"),
    "bad_status": (_edit(F1, "status: reported", "status: open"), "finding_schema"),
    "empty_counterevidence": (
        _edit(
            F1,
            'counterevidence: "A gateway rule could scope the id; none was observed."',
            'counterevidence: ""',
        ),
        "finding_schema",
    ),
    "missing_assumptions_key": (
        _edit(F1, 'assumptions: "Attacker holds any valid low-privilege account."\n', ""),
        "finding_schema",
    ),
    "unparsable_frontmatter": (_edit(F1, "id: idor-users-7f3a", "id idor"), "finding_schema"),
    "cvss_score_mismatch": (_edit(F1, "cvss_score: 6.5", "cvss_score: 9.9"), "cvss_consistency"),
    "severity_mismatch": (_edit(F1, "severity: medium", "severity: critical"), "cvss_consistency"),
    "medium_without_rationale": (
        _edit(F1, "confidence: high", "confidence: medium"),
        "finding_rules",
    ),
    "fix_after_without_verification": (
        _edit(F1, 'fix_verification: "Re-run trigger.http as another user; expect 403."\n', ""),
        "finding_rules",
    ),
    "fix_before_without_fix_after": (
        _edit(F1, '    fix_after: "user = db.get(id, owner=caller)"\n', ""),
        "finding_rules",
    ),
    "fix_after_without_fix_before": (
        _edit(F1, '    fix_before: "user = db.get(id)"\n', ""),
        "finding_rules",
    ),
    "end_before_start": (_edit(F1, "end_line: 48", "end_line: 40"), "finding_rules"),
    "ruled_out_without_evidence": (
        _coverage_rows([_row(outcome="ruled_out", evidence="")]),
        "coverage_rows",
    ),
    "not_applicable_without_evidence": (
        _coverage_rows([_row(outcome="not_applicable", evidence="  ")]),
        "coverage_rows",
    ),
    "invalid_outcome": (_coverage_rows([_row(outcome="done")]), "coverage_rows"),
    "duplicate_surface_different_outcome": (
        _coverage_rows([_row(), _row(outcome="no_issue_found", agent="strix-hunter-9")]),
        "coverage_rows",
    ),
    "invalid_json_row": (
        lambda run_dir: (run_dir / "coverage" / "strix-hunter-9.jsonl").write_text(
            "{not json\n", encoding="utf-8"
        ),
        "coverage_rows",
    ),
    "confirmed_without_finding": (_unlink(F1), "confirmed_have_findings"),
    "validated_bad_closure": (
        _edit(f"validated/{FINDING_1}.md", "closure: confirmed", "closure: maybe"),
        "confirmed_have_findings",
    ),
    "ruled_out_without_reason": (
        _edit(f"validated/{FINDING_1}.md", "closure: confirmed", "closure: ruled_out"),
        "confirmed_have_findings",
    ),
    "proof_gap_without_text": (
        _edit(f"validated/{FINDING_1}.md", "closure: confirmed", "closure: open_proof_gap"),
        "confirmed_have_findings",
    ),
    "dangling_http_evidence": (
        _unlink(f"evidence/{FINDING_1}/victim.http"),
        "cross_refs",
    ),
    "http_evidence_escapes_run_dir": (
        _edit(F1, f"  - evidence/{FINDING_1}/victim.http", "  - ../../../etc/hosts"),
        "cross_refs",
    ),
    "dangling_code_location": (
        _edit(F1, "file: app/api/users.py", "file: app/api/missing.py"),
        "cross_refs",
    ),
    "finding_id_mismatch": (_edit(F1, "id: idor-users-7f3a", "id: other-0000"), "cross_refs"),
    "finding_without_validated": (_unlink(f"validated/{FINDING_1}.md"), "cross_refs"),
    "validated_without_candidate": (_unlink(f"candidates/{FINDING_1}.md"), "cross_refs"),
}


@pytest.mark.parametrize("case", sorted(NEGATIVE_CASES))
def test_verify_negative(case: str, golden: Path, capsys: pytest.CaptureFixture[str]) -> None:
    mutate, expected_check = NEGATIVE_CASES[case]
    mutate(golden)
    code, result = run_cli(capsys, "verify", str(golden))
    assert result["ok"] is False
    assert code == 2
    assert expected_check in failed_checks(result)
    failing = [row for row in result["checks"] if row["name"] == expected_check]
    assert all(row["status"] == "fail" and row["detail"] for row in failing)


def test_verify_negative_cases_cover_every_check() -> None:
    covered = {check for _mutate, check in NEGATIVE_CASES.values()}
    assert covered == set(st.CHECK_NAMES) - {"needs_follow_up"}


def test_verify_flags_are_independent(golden: Path, capsys: pytest.CaptureFixture[str]) -> None:
    edit(golden / F1, "cvss_score: 6.5", "cvss_score: 9.9")
    _code, result = run_cli(capsys, "verify", str(golden))
    assert failed_checks(result) == {"cvss_consistency"}
    detail = next(r["detail"] for r in result["checks"] if r["status"] == "fail")
    assert detail == "cvss_score 9.9 != recomputed 6.5"
    assert next(r["path"] for r in result["checks"] if r["status"] == "fail") == F1


def test_verify_same_outcome_duplicate_rows_are_allowed(
    golden: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    write_jsonl(
        golden / "coverage" / "strix-hunter-3.jsonl",
        [_row(), _row(agent="strix-hunter-9")],
    )
    code, _result = run_cli(capsys, "verify", str(golden))
    assert code == 0


# --------------------------------------------------------------------------- status


def test_status_counts(golden: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, data = run_cli(capsys, "status", str(golden))
    assert code == 0
    assert data["candidates"] == 2
    assert data["validated"] == {"confirmed": 2, "ruled_out": 0, "open_proof_gap": 0}
    assert data["findings"] == 2
    assert data["coverage"] == {
        "reported": 2,
        "no_issue_found": 1,
        "ruled_out": 1,
        "not_applicable": 0,
        "needs_follow_up": 1,
    }
    assert data["needs_follow_up"] == [
        {
            "surface": "POST /upload",
            "risk_area": "File upload",
            "evidence": "notes/strix-hunter-4--upload.md",
            "agent": "strix-hunter-4",
            "path": "coverage/strix-hunter-4.jsonl:1",
        }
    ]
    assert data["amendments"] == 0


def test_status_counts_amendments_and_closures(
    golden: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (golden / "amendments" / "strix-validator-1-1.md").write_text("fix boundary\n", "utf-8")
    edit(golden / "validated" / f"{FINDING_2}.md", "closure: confirmed", "closure: ruled_out")
    _code, data = run_cli(capsys, "status", str(golden))
    assert data["amendments"] == 1
    assert data["validated"]["confirmed"] == 1
    assert data["validated"]["ruled_out"] == 1


# --------------------------------------------------------------------------- assemble

ASSEMBLED = (
    "vulnerabilities.json",
    "vulnerabilities.csv",
    "findings.sarif",
    "coverage.json",
    "penetration_test_report.md",
)


def test_assemble_outputs(golden: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, data = run_cli(capsys, "assemble", str(golden))
    assert code == 0
    assert data["findings"] == 2
    assert data["written"] == [str(golden / name) for name in ASSEMBLED]
    for name in ASSEMBLED:
        assert (golden / name).stat().st_size > 0

    findings = json.loads((golden / "vulnerabilities.json").read_text(encoding="utf-8"))
    assert isinstance(findings, list)
    assert len(findings) == len(list((golden / "vulnerabilities").glob("*.md"))) == 2
    assert {f["id"] for f in findings} == {
        p.stem for p in (golden / "vulnerabilities").glob("*.md")
    }
    assert [f["id"] for f in findings] == [FINDING_2, FINDING_1]  # critical first
    first = findings[1]
    assert first["cvss"]["AV"] == "N"
    assert first["code_locations"][0]["start_line"] == 42
    assert first["description"].startswith("IDOR on GET")
    assert first["remediation"] == "Scope the query to the caller."
    assert first["path"] == F1

    with (golden / "vulnerabilities.csv").open(encoding="utf-8", newline="") as handle:
        rows = list(csv.reader(handle))
    assert rows[0] == [
        "id",
        "title",
        "severity",
        "cvss_score",
        "cwe",
        "target",
        "endpoint",
        "method",
        "confidence",
        "fix_effort",
        "status",
        "discovered_by",
        "validated_by",
    ]
    assert len(rows) == 3
    assert rows[1][:5] == [FINDING_2, "SQL injection in POST /search", "critical", "10.0", "CWE-89"]

    sarif = json.loads((golden / "findings.sarif").read_text(encoding="utf-8"))
    assert sarif["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert sarif["version"] == "2.1.0"
    results = sarif["runs"][0]["results"]
    assert len(results) == 2
    by_id = {r["properties"]["id"]: r for r in results}
    assert by_id[FINDING_1]["ruleId"] == "CWE-639"
    assert by_id[FINDING_2]["ruleId"] == "CWE-89"
    assert by_id[FINDING_1]["level"] == "warning"
    assert by_id[FINDING_2]["level"] == "error"
    location = by_id[FINDING_1]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "app/api/users.py"
    assert location["region"] == {"startLine": 42, "endLine": 48}
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    assert [rule["id"] for rule in rules] == ["CWE-639", "CWE-89"]
    assert all(
        results[i]["ruleIndex"] == [r["id"] for r in rules].index(results[i]["ruleId"])
        for i in range(2)
    )

    coverage = json.loads((golden / "coverage.json").read_text(encoding="utf-8"))
    assert coverage["total"] == 5
    assert coverage["counts"] == {
        "reported": 2,
        "no_issue_found": 1,
        "ruled_out": 1,
        "not_applicable": 0,
        "needs_follow_up": 1,
    }
    assert [r["surface"] for r in coverage["by_outcome"]["reported"]] == [
        "GET /api/users/{id}",
        "POST /search",
    ]
    assert coverage["by_outcome"]["needs_follow_up"][0]["surface"] == "POST /upload"

    report = (golden / "penetration_test_report.md").read_text(encoding="utf-8")
    assert report.startswith("# Penetration Test Report")
    assert FINDING_1 in report
    assert "Suggested fix" in report
    assert "## Threat model" in report
    assert "### Open follow-ups" in report


def test_assemble_excludes_withdrawn_findings_from_sarif_only(
    golden: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    edit(golden / F1, "status: reported", "status: withdrawn")
    code, data = run_cli(capsys, "assemble", str(golden))
    assert code == 0
    assert data["findings"] == 2
    sarif = json.loads((golden / "findings.sarif").read_text(encoding="utf-8"))
    assert [r["properties"]["id"] for r in sarif["runs"][0]["results"]] == [FINDING_2]
    report = (golden / "penetration_test_report.md").read_text(encoding="utf-8")
    assert "## Withdrawn findings" in report


def test_assemble_empty_run_dir(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _code, init = run_cli(
        capsys, "init", "https://example.com", "--out-dir", str(tmp_path), "--run-name", "e"
    )
    code, data = run_cli(capsys, "assemble", init["run_dir"])
    assert code == 0
    assert data["findings"] == 0
    run_dir = Path(init["run_dir"])
    assert json.loads((run_dir / "vulnerabilities.json").read_text(encoding="utf-8")) == []
    sarif = json.loads((run_dir / "findings.sarif").read_text(encoding="utf-8"))
    assert sarif["runs"][0]["results"] == []


def test_assemble_rejects_unparsable_finding(
    golden: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (golden / "vulnerabilities" / "broken-0000.md").write_text("no frontmatter\n", "utf-8")
    code, data = run_cli(capsys, "assemble", str(golden))
    assert code == 1
    assert "broken-0000.md" in data["error"]


def test_assemble_is_byte_deterministic(
    golden: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    copy_a = tmp_path / "copy_a"
    copy_b = tmp_path / "copy_b"
    shutil.copytree(golden, copy_a)
    shutil.copytree(golden, copy_b)
    assert run_cli(capsys, "assemble", str(copy_a))[0] == 0
    assert run_cli(capsys, "assemble", str(copy_b))[0] == 0
    first = {name: (copy_a / name).read_bytes() for name in ASSEMBLED}
    assert first == {name: (copy_b / name).read_bytes() for name in ASSEMBLED}
    assert run_cli(capsys, "assemble", str(copy_a))[0] == 0
    assert first == {name: (copy_a / name).read_bytes() for name in ASSEMBLED}


def test_verify_still_passes_after_assemble(
    golden: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run_cli(capsys, "assemble", str(golden))
    code, result = run_cli(capsys, "verify", str(golden))
    assert code == 0
    assert result["ok"] is True


# --------------------------------------------------------------------------- resolver, script lint


def test_resolver_finds_knowledge_packs() -> None:
    root = st.resolve_skills_root()
    assert root is not None
    assert (root / "vulnerabilities" / "sql_injection.md").is_file()
    assert root == ROOT / "strix" / "skills"


def test_resolver_honours_plugin_root_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "strix" / "skills" / "vulnerabilities").mkdir(parents=True)
    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(tmp_path))
    assert st.resolve_skills_root() == tmp_path / "strix" / "skills"


def test_resolver_honours_strix_home_when_plugin_root_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(tmp_path / "missing"))
    (tmp_path / "home" / "strix" / "skills").mkdir(parents=True)
    monkeypatch.setenv("STRIX_HOME", str(tmp_path / "home"))
    resolved = st.resolve_skills_root()
    assert resolved is not None
    assert resolved.is_dir()


def test_script_is_stdlib_only() -> None:
    stdlib = set(sys.stdlib_module_names) | {"__future__"}
    imported = set(re.findall(r"^(?:from|import) (\w+)", SCRIPT.read_text("utf-8"), re.MULTILINE))
    assert imported <= stdlib, imported - stdlib


def test_script_passes_ruff() -> None:
    if importlib.util.find_spec("ruff") is None and shutil.which("ruff") is None:
        pytest.skip("ruff not installed")
    command = [sys.executable, "-m", "ruff"] if importlib.util.find_spec("ruff") else ["ruff"]
    result = subprocess.run(  # noqa: S603
        [*command, "check", str(SCRIPT.relative_to(ROOT))],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_script_runs_as_a_standalone_program(tmp_path: Path) -> None:
    result = subprocess.run(  # noqa: S603
        [sys.executable, str(SCRIPT), "cvss", *"NLLNUHNN", "--json"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert json.loads(result.stdout)["score"] == 6.5


# --------------------------------------------------------------------------- agents / manifests

AGENT_MODELS = {
    "strix-architect": "opus",
    "strix-recon": "sonnet",
    "strix-code-mapper": "sonnet",
    "strix-sast-triage": "sonnet",
    "strix-hunter": "sonnet",
    "strix-validator": "sonnet",
    "strix-reporter": "sonnet",
    "strix-checker": "haiku",
}
AGENTS_DIR = ROOT / "agents"
COMMAND = ROOT / "commands" / "strix.md"
SKILL_DIR = ROOT / "skills" / "strix-team"
COMMAND_FLAGS = (
    "--mode",
    "--instruction",
    "--authorized",
    "--static-only",
    "--run-code",
    "--max-agents",
)


def _tool_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    return [str(part).strip() for part in value or []]


def _agent_frontmatter(name: str) -> dict[str, Any]:
    path = AGENTS_DIR / f"{name}.md"
    assert path.is_file(), f"missing agent file {path}"
    frontmatter, _body = st.read_frontmatter(path)
    return frontmatter


def test_agent_files_match_the_tier_table() -> None:
    present = {path.stem for path in AGENTS_DIR.glob("strix-*.md")}
    assert present == set(AGENT_MODELS)


@pytest.mark.parametrize("name", sorted(AGENT_MODELS))
def test_agent_frontmatter(name: str) -> None:
    frontmatter = _agent_frontmatter(name)
    assert frontmatter["name"] == name
    assert isinstance(frontmatter["description"], str)
    assert frontmatter["description"].strip()
    assert frontmatter["model"] in {"opus", "sonnet", "haiku"}
    assert frontmatter["model"] == AGENT_MODELS[name]


def test_checker_tools_are_read_only() -> None:
    frontmatter = _agent_frontmatter("strix-checker")
    assert _tool_list(frontmatter["tools"]) == ["Read", "Grep", "Glob", "Bash"]


def test_plugin_manifest() -> None:
    manifest = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text("utf-8"))
    assert manifest["name"]
    assert re.fullmatch(r"\d+\.\d+\.\d+", manifest["version"])


def test_marketplace_manifest() -> None:
    manifest = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text("utf-8"))
    plugin = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text("utf-8"))
    assert manifest["name"]
    sources = [entry["source"] for entry in manifest["plugins"]]
    assert "./" in sources
    entry = next(e for e in manifest["plugins"] if e["source"] == "./")
    assert entry["name"] == plugin["name"]


def test_command_declares_flags() -> None:
    assert COMMAND.is_file()
    text = COMMAND.read_text(encoding="utf-8")
    frontmatter, _body = st.read_frontmatter(COMMAND)
    assert str(frontmatter["description"]).strip()
    for flag in COMMAND_FLAGS:
        assert flag in text, flag
        assert flag in str(frontmatter["argument-hint"]), flag


def test_skill_frontmatter() -> None:
    frontmatter, _body = st.read_frontmatter(SKILL_DIR / "SKILL.md")
    assert frontmatter["name"] == "strix-team"
    assert str(frontmatter["description"]).strip()


# --------------------------------------------------------------------------- cross references


def _doc_files() -> list[Path]:
    files = [*sorted(AGENTS_DIR.glob("*.md")), COMMAND, SKILL_DIR / "SKILL.md"]
    files += sorted((SKILL_DIR / "references").glob("*.md"))
    return [path for path in files if path.is_file()]


def _pack_references(text: str, categories: list[str]) -> set[tuple[str, str]]:
    names = "|".join(re.escape(category) for category in categories)
    prefixed = re.findall(rf"strix/skills/({names})/([a-z0-9_]+)(?:\.md)?\b", text)
    bare = re.findall(rf"(?<![\w/.-])({names})/([a-z0-9_]+)\.md\b", text)
    return {*prefixed, *bare}


def test_knowledge_pack_references_resolve() -> None:
    root = st.resolve_skills_root()
    assert root is not None
    categories = sorted(p.name for p in root.iterdir() if p.is_dir() and p.name != "__pycache__")
    missing = []
    checked = 0
    for path in _doc_files():
        for category, name in sorted(_pack_references(path.read_text("utf-8"), categories)):
            checked += 1
            if not (root / category / f"{name}.md").is_file():
                missing.append(f"{path.relative_to(ROOT)}: {category}/{name}.md")
    assert checked > 0, "no knowledge-pack references found in agents/commands/skill docs"
    assert missing == []


def test_agent_names_used_in_docs_exist() -> None:
    roles = {"recon", "code", "sast", "architect", "hunter", "validator", "reporter", "checker"}
    known = {path.stem for path in AGENTS_DIR.glob("strix-*.md")}
    unknown = []
    for path in [COMMAND, SKILL_DIR / "SKILL.md", *sorted((SKILL_DIR / "references").glob("*.md"))]:
        if not path.is_file():
            continue
        tokens = set(re.findall(r"\bstrix-[a-z]+(?:-[a-z]+)*", path.read_text("utf-8")))
        unknown.extend(
            f"{path.relative_to(ROOT)}: {token}"
            for token in sorted(tokens)
            if token.split("-")[1] in roles and token not in known
        )
    assert unknown == []


def test_helper_script_referenced_by_docs_exists() -> None:
    for path in [COMMAND, SKILL_DIR / "SKILL.md"]:
        text = path.read_text("utf-8")
        assert "strix_team.py" in text, path
    assert SCRIPT.is_file()
