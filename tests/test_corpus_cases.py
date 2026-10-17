import json
import os
import subprocess
import sys
from pathlib import Path

from mcp_guard.cli import scan_file, as_json


CORPUS = Path(__file__).parent / "corpus"
CASES = CORPUS / "cases.json"
MANIFEST = CORPUS / "manifest.json"
ROOT = CORPUS.parent.parent


def _run(*args):
    return subprocess.run(
        [sys.executable, "-m", "mcp_guard.cli", *args],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        capture_output=True,
        text=True,
    )


def test_sanitized_d2_cases_cover_registered_samples_and_expected_rules():
    data = json.loads(CASES.read_text(encoding="utf-8-sig"))
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8-sig"))
    sample_ids = {sample["id"] for sample in manifest["samples"]}
    assert data["schema_version"] == 1
    assert len(data["cases"]) == 8
    assert len({case["id"] for case in data["cases"]}) == len(data["cases"])
    assert all(case["sample_ids"] and set(case["sample_ids"]) <= sample_ids for case in data["cases"])
    server_map_ids = {sample["id"] for sample in manifest["samples"] if sample["expected_input"] == "server-map"}
    covered_ids = {sample_id for case in data["cases"] for sample_id in case["sample_ids"]}
    assert covered_ids >= server_map_ids
    assert all(case["rationale"].strip() for case in data["cases"])

    for case in data["cases"]:
        findings = scan_file(CORPUS / "fixtures" / case["fixture"])
        assert {finding.rule_id for finding in findings} == set(case["expected_rules"]), case["id"]


def test_sanitized_d2_cases_are_safe_to_report_without_placeholder_secret_leaks():
    data = json.loads(CASES.read_text(encoding="utf-8-sig"))
    for case in data["cases"]:
        fixture = CORPUS / "fixtures" / case["fixture"]
        report = as_json(scan_file(fixture))
        assert "D2_PLACEHOLDER_SECRET" not in report


def test_registry_adapter_scans_pinned_package_and_oauth_remote_without_leaks():
    findings = scan_file(CORPUS / "fixtures" / "registry-pinned-clean.json", input_format="registry")
    assert findings == []
    assert "MCP_GUARD_REGISTRY_SECRET" not in as_json(findings)


def test_registry_adapter_reports_remote_without_auth():
    findings = scan_file(CORPUS / "fixtures" / "registry-missing-auth.json", input_format="registry")
    assert {finding.rule_id for finding in findings} == {"MCPG006"}


def test_registry_adapter_reports_unpinned_package():
    findings = scan_file(CORPUS / "fixtures" / "registry-unpinned.json", input_format="registry")
    assert {finding.rule_id for finding in findings} == {"MCPG005"}


def test_registry_adapter_rejects_malformed_and_unknown_schema():
    import pytest
    for filename in ("registry-malformed.json", "registry-unknown-schema.json"):
        with pytest.raises(ValueError):
            scan_file(CORPUS / "fixtures" / filename, input_format="registry")
    bad_schema = CORPUS / "fixtures" / "registry-bad-schema.json"
    bad_schema.write_text(json.dumps({"$schema": "https://example.test/schema.json", "packages": []}))
    try:
        with pytest.raises(ValueError):
            scan_file(bad_schema, input_format="registry")
    finally:
        bad_schema.unlink()


def test_registry_baseline_is_bound_to_input_format(tmp_path):
    source = CORPUS / "fixtures" / "registry-missing-auth.json"
    baseline = tmp_path / "registry-baseline.json"
    assert _run("baseline", str(source), "--input-format", "registry", "--output", str(baseline)).returncode == 0
    data = json.loads(baseline.read_text())
    assert data["input_format"] == "registry"
    same = _run("diff", str(source), "--input-format", "registry", "--baseline", str(baseline), "--format", "json")
    assert same.returncode == 0
    assert json.loads(same.stdout) == []
    mismatch = _run("diff", str(source), "--baseline", str(baseline), "--format", "json")
    assert mismatch.returncode == 2
    assert "baseline input format mismatch" in mismatch.stderr
