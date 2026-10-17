import json
from pathlib import Path

from mcp_guard.cli import scan_file, as_json


CORPUS = Path(__file__).parent / "corpus"
CASES = CORPUS / "cases.json"
MANIFEST = CORPUS / "manifest.json"


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
