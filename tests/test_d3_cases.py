import json
from pathlib import Path

from mcp_guard.cli import as_json, scan_file


CORPUS = Path(__file__).parent / "corpus"
CASES = CORPUS / "d3_cases.json"
MANIFEST = CORPUS / "manifest.json"


def test_d3_cases_match_expected_rules_and_registered_samples():
    data = json.loads(CASES.read_text(encoding="utf-8-sig"))
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8-sig"))
    sample_ids = {sample["id"] for sample in manifest["samples"]}

    assert data["schema_version"] == 1
    assert len(data["cases"]) == 5
    assert len({case["id"] for case in data["cases"]}) == len(data["cases"])

    for case in data["cases"]:
        assert case["sample_ids"]
        assert set(case["sample_ids"]) <= sample_ids
        assert case["source"].startswith("https://github.com/")
        assert case["rationale"].strip()
        findings = scan_file(CORPUS / "fixtures" / case["fixture"])
        assert {finding.rule_id for finding in findings} == set(case["expected_rules"]), case["id"]


def test_d3_cases_are_safe_to_report_without_secret_leaks():
    data = json.loads(CASES.read_text(encoding="utf-8-sig"))
    for case in data["cases"]:
        report = as_json(scan_file(CORPUS / "fixtures" / case["fixture"]))
        assert "YOUR_API_KEY" not in report
        assert "GRAFANA_SERVICE_ACCOUNT_TOKEN}" not in report
        assert "FIRECRAWL_API_KEY}" not in report
