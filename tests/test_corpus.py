import json
import re
from collections import Counter
from pathlib import Path


MANIFEST = Path(__file__).parent / "corpus" / "manifest.json"


def test_d2_manifest_has_all_30_stratified_samples():
    data = json.loads(MANIFEST.read_text(encoding="utf-8-sig"))
    samples = data["samples"]
    assert data["schema_version"] == 1
    assert len(samples) == 30
    assert len({sample["id"] for sample in samples}) == 30
    assert Counter(sample["stratum"] for sample in samples) == Counter({
        "MCP server": 19,
        "skill": 5,
        "SDK": 2,
        "registry": 1,
        "gateway": 1,
        "adapter": 1,
        "plugin": 1,
    })


def test_d2_manifest_has_pinned_evidence_and_explicit_boundary():
    data = json.loads(MANIFEST.read_text(encoding="utf-8-sig"))
    for sample in data["samples"]:
        assert re.fullmatch(r"[0-9a-f]{40}", sample["commit"])
        assert sample["repo"] and sample["config_format"] and sample["transport"]
        assert sample["expected_input"] == ("server-map" if sample["stratum"] == "MCP server" else "unsupported")
    assert "third-party source code" in data["policy"]
