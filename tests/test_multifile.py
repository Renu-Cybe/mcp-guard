import json
from pathlib import Path

from test_cli import run


def write_cfg(path, command="node"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"mcpServers": {"same": {"command": command}}}), encoding="utf-8")


def test_multifile_sources_prevent_same_name_collisions_and_are_deterministic(tmp_path):
    first = tmp_path / "z" / "config.json"
    second = tmp_path / "a" / "config.json"
    write_cfg(first, "bash")
    write_cfg(second, "bash")
    result = run("scan", str(first), str(second), "--format", "json")
    assert result.returncode == 1
    findings = json.loads(result.stdout)
    assert [item["source"] for item in findings] == ["a/config.json", "z/config.json"]
    assert len({item["fingerprint"] for item in findings}) == 2
    again = run("scan", str(second), str(first), "--format", "json")
    assert again.stdout == result.stdout


def test_multifile_sarif_uses_source_uri_and_v2_fingerprint(tmp_path):
    first = tmp_path / "one.json"
    second = tmp_path / "two.json"
    write_cfg(first, "bash")
    write_cfg(second, "bash")
    result = run("scan", str(first), str(second), "--format", "sarif")
    data = json.loads(result.stdout)
    locations = data["runs"][0]["results"]
    assert {item["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for item in locations} == {"one.json", "two.json"}
    assert all("mcpGuard/v2" in item["fingerprints"] for item in locations)


def test_multifile_baseline_round_trip_and_precise_suppression(tmp_path):
    first = tmp_path / "one.json"
    second = tmp_path / "two.json"
    write_cfg(first, "bash")
    write_cfg(second, "node")
    baseline = tmp_path / "baseline.json"
    assert run("baseline", str(first), str(second), "--output", str(baseline)).returncode == 0
    data = json.loads(baseline.read_text(encoding="utf-8"))
    assert data["version"] == 4
    assert data["scope"] == "multi-file"
    assert data["fingerprint_version"] == 2
    assert all(not Path(item["source"]).is_absolute() for item in data["findings"])
    assert run("diff", str(first), str(second), "--baseline", str(baseline), "--format", "json").stdout.strip() == "[]"
    write_cfg(second, "bash")
    diff = run("diff", str(first), str(second), "--baseline", str(baseline), "--format", "json")
    findings = json.loads(diff.stdout)
    assert {item["source"] for item in findings} == {"two.json"}


def test_multifile_baseline_rejects_input_format_mismatch(tmp_path):
    first = tmp_path / "one.json"
    second = tmp_path / "two.json"
    write_cfg(first, "bash")
    write_cfg(second, "node")
    baseline = tmp_path / "baseline.json"
    assert run("baseline", str(first), str(second), "--output", str(baseline)).returncode == 0
    data = json.loads(baseline.read_text(encoding="utf-8"))
    data["input_format"] = "registry"
    baseline.write_text(json.dumps(data), encoding="utf-8")
    result = run("diff", str(first), str(second), "--baseline", str(baseline), "--format", "json")
    assert result.returncode == 2
    assert "multi-file baseline requires mcp-json input" in result.stderr


def test_multifile_baseline_binds_source_set_and_scope(tmp_path):
    first = tmp_path / "one.json"
    second = tmp_path / "two.json"
    third = tmp_path / "three.json"
    write_cfg(first, "bash")
    write_cfg(second, "node")
    write_cfg(third, "bash")
    baseline = tmp_path / "baseline.json"
    assert run("baseline", str(first), str(second), "--output", str(baseline)).returncode == 0

    mismatch = run("diff", str(first), str(third), "--baseline", str(baseline), "--format", "json")
    assert mismatch.returncode == 2
    assert "baseline sources mismatch" in mismatch.stderr

    mismatch = run("scan", str(first), str(third), "--baseline", str(baseline), "--format", "json")
    assert mismatch.returncode == 2
    assert "baseline sources mismatch" in mismatch.stderr

    single = tmp_path / "single-baseline.json"
    assert run("baseline", str(first), "--output", str(single)).returncode == 0
    mismatch = run("diff", str(first), str(second), "--baseline", str(single), "--format", "json")
    assert mismatch.returncode == 2
    assert "version 4 baseline" in mismatch.stderr


def test_multifile_baseline_schema_rejects_unsafe_metadata(tmp_path):
    first = tmp_path / "one.json"
    second = tmp_path / "two.json"
    write_cfg(first, "bash")
    write_cfg(second, "bash")
    baseline = tmp_path / "baseline.json"
    assert run("baseline", str(first), str(second), "--output", str(baseline)).returncode == 0
    original = json.loads(baseline.read_text(encoding="utf-8"))

    cases = []
    extra = json.loads(json.dumps(original))
    extra["unexpected"] = True
    cases.append((extra, "unsupported fields"))
    absolute = json.loads(json.dumps(original))
    absolute["sources"][0] = "C:/outside.json"
    cases.append((absolute, "relative POSIX paths"))
    unknown = json.loads(json.dumps(original))
    unknown["findings"][0]["source"] = "missing.json"
    cases.append((unknown, "unknown source"))
    duplicate = json.loads(json.dumps(original))
    duplicate["findings"][1]["fingerprint"] = duplicate["findings"][0]["fingerprint"]
    cases.append((duplicate, "duplicates a fingerprint"))
    non_object = json.loads(json.dumps(original))
    non_object["findings"] = ["not-an-object"]
    cases.append((non_object, "invalid fields"))

    for index, (data, message) in enumerate(cases):
        candidate = tmp_path / f"bad-{index}.json"
        candidate.write_text(json.dumps(data), encoding="utf-8")
        result = run("diff", str(first), str(second), "--baseline", str(candidate), "--format", "json")
        assert result.returncode == 2
        assert message in result.stderr


def test_multifile_rejects_registry_and_invalid_inputs_without_partial_output(tmp_path):
    first = tmp_path / "one.json"
    unsupported = tmp_path / "two.toml"
    write_cfg(first)
    unsupported.write_text("[mcpServers]\n", encoding="utf-8")
    registry = run("scan", str(first), str(first), "--input-format", "registry", "--format", "json")
    assert registry.returncode == 2 and registry.stdout == ""
    invalid = run("scan", str(first), str(unsupported), "--format", "json")
    assert invalid.returncode == 2 and invalid.stdout == ""


def test_multifile_rejects_symlink_and_total_size_limit(tmp_path):
    target = tmp_path / "target.json"
    write_cfg(target)
    link = tmp_path / "link.json"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        link = None
    if link is not None:
        rejected = run("scan", str(target), str(link), "--format", "json")
        assert rejected.returncode == 2 and rejected.stdout == ""
    large = tmp_path / "large.json"
    large.write_text(json.dumps({"mcpServers": {}, "padding": "x" * (17 * 1024 * 1024)}), encoding="utf-8")
    rejected = run("scan", str(target), str(large), "--format", "json")
    assert rejected.returncode == 2 and rejected.stdout == ""


def test_multifile_rejects_directory_duplicate_count_and_total_limits(tmp_path):
    target = tmp_path / "target.json"
    write_cfg(target)
    directory = run("scan", str(tmp_path), "--format", "json")
    assert directory.returncode == 2 and directory.stdout == ""
    duplicate = run("scan", str(target), str(target), "--format", "json")
    assert duplicate.returncode == 2 and duplicate.stdout == ""

    many = []
    for index in range(65):
        path = tmp_path / f"many-{index}.json"
        write_cfg(path, "node")
        many.append(str(path))
    too_many = run("scan", *many, "--format", "json")
    assert too_many.returncode == 2 and too_many.stdout == ""

    total = []
    padding = "x" * (1_900_000)
    for index in range(9):
        path = tmp_path / f"total-{index}.json"
        path.write_text(json.dumps({"mcpServers": {}, "padding": padding}), encoding="utf-8")
        total.append(str(path))
    too_large = run("scan", *total, "--format", "json")
    assert too_large.returncode == 2 and too_large.stdout == ""


def test_single_file_json_shape_and_fingerprint_remain_compatible(tmp_path):
    source = tmp_path / "one.json"
    write_cfg(source, "bash")
    result = run("scan", str(source), "--format", "json")
    findings = json.loads(result.stdout)
    assert findings and all("source" not in item for item in findings)
    assert all(item["fingerprint"] == item["fingerprint"] for item in findings)
