import json, re, subprocess, sys
from pathlib import Path
from mcp_guard import __version__

ROOT = Path(__file__).parents[1]
CLI = [sys.executable, '-m', 'mcp_guard.cli']

def run(*args):
    return subprocess.run(CLI + list(args), cwd=ROOT, env={**__import__('os').environ, 'PYTHONPATH': str(ROOT/'src')}, capture_output=True, text=True)

def test_scan_outputs_findings(tmp_path):
    cfg = {'mcpServers': {'bad': {'command':'bash', 'args':['-c','run'], 'env': {'secret':'not-a-real-secret'}, 'url':'http://169.254.169.254/latest'}}}
    f = tmp_path/'config.json'; f.write_text(json.dumps(cfg))
    r = run('scan', str(f), '--format','json')
    assert r.returncode == 1
    data = json.loads(r.stdout)
    assert {'MCPG001','MCPG002','MCPG004'} <= {x['rule_id'] for x in data}
    assert 'not-a-real-secret' not in r.stdout

def test_sarif_and_baseline_diff(tmp_path):
    cfg = {'servers': {'ok': {'command':'node', 'args':['server.js']}}}
    f = tmp_path/'config.json'; f.write_text(json.dumps(cfg))
    base = tmp_path/'base.json'
    assert run('baseline', str(f), '--output', str(base)).returncode == 0
    r = run('diff', str(f), '--baseline', str(base), '--format','sarif')
    assert r.returncode == 0
    assert '"results": []' in r.stdout

def test_nested_claude_format(tmp_path):
    cfg = {'config': {'mcpServers': {'remote': {'url':'https://example.test/mcp'}}}}
    f = tmp_path/'config.json'; f.write_text(json.dumps(cfg))
    r = run('scan', str(f), '--format','json')
    assert r.returncode == 0
    assert 'MCPG006' in r.stdout

def test_sarif_uses_source_file_and_redacts_query_secret(tmp_path):
    cfg = {'mcpServers': {'remote': {'url':'https://example.test/mcp?token=not-a-real-token'}}}
    f = tmp_path/'config.json'; f.write_text(json.dumps(cfg))
    r = run('scan', str(f), '--format','sarif')
    assert r.returncode == 1
    data = json.loads(r.stdout)
    uri = data['runs'][0]['results'][0]['locations'][0]['physicalLocation']['artifactLocation']['uri']
    assert uri == 'config.json'
    assert str(tmp_path) not in r.stdout
    assert 'not-a-real-token' not in r.stdout

def test_command_evidence_is_redacted(tmp_path):
    cfg = {'mcpServers': {'shell': {'command':'bash', 'args':['-c', '--token', 'not-a-real-token']}}}
    f = tmp_path/'config.json'; f.write_text(json.dumps(cfg))
    r = run('scan', str(f), '--format','json')
    assert r.returncode == 1
    assert 'not-a-real-token' not in r.stdout
    assert '<redacted>' in r.stdout

def test_command_assignment_evidence_is_redacted(tmp_path):
    cfg = {'mcpServers': {'shell': {'command':'bash', 'args':['-c', 'TOKEN=not-a-real-token']}}}
    f = tmp_path/'config.json'; f.write_text(json.dumps(cfg))
    r = run('scan', str(f), '--format','json')
    assert r.returncode == 1
    assert 'not-a-real-token' not in r.stdout
    assert 'TOKEN=<redacted>' in r.stdout

def test_endpoint_alias_and_auth_key(tmp_path):
    cfg = {'mcpServers': {
        'private': {'endpoint':'http://10.0.0.5:8080/mcp'},
        'local_bridge': {'url':'http://127.0.0.1:9222/mcp'},
        'authenticated': {'serverUrl':'https://example.test/mcp', 'api_key':'${MCP_TOKEN}'},
    }}
    f = tmp_path/'config.json'; f.write_text(json.dumps(cfg))
    r = run('scan', str(f), '--format','json')
    data = json.loads(r.stdout)
    assert any(x['server'] == 'private' and x['rule_id'] == 'MCPG004' for x in data)
    assert not any(x['server'] == 'local_bridge' for x in data)
    assert not any(x['server'] == 'authenticated' and x['rule_id'] == 'MCPG006' for x in data)


def test_auth_query_and_bearer_variable_are_not_false_positives(tmp_path):
    cfg = {'mcpServers': {
        'query_auth': {'url':'https://example.test/mcp?token=${MCP_TOKEN}'},
        'bearer_auth': {'url':'https://example.test/mcp', 'token':'Bearer ${MCP_TOKEN}'},
        'token_scheme': {'url':'https://example.test/mcp', 'headers': {'Authorization': 'Token ${MCP_TOKEN}'}},
    }}
    f = tmp_path/'config.json'; f.write_text(json.dumps(cfg))
    r = run('scan', str(f), '--format', 'json')
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout) == []


def test_arbitrary_headers_do_not_count_as_authentication(tmp_path):
    cfg = {'mcpServers': {'remote': {
        'url':'https://example.test/mcp',
        'headers': {'X-Request-ID': 'trace-123'},
        'auth': 'none',
    }}}
    f = tmp_path/'config.json'; f.write_text(json.dumps(cfg))
    r = run('scan', str(f), '--format', 'json')
    assert r.returncode == 0
    findings = json.loads(r.stdout)
    assert any(item['rule_id'] == 'MCPG006' for item in findings)


def test_docker_network_none_is_safe_but_host_network_is_not(tmp_path):
    cfg = {'mcpServers': {
        'safe': {'command':'docker', 'args':['run', '--network=none', 'example/server:1.0']},
        'risky': {'command':'docker', 'args':['run', '--network', 'host', 'example/server:1.0']},
    }}
    f = tmp_path/'config.json'; f.write_text(json.dumps(cfg))
    r = run('scan', str(f), '--format', 'json')
    assert r.returncode == 1
    findings = json.loads(r.stdout)
    assert not any(item['server'] == 'safe' and item['rule_id'] == 'MCPG008' for item in findings)
    assert any(item['server'] == 'risky' and item['rule_id'] == 'MCPG008' for item in findings)


def test_complete_executor_command_has_one_unpinned_finding(tmp_path):
    cfg = {'mcpServers': {'browser': {'command':'npx @playwright/mcp'}}}
    f = tmp_path/'config.json'; f.write_text(json.dumps(cfg))
    r = run('scan', str(f), '--format', 'json')
    findings = json.loads(r.stdout)
    assert [item['rule_id'] for item in findings] == ['MCPG005']

def test_action_contract():
    action = (ROOT / 'action.yml').read_text(encoding='utf-8')
    assert 'continue-on-error' not in action
    assert 'if: always()' in action
    assert 'actions/upload-artifact@' in action
    assert 'github/codeql-action/upload-sarif@' in action
    assert 'upload-artifact:' in action
    assert 'upload-sarif:' in action
    assert 'artifact-name:' in action
    assert 'run: PYTHONPATH="${{ github.action_path }}/src"' not in action


def test_version_is_consistent_across_package_cli_and_sarif(tmp_path):
    metadata = re.search(r'^version\s*=\s*"([^"]+)"$', (ROOT / 'pyproject.toml').read_text(encoding='utf-8'), re.MULTILINE)
    assert metadata and metadata.group(1) == __version__
    version = run('--version')
    assert version.returncode == 0
    assert version.stdout.strip() == f'mcp-guard {__version__}'
    f = tmp_path/'config.json'; f.write_text(json.dumps({'mcpServers': {'ok': {'command':'node', 'args':['server.js']}}}))
    report = run('scan', str(f), '--format', 'sarif')
    data = json.loads(report.stdout)
    assert data['runs'][0]['tool']['driver']['version'] == __version__

def test_rejects_symlink_input(tmp_path):
    target = tmp_path/'real.json'; target.write_text(json.dumps({'mcpServers': {}}))
    link = tmp_path/'link.json'
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        return
    r = run('scan', str(link), '--format','json')
    assert r.returncode == 2

def test_jsonc_cursor_style_config_is_supported(tmp_path):
    f = tmp_path/'mcp.jsonc'
    f.write_text('''{
      // Cursor and VS Code commonly allow comments and trailing commas.
      "servers": {"browser": {"command": "npx", "args": ["@playwright/mcp@1.2.3",],},}, // trailing comment
    }''')
    r = run('scan', str(f), '--format', 'json')
    assert r.returncode == 0
    assert r.stdout.strip() == '[]'

def test_jsonc_scoped_executor_without_pin_is_reported(tmp_path):
    f = tmp_path/'mcp.jsonc'
    f.write_text('{"mcpServers":{"browser":{"command":"npx","args":["-y","@playwright/mcp"]}}}')
    r = run('scan', str(f), '--format', 'json')
    assert r.returncode == 0
    assert {item['rule_id'] for item in json.loads(r.stdout)} == {'MCPG005'}

def test_new_high_risk_rules(tmp_path):
    cfg = {'mcpServers': {'risky': {
        'url': 'http://service.example.test/mcp',
        'permissions': ['*'],
        'args': ['--privileged', '-v', '/var/run/docker.sock:/var/run/docker.sock'],
    }}}
    f = tmp_path/'config.json'; f.write_text(json.dumps(cfg))
    r = run('scan', str(f), '--format', 'json')
    assert r.returncode == 1
    ids = {x['rule_id'] for x in json.loads(r.stdout)}
    assert {'MCPG006', 'MCPG007', 'MCPG008', 'MCPG009'} <= ids

def test_safe_real_world_patterns_do_not_raise_false_positives(tmp_path):
    cfg = {'mcpServers': {
        'github': {
            'command': 'docker',
            'args': ['run', '--rm', 'ghcr.io/example/mcp-server:1.4.2'],
            'env': {'GITHUB_TOKEN': '${GITHUB_TOKEN}'},
        },
        'local': {
            'command': 'node',
            'args': ['server.js', 'http://127.0.0.1:9222'],
        },
        'remote': {
            'url': 'https://service.example.test/mcp',
            'auth': {'headers': {'Authorization': 'Bearer ${MCP_AUTH_HEADER}'}},
        },
    }}
    f = tmp_path/'safe.json'; f.write_text(json.dumps(cfg))
    r = run('scan', str(f), '--format', 'json')
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout) == []

def test_unsupported_registry_skill_or_toml_inputs_fail_clearly(tmp_path):
    registry = tmp_path/'server.json'; registry.write_text(json.dumps({'name': 'demo', 'remotes': [{'url': 'https://example.test'}]}))
    skill = tmp_path/'SKILL.md'; skill.write_text('# Demo skill\n\nRun scripts deliberately.')
    toml = tmp_path/'mcp.toml'; toml.write_text('[mcpServers.docs]\ncommand = "uvx"\n')
    for path in (registry, skill, toml):
        r = run('scan', str(path), '--format', 'json')
        assert r.returncode == 2
        assert 'supported' in r.stderr.lower() or 'no supported' in r.stderr.lower()
