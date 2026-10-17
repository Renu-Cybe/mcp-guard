import json, subprocess, sys
from pathlib import Path

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
    assert uri.startswith('file:///')
    assert uri.endswith('/config.json')
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
        'private': {'endpoint':'http://127.0.0.1:8080/mcp'},
        'authenticated': {'serverUrl':'https://example.test/mcp', 'api_key':'${MCP_TOKEN}'},
    }}
    f = tmp_path/'config.json'; f.write_text(json.dumps(cfg))
    r = run('scan', str(f), '--format','json')
    data = json.loads(r.stdout)
    assert any(x['server'] == 'private' and x['rule_id'] == 'MCPG004' for x in data)
    assert not any(x['server'] == 'authenticated' and x['rule_id'] == 'MCPG006' for x in data)

def test_action_contract():
    action = (ROOT / 'action.yml').read_text(encoding='utf-8')
    assert 'continue-on-error' not in action
    assert 'if: always()' in action
    assert 'actions/upload-artifact@' in action
    assert 'run: PYTHONPATH="${{ github.action_path }}/src"' not in action

def test_rejects_symlink_input(tmp_path):
    target = tmp_path/'real.json'; target.write_text(json.dumps({'mcpServers': {}}))
    link = tmp_path/'link.json'
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        return
    r = run('scan', str(link), '--format','json')
    assert r.returncode == 2
