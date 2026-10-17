from __future__ import annotations
import argparse, hashlib, json, re, sys
from dataclasses import dataclass, asdict
from pathlib import Path
from urllib.parse import urlparse

SECRET = re.compile(r"(?i)(sk-[A-Za-z0-9]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|bearer\s+[A-Za-z0-9._-]{12,}|(?:api[_-]?key|token|secret|password)\s*[:=]\s*[^\s,;]+)")
PRIVATE = re.compile(r"(?i)(169\.254\.169\.254|metadata\.google\.internal|localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)")
DANGEROUS = re.compile(r"(?i)(^|[/\\\s])(sh|bash|zsh|fish|cmd|powershell|pwsh)(\.exe)?$|(^|\s)(-c|/c)(\s|$)")
BROAD_PATH = re.compile(r"(^|[/\\])(?:\.ssh|\.aws|\.kube|etc|var[/\\]run)([/\\]|$)|^(?:/|[A-Za-z]:[\\/])$|^~(?:[/\\]|$)")
UNPINNED = re.compile(r"(?i)(?:@latest$|\b(?:npx|uvx|pipx|bunx)\s+[^\s@]+$|\b(?:npm|pypi|github):[^@\s]+$)")
MAX_INPUT_BYTES = 2 * 1024 * 1024


def redact(value: str) -> str:
    """Keep reports useful without copying credential-like values."""
    value = re.sub(r"(?i)(authorization\s*[:=]\s*)([^\s,;]+)", r"\1<redacted>", value)
    value = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._-]+", r"\1<redacted>", value)
    value = re.sub(r"(?i)(sk-[A-Za-z0-9]{8,}|gh[pousr]_[A-Za-z0-9]{8,}|AKIA[0-9A-Z]{8,})", "<redacted>", value)
    value = re.sub(r"(?i)([?&](?:access[_-]?token|refresh[_-]?token|client[_-]?secret|token|key|secret|password|api[_-]?key)=)[^&\s]+", r"\1<redacted>", value)
    value = re.sub(r"(?i)((?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|token|secret|password)\s*[:=]\s*)[^\s,;]+", r"\1<redacted>", value)
    value = re.sub(r"(?i)(--?(?:api[-_]?key|token|secret|password|authorization)(?:=|\s+))[^\s]+", r"\1<redacted>", value)
    value = re.sub(r"(?i)(https?://)[^/@\s]+:[^/@\s]+@", r"\1<redacted>@", value)
    return value[:160]

@dataclass
class Finding:
    rule_id: str
    severity: str
    server: str
    message: str
    path: str
    evidence: str
    remediation: str
    fingerprint: str = ""
    def finalize(self):
        raw = f"{self.rule_id}|{self.server}|{self.path}|{self.evidence}"
        self.fingerprint = hashlib.sha256(raw.encode()).hexdigest()[:16]
        return self


def _strings(value, path=""):
    if isinstance(value, dict):
        for k, v in value.items():
            yield from _strings(v, f"{path}.{k}" if path else k)
    elif isinstance(value, list):
        for i, v in enumerate(value): yield from _strings(v, f"{path}[{i}]")
    elif isinstance(value, str): yield path, value


def load_servers(path: Path):
    if path.is_symlink():
        raise ValueError("symlink input is not supported")
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError(f"input exceeds {MAX_INPUT_BYTES} bytes")
    data = json.loads(path.read_text(encoding="utf-8"))
    candidates = []
    def walk(obj, where="$"):
        if isinstance(obj, dict):
            for key in ("mcpServers", "mcp_servers", "servers"):
                if isinstance(obj.get(key), dict): candidates.append((where + "." + key, obj[key]))
            for k,v in obj.items(): walk(v, where + "." + k)
    walk(data)
    if not candidates and isinstance(data, dict):
        candidates = [("$.mcpServers", data)] if any(isinstance(v, dict) for v in data.values()) else []
    if not candidates: raise ValueError("No mcpServers/servers object found")
    # Prefer the shallowest candidate and avoid duplicate nested matches.
    _, servers = sorted(candidates, key=lambda x: len(x[0]))[0]
    return servers


def scan_file(path: Path):
    servers = load_servers(path)
    findings = []
    for name, cfg in servers.items():
        if not isinstance(cfg, dict): continue
        values = list(_strings(cfg))
        for p, val in values:
            key = p.rsplit('.', 1)[-1].split('[', 1)[0].lower()
            sensitive_key = key in {"password", "passwd", "secret", "token", "api_key", "apikey", "authorization", "access_key", "private_key", "client_secret", "refresh_token"}
            variable_ref = bool(re.fullmatch(r"\s*\$\{[^}]+}\s*", val))
            if (SECRET.search(val) or (sensitive_key and bool(val.strip()))) and not variable_ref:
                findings.append(Finding("MCPG001", "high", name, "Possible hardcoded credential", p, "credential-like value redacted", "Use environment references or a secret manager; do not commit credentials.").finalize())
            if PRIVATE.search(val) and ("url" in p.lower() or "host" in p.lower() or "endpoint" in p.lower() or "command" in p.lower() or "args" in p.lower()):
                findings.append(Finding("MCPG004", "high", name, "Private or cloud-metadata network target", p, redact(val), "Review network target and block metadata/private access unless explicitly required.").finalize())
            if BROAD_PATH.search(val) and ("arg" in p.lower() or "path" in p.lower() or "directory" in p.lower()):
                findings.append(Finding("MCPG003", "high", name, "Broad or sensitive filesystem path", p, redact(val), "Scope filesystem access to a dedicated project directory.").finalize())
            if UNPINNED.search(val):
                findings.append(Finding("MCPG005", "medium", name, "Dependency or package is not version-pinned", p, redact(val), "Pin an immutable version or commit and review updates deliberately.").finalize())
        cmd = str(cfg.get("command", ""))
        args = cfg.get("args", [])
        command_text = " ".join([cmd] + [str(x) for x in args])
        if DANGEROUS.search(cmd) or re.search(r"(?i)(?:^|\s)(?:sh|bash|cmd|powershell|pwsh)\s+-c\b", command_text):
            findings.append(Finding("MCPG002", "high", name, "Shell interpreter or inline command execution", "command", redact(command_text), "Use a fixed executable and explicit arguments; avoid shell evaluation.").finalize())
        url = cfg.get("url") or cfg.get("serverUrl") or cfg.get("endpoint")
        if isinstance(url, str) and urlparse(url).scheme in ("http", "https"):
            auth = any(
                k.lower() in {"auth", "authorization", "headers", "token", "oauth", "api_key", "apikey", "client_secret"}
                and bool(v)
                for k, v in cfg.items()
            )
            if not auth:
                findings.append(Finding("MCPG006", "medium", name, "Remote MCP endpoint has no visible authentication configuration", "url", redact(url), "Require explicit authentication and validate token audience at the client boundary.").finalize())
    return findings


def as_json(findings): return json.dumps([asdict(f) for f in findings], ensure_ascii=False, indent=2)
def as_markdown(findings):
    lines = ["# MCP Guard report", "", f"Findings: {len(findings)}", "", "| Severity | Rule | Server | Location | Message |", "|---|---|---|---|---|"]
    for f in findings: lines.append(f"| {f.severity} | {f.rule_id} | `{f.server}` | `{f.path}` | {f.message} |")
    return "\n".join(lines) + "\n"
def as_sarif(findings, source_path=None):
    rules = {}
    results = []
    source_uri = Path(source_path).resolve().as_uri() if source_path else None
    for f in findings:
        rules.setdefault(f.rule_id, {"id": f.rule_id, "shortDescription": {"text": f.message}, "help": {"text": f.remediation}})
        results.append({"ruleId": f.rule_id, "level": "error" if f.severity == "high" else "warning", "message": {"text": f.message + ": " + redact(f.evidence)}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": source_uri or f.path}, "region": {"snippet": {"text": f.path}}}}], "fingerprints": {"mcpGuard/v1": f.fingerprint}})
    return json.dumps({"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{"tool":{"driver":{"name":"mcp-guard","version":"0.1.0","rules":list(rules.values())}},"results":results}]}, ensure_ascii=False, indent=2)

def write_output(text, output):
    if output: Path(output).write_text(text, encoding="utf-8")
    else: print(text)

def main(argv=None):
    p = argparse.ArgumentParser(prog="mcp-guard")
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("scan"); s.add_argument("path"); s.add_argument("--format", choices=["json","markdown","sarif"], default="markdown"); s.add_argument("--output"); s.add_argument("--baseline")
    b = sub.add_parser("baseline"); b.add_argument("path"); b.add_argument("--output", required=True)
    d = sub.add_parser("diff"); d.add_argument("path"); d.add_argument("--baseline", required=True); d.add_argument("--format", choices=["json","markdown","sarif"], default="markdown"); d.add_argument("--output")
    args = p.parse_args(argv)
    try:
        findings = scan_file(Path(args.path))
        if args.command == "baseline":
            Path(args.output).write_text(json.dumps({"version":1,"findings":[f.fingerprint for f in findings]}, indent=2), encoding="utf-8"); return 0
        if args.command == "diff":
            old = json.loads(Path(args.baseline).read_text(encoding="utf-8")); known = set(old.get("findings", [])); findings = [f for f in findings if f.fingerprint not in known]
            fmt = args.format
        else:
            fmt = args.format
            if args.baseline:
                old = json.loads(Path(args.baseline).read_text(encoding="utf-8")); known = set(old.get("findings", [])); findings = [f for f in findings if f.fingerprint not in known]
        text = as_json(findings) if fmt == "json" else as_sarif(findings, str(Path(args.path))) if fmt == "sarif" else as_markdown(findings)
        write_output(text, args.output)
        return 1 if any(f.severity == "high" for f in findings) else 0
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print(f"mcp-guard: {e}", file=sys.stderr); return 2
if __name__ == "__main__": raise SystemExit(main())
