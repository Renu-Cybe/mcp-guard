from __future__ import annotations
import argparse, hashlib, json, re, sys
from dataclasses import dataclass, asdict
from pathlib import Path
from urllib.parse import parse_qsl, urlparse
from . import __version__

SECRET = re.compile(r"(?i)(sk-[A-Za-z0-9]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|bearer\s+[A-Za-z0-9._-]{12,}|(?:api[_-]?key|token|secret|password)\s*[:=]\s*[^\s,;]+)")
PRIVATE = re.compile(r"(?i)(169\.254\.169\.254|metadata\.google\.internal|localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)")
DANGEROUS = re.compile(r"(?i)(^|[/\\\s])(sh|bash|zsh|fish|cmd|powershell|pwsh)(\.exe)?$|(^|\s)(-c|/c)(\s|$)")
INLINE_EXEC = re.compile(r"(?i)(?:^|\s)(?:python(?:\d+(?:\.\d+)?)?|node|ruby|perl|php)\s+(?:-c|-e)\b")
BROAD_PATH = re.compile(r"(^|[/\\])(?:\.ssh|\.aws|\.kube|etc|var[/\\]run)([/\\]|$)|^(?:/|[A-Za-z]:[\\/])$|^~(?:[/\\]|$)")
UNPINNED = re.compile(r"(?i)(?:@latest$|\b(?:npm|pypi|github):[^@\s]+$)")
EXECUTOR = re.compile(r"(?i)\b(?:npx|uvx|pipx|bunx)\s+(?:(?:-[^\s]+)\s+)*(?P<package>@?[\w.-]+(?:/[\w.-]+)?)(?:\s|$)")
WILDCARD = re.compile(r"(^|[\s,])\*($|[\s,])")
MAX_INPUT_BYTES = 2 * 1024 * 1024
SUPPORTED_SUFFIXES = {".json", ".jsonc"}
AUTH_VALUE_KEYS = {
    "authorization", "token", "oauth", "api_key", "apikey", "access_token",
    "refresh_token", "client_secret", "x_api_key", "x-api-key",
}
AUTH_QUERY_KEYS = AUTH_VALUE_KEYS | {"key", "password", "secret"}
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
SEVERITY_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3}
FAIL_ON_CHOICES = ("none", "low", "medium", "high")


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


def _executor_unpinned(value: str) -> bool:
    match = EXECUTOR.search(value)
    if not match:
        return False
    package = match.group("package")
    return (package.startswith("@") and package.count("@") == 1) or (not package.startswith("@") and "@" not in package)

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


def _parse_jsonc(text: str):
    # Accept the JSON-with-comments/trailing-commas variants used by editor configs.
    out, i, quote, escape = [], 0, False, False
    while i < len(text):
        ch = text[i]
        if quote:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                quote = False
            i += 1
            continue
        if ch == '"':
            quote = True
            out.append(ch)
            i += 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = len(text) if end < 0 else end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = len(text) if end < 0 else end + 2
        else:
            out.append(ch)
            i += 1
    text = "".join(out)
    text = re.sub(r",\s*([}\]])", r"\1", text)
    return json.loads(text)


def _parse_config(path: Path):
    if path.suffix and path.suffix.lower() not in SUPPORTED_SUFFIXES:
        raise ValueError(f"unsupported config format {path.suffix}; supported formats: JSON, JSONC")
    text = path.read_text(encoding="utf-8")
    return _parse_jsonc(text)


def load_servers(path: Path):
    if path.is_symlink():
        raise ValueError("symlink input is not supported")
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError(f"input exceeds {MAX_INPUT_BYTES} bytes")
    data = _parse_config(path)
    candidates = []
    def walk(obj, where="$"):
        if isinstance(obj, dict):
            for key in ("mcpServers", "mcp_servers", "servers"):
                if isinstance(obj.get(key), dict): candidates.append((where + "." + key, obj[key]))
            for k,v in obj.items(): walk(v, where + "." + k)
    walk(data)
    if not candidates: raise ValueError("No supported mcpServers/servers object found")
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
            variable_ref = bool(re.fullmatch(r"\s*(?:[A-Za-z][A-Za-z0-9_-]*\s+)?\$\{[^}]+}\s*", val)) or _url_has_variable_auth(val)
            if (SECRET.search(val) or (sensitive_key and bool(val.strip()))) and not variable_ref:
                findings.append(Finding("MCPG001", "high", name, "Possible hardcoded credential", p, "credential-like value redacted", "Use environment references or a secret manager; do not commit credentials.").finalize())
            if PRIVATE.search(val) and ("url" in p.lower() or "host" in p.lower() or "endpoint" in p.lower()) and not _is_loopback_url(val):
                findings.append(Finding("MCPG004", "high", name, "Private or cloud-metadata network target", p, redact(val), "Review network target and block metadata/private access unless explicitly required.").finalize())
            if BROAD_PATH.search(val) and ("arg" in p.lower() or "path" in p.lower() or "directory" in p.lower()):
                findings.append(Finding("MCPG003", "high", name, "Broad or sensitive filesystem path", p, redact(val), "Scope filesystem access to a dedicated project directory.").finalize())
            if UNPINNED.search(val):
                findings.append(Finding("MCPG005", "medium", name, "Dependency or package is not version-pinned", p, redact(val), "Pin an immutable version or commit and review updates deliberately.").finalize())
            if WILDCARD.search(val) and any(k in p.lower() for k in ("tool", "permission", "allow", "scope")):
                findings.append(Finding("MCPG007", "high", name, "Wildcard tool or permission scope", p, redact(val), "Replace wildcard access with an explicit least-privilege allowlist.").finalize())
        cmd = str(cfg.get("command", ""))
        args = cfg.get("args", [])
        command_text = " ".join([cmd] + [str(x) for x in args])
        if _executor_unpinned(command_text):
            findings.append(Finding("MCPG005", "medium", name, "Dependency or package is not version-pinned", "command", redact(command_text), "Pin an immutable version or commit and review updates deliberately.").finalize())
        if DANGEROUS.search(cmd) or re.search(r"(?i)(?:^|\s)(?:sh|bash|cmd|powershell|pwsh)\s+-c\b", command_text) or INLINE_EXEC.search(command_text):
            findings.append(Finding("MCPG002", "high", name, "Shell interpreter or inline command execution", "command", redact(command_text), "Use a fixed executable and explicit arguments; avoid shell evaluation.").finalize())
        url = cfg.get("url") or cfg.get("serverUrl") or cfg.get("endpoint")
        if isinstance(url, str) and urlparse(url).scheme in ("http", "https"):
            loopback = _is_loopback_url(url)
            auth = _has_auth_config(cfg) or _url_has_auth_config(url)
            if not auth and not loopback:
                findings.append(Finding("MCPG006", "medium", name, "Remote MCP endpoint has no visible authentication configuration", "url", redact(url), "Require explicit authentication and validate token audience at the client boundary.").finalize())
            if urlparse(url).scheme == "http" and not loopback and not PRIVATE.search(url):
                findings.append(Finding("MCPG009", "high", name, "Remote MCP endpoint uses unencrypted HTTP", "url", redact(url), "Use HTTPS or an explicitly isolated local transport.").finalize())
        docker_text = " ".join([str(cfg.get("command", ""))] + [str(x) for x in cfg.get("args", [])])
        if re.search(r"(?i)(--privileged|/var/run/docker\.sock|--network(?:=|\s+)host)", docker_text):
            findings.append(Finding("MCPG008", "high", name, "Container configuration grants broad host access", "args", redact(docker_text), "Drop privileged, host-network, and Docker socket access unless it is explicitly required.").finalize())
    return findings


def _has_auth_config(value):
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = key.lower().replace("-", "_")
            if normalized in AUTH_VALUE_KEYS and _has_auth_value(child):
                return True
            if normalized == "auth":
                if isinstance(child, str) and child.strip().lower() not in {"", "none", "false", "anonymous", "no"}:
                    return True
                if isinstance(child, (dict, list)) and _has_auth_config(child):
                    return True
            elif normalized in {"headers", "credentials"} and isinstance(child, (dict, list)) and _has_auth_config(child):
                return True
    elif isinstance(value, list):
        return any(_has_auth_config(child) for child in value)
    return False


def _has_auth_value(value):
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (dict, list)):
        return _has_auth_config(value)
    return bool(value)


def _is_loopback_url(value):
    try:
        return urlparse(value).hostname in LOOPBACK_HOSTS
    except ValueError:
        return False


def _url_has_auth_config(value):
    try:
        return any(
            key.lower().replace("-", "_") in AUTH_QUERY_KEYS and bool(item.strip())
            for key, item in parse_qsl(urlparse(value).query, keep_blank_values=True)
        )
    except ValueError:
        return False


def _url_has_variable_auth(value):
    try:
        pairs = parse_qsl(urlparse(value).query, keep_blank_values=True)
        auth_pairs = [(key, item) for key, item in pairs if key.lower().replace("-", "_") in AUTH_QUERY_KEYS]
        return bool(auth_pairs) and all(re.fullmatch(r"\s*(?:[A-Za-z][A-Za-z0-9_-]*\s+)?\$\{[^}]+}\s*", item) for _, item in auth_pairs)
    except ValueError:
        return False


def as_json(findings): return json.dumps([asdict(f) for f in findings], ensure_ascii=False, indent=2)
def as_markdown(findings):
    lines = ["# MCP Guard report", "", f"Findings: {len(findings)}", "", "| Severity | Rule | Server | Location | Message |", "|---|---|---|---|---|"]
    for f in findings: lines.append(f"| {f.severity} | {f.rule_id} | `{f.server}` | `{f.path}` | {f.message} |")
    return "\n".join(lines) + "\n"
def as_sarif(findings, source_path=None):
    rules = {}
    results = []
    if source_path:
        source = Path(source_path)
        try:
            source_uri = source.resolve().relative_to(Path.cwd().resolve()).as_posix()
        except (OSError, ValueError):
            source_uri = source.name
    else:
        source_uri = None
    for f in findings:
        rules.setdefault(f.rule_id, {"id": f.rule_id, "shortDescription": {"text": f.message}, "help": {"text": f.remediation}})
        results.append({"ruleId": f.rule_id, "level": "error" if f.severity == "high" else "warning", "message": {"text": f.message + ": " + redact(f.evidence)}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": source_uri or f.path}, "region": {"snippet": {"text": f.path}}}}], "fingerprints": {"mcpGuard/v1": f.fingerprint}})
    return json.dumps({"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{"tool":{"driver":{"name":"mcp-guard","version":__version__,"rules":list(rules.values())}},"results":results}]}, ensure_ascii=False, indent=2)

def write_output(text, output):
    if output: Path(output).write_text(text, encoding="utf-8")
    else: print(text)


def _fails_threshold(findings, fail_on):
    threshold = SEVERITY_RANK[fail_on]
    return any(SEVERITY_RANK.get(finding.severity, 0) >= threshold for finding in findings)

def main(argv=None):
    p = argparse.ArgumentParser(prog="mcp-guard")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("scan"); s.add_argument("path"); s.add_argument("--format", choices=["json","markdown","sarif"], default="markdown"); s.add_argument("--output"); s.add_argument("--baseline"); s.add_argument("--fail-on", choices=FAIL_ON_CHOICES, default="high")
    b = sub.add_parser("baseline"); b.add_argument("path"); b.add_argument("--output", required=True)
    d = sub.add_parser("diff"); d.add_argument("path"); d.add_argument("--baseline", required=True); d.add_argument("--format", choices=["json","markdown","sarif"], default="markdown"); d.add_argument("--output"); d.add_argument("--fail-on", choices=FAIL_ON_CHOICES, default="high")
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
        return 1 if _fails_threshold(findings, args.fail_on) else 0
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print(f"mcp-guard: {e}", file=sys.stderr); return 2
if __name__ == "__main__": raise SystemExit(main())
