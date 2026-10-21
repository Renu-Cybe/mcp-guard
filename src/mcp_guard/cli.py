from __future__ import annotations
import argparse, hashlib, json, re, sys, os
from dataclasses import dataclass, asdict
from pathlib import Path, PurePosixPath, PureWindowsPath
from urllib.parse import parse_qsl, urlparse
from . import __version__

SECRET = re.compile(r"(?i)(sk-[A-Za-z0-9]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|bearer\s+[A-Za-z0-9._-]{12,}|(?:api[_-]?key|token|secret|password)\s*[:=]\s*[^\s,;]+)")
PRIVATE = re.compile(r"(?i)(169\.254\.169\.254|metadata\.google\.internal|localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)")
DANGEROUS = re.compile(r"(?i)(^|[/\\\s])(sh|bash|zsh|fish|cmd|powershell|pwsh)(\.exe)?$|(^|\s)(-c|/c)(\s|$)")
INLINE_EXEC = re.compile(r"(?i)(?:^|\s)(?:python(?:\d+(?:\.\d+)?)?|node|ruby|perl|php)\s+(?:-c|-e)\b")
BROAD_PATH = re.compile(r"(^|[/\\])(?:\.ssh|\.aws|\.kube|etc|var[/\\]run)([/\\]|$)|^(?:/|[A-Za-z]:[\\/])$|^~(?:[/\\]|$)")
UNPINNED = re.compile(r"(?i)(?:@latest$|\b(?:npm|pypi|github):[^@\s]+$)")
EXECUTOR = re.compile(r"(?i)\b(?:npx|uvx|pipx|bunx)\s+(?:(?:-[^\s]+)\s+)*(?P<package>@?[\w.-]+(?:/[\w.-]+)?(?:@[\w.+-]+)?)(?:\s|$)")
WILDCARD = re.compile(r"(^|[\s,])\*($|[\s,])")
MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_INPUT_FILES = 64
MAX_TOTAL_INPUT_BYTES = 16 * 1024 * 1024
SUPPORTED_SUFFIXES = {".json", ".jsonc"}
INPUT_FORMATS = ("mcp-json", "registry")
AUTH_VALUE_KEYS = {
    "authorization", "token", "oauth", "api_key", "apikey", "access_token",
    "refresh_token", "client_secret", "x_api_key", "x-api-key",
}
AUTH_QUERY_KEYS = AUTH_VALUE_KEYS | {"key", "password", "secret"}
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
# Rules whose per-finding message varies keep one stable SARIF rule description.
RULE_SUMMARY = {"MCPG005": "Dependency or package is not version-pinned"}
RULE_HELP = {"MCPG005": "Pin an immutable version or commit and review updates deliberately."}
OAUTH_DISABLED = {"", "none", "false", "no", "off", "disabled"}
MCPG006_REMEDIATION = (
    "Declare authentication in the config (headers, auth, or an oauth block). "
    "If the MCP client handles OAuth itself, confirm that and record this finding in a reviewed baseline; "
    "static analysis cannot see client-managed sign-in."
)
SEVERITY_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3}
FAIL_ON_CHOICES = ("none", "low", "medium", "high")
SARIF_SECURITY_SEVERITY = {"high": "9.0", "medium": "6.0", "low": "3.0", "none": "0.0"}


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

def _executor_package(value: str):
    match = EXECUTOR.search(value)
    return match.group("package") if match else None


def _pin_remediation(value: str):
    """Tell the reader whether the version is a mutable tag or missing, and what to write instead."""
    package = _executor_package(value)
    if re.search(r"(?i)@latest$", value):
        package = package or value
        package = re.sub(r"(?i)@latest$", "", package)
        if re.search(r"\s", package):
            return "Package uses the mutable @latest tag", "Replace @latest with an exact version and review updates deliberately."
        return "Package uses the mutable @latest tag", f"Replace @latest with an exact version, for example {package}@<exact-version>, and review updates deliberately."
    if package:
        return "Package version is not specified", f"Pin an exact version, for example {package}@<exact-version>, and review updates deliberately."
    return "Dependency or package is not version-pinned", "Pin an immutable version or commit and review updates deliberately."


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
    source: str = ""
    fingerprint_version: int = 1
    def finalize(self, source=None, fingerprint_version=None):
        if source is not None:
            self.source = source
        if fingerprint_version is not None:
            self.fingerprint_version = fingerprint_version
        raw = f"{self.rule_id}|{self.server}|{self.path}|{self.evidence}"
        if self.fingerprint_version >= 2:
            raw = f"v2|{self.source}|{raw}"
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


def _registry_server_name(registry_name, item, fallback):
    name = item.get("name") if isinstance(item, dict) else None
    if isinstance(name, str) and name.strip():
        return name.strip()
    if isinstance(registry_name, str) and registry_name.strip():
        return f"{registry_name.strip()}:{fallback}"
    return fallback


def _load_registry_servers(data):
    """Translate the explicit MCP Registry server.json shape to server maps.

    Registry metadata is never executed or fetched.  Only the small, published
    package/remote contract is accepted, and unknown top-level fields fail closed
    so an arbitrary server.json cannot silently become a scan target.
    """
    if not isinstance(data, dict):
        raise ValueError("registry input must be a JSON object")
    schema_uri = data.get("$schema")
    if schema_uri is not None and (
        not isinstance(schema_uri, str)
        or not schema_uri.startswith("https://static.modelcontextprotocol.io/schemas/")
    ):
        raise ValueError("unsupported registry schema URI")
    allowed = {"$schema", "name", "title", "description", "version", "websiteUrl", "repository", "icons", "packages", "remotes", "_meta"}
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise ValueError(f"unsupported registry fields: {', '.join(unknown)}")
    if not any(key in data for key in ("packages", "remotes")):
        raise ValueError("registry input requires packages or remotes")
    registry_name = data.get("name")
    if registry_name is not None and (not isinstance(registry_name, str) or not registry_name.strip()):
        raise ValueError("registry name must be a non-empty string")
    servers = {}
    packages = data.get("packages", [])
    remotes = data.get("remotes", [])
    if not isinstance(packages, list) or not isinstance(remotes, list):
        raise ValueError("registry packages and remotes must be arrays")
    for index, item in enumerate(packages):
        if not isinstance(item, dict):
            raise ValueError(f"registry package {index} must be an object")
        allowed_package = {"name", "registryType", "identifier", "version", "transport", "environmentVariables"}
        unknown = sorted(set(item) - allowed_package)
        if unknown:
            raise ValueError(f"unsupported registry package fields: {', '.join(unknown)}")
        registry_type = item.get("registryType")
        identifier = item.get("identifier")
        if registry_type not in {"npm", "pypi"} or not isinstance(identifier, str) or not identifier.strip():
            raise ValueError(f"registry package {index} requires registryType npm/pypi and identifier")
        version = item.get("version")
        if version is not None and (not isinstance(version, str) or not version.strip()):
            raise ValueError(f"registry package {index} version must be a non-empty string")
        transport = item.get("transport")
        if transport is not None:
            if not isinstance(transport, dict) or set(transport) - {"type"} or transport.get("type") not in {"stdio", None}:
                raise ValueError(f"registry package {index} has unsupported transport")
        environment = item.get("environmentVariables", [])
        if not isinstance(environment, list) or any(not isinstance(entry, dict) or set(entry) - {"name", "description", "isSecret", "isRequired"} or not isinstance(entry.get("name"), str) for entry in environment):
            raise ValueError(f"registry package {index} has invalid environmentVariables")
        command = "npx" if registry_type == "npm" else "uvx"
        package_ref = identifier.strip() + (f"@{version.strip()}" if version else "")
        cfg = {"command": command, "args": ["-y", package_ref]}
        if environment:
            cfg["env"] = {entry["name"]: "${MCP_GUARD_REGISTRY_SECRET}" for entry in environment if entry.get("isSecret")}
        name = _registry_server_name(registry_name, item, identifier.strip())
        if name in servers:
            raise ValueError(f"duplicate registry server name: {name}")
        servers[name] = cfg
    for index, item in enumerate(remotes):
        if not isinstance(item, dict):
            raise ValueError(f"registry remote {index} must be an object")
        allowed_remote = {"name", "type", "url", "headers"}
        unknown = sorted(set(item) - allowed_remote)
        if unknown:
            raise ValueError(f"unsupported registry remote fields: {', '.join(unknown)}")
        url = item.get("url")
        remote_type = item.get("type")
        if remote_type not in {"sse", "streamable-http", "streamableHttp"} or not isinstance(url, str) or urlparse(url).scheme not in {"http", "https"}:
            raise ValueError(f"registry remote {index} requires a supported type and http(s) url")
        headers = item.get("headers", [])
        if not isinstance(headers, list) or any(not isinstance(header, dict) or set(header) - {"name", "description", "isSecret", "isRequired"} or not isinstance(header.get("name"), str) for header in headers):
            raise ValueError(f"registry remote {index} has invalid headers")
        cfg = {"url": url}
        auth_headers = {header["name"]: "${MCP_GUARD_REGISTRY_SECRET}" for header in headers if header.get("isSecret") or header["name"].lower() in {"authorization", "proxy-authorization", "x-api-key", "api-key"}}
        if auth_headers:
            cfg["headers"] = auth_headers
        name = _registry_server_name(registry_name, item, f"remote-{index + 1}")
        if name in servers:
            raise ValueError(f"duplicate registry server name: {name}")
        servers[name] = cfg
    if not servers:
        raise ValueError("registry input contains no packages or remotes")
    return servers


def load_servers(path: Path, selector=None, input_format="mcp-json"):
    _validate_input_path(path)
    if input_format not in INPUT_FORMATS:
        raise ValueError(f"unsupported input format {input_format!r}; supported formats: {', '.join(INPUT_FORMATS)}")
    data = _parse_config(path)
    if input_format == "registry":
        if selector:
            raise ValueError("--selector is only supported with mcp-json input")
        return _load_registry_servers(data)
    candidates = []
    def walk(obj, where="$"):
        if isinstance(obj, dict):
            for key in ("mcpServers", "mcp_servers", "servers"):
                if isinstance(obj.get(key), dict): candidates.append((where + "." + key, obj[key]))
            for k,v in obj.items(): walk(v, where + "." + k)
    walk(data)
    if not candidates: raise ValueError("No supported mcpServers/servers object found")
    by_path = {where: servers for where, servers in candidates}
    if selector:
        if selector not in by_path:
            available = ", ".join(sorted(by_path))
            raise ValueError(f"selector {selector!r} did not match a supported server map; available: {available}")
        return by_path[selector]
    if len(by_path) > 1:
        available = ", ".join(sorted(by_path))
        raise ValueError(f"multiple supported server maps found; use --selector with one of: {available}")
    return next(iter(by_path.values()))


def _validate_input_path(path: Path):
    if path.is_symlink():
        raise ValueError("symlink input is not supported")
    if not path.is_file():
        raise ValueError(f"input is not a regular file: {path}")
    if path.suffix.lower() not in SUPPORTED_SUFFIXES:
        raise ValueError(f"unsupported config format {path.suffix}; supported formats: JSON, JSONC")
    size = path.stat().st_size
    if size > MAX_INPUT_BYTES:
        raise ValueError(f"input exceeds {MAX_INPUT_BYTES} bytes")
    return size


def scan_file(path: Path, selector=None, input_format="mcp-json", source="", fingerprint_version=1):
    servers = load_servers(path, selector=selector, input_format=input_format)
    findings = []
    for name, cfg in servers.items():
        if not isinstance(cfg, dict): continue
        values = list(_strings(cfg))
        for p, val in values:
            key = p.rsplit('.', 1)[-1].split('[', 1)[0].lower()
            sensitive_key = key in {"password", "passwd", "secret", "token", "api_key", "apikey", "authorization", "access_key", "private_key", "client_secret", "refresh_token"}
            variable_ref = bool(re.fullmatch(r"\s*(?:[A-Za-z][A-Za-z0-9_-]*\s+)?\$\{[^}]+}\s*", val)) or _url_has_variable_auth(val)
            if (SECRET.search(val) or (sensitive_key and bool(val.strip()))) and not variable_ref:
                findings.append(Finding("MCPG001", "high", name, "Possible hardcoded credential", p, "credential-like value redacted", "Use environment references or a secret manager; do not commit credentials.").finalize(source, fingerprint_version))
            if PRIVATE.search(val) and ("url" in p.lower() or "host" in p.lower() or "endpoint" in p.lower()) and not _is_loopback_url(val):
                findings.append(Finding("MCPG004", "high", name, "Private or cloud-metadata network target", p, redact(val), "Review network target and block metadata/private access unless explicitly required.").finalize(source, fingerprint_version))
            if BROAD_PATH.search(val) and ("arg" in p.lower() or "path" in p.lower() or "directory" in p.lower()):
                findings.append(Finding("MCPG003", "high", name, "Broad or sensitive filesystem path", p, redact(val), "Scope filesystem access to a dedicated project directory.").finalize(source, fingerprint_version))
            if UNPINNED.search(val):
                message, remediation = _pin_remediation(val)
                findings.append(Finding("MCPG005", "medium", name, message, p, redact(val), remediation).finalize(source, fingerprint_version))
            if WILDCARD.search(val) and any(k in p.lower() for k in ("tool", "permission", "allow", "scope")):
                findings.append(Finding("MCPG007", "high", name, "Wildcard tool or permission scope", p, redact(val), "Replace wildcard access with an explicit least-privilege allowlist.").finalize(source, fingerprint_version))
        cmd = str(cfg.get("command", ""))
        args = cfg.get("args", [])
        command_text = " ".join([cmd] + [str(x) for x in args])
        if _executor_unpinned(command_text):
            message, remediation = _pin_remediation(command_text)
            findings.append(Finding("MCPG005", "medium", name, message, "command", redact(command_text), remediation).finalize(source, fingerprint_version))
        if DANGEROUS.search(cmd) or re.search(r"(?i)(?:^|\s)(?:sh|bash|cmd|powershell|pwsh)\s+-c\b", command_text) or INLINE_EXEC.search(command_text):
            findings.append(Finding("MCPG002", "high", name, "Shell interpreter or inline command execution", "command", redact(command_text), "Use a fixed executable and explicit arguments; avoid shell evaluation.").finalize(source, fingerprint_version))
        url = cfg.get("url") or cfg.get("serverUrl") or cfg.get("endpoint")
        if isinstance(url, str) and urlparse(url).scheme in ("http", "https"):
            loopback = _is_loopback_url(url)
            auth = _has_auth_config(cfg) or _url_has_auth_config(url)
            if not auth and not loopback:
                findings.append(Finding("MCPG006", "medium", name, "Remote MCP endpoint has no visible authentication configuration", "url", redact(url), MCPG006_REMEDIATION).finalize(source, fingerprint_version))
            if urlparse(url).scheme == "http" and not loopback and not PRIVATE.search(url):
                findings.append(Finding("MCPG009", "high", name, "Remote MCP endpoint uses unencrypted HTTP", "url", redact(url), "Use HTTPS or an explicitly isolated local transport.").finalize(source, fingerprint_version))
        docker_text = " ".join([str(cfg.get("command", ""))] + [str(x) for x in cfg.get("args", [])])
        if re.search(r"(?i)(--privileged|/var/run/docker\.sock|--network(?:=|\s+)host)", docker_text):
            findings.append(Finding("MCPG008", "high", name, "Container configuration grants broad host access", "args", redact(docker_text), "Drop privileged, host-network, and Docker socket access unless it is explicitly required.").finalize(source, fingerprint_version))
    return sorted(findings, key=lambda f: (f.source, f.rule_id, f.server, f.path, f.evidence))


def _source_root(paths):
    resolved = [p.resolve() for p in paths]
    return Path(os.path.commonpath([str(p.parent) for p in resolved]))


def _validate_source_root(source_root, paths):
    """Validate an explicit root and prove every input is beneath it.

    The root is a runtime option only.  It is deliberately not persisted in a
    baseline; the relative source set remains the portable scope binding.
    """
    root = Path(source_root)
    if root.is_symlink():
        raise ValueError("source root symlink is not supported")
    if not root.exists() or not root.is_dir():
        raise ValueError(f"source root is not a regular directory: {source_root}")
    resolved_root = root.resolve()
    for path in paths:
        try:
            path.resolve().relative_to(resolved_root)
        except ValueError as exc:
            raise ValueError(f"input is outside source root: {path}") from exc
    return resolved_root


def _source_name(path, root):
    return path.resolve().relative_to(root).as_posix()


def scan_files(paths, selector=None, input_format="mcp-json", source_root=None):
    """Scan a deterministic, bounded set of mcp-json files."""
    if input_format != "mcp-json" and len(paths) > 1:
        raise ValueError("multi-file scanning is only supported with mcp-json input")
    if not paths:
        raise ValueError("at least one input path is required")
    if len(paths) > MAX_INPUT_FILES:
        raise ValueError(f"too many input files; maximum is {MAX_INPUT_FILES}")
    normalized = [Path(p) for p in paths]
    seen = set()
    total = 0
    for path in normalized:
        resolved = path.resolve()
        if resolved in seen:
            raise ValueError(f"duplicate input path: {path}")
        seen.add(resolved)
        total += _validate_input_path(path)
    if total > MAX_TOTAL_INPUT_BYTES:
        raise ValueError(f"total input exceeds {MAX_TOTAL_INPUT_BYTES} bytes")
    ordered = sorted(normalized, key=lambda p: p.resolve().as_posix())
    if source_root is None:
        root = _source_root(ordered)
    else:
        root = _validate_source_root(source_root, ordered)
    findings = []
    for path in ordered:
        source = _source_name(path, root) if len(ordered) > 1 else ""
        findings.extend(scan_file(path, selector=selector, input_format=input_format, source=source, fingerprint_version=2 if len(ordered) > 1 else 1))
    return sorted(findings, key=lambda f: (f.source, f.rule_id, f.server, f.path, f.evidence))


def _has_auth_config(value):
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = key.lower().replace("-", "_")
            if normalized == "oauth":
                if _declares_oauth(child):
                    return True
            elif normalized in AUTH_VALUE_KEYS and _has_auth_value(child):
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


def _declares_oauth(value):
    """An explicit client OAuth block (for example `oauth: {clientId: ...}`) is
    visible auth configuration even though it carries no secret.  A disabled or
    empty block is not."""
    if isinstance(value, str):
        return value.strip().lower() not in OAUTH_DISABLED
    if value is True:
        return True
    if isinstance(value, dict):
        enabled = value.get("enabled", True)
        if enabled is False or (isinstance(enabled, str) and enabled.strip().lower() in OAUTH_DISABLED):
            return False
        return any(
            child is True or (isinstance(child, str) and child.strip()) or (isinstance(child, (dict, list)) and child)
            for key, child in value.items() if key != "enabled"
        ) or value.get("enabled") is True
    return False


def _has_auth_value(value):
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (dict, list)):
        return _has_auth_config(value)
    # Boolean/numeric flags describe whether auth is enabled, but carry no
    # credential or token value that can authenticate a remote endpoint.
    # Treating truthy primitives as auth caused `token: true` and `api_key: 1`
    # to suppress MCPG006.
    return False


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


def _multi(findings):
    return any(f.source for f in findings) or any(f.fingerprint_version >= 2 for f in findings)


def _finding_dict(f, multi=None):
    data = asdict(f)
    data.pop("fingerprint_version", None)
    if not (multi if multi is not None else _multi([f])):
        data.pop("source", None)
    return data


def as_json(findings): return json.dumps([_finding_dict(f) for f in findings], ensure_ascii=False, indent=2)
def as_markdown(findings):
    multi = _multi(findings)
    lines = ["# MCP Guard report", "", f"Findings: {len(findings)}", ""]
    if multi:
        lines.extend(["| Severity | Rule | Source | Server | Location | Message |", "|---|---|---|---|---|---|"])
        for f in findings: lines.append(f"| {f.severity} | {f.rule_id} | `{f.source}` | `{f.server}` | `{f.path}` | {f.message} |")
    else:
        lines.extend(["| Severity | Rule | Server | Location | Message |", "|---|---|---|---|---|"])
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
        rules.setdefault(f.rule_id, {"id": f.rule_id, "shortDescription": {"text": RULE_SUMMARY.get(f.rule_id, f.message)}, "help": {"text": RULE_HELP.get(f.rule_id, f.remediation)}, "properties": {"security-severity": SARIF_SECURITY_SEVERITY.get(f.severity, "0.0")}})
        uri = f.source or source_uri or f.path
        key = "mcpGuard/v2" if f.fingerprint_version >= 2 else "mcpGuard/v1"
        results.append({"ruleId": f.rule_id, "level": "error" if f.severity == "high" else "warning", "message": {"text": f.message + ": " + redact(f.evidence)}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"snippet": {"text": f.path}}}}], "fingerprints": {key: f.fingerprint}})
    return json.dumps({"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{"tool":{"driver":{"name":"mcp-guard","version":__version__,"rules":list(rules.values())}},"results":results}]}, ensure_ascii=False, indent=2)

def write_output(text, output):
    if output: Path(output).write_text(text, encoding="utf-8")
    else: print(text)


def _fails_threshold(findings, fail_on):
    threshold = SEVERITY_RANK[fail_on]
    return any(SEVERITY_RANK.get(finding.severity, 0) >= threshold for finding in findings)


_BASELINE_V3_FIELDS = {
    "fingerprint", "rule_id", "severity", "server", "path", "message", "remediation",
}
_BASELINE_V3_TOP_LEVEL = {"version", "selector", "input_format", "findings"}


def _baseline_finding(finding):
    """Return the review metadata persisted in a v3 baseline.

    Evidence is intentionally excluded: a baseline is a durable project file and
    must never become a second copy of credential-like input values.
    """
    return {
        "fingerprint": finding.fingerprint,
        "rule_id": finding.rule_id,
        "severity": finding.severity,
        "server": finding.server,
        "path": finding.path,
        "message": finding.message,
        "remediation": finding.remediation,
    }


def _baseline_finding_v4(finding):
    item = _baseline_finding(finding)
    item["source"] = finding.source
    return item


def _validate_baseline_v3_findings(findings):
    if not isinstance(findings, list):
        raise ValueError("baseline findings must be a list of objects for version 3")
    fingerprints = set()
    for index, item in enumerate(findings):
        if not isinstance(item, dict):
            raise ValueError(f"baseline finding {index} must be an object")
        unknown = sorted(set(item) - _BASELINE_V3_FIELDS)
        if unknown:
            raise ValueError(f"baseline finding {index} has unsupported fields: {', '.join(unknown)}")
        missing = sorted(_BASELINE_V3_FIELDS - set(item))
        if missing:
            raise ValueError(f"baseline finding {index} is missing fields: {', '.join(missing)}")
        if any(not isinstance(item[field], str) or not item[field].strip() for field in _BASELINE_V3_FIELDS):
            raise ValueError(f"baseline finding {index} fields must be non-empty strings")
        if not re.fullmatch(r"[0-9a-f]{16}", item["fingerprint"]):
            raise ValueError(f"baseline finding {index} has invalid fingerprint")
        if item["severity"] not in SEVERITY_RANK or not re.fullmatch(r"MCPG\d{3}", item["rule_id"]):
            raise ValueError(f"baseline finding {index} has invalid severity or rule_id")
        fingerprints.add(item["fingerprint"])
    return fingerprints


def _read_baseline(path, selector, input_format="mcp-json", multi=False, sources=None):
    old = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(old, dict):
        raise ValueError("baseline must be a JSON object")
    version = old.get("version", 1)
    if isinstance(version, bool) or not isinstance(version, int) or version not in {1, 2, 3, 4}:
        raise ValueError(f"unsupported baseline version: {version}")
    if version == 4:
        if not multi:
            raise ValueError("baseline version 4 requires multi-file input")
        if old.get("scope") != "multi-file":
            raise ValueError("baseline version 4 must have multi-file scope")
        if input_format != "mcp-json" or old.get("input_format") != "mcp-json":
            raise ValueError("multi-file baseline requires mcp-json input")
        if set(old) != {"version", "scope", "selector", "input_format", "fingerprint_version", "sources", "findings"}:
            raise ValueError("baseline version 4 has unsupported fields")
        if old.get("fingerprint_version") != 2 or not isinstance(old.get("sources"), list):
            raise ValueError("baseline version 4 has invalid source metadata")
        if any(not isinstance(s, str) for s in old["sources"]) or len(set(old["sources"])) != len(old["sources"]):
            raise ValueError("baseline version 4 has invalid source metadata")
        if any(
            not isinstance(s, str)
            or not s
            or PurePosixPath(s).is_absolute()
            or PureWindowsPath(s).drive
            or PureWindowsPath(s).root
            or "\\" in s
            or any(part in {".", ".."} for part in PurePosixPath(s).parts)
            for s in old["sources"]
        ):
            raise ValueError("baseline version 4 sources must be relative POSIX paths")
        if old.get("selector") != selector:
            raise ValueError(f"baseline selector mismatch: baseline has {old.get('selector')!r}, current scan has {selector!r}")
        if sources is not None and old["sources"] != list(sources):
            raise ValueError("baseline sources mismatch: the multi-file input set or source root changed")
        allowed = _BASELINE_V3_FIELDS | {"source"}
        if not isinstance(old.get("findings"), list):
            raise ValueError("baseline version 4 findings must be a list")
        fingerprints = set()
        for index, item in enumerate(old.get("findings", [])):
            if not isinstance(item, dict) or set(item) != allowed:
                raise ValueError(f"baseline finding {index} has invalid fields")
            if item["source"] not in old["sources"]:
                raise ValueError(f"baseline finding {index} has unknown source")
            if any(not isinstance(item[field], str) or not item[field].strip() for field in allowed):
                raise ValueError(f"baseline finding {index} fields must be non-empty strings")
            if not re.fullmatch(r"[0-9a-f]{16}", item["fingerprint"]):
                raise ValueError(f"baseline finding {index} has invalid fingerprint")
            if item["severity"] not in SEVERITY_RANK or not re.fullmatch(r"MCPG\d{3}", item["rule_id"]):
                raise ValueError(f"baseline finding {index} has invalid severity or rule_id")
            if item["fingerprint"] in fingerprints:
                raise ValueError(f"baseline finding {index} duplicates a fingerprint")
            fingerprints.add(item["fingerprint"])
        return fingerprints
    if multi:
        raise ValueError("multi-file input requires a version 4 baseline")
    if version >= 4:
        raise ValueError(f"unsupported baseline version: {version}")
    if version >= 2 and old.get("selector") != selector:
        raise ValueError(f"baseline selector mismatch: baseline has {old.get('selector')!r}, current scan has {selector!r}")
    if version >= 2 and old.get("input_format", "mcp-json") != input_format:
        raise ValueError(
            f"baseline input format mismatch: baseline has {old.get('input_format', 'mcp-json')!r}, "
            f"current scan has {input_format!r}"
        )
    fingerprints = old.get("findings", [])
    if version == 3:
        if set(old) != _BASELINE_V3_TOP_LEVEL:
            raise ValueError("baseline version 3 must contain exactly version, selector, input_format, and findings")
        if old.get("selector") is not None and not isinstance(old.get("selector"), str):
            raise ValueError("baseline selector must be a string or null")
        baseline_format = old.get("input_format")
        if baseline_format not in INPUT_FORMATS:
            raise ValueError(f"baseline input_format must be one of: {', '.join(INPUT_FORMATS)}")
        return _validate_baseline_v3_findings(fingerprints)
    if not isinstance(fingerprints, list) or any(not isinstance(item, str) for item in fingerprints):
        raise ValueError("baseline findings must be a list of strings")
    return set(fingerprints)


def main(argv=None):
    p = argparse.ArgumentParser(prog="mcp-guard")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("scan"); s.add_argument("path", nargs="+"); s.add_argument("--format", choices=["json","markdown","sarif"], default="markdown"); s.add_argument("--output"); s.add_argument("--baseline"); s.add_argument("--selector"); s.add_argument("--input-format", choices=INPUT_FORMATS, default="mcp-json"); s.add_argument("--source-root"); s.add_argument("--fail-on", choices=FAIL_ON_CHOICES, default="high")
    b = sub.add_parser("baseline"); b.add_argument("path", nargs="+"); b.add_argument("--output", required=True); b.add_argument("--selector"); b.add_argument("--input-format", choices=INPUT_FORMATS, default="mcp-json"); b.add_argument("--source-root")
    d = sub.add_parser("diff"); d.add_argument("path", nargs="+"); d.add_argument("--baseline", required=True); d.add_argument("--format", choices=["json","markdown","sarif"], default="markdown"); d.add_argument("--output"); d.add_argument("--selector"); d.add_argument("--input-format", choices=INPUT_FORMATS, default="mcp-json"); d.add_argument("--source-root"); d.add_argument("--fail-on", choices=FAIL_ON_CHOICES, default="high")
    args = p.parse_args(argv)
    try:
        multi = len(args.path) > 1
        known = _read_baseline(args.baseline, args.selector, args.input_format, multi=False) if args.command == "diff" and not multi else None
        source_root = Path(args.source_root) if args.source_root else None
        findings = scan_files([Path(p) for p in args.path], selector=args.selector, input_format=args.input_format, source_root=source_root)
        current_sources = None
        if multi:
            normalized = sorted((Path(p) for p in args.path), key=lambda p: p.resolve().as_posix())
            root = _validate_source_root(source_root, normalized) if source_root is not None else _source_root(normalized)
            current_sources = sorted(_source_name(p, root) for p in normalized)
        if args.command == "diff" and multi:
            known = _read_baseline(args.baseline, args.selector, args.input_format, multi=True, sources=current_sources)
        if args.command == "baseline":
            if multi:
                normalized = [Path(p) for p in args.path]
                ordered = sorted(normalized, key=lambda p: p.resolve().as_posix())
                root = _validate_source_root(source_root, ordered) if source_root is not None else _source_root(ordered)
                sources = sorted(_source_name(p, root) for p in ordered)
                baseline = {"version": 4, "scope": "multi-file", "selector": args.selector, "input_format": "mcp-json", "fingerprint_version": 2, "sources": sources, "findings": [_baseline_finding_v4(f) for f in findings]}
            else:
                baseline = {"version": 3, "selector": args.selector, "input_format": args.input_format, "findings": [_baseline_finding(f) for f in findings]}
            Path(args.output).write_text(json.dumps(baseline, ensure_ascii=False, indent=2), encoding="utf-8"); return 0
        if args.command == "diff":
            findings = [f for f in findings if f.fingerprint not in known]
            fmt = args.format
        else:
            fmt = args.format
            if args.baseline:
                known = _read_baseline(args.baseline, args.selector, args.input_format, multi=multi, sources=current_sources); findings = [f for f in findings if f.fingerprint not in known]
        text = as_json(findings) if fmt == "json" else as_sarif(findings, str(Path(args.path[0]))) if fmt == "sarif" else as_markdown(findings)
        write_output(text, args.output)
        return 1 if _fails_threshold(findings, args.fail_on) else 0
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print(f"mcp-guard: {e}", file=sys.stderr); return 2
if __name__ == "__main__": raise SystemExit(main())
