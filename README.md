# MCP Guard

[![CI](https://github.com/Renu-Cybe/mcp-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/Renu-Cybe/mcp-guard/actions/workflows/ci.yml)

MCP Guard is a local-first static checker for MCP and agent configuration. It is intended as a release and CI gate, not a security certification.

See [CONTRIBUTING.md](CONTRIBUTING.md) for safe fixture and rule changes. Use the [false-positive issue form](https://github.com/Renu-Cybe/mcp-guard/issues/new?template=false-positive.yml) for sanitized findings and [SECURITY.md](SECURITY.md) for private vulnerability reports.

## What it does

- Reads JSON or JSONC containing `mcpServers`, `mcp_servers`, or `servers`.
- Runs nine high-confidence checks for credentials, shell execution, broad filesystem paths, private/cloud metadata targets, unpinned dependencies, missing remote authentication, wildcard permissions, broad Docker host access, and unencrypted remote HTTP. Baseline filtering is a separate workflow.
- Emits JSON, Markdown, or SARIF.
- Exposes the package version through `mcp-guard --version` and SARIF metadata.
- The CLI does not start a server, install dependencies, or make network requests. The GitHub Action only uploads the generated SARIF artifact when configured to do so.

## Install and use

```bash
python -m pip install -e .
mcp-guard scan .mcp.json --format markdown
mcp-guard scan .mcp.json --format sarif --output mcp-guard.sarif
mcp-guard baseline .mcp.json --output .mcp-guard-baseline.json
mcp-guard diff .mcp.json --baseline .mcp-guard-baseline.json --format markdown
# Bounded multi-file scan (mcp-json only)
mcp-guard scan configs/a.json configs/b.json --format sarif --output mcp-guard.sarif
# Treat medium and high findings as a CI failure
mcp-guard scan .mcp.json --fail-on medium
# Select a nested server map when a file contains more than one
mcp-guard scan settings.json --selector '$.config.mcpServers'
# Explicit MCP Registry server.json subset (no network or execution)
mcp-guard scan server.json --input-format registry --format sarif --output mcp-guard.sarif
```

By default, high-severity findings return exit code 1. Use `--fail-on medium` (or `low`/`none`) to make the gate stricter; `none` fails whenever any finding exists. Invalid or ambiguous input returns 2. If a file contains multiple supported server maps, pass the exact JSON selector shown in the error, such as `$.config.mcpServers`. New single-file baselines use version 3, while multi-file `mcp-json` baselines use version 4 and include relative POSIX `source` paths with source-aware fingerprints. Sources are relative to the common parent of the explicit input files, so changing that file set or parent changes the baseline scope. Multi-file scans are capped at 64 files and 16 MiB total (2 MiB per file), sort inputs deterministically, and reject symlinks, directories, unsupported suffixes, and registry input. Each entry stores only review metadata and its fingerprint; evidence and credential-like input values are never copied into the baseline. Legacy version 1 and 2 fingerprint-list baselines remain readable for single-file scans. Reports contain fingerprints so a baseline can suppress previously reviewed findings.

## GitHub Action

The v0.3.0 action input `path` remains a single JSON/JSONC or Registry file. Use the CLI examples above for explicit multi-file scans; whitespace-separated paths are not expanded by the action.

Use the action from a tagged copy of this repository. It writes a SARIF file and uploads it as an artifact. It does not comment on pull requests, upload configuration to a service, auto-fix files, or grant write permissions.
The artifact is uploaded before the configured severity threshold fails the job; invalid input fails the action as an error. Set `fail-on: medium` to gate on medium and high findings.

```yaml
jobs:
  mcp-guard:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: Renu-Cybe/mcp-guard@v0.3.0
        with:
          path: .mcp.json
          fail-on: medium

```

For a published MCP Registry `server.json`, opt into the explicit adapter:

```yaml
steps:
  - uses: Renu-Cybe/mcp-guard@v0.3.0
    with:
      path: server.json
      input-format: registry
```

To publish findings to GitHub Code Scanning, grant `security-events: write` and opt in explicitly. The artifact upload remains enabled by default and can be disabled for private workflows.

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: Renu-Cybe/mcp-guard@v0.3.0
    with:
      path: .mcp.json
      upload-sarif: true
      artifact-name: mcp-guard-${{ github.job }}
```

## Scope and limitations

This release is static and configuration-focused. It does not execute MCP servers, inspect runtime `tools/list`, analyze prompt injection with an LLM, or prove that a project is secure. Supported input formats are JSON and JSONC MCP server maps. An explicit restricted MCP Registry `server.json` subset can be selected with `--input-format registry`; it parses only published `packages` (npm/PyPI with stdio transport) and `remotes` metadata (no network access or execution), maps declared secret environment/header inputs to placeholders, and rejects unknown fields or schema URIs. `SKILL.md`, plugin manifests, SDK source files, and TOML files remain unsupported. When several server maps are present, scanning stops until `--selector` identifies the intended map. Reports redact common credential and URL query patterns, but input files and output paths remain under the caller's control. Review every finding before accepting an exception. Do not commit secrets to fixtures or issue reports.

Loopback endpoints (`localhost`, `127.0.0.1`, and `::1`) are treated as local transports, which avoids flagging common browser-extension bridges for remote authentication or plaintext HTTP. Other private-network and cloud-metadata targets remain high-severity findings.

### D2 sample register

`tests/corpus/manifest.json` records the 30 public D2 samples by repository, fixed commit, license, configuration shape, client, transport, and sensitivity. It is a metadata-only register: the project does not clone, execute, or redistribute third-party sample code. The 19 MCP-server rows define the current server-map boundary; registry, gateway, adapter, SDK, skill, and plugin rows remain explicit unsupported inputs until they have separate adapters and rules. `tests/corpus/cases.json` maps all 19 server-map rows to eight small, sanitized JSON/JSONC regressions. The cases cover stdio executors, remote authentication references, loopback bridges, metadata targets, Docker host access, pinned configurations, and credential redaction; each case records its expected rule set and rationale.

## Development

```bash
python -m pytest -q
```

The public CI workflow tests the package on Ubuntu, Windows, and macOS with Python 3.10 and 3.13. It also builds and installs a wheel, runs the local GitHub Action against safe and high-risk fixtures, checks the failure gate, and downloads the uploaded SARIF artifact for a second verification job.

After tag CI is green, dispatch the release workflow for a tag to attach wheel, source archive, and `SHA256SUMS` assets. It validates the tag and package version, defaults to a dry-run, and refuses to overwrite an existing asset with different content.
