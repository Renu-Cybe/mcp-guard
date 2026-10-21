# MCP Guard

[![CI](https://github.com/latentide/mcp-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/latentide/mcp-guard/actions/workflows/ci.yml)

MCP Guard is a local-first static checker for MCP and agent configuration. It is intended as a release and CI gate, not a security certification.

See [CONTRIBUTING.md](CONTRIBUTING.md) for safe fixture and rule changes. Use the [false-positive issue form](https://github.com/latentide/mcp-guard/issues/new?template=false-positive.yml) for sanitized findings and [SECURITY.md](SECURITY.md) for private vulnerability reports.

## What it does

- Reads JSON or JSONC containing `mcpServers`, `mcp_servers`, or `servers`.
- Runs nine high-confidence checks for credentials, shell execution, broad filesystem paths, private/cloud metadata targets, unpinned dependencies, missing remote authentication, wildcard permissions, broad Docker host access, and unencrypted remote HTTP. Baseline filtering is a separate workflow.
- Emits JSON, Markdown, or SARIF.
- Exposes the package version through `mcp-guard --version` and SARIF metadata.
- The CLI does not start a server, install dependencies, or make network requests. The GitHub Action uploads the generated SARIF as a workflow artifact by default (`upload-artifact: true`) and to Code Scanning only when `upload-sarif: true`.

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

## Try it in 60 seconds

The repository includes two sanitized fixtures so you can see both sides of the gate without starting a server or sending a network request:

```bash
python -m pip install .
python -m mcp_guard.cli scan tests/fixtures/high-risk.json --format markdown --fail-on none
```

The high-risk fixture reports four findings: `MCPG001` (credential-like value), `MCPG002` (shell execution), `MCPG004` (private or cloud-metadata target), and `MCPG006` (missing visible remote authentication). Because `--fail-on none` makes any finding fail the gate, this command exits with status `1` after printing the report.

For the clean path:

```bash
python -m mcp_guard.cli scan tests/fixtures/safe.json --format markdown --fail-on none
```

This prints `Findings: 0` and exits with status `0`. The fixtures are test data only; MCP Guard does not execute the configured command, install a server, or contact the configured URL.

The first seven-day user-validation materials are in [`validation/targets.md`](validation/targets.md) and [`validation/validation-log.md`](validation/validation-log.md). They contain public repository candidates and local evidence records; no automatic outreach is performed.

By default, high-severity findings return exit code 1. Use `--fail-on medium` (or `low`/`none`) to make the gate stricter; `none` fails whenever any finding exists. Invalid or ambiguous input returns 2. If a file contains multiple supported server maps, pass the exact JSON selector shown in the error, such as `$.config.mcpServers`. New single-file baselines use version 3, while multi-file `mcp-json` baselines use version 4 and include relative POSIX `source` paths with source-aware fingerprints. Sources are relative to the common parent of the explicit input files by default; pass `--source-root <directory>` to anchor them to a repository root. The source root must be a real directory containing every input, and is a runtime option rather than baseline metadata, so reuse the same value when applying a baseline. Changing the file set, root, or parent changes the baseline scope. Multi-file scans are capped at 64 files and 16 MiB total (2 MiB per file), sort inputs deterministically, and reject symlinks, directories, unsupported suffixes, and registry input. Each entry stores only review metadata and its fingerprint; evidence and credential-like input values are never copied into the baseline. Legacy version 1 and 2 fingerprint-list baselines remain readable for single-file scans. Reports contain fingerprints so a baseline can suppress previously reviewed findings.

## GitHub Action

### Quick start

Add this workflow as `.github/workflows/mcp-guard.yml` in your repository. It scans `.mcp.json`, fails the job on high-severity findings, and keeps the SARIF report as a workflow artifact.

```yaml
name: MCP Guard
on: [pull_request, push]

jobs:
  mcp-guard:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0
        with:
          python-version: '3.13'
      - uses: latentide/mcp-guard@v0.4.0
        with:
          path: .mcp.json
```

**Requirements.** The action is a composite action. It runs the scanner from its own checkout with `python` and `bash`, and it does not install Python for you. It needs Python 3.10 or newer on `PATH`. The `actions/setup-python` step above makes that explicit, and GitHub-hosted Ubuntu runners usually have a suitable Python already. The scanner has no third-party dependencies and makes no network requests. The action itself is tested on `ubuntu-latest`; the CLI is tested on Ubuntu, Windows, and macOS, but Windows and macOS runners are not yet covered for the action.

**Defaults to know about.**

| Input | Default | What it means |
|---|---|---|
| `fail-on` | `high` | Only high-severity findings fail the job. Use `medium` to also fail on medium findings such as unpinned packages (`MCPG005`) or missing visible remote auth (`MCPG006`), or `none` to fail on any finding. |
| `upload-artifact` | `true` | The SARIF file is uploaded as the `mcp-guard-sarif` artifact, even when findings fail the job. Set `false` for private workflows, or give each invocation a unique `artifact-name` when a job runs the action more than once. |
| `upload-sarif` | `false` | Code Scanning upload is opt-in and needs `security-events: write`; see below. |

Exit behavior: status `1` (findings at or above `fail-on`) still writes and uploads SARIF and then fails the job. Status `2` (invalid or ambiguous input) fails immediately and uploads nothing.

### Inputs and more examples

The v0.4.0 action accepts either the existing single-file `path` input or a multiline `paths` input. When `paths` contains one or more non-blank lines, each line becomes exactly one CLI argument; paths are not shell-split, glob-expanded, or recursively traversed. Blank and whitespace-only lines are ignored. `paths` takes precedence over `path`.

Use `paths` for an explicit multi-file MCP JSON scan. The files must be JSON/JSONC, and the action preserves source-aware SARIF URIs for every file:

Use the action from a tagged release of this repository. It writes a SARIF file and, by default, uploads it as an artifact. It does not comment on pull requests, upload configuration to a service, auto-fix files, or grant write permissions.
The artifact is uploaded before the configured severity threshold fails the job; invalid input fails the action as an error and uploads neither SARIF nor an artifact. With `paths`, selecting more than one file while `input-format: registry` is rejected. Set `fail-on: medium` to gate on medium and high findings.

```yaml
jobs:
  mcp-guard:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: latentide/mcp-guard@v0.4.0
        with:
          paths: |
            configs/team one.json
            configs/team-two.json

          # path is ignored when paths has a non-blank entry.
          path: .mcp.json
          fail-on: medium

```

For a published MCP Registry `server.json`, opt into the explicit adapter:

```yaml
steps:
  - uses: latentide/mcp-guard@v0.4.0
    with:
      path: server.json
      input-format: registry
```

To publish findings to GitHub Code Scanning, grant `security-events: write` and opt in explicitly. Code Scanning must be available for the repository (public repositories, or private repositories with GitHub Advanced Security). The artifact upload remains enabled by default and can be disabled for private workflows.

```yaml
jobs:
  mcp-guard:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0
        with:
          python-version: '3.13'
      - uses: latentide/mcp-guard@v0.4.0
        with:
          path: .mcp.json
          upload-sarif: true
          artifact-name: mcp-guard-${{ github.job }}
```

### When a finding is expected

Some findings depend on context the file cannot show. For example, `MCPG006` reports a remote endpoint with no visible authentication even when the MCP client signs in with OAuth on its own. Declare auth in the config when your client supports it (headers, `auth`, or an `oauth` block). Otherwise, review the finding and record it in a baseline, then commit that file so the exception is visible in code review:

```bash
mcp-guard baseline .mcp.json --output .mcp-guard-baseline.json
mcp-guard scan .mcp.json --baseline .mcp-guard-baseline.json
```

The baseline stores fingerprints and review metadata only, never credential values. In CI, pass the committed file to the action:

```yaml
      - uses: latentide/mcp-guard@v0.4.0
        with:
          path: .mcp.json
          baseline: .mcp-guard-baseline.json
```

The `baseline` input is new after v0.4.0 and is available from the next release; with `@v0.4.0`, run the CLI in a workflow step instead.

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
