# MCP Guard

MCP Guard is a local-first static checker for MCP and agent configuration. It is intended as a release and CI gate, not a security certification.

## What it does

- Reads JSON containing `mcpServers`, `mcp_servers`, or `servers`.
- Runs six high-confidence checks for credentials, shell execution, broad filesystem paths, private/cloud metadata targets, unpinned dependencies, and missing remote authentication. Baseline filtering is a separate workflow.
- Emits JSON, Markdown, or SARIF.
- The CLI does not start a server, install dependencies, or make network requests. The GitHub Action only uploads the generated SARIF artifact when configured to do so.

## Install and use

```bash
python -m pip install -e .
mcp-guard scan .mcp.json --format markdown
mcp-guard scan .mcp.json --format sarif --output mcp-guard.sarif
mcp-guard baseline .mcp.json --output .mcp-guard-baseline.json
mcp-guard diff .mcp.json --baseline .mcp-guard-baseline.json --format markdown
```

A high-severity finding returns exit code 1. Invalid input returns 2. Reports contain fingerprints so a baseline can suppress previously reviewed findings.

## GitHub Action

Use the action from a tagged copy of this repository. It writes a SARIF file and uploads it as an artifact. It does not comment on pull requests, upload configuration to a service, auto-fix files, or grant write permissions.
The artifact is uploaded before a high-severity result fails the job; invalid input fails the action as an error.

```yaml
jobs:
  mcp-guard:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: Renu-Cybe/mcp-guard@v0.1.0
        with:
          path: .mcp.json
```

## Scope and limitations

This release is static and configuration-focused. It does not execute MCP servers, inspect runtime `tools/list`, analyze prompt injection with an LLM, or prove that a project is secure. Reports redact common credential and URL query patterns, but input files and output paths remain under the caller's control. Review every finding before accepting an exception. Do not commit secrets to fixtures or issue reports.

## Development

```bash
python -m pytest -q
```
