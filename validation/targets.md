# Seven-day validation targets

This is a candidate list for manual product validation. It is not a contact list, a security finding list, or a claim that a repository is actively maintained. The candidates were selected from the fixed D2 register because their public metadata describes a server-map configuration that MCP Guard can scan today.

**Boundary:** do not automatically contact, file issues, publish findings, or infer maintainer intent from this file. Before any manual outreach, re-check the repository's current contribution policy, current configuration examples, and whether the target still fits the supported input boundary. Use sanitized examples only.

## Candidate list

| ID | Priority | Public GitHub handle | Repository | D2 sample | Fixed commit | Configuration and transport | Clients | Sensitivity | First validation hypothesis | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| T-01 | A | `github` | [`github/github-mcp-server`](https://github.com/github/github-mcp-server) | MCP-003 | `e3809fe91c7546633241006bf0b91f23b2595e28` | Remote URL plus OAuth/PAT; Streamable HTTP / HTTPS | VS Code, Claude Desktop, Cursor, Windsurf, Codex | high | A remote configuration with visible authentication references should produce useful, reviewable findings without exposing credentials. | D2 public-read verified / no contact |
| T-02 | A | `microsoft` | [`microsoft/playwright-mcp`](https://github.com/microsoft/playwright-mcp) | MCP-004 | `b8b4183e099f136cbec0388a6088d4aa2f6b9685` | `mcpServers` JSON with `npx @playwright/mcp`; stdio | VS Code, Cursor, Windsurf, Claude Desktop, Cline, Codex | high | A common `npx` stdio configuration should scan cleanly or explain exactly which command/path risks need review. | D2 public-read verified / no contact |
| T-03 | A | `containers` | [`containers/kubernetes-mcp-server`](https://github.com/containers/kubernetes-mcp-server) | MCP-008 | `970df6a7169c943fc0c82641fde6eed38f1e153c` | `mcpServers` JSON and local server command; stdio | Claude, Cursor, VS Code, compatible clients | high | A Kubernetes-oriented server is a useful test of high-impact local/container permissions and rule explanations. | D2 public-read verified / no contact |
| T-04 | A | `grafana` | [`grafana/mcp-grafana`](https://github.com/grafana/mcp-grafana) | MCP-015 | `5ea0cc34678cdd6fcd2f5c731b6619a8433bcb20` | `mcpServers` JSON with environment/token references; stdio | Claude, Cursor, VS Code, compatible clients | high | Environment and token references should be distinguishable from hardcoded secrets with low false-positive cost. | D2 public-read verified / no contact |
| T-05 | A | `firecrawl` | [`firecrawl/firecrawl-mcp-server`](https://github.com/firecrawl/firecrawl-mcp-server) | MCP-019 | `26a23f28ec22241cb16e2115f27a6370ce2a00e0` | `mcpServers` JSON with `npx` and API-key references; stdio | Cursor, Claude, Gemini CLI, compatible clients | high | A recognizable API-key configuration should demonstrate whether the report is actionable before CI adoption. | D2 public-read verified / no contact |

Commit evidence links for reproducibility:

- [MCP-003 commit](https://github.com/github/github-mcp-server/commit/e3809fe91c7546633241006bf0b91f23b2595e28)
- [MCP-004 commit](https://github.com/microsoft/playwright-mcp/commit/b8b4183e099f136cbec0388a6088d4aa2f6b9685)
- [MCP-008 commit](https://github.com/containers/kubernetes-mcp-server/commit/970df6a7169c943fc0c82641fde6eed38f1e153c)
- [MCP-015 commit](https://github.com/grafana/mcp-grafana/commit/5ea0cc34678cdd6fcd2f5c731b6619a8433bcb20)
- [MCP-019 commit](https://github.com/firecrawl/firecrawl-mcp-server/commit/26a23f28ec22241cb16e2115f27a6370ce2a00e0)

## D2 read-only findings (2026-10-17 UTC)

The activity figures below are public GitHub API snapshots. They show a current public signal, not maintainer intent or willingness to try MCP Guard. No repository was contacted or modified.

| ID | Current public activity signal | Current configuration evidence | MCP Guard v0.4.0 fit | D2 result and blocker |
|---|---|---|---|---|
| T-01 | Non-archived; 33,694 stars, 5,260 forks, 377 open issues; `pushed_at` 2026-10-15 21:16:40Z; latest API commit `e3809fe` at 2026-10-15 21:16:37Z. | [`agent-plugin/mcp.json`](https://github.com/github/github-mcp-server/blob/main/agent-plugin/mcp.json) is a real JSON server map with `type: streamable-http` and `https://api.githubcopilot.com/mcp/`; README also documents OAuth/PAT and Docker variants. | High for the tracked JSON file and remote URL rules. | Actual file scan: `MCPG006` medium, exit 1, because the file has no visible auth field. Host-managed OAuth may be legitimate; treat this as a review/false-positive candidate, not a vulnerability claim. |
| T-02 | Non-archived; 38,284 stars, 3,273 forks, 3 open issues; `pushed_at` 2026-10-16 22:43:43Z; latest API commit `b8b4183` at 2026-10-08 17:51:55Z. | [README configuration examples](https://github.com/microsoft/playwright-mcp/blob/main/README.md) repeatedly use `mcpServers.playwright`, `command: npx`, and `@playwright/mcp@latest`; the tree has no dedicated JSON server-map file. | High for a copied JSON/JSONC client configuration; HTTP and Docker variants need separate fixtures. | Sanitized README reproduction: `MCPG005` medium, exit 1, for the unpinned `@playwright/mcp@latest`. Blocker is only the absence of a tracked config file; use a sanitized client config for the next trial. |
| T-03 | Non-archived; 2,163 stars, 462 forks, 132 open issues; `pushed_at` 2026-10-17 14:05:50Z; latest API commit `970df6a` at 2026-10-17 14:05:49Z. | [README client setup](https://github.com/containers/kubernetes-mcp-server/blob/main/README.md) has a `mcpServers`/`npx kubernetes-mcp-server@latest` example; the server's own persistent configuration is [TOML](https://github.com/containers/kubernetes-mcp-server/blob/main/docs/configuration.md), with `read_only`, kubeconfig, and toolset settings. | Medium: direct fit for the client JSON, no direct fit for the server TOML or runtime Kubernetes permissions. | Sanitized client reproduction: `MCPG005` medium, exit 1, for `kubernetes-mcp-server@latest`. The TOML/runtime boundary is the main blocker for broader coverage. |
| T-04 | Non-archived; 3,570 stars, 468 forks, 94 open issues; `pushed_at` 2026-10-17 17:16:20Z; latest API commit `5ea0cc3` at 2026-10-14 13:20:05Z. | [Client configuration examples](https://github.com/grafana/mcp-grafana/blob/main/docs/sources/set-up/client-configuration-examples.md) use `mcpServers`, `mcp-grafana`, `GRAFANA_URL`, and `GRAFANA_SERVICE_ACCOUNT_TOKEN`; docs cover stdio, SSE, and streamable HTTP. | High for JSON client configurations. Loopback URLs and environment placeholders are already within the current rule boundary. | Sanitized client reproduction: 0 findings, exit 0. This is a useful clean-path candidate; actual team policy and CI adoption remain unverified. |
| T-05 | Non-archived; 7,624 stars, 922 forks, 171 open issues; `pushed_at` 2026-10-17 00:39:27Z; latest API commit `26a23f2` at 2026-10-17 00:29:03Z. | [README installation/configuration](https://github.com/firecrawl/firecrawl-mcp-server/blob/main/README.md) documents hosted HTTP endpoints, stdio `npx -y firecrawl-mcp`, `FIRECRAWL_API_KEY`/OAuth references, Docker, and Cursor/VS Code examples; no dedicated client JSON file was identified in the tree scan. | High for sanitized JSON client configs and remote URL/auth rules; no runtime or API behavior is inferred. | Sanitized stdio reproduction: `MCPG005` medium, exit 1, because the command is unpinned. The public README is the current evidence source; no maintainer feedback exists. |

The scanner results above are local reproductions or the one public JSON file, not claims about runtime security. They are enough to select D3 fixtures, but not enough to mark any candidate as a user or CI adopter.

## Pre-contact checklist

Before a human decides to contact a candidate, record these checks in the validation log:

- current repository and owner contribution policy;
- current configuration example and whether it is JSON/JSONC server-map input;
- whether the example can be tested with a sanitized local fixture;
- expected finding IDs and the reason each one should be useful;
- the least intrusive manual channel, if any, and the exact opt-in message;
- a link to the public evidence used for the check.

Until those checks are complete, keep the candidate at `D2 public-read verified / no contact`; do not record outreach, maintainer intent, or CI adoption.
