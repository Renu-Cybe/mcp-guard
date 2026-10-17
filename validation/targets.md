# Seven-day validation targets

This is a candidate list for manual product validation. It is not a contact list, a security finding list, or a claim that a repository is actively maintained. The candidates were selected from the fixed D2 register because their public metadata describes a server-map configuration that MCP Guard can scan today.

**Boundary:** do not automatically contact, file issues, publish findings, or infer maintainer intent from this file. Before any manual outreach, re-check the repository's current contribution policy, current configuration examples, and whether the target still fits the supported input boundary. Use sanitized examples only.

## Candidate list

| ID | Priority | Public GitHub handle | Repository | D2 sample | Fixed commit | Configuration and transport | Clients | Sensitivity | First validation hypothesis | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| T-01 | A | `github` | [`github/github-mcp-server`](https://github.com/github/github-mcp-server) | MCP-003 | `e3809fe91c7546633241006bf0b91f23b2595e28` | Remote URL plus OAuth/PAT; Streamable HTTP / HTTPS | VS Code, Claude Desktop, Cursor, Windsurf, Codex | high | A remote configuration with visible authentication references should produce useful, reviewable findings without exposing credentials. | candidate / public metadata only |
| T-02 | A | `microsoft` | [`microsoft/playwright-mcp`](https://github.com/microsoft/playwright-mcp) | MCP-004 | `b8b4183e099f136cbec0388a6088d4aa2f6b9685` | `mcpServers` JSON with `npx @playwright/mcp`; stdio | VS Code, Cursor, Windsurf, Claude Desktop, Cline, Codex | high | A common `npx` stdio configuration should scan cleanly or explain exactly which command/path risks need review. | candidate / public metadata only |
| T-03 | A | `containers` | [`containers/kubernetes-mcp-server`](https://github.com/containers/kubernetes-mcp-server) | MCP-008 | `970df6a7169c943fc0c82641fde6eed38f1e153c` | `mcpServers` JSON and local server command; stdio | Claude, Cursor, VS Code, compatible clients | high | A Kubernetes-oriented server is a useful test of high-impact local/container permissions and rule explanations. | candidate / public metadata only |
| T-04 | A | `grafana` | [`grafana/mcp-grafana`](https://github.com/grafana/mcp-grafana) | MCP-015 | `5ea0cc34678cdd6fcd2f5c731b6619a8433bcb20` | `mcpServers` JSON with environment/token references; stdio | Claude, Cursor, VS Code, compatible clients | high | Environment and token references should be distinguishable from hardcoded secrets with low false-positive cost. | candidate / public metadata only |
| T-05 | A | `firecrawl` | [`firecrawl/firecrawl-mcp-server`](https://github.com/firecrawl/firecrawl-mcp-server) | MCP-019 | `26a23f28ec22241cb16e2115f27a6370ce2a00e0` | `mcpServers` JSON with `npx` and API-key references; stdio | Cursor, Claude, Gemini CLI, compatible clients | high | A recognizable API-key configuration should demonstrate whether the report is actionable before CI adoption. | candidate / public metadata only |

Commit evidence links for reproducibility:

- [MCP-003 commit](https://github.com/github/github-mcp-server/commit/e3809fe91c7546633241006bf0b91f23b2595e28)
- [MCP-004 commit](https://github.com/microsoft/playwright-mcp/commit/b8b4183e099f136cbec0388a6088d4aa2f6b9685)
- [MCP-008 commit](https://github.com/containers/kubernetes-mcp-server/commit/970df6a7169c943fc0c82641fde6eed38f1e153c)
- [MCP-015 commit](https://github.com/grafana/mcp-grafana/commit/5ea0cc34678cdd6fcd2f5c731b6619a8433bcb20)
- [MCP-019 commit](https://github.com/firecrawl/firecrawl-mcp-server/commit/26a23f28ec22241cb16e2115f27a6370ce2a00e0)

## Pre-contact checklist

Before a human decides to contact a candidate, record these checks in the validation log:

- current repository and owner contribution policy;
- current configuration example and whether it is JSON/JSONC server-map input;
- whether the example can be tested with a sanitized local fixture;
- expected finding IDs and the reason each one should be useful;
- the least intrusive manual channel, if any, and the exact opt-in message;
- a link to the public evidence used for the check.

Until those checks are complete, leave the candidate as `candidate / public metadata only`.
