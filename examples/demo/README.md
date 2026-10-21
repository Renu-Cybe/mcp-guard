# Consumer demo

This folder plays the part of an outside repository that adopts MCP Guard. The workflow in [`.github/workflows/demo.yml`](../../.github/workflows/demo.yml) references the action as `latentide/mcp-guard@v0.5.0`, exactly as another project would, instead of the local `uses: ./` used by the main CI. All configurations are sanitized examples; no real endpoints, tokens, or servers are used.

| File | What it shows | Expected result |
|---|---|---|
| `.mcp.json` | Pinned `npx` package and an environment-variable token reference | 0 findings |
| `configs/remote.json` | One remote server with an explicit `oauth` block, one that relies on client-managed OAuth | 1 `MCPG006` finding, accepted by `.mcp-guard-baseline.json` |
| `configs/unpinned.json` | `npx @playwright/mcp@latest` | 1 `MCPG005` finding, published to Code Scanning |

The workflow runs three jobs:

- **quick start**: the README quick-start setup with `fail-on: medium`.
- **reviewed baseline**: the `baseline` input accepts a finding that was reviewed and committed.
- **Code Scanning upload and failure gate**: uploads SARIF with `upload-sarif: true`, then confirms a `fail-on: medium` gate fails on the same file and still writes SARIF.

To refresh the baseline after reviewing a finding:

```bash
mcp-guard baseline examples/demo/configs/remote.json --output examples/demo/.mcp-guard-baseline.json
```
