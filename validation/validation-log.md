# Seven-day user-validation log

This is a manual evidence log for the first validation cycle. Empty fields must remain `pending` or `unverified`; do not convert a candidate into a user, a successful scan, or a maintainer response without evidence.

## Decision gates

The goal is evidence of usefulness, not star count:

- at least 5 candidates reviewed;
- at least 3 real configurations or sanitized reproductions run successfully;
- at least 2 projects complete a GitHub Action or equivalent CI trial;
- at least 1 maintainer or team asks for continued maintenance, a rule change, or a team-oriented capability.

If these gates are not met, stop expanding features and record the blocking reason before choosing a different product direction.

## Day plan

| Day | Focus | Exit evidence |
|---|---|---|
| D1 | README demo and baseline local run | A new user can reproduce the clean and high-risk examples in under five minutes. |
| D2 | Review the five public candidates | Each row has current configuration evidence or is marked `unverified`. |
| D3 | Prepare sanitized CLI trials | At least three reproducible inputs and expected findings are recorded. |
| D4 | Manual trial with selected candidates | Run results, exit codes, and false-positive notes are recorded. |
| D5 | Manual GitHub Action trial | Action setup time, SARIF/artifact behavior, and blockers are recorded. |
| D6 | Fix only trial-blocking issues | Each change links to a recorded blocker; no SaaS work is started. |
| D7 | Review gates and decide | Continue, narrow the scope, or stop based on evidence. |

## Record template

| Date | Day | Target ID | Repository | Commit | Scenario | Input fixture or path | Command or workflow | Install minutes | Run result | Exit code | Finding IDs / severity | False positive? | SARIF / artifact | Maintainer feedback | Requested change | CI adopted? | Evidence URL | Owner | Next action |
|---|---|---|---|---|---|---|---|---:|---|---:|---|---|---|---|---|---|---|---|---|
| 2026-10-17 | D1 | internal-demo | `Renu-Cybe/mcp-guard` | `a11942fe62d544370dbff94fd7ff063631eae6aa` | CLI demo | `tests/fixtures/high-risk.json` | `python -m mcp_guard.cli scan tests/fixtures/high-risk.json --format markdown --fail-on none` | pending | 4 findings printed | 1 | `MCPG001` high; `MCPG002` high; `MCPG004` high; `MCPG006` medium | not assessed | not applicable | no outreach | none | n/a | https://github.com/Renu-Cybe/mcp-guard/blob/v0.4.0/tests/fixtures/high-risk.json | codex | Use output as README demo evidence |
| 2026-10-17 | D1 | internal-demo | `Renu-Cybe/mcp-guard` | `a11942fe62d544370dbff94fd7ff063631eae6aa` | CLI demo | `tests/fixtures/safe.json` | `python -m mcp_guard.cli scan tests/fixtures/safe.json --format markdown --fail-on none` | pending | `Findings: 0` | 0 | none | not applicable | not applicable | no outreach | none | n/a | https://github.com/Renu-Cybe/mcp-guard/blob/v0.4.0/tests/fixtures/safe.json | codex | Confirm zero-finding path |
| pending | D2 | T-01 | `github/github-mcp-server` | `e3809fe91c7546633241006bf0b91f23b2595e28` | candidate review | pending | pending | pending | not contacted | pending | pending | unverified | pending | not contacted | pending | pending | https://github.com/github/github-mcp-server/commit/e3809fe91c7546633241006bf0b91f23b2595e28 | codex | Check current public configuration |
| pending | D2 | T-02 | `microsoft/playwright-mcp` | `b8b4183e099f136cbec0388a6088d4aa2f6b9685` | candidate review | pending | pending | pending | not contacted | pending | pending | unverified | pending | not contacted | pending | pending | https://github.com/microsoft/playwright-mcp/commit/b8b4183e099f136cbec0388a6088d4aa2f6b9685 | codex | Check current public configuration |
| pending | D2 | T-03 | `containers/kubernetes-mcp-server` | `970df6a7169c943fc0c82641fde6eed38f1e153c` | candidate review | pending | pending | pending | not contacted | pending | pending | unverified | pending | not contacted | pending | pending | https://github.com/containers/kubernetes-mcp-server/commit/970df6a7169c943fc0c82641fde6eed38f1e153c | codex | Check current public configuration |
| pending | D2 | T-04 | `grafana/mcp-grafana` | `5ea0cc34678cdd6fcd2f5c731b6619a8433bcb20` | candidate review | pending | pending | pending | not contacted | pending | pending | unverified | pending | not contacted | pending | pending | https://github.com/grafana/mcp-grafana/commit/5ea0cc34678cdd6fcd2f5c731b6619a8433bcb20 | codex | Check current public configuration |
| pending | D2 | T-05 | `firecrawl/firecrawl-mcp-server` | `26a23f28ec22241cb16e2115f27a6370ce2a00e0` | candidate review | pending | pending | pending | not contacted | pending | pending | unverified | pending | not contacted | pending | pending | https://github.com/firecrawl/firecrawl-mcp-server/commit/26a23f28ec22241cb16e2115f27a6370ce2a00e0 | codex | Check current public configuration |

## Evidence rules

- Record public links, commands, exit codes, and sanitized output only.
- Never paste credentials, tokens, private configuration, or private messages into this file.
- A static finding is a review signal, not a vulnerability claim.
- Do not record outreach as completed until a human has explicitly chosen and performed it.
