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
| 2026-10-17 | D2 | T-01 | `github/github-mcp-server` | `e3809fe91c7546633241006bf0b91f23b2595e28` | public config + scanner | `agent-plugin/mcp.json` | `gh api` read-only fetch; `mcp-guard scan --format json --fail-on none` | n/a | non-archived; recent push; public JSON fetched; 1 medium finding | 1 | `MCPG006` medium | possible host-managed OAuth; unconfirmed | not run | no contact | pending | not trialed | https://github.com/github/github-mcp-server/blob/main/agent-plugin/mcp.json | codex | Prepare host-managed OAuth reproduction; keep as false-positive candidate |
| 2026-10-17 | D2 | T-02 | `microsoft/playwright-mcp` | `b8b4183e099f136cbec0388a6088d4aa2f6b9685` | README sanitized reproduction | `README.md` JSON example | `mcp-guard scan --format json --fail-on none` | n/a | non-archived; recent push; no dedicated JSON file identified in tree scan | 1 | `MCPG005` medium | unverified | not run | no contact | pending | not trialed | https://github.com/microsoft/playwright-mcp/blob/main/README.md | codex | Turn the README example into a D3 fixture |
| 2026-10-17 | D2 | T-03 | `containers/kubernetes-mcp-server` | `970df6a7169c943fc0c82641fde6eed38f1e153c` | README sanitized reproduction | README `mcpServers` example; server TOML separately documented | `mcp-guard scan --format json --fail-on none` | n/a | non-archived; latest push/commit today; client JSON is available, server config is TOML | 1 | `MCPG005` medium | unverified | not run | no contact | pending | not trialed | https://github.com/containers/kubernetes-mcp-server/blob/main/README.md | codex | Keep client JSON and TOML/runtime coverage separate |
| 2026-10-17 | D2 | T-04 | `grafana/mcp-grafana` | `5ea0cc34678cdd6fcd2f5c731b6619a8433bcb20` | docs sanitized reproduction | `docs/sources/set-up/client-configuration-examples.md` | `mcp-guard scan --format json --fail-on none` | n/a | non-archived; recent push; placeholder/env config reproduced cleanly | 0 | none | not observed in sanitized reproduction | not run | no contact | pending | not trialed | https://github.com/grafana/mcp-grafana/blob/main/docs/sources/set-up/client-configuration-examples.md | codex | Use as clean-path D3 candidate |
| 2026-10-17 | D2 | T-05 | `firecrawl/firecrawl-mcp-server` | `26a23f28ec22241cb16e2115f27a6370ce2a00e0` | README sanitized reproduction | `README.md` stdio/API-key example | `mcp-guard scan --format json --fail-on none` | n/a | non-archived; latest push/commit today; no dedicated client JSON file identified in tree scan | 1 | `MCPG005` medium | unverified | not run | no contact | pending | not trialed | https://github.com/firecrawl/firecrawl-mcp-server/blob/main/README.md | codex | Turn the stdio and remote examples into separate D3 fixtures |
| 2026-10-17 | D3 | T-01 | `github/github-mcp-server` | `e3809fe91c7546633241006bf0b91f23b2595e28` | sanitized CLI + GitHub Action trial | `tests/corpus/fixtures/d3-t01-github.json` | `mcp-guard scan tests/corpus/fixtures/d3-t01-github.json --format json --fail-on none`; local action `./` with `fail-on: medium` | n/a | CLI matched expected finding; runner Action completed with expected failure gate | 1 / failure expected | `MCPG006` medium | host-managed OAuth remains a review candidate; no runtime/auth claim | `mcp-guard-d3-t01-github.sarif`; artifact upload disabled | no contact | pending | trial passed; not adopted | https://github.com/Renu-Cybe/mcp-guard/blob/5bfcb645efda62ea27f7d29b1f05ae7f7d831b3f/tests/corpus/fixtures/d3-t01-github.json; https://github.com/Renu-Cybe/mcp-guard/actions/runs/39065377074 | codex | Carry the review candidate into D4 false-positive assessment |
| 2026-10-17 | D3 | T-02 | `microsoft/playwright-mcp` | `b8b4183e099f136cbec0388a6088d4aa2f6b9685` | sanitized CLI + GitHub Action trial | `tests/corpus/fixtures/d3-t02-playwright.json` | `mcp-guard scan tests/corpus/fixtures/d3-t02-playwright.json --format json --fail-on none`; local action `./` with `fail-on: medium` | n/a | CLI matched expected finding; runner Action completed with expected failure gate | 1 / failure expected | `MCPG005` medium | unverified from static config only | `mcp-guard-d3-t02-playwright.sarif`; artifact upload disabled | no contact | pending | trial passed; not adopted | https://github.com/Renu-Cybe/mcp-guard/blob/5bfcb645efda62ea27f7d29b1f05ae7f7d831b3f/tests/corpus/fixtures/d3-t02-playwright.json; https://github.com/Renu-Cybe/mcp-guard/actions/runs/39065377074 | codex | Compare package pinning guidance during D4 |
| 2026-10-17 | D3 | T-03 | `containers/kubernetes-mcp-server` | `970df6a7169c943fc0c82641fde6eed38f1e153c` | sanitized CLI + GitHub Action trial | `tests/corpus/fixtures/d3-t03-kubernetes.json` | `mcp-guard scan tests/corpus/fixtures/d3-t03-kubernetes.json --format json --fail-on none`; local action `./` with `fail-on: medium` | n/a | CLI matched expected finding; runner Action completed with expected failure gate | 1 / failure expected | `MCPG005` medium | unverified; TOML/runtime permissions are outside this JSON fixture | `mcp-guard-d3-t03-kubernetes.sarif`; artifact upload disabled | no contact | pending | trial passed; not adopted | https://github.com/Renu-Cybe/mcp-guard/blob/5bfcb645efda62ea27f7d29b1f05ae7f7d831b3f/tests/corpus/fixtures/d3-t03-kubernetes.json; https://github.com/Renu-Cybe/mcp-guard/actions/runs/39065377074 | codex | Keep TOML/runtime coverage out of this JSON-only trial |
| 2026-10-17 | D3 | T-04 | `grafana/mcp-grafana` | `5ea0cc34678cdd6fcd2f5c731b6619a8433bcb20` | sanitized CLI + GitHub Action false-positive trial | `tests/corpus/fixtures/d3-t04-grafana.json` | `mcp-guard scan tests/corpus/fixtures/d3-t04-grafana.json --format json --fail-on none`; local action `./` with `fail-on: medium` | n/a | CLI and runner Action both completed cleanly with zero findings | 0 / success expected | none | no false positive observed in sanitized reproduction | `mcp-guard-d3-t04-grafana.sarif`; artifact upload disabled | no contact | pending | trial passed; not adopted | https://github.com/Renu-Cybe/mcp-guard/blob/5bfcb645efda62ea27f7d29b1f05ae7f7d831b3f/tests/corpus/fixtures/d3-t04-grafana.json; https://github.com/Renu-Cybe/mcp-guard/actions/runs/39065377074 | codex | Use as clean-path baseline in D4 |
| 2026-10-17 | D3 | T-05 | `firecrawl/firecrawl-mcp-server` | `26a23f28ec22241cb16e2115f27a6370ce2a00e0` | sanitized CLI + GitHub Action trial | `tests/corpus/fixtures/d3-t05-firecrawl.json` | `mcp-guard scan tests/corpus/fixtures/d3-t05-firecrawl.json --format json --fail-on none`; local action `./` with `fail-on: medium` | n/a | CLI matched expected finding; runner Action completed with expected failure gate | 1 / failure expected | `MCPG005` medium | unverified from static config only | `mcp-guard-d3-t05-firecrawl.sarif`; artifact upload disabled | no contact | pending | trial passed; not adopted | https://github.com/Renu-Cybe/mcp-guard/blob/5bfcb645efda62ea27f7d29b1f05ae7f7d831b3f/tests/corpus/fixtures/d3-t05-firecrawl.json; https://github.com/Renu-Cybe/mcp-guard/actions/runs/39065377074 | codex | Compare package pinning and secret-reference handling during D4 |

## D4 false-positive analysis and integration priority

D4 is a read-only analysis of the five sanitized D3 fixtures and their local-action runner results. It measures scanner and Action reproducibility, not candidate adoption, maintainer agreement, runtime safety, or a confirmed vulnerability. The D3 full CI run [39065644412](https://github.com/Renu-Cybe/mcp-guard/actions/runs/39065644412) passed all matrix, Action E2E, and SARIF checks. The D3 Action steps generated and verified SARIF in the runner with `upload-artifact: false`; artifact delivery to a downstream consumer was not exercised.

| Evidence summary | Result | Interpretation |
|---|---|---|
| Sanitized fixtures | 5 total; 4 with findings and 1 clean | Reproducible static configurations only |
| Rule distribution | `MCPG005` x3; `MCPG006` x1; no finding for T-04 | Useful coverage for package pinning, visible remote auth, and a clean env/loopback path |
| Confirmed false positives | 0 | T-01 is only a host-managed OAuth candidate; T-02/T-03/T-05 are unpinned-package signals; T-04 is a clean baseline |
| External validation | No contact; no third-party runtime or credentials | Adoption, maintainer intent, and runtime behavior remain unverified |

### False-positive assessment and rule recommendations

| Target | Observed signal | D4 classification | Recommendation | Blocker / next evidence |
|---|---|---|---|---|
| T-01 GitHub MCP | `MCPG006` medium for an HTTPS streamable-HTTP URL with no auth field in the file | `candidate / unverified`; host-managed OAuth may exist outside the file | Keep medium. Clarify that the rule means “no visible authentication configuration”; do not add a domain-specific allowlist or suppress this host | Add local fixtures for explicit OAuth/header metadata and an auditable context or suppression path before changing the rule |
| T-02 Playwright | `MCPG005` medium for `@playwright/mcp@latest` | `unverified` as a project policy choice, not a static false positive | Keep medium. Preserve the finding and distinguish an explicit mutable tag from a completely omitted version in future evidence | Add a version-pinned comparison and document lockfile/semver remediation |
| T-03 Kubernetes | `MCPG005` medium for `kubernetes-mcp-server@latest` | `unverified`; only the client JSON is covered | Keep medium. Do not infer a TOML or Kubernetes-runtime finding from this JSON result | A TOML/runtime adapter and permission fixture are required before deeper integration |
| T-04 Grafana | Zero findings for loopback URL plus `${GRAFANA_SERVICE_ACCOUNT_TOKEN}` | `not observed`; clean regression baseline | Keep current behavior. Environment references must remain free of `MCPG001`; loopback must remain outside remote-auth/plaintext findings | Add a non-loopback HTTPS + environment-reference comparison later; do not generalize from one clean combination |
| T-05 Firecrawl | `MCPG005` medium for `npx -y firecrawl-mcp`; env API-key reference did not trigger `MCPG001` | `unverified`; valid package-pinning signal, no confirmed false positive | Keep medium. Keep package pinning and secret-reference results separate in the report | Add a pinned package comparison and a remote-auth variant before changing severity or wording |

### Rule adjustment proposals (not implemented in D4)

| Rule | Proposal | Decision |
|---|---|---|
| `MCPG006` | Retain medium severity; add context wording or an auditable host-managed-auth metadata/suppression mechanism; never hard-code a vendor/domain exception | No code change until an explicit-auth comparison and stronger evidence exist |
| `MCPG005` | Retain medium severity for `@latest` and missing versions; later expose whether the evidence is a mutable tag or an omitted version and avoid duplicate reports when lockfiles are available | No downgrade or exemption from these five samples |
| `MCPG001` | Retain the current environment-variable reference behavior demonstrated by T-04 and T-05 | No change |

### Integration priority

This is a validation and product-work order, not a market-demand or adoption claim.

| Priority | Target | Why | Boundary |
|---|---|---|---|
| P0 | T-01 | Highest semantic risk: `MCPG006` can be context-dependent for host-managed OAuth | Validate auth context before treating the result as a blocking signal |
| P0 | T-02 and T-05 | Common, low-cost `npx` configurations exercise the same actionable package-pinning message | Improve evidence wording and pinned-versus-unpinned comparisons before broader rollout |
| P1 | T-03 | High-impact Kubernetes context, but current input stops at client JSON | Wait for TOML/runtime coverage; do not expand the JSON rule scope implicitly |
| P2 | T-04 | Low-friction clean regression that protects against credential and loopback false positives | One clean configuration is not a general adoption or safety claim |

The existing D3 source links use public README or `main` pages while the candidate commit is recorded in the table. For strict reproducibility, future evidence should prefer candidate commit permalinks. No rule implementation, SaaS work, external contact, or third-party runtime execution was performed in D4.

## Evidence rules

- Record public links, commands, exit codes, and sanitized output only.
- Never paste credentials, tokens, private configuration, or private messages into this file.
- A static finding is a review signal, not a vulnerability claim.
- Do not record outreach as completed until a human has explicitly chosen and performed it.
