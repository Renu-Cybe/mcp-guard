# Contributing to MCP Guard

Thanks for helping improve MCP Guard. The project is intentionally local-first: tests and scans must not start MCP servers, install third-party server dependencies, or send configuration to a service.

## Development checks

From the repository root:

```bash
python -m pip install -e .
python -m pytest -q
python -m build
python -m twine check dist/*
```

Keep fixtures small and synthetic. Never commit API keys, bearer tokens, private URLs, personal data, or copied third-party configuration that the project does not have permission to redistribute.

## Adding a rule or fixture

- Explain the concrete configuration pattern and the security decision it represents.
- Add a positive test and a safe negative test, including environment-variable references or loopback cases when relevant.
- Keep evidence redacted and stable so fingerprints remain useful for baselines.
- If a file contains more than one supported server map, use an explicit selector such as `$.config.mcpServers` in tests.
- Update the README rule or scope text when behavior changes.

## Pull requests

Describe the user-visible behavior, the input shape covered, and the validation you ran. Changes to the GitHub Action must include a real runner check in `.github/workflows/ci.yml` when practical.
