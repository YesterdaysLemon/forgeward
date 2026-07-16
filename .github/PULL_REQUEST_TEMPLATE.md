## What changed

<!-- Describe the behavior and scope. -->

## Why

<!-- Link the issue or explain the user/security outcome. -->

## Evidence

- [ ] Tests added or updated
- [ ] `uv run ruff check .`
- [ ] `uv run mypy src/forgeward`
- [ ] `uv run pytest`
- [ ] Documentation updated where behavior or trust boundaries changed

## Security review

<!-- Note changes to provider payloads, prompts, paths, subprocesses, credentials, gates, or evidence. -->

- [ ] No secret or credential material is included
- [ ] Untrusted inputs remain bounded and typed
- [ ] Gate and author/reviewer separation remains intact
