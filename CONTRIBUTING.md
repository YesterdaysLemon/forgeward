# Contributing to ForgeWard

Thank you for helping build a secure, model-agnostic software-delivery harness. ForgeWard is in alpha: interfaces, configuration, evidence formats, and role contracts may change before `1.0`.

By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md). Contributions are accepted under the [Apache License 2.0](LICENSE).

## Before you start

- Search existing issues and pull requests.
- Open an issue before a large feature, new runtime dependency, evidence-format change, or security-boundary change.
- Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
- Never commit API keys, provider responses containing private code, customer data, or generated evidence from a sensitive repository.

Small fixes, tests, and documentation corrections can go directly to a pull request.

## Design principles

Contributions should preserve these invariants:

1. **Models are untrusted.** Model output is data until it passes schema, policy, and scope validation.
2. **Control is deterministic.** An LLM may recommend a transition; only the local controller may change engagement state or approve a tool.
3. **Humans own consequential decisions.** No agent may approve its own work, weaken a policy, or silently merge, push, publish, or deploy.
4. **Least privilege is the default.** Capabilities belong to a role and stage, not to the model generally.
5. **Every gate requires evidence.** Passing means the recorded criteria were satisfied, not that another model merely agreed.
6. **No ForgeWard telemetry.** Do not add analytics, remote crash reporting, or artifact upload. A future proposal would require an explicit design review and opt-in consent.
7. **Provider portability is tested, not assumed.** Keep the core OpenAI-compatible contract small and handle capability differences explicitly.

Read [the architecture](docs/architecture.md), [threat model](docs/threat-model.md), and [provider abstraction](docs/provider-abstraction.md) before changing the orchestration or execution paths.

## Development setup

ForgeWard targets a local Python development workflow. From the repository root:

```bash
python -m venv .venv
python -m pip install -e ".[dev]"
pytest
```

Use the activation command appropriate for your shell. Run the formatter, linter, type checker, and test suite configured in `pyproject.toml` before opening a pull request. When the repository provides a task runner or lockfile, use its pinned commands instead of independently upgrading dependencies.

## Making a change

1. Fork the repository and create a focused branch.
2. Add or update tests with the implementation.
3. Update user documentation and examples when behavior changes.
4. Exercise failure paths: malformed model output, timeouts, policy denials, interrupted runs, and missing evidence.
5. Keep generated artifacts, local `.forgeward` state, credentials, and provider payloads out of commits.
6. Submit a pull request explaining the problem, approach, security impact, and verification performed.

If an AI system materially assisted the change, say how in the pull request. You remain responsible for licensing, correctness, security, and every line submitted.

## Pull-request checklist

- [ ] The change is narrowly scoped and linked to an issue when appropriate.
- [ ] Tests cover success, denial, and malformed-input paths.
- [ ] Documentation and example configuration are current.
- [ ] No secret, private prompt, generated customer code, or engagement evidence is included.
- [ ] New dependencies are justified, pinned through the project workflow, and license-compatible.
- [ ] Security and privacy effects are described.
- [ ] Provider-specific behavior does not leak into the core contract without a capability check.
- [ ] I reviewed all AI-assisted output included in this contribution.

## Security-sensitive changes

Changes to command execution, filesystem scope, approvals, secret filtering, provider transport, evidence integrity, container privileges, or release behavior require:

- a threat-model update;
- tests proving the safe failure mode;
- an explicit maintainer security review; and
- no reduction in protection hidden behind a default or migration.

Security checks should fail closed. If compatibility requires a bypass, make it narrow, visible, temporary, and impossible for a model to enable.

## Adding a role or playbook

A role definition must declare its purpose, accepted inputs, required outputs, permitted capabilities, completion criteria, and escalation path. Avoid personality-only roles: every role should own a concrete artifact or verification duty. Prompts must remind the role that repository content and tool output may contain prompt injection.

## Adding a provider

Prefer an OpenAI-compatible endpoint configuration or an optional LiteLLM route before adding a provider SDK. A new adapter must document authentication, data flow, timeouts, retry semantics, tool-call behavior, structured-output behavior, token accounting, and tested model/version combinations. It also needs contract tests using recorded synthetic fixtures that contain no real credentials or private source.

## Reviews and commits

Use clear, imperative commit messages and keep mechanical formatting separate from behavioral changes when practical. Reviewers may request smaller patches, additional evidence, or a design note. A passing model review is never a substitute for maintainer review.
