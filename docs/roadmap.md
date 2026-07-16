# Roadmap

ForgeWard is an experimental alpha. This roadmap describes direction and release bars, not dates or commitments. Security claims follow tested behavior in a release, never the other way around.

## North star

Run a model-agnostic product, design, architecture, engineering, review, security, QA, and release team from the terminal while keeping workflow authority deterministic, changes reviewable, and every release decision tied to evidence.

The repository remains the system of record. Models remain untrusted. Humans retain consequential approval.

## Milestone 0 — Walkable alpha

**Status:** current focus; expect breaking changes.

Scope:

- `forgeward init`, `doctor`, `plan`, `run`, `resume`, `status`, `approve`, `reject`, `inspect`, `report`, and `export`;
- provider, team, policy, and provider-context inspection commands;
- deterministic lifecycle from `CREATED` through `COMPLETE`;
- product, designer, architect, scrum-master, builder, reviewer, tester, security, and release role contracts;
- human `PLAN_GATE` and `RELEASE_GATE` by default;
- explicit `--apply` behavior with no autonomous merge, push, publication, or deployment;
- local `.forgeward/firm.yaml` configuration;
- OpenAI-compatible Chat Completions boundary;
- atomic `run.json`, hash-chained `events.jsonl`, artifacts, and human-readable reporting;
- resumable failure states; and
- no ForgeWard telemetry.

Exit criteria:

- a new user can safely complete a synthetic engagement from init to export;
- malformed model output, gate rejection, interruption, and provider failure have automated tests;
- docs and `doctor` state the alpha limitations accurately;
- an export can detect ordinary event/artifact tampering; and
- CI covers the supported Python versions and operating systems.

## Milestone 1 — Hardened local runner

Planned work:

- versioned schemas for config, role output, events, and evidence;
- extend gate evidence binding to the effective policy/configuration and support independent event replay into a reconstructed projection;
- stricter path, symlink, command, environment, and network policy checks;
- bounded, idempotent provider retry policy, cancellation, and per-role token/cost budgets;
- broader secret classification and configurable organization-specific context rules;
- provider capability probes and a dated compatibility matrix;
- deterministic fixtures and fault-injection tests for resume and atomic writes;
- evidence verification independent of report rendering;
- verifiable export manifests that distinguish original bytes from best-effort redacted derivatives;
- clear dry-run/change-preview semantics; and
- macOS packaging validation and release provenance across supported platforms.

Exit criteria include a published security test matrix and closure or explicit acceptance of all high-severity MVP threat-model findings.

## Milestone 2 — Isolation and supply-chain evidence

Planned work:

- isolated Git worktrees for builders and reviewers;
- optional per-role container/process profiles with resource and network limits;
- stronger tool mediation and write-set inspection;
- dependency review automation and lockfile policy;
- SBOM generation for ForgeWard packages and containers;
- signed release artifacts, checksums, and build provenance;
- artifact manifests and optional externally anchored evidence digests; and
- evaluation of SQLite only if concurrency/query requirements justify migrations and locking.

Worktrees, SBOMs, signatures, and SQLite are not current MVP guarantees.

## Milestone 3 — Provider and team ecosystem

Planned work:

- supported LiteLLM gateway profile and expanded adapter contract suite;
- separately negotiated OpenAI Responses API transport;
- provider/model capability registry with tested versions and known deviations;
- reusable, versioned playbooks and team packages;
- role and provider extension API with explicit capability manifests;
- quality, security, latency, and cost evaluations per role;
- budget-aware routing without giving the router policy authority; and
- migration tooling for config and evidence schemas.

The goal is portability with visible differences, not a claim that all models behave identically.

## Milestone 4 — Assured collaboration

Candidates, subject to threat modeling and demand:

- cryptographically signed human approvals and evidence manifests;
- policy-as-code bundles with organization-level constraints;
- protected remote evidence anchoring;
- SLSA-aligned provenance for ForgeWard-produced release candidates;
- multi-operator review without turning ForgeWard into a hosted source-code service;
- CI integrations that consume packs but cannot forge local approvals; and
- narrowly scoped Git-host workflows with separate authorization.

None of these candidates implies autonomous production deployment.

## `1.0` release bar

ForgeWard will not call itself stable until:

- its config, provider port, lifecycle, and evidence schemas have documented compatibility policies;
- human gates cannot be bypassed through supported CLI paths;
- the event/artifact verifier has adversarial tests and migration coverage;
- command and filesystem policy have a completed security review;
- supported provider claims come from repeatable contract tests;
- packages and container images have reproducible provenance, SBOMs, and signatures;
- a third-party security assessment has no unresolved critical findings;
- upgrade, rollback, backup, and vulnerability-response procedures are documented; and
- the project can maintain its published support policy.

## Explicit non-goals

ForgeWard is not planning to become:

- an unsupervised production deployer;
- a guarantee that generated software is secure or correct;
- a replacement for OS/container isolation, CI, code review, or incident response;
- a hosted service that collects private repositories or engagement telemetry;
- a model-training data broker;
- a system where agent votes replace evidence or human accountability; or
- a provider abstraction that hides meaningful capability and privacy differences.

## How to influence the roadmap

Open a focused issue describing the user, threat model, expected artifact, and measurable exit criteria. For large or security-boundary changes, start with a design discussion before code. See [CONTRIBUTING.md](../CONTRIBUTING.md).

High-value alpha contributions include failure-path tests, provider contract fixtures, Windows portability, evidence verification, documentation corrections, and concrete threat-model improvements.
