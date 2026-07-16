<div align="center">

# FORGEWARD

### Build as a team. Ship with evidence.

A security-first, model-agnostic AI software firm that runs from your terminal.

[![CI](https://github.com/YesterdaysLemon/forgeward/actions/workflows/ci.yml/badge.svg)](https://github.com/YesterdaysLemon/forgeward/actions/workflows/ci.yml)
[![CodeQL](https://github.com/YesterdaysLemon/forgeward/actions/workflows/codeql.yml/badge.svg)](https://github.com/YesterdaysLemon/forgeward/actions/workflows/codeql.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-101311.svg)](LICENSE)
[![Status: Alpha](https://img.shields.io/badge/status-alpha-FF6B35.svg)](#alpha-status)

[How it works](#how-an-engagement-works) · [Quick start](#five-minute-quick-start) · [Providers](#one-contract-any-model-bench) · [Security](#gates-not-vibes) · [Architecture](docs/architecture.md)

</div>

> [!WARNING]
> ForgeWard is alpha software. Models are untrusted proposal engines, not security boundaries. Review
> plans and diffs, configure deterministic project checks, keep provider credentials out of files and
> logs, and do not treat a completed run as proof that software is safe or production-ready.

## What ForgeWard is

ForgeWard assembles product, design, architecture, scrum, engineering, security, testing, review, and
release roles around a deterministic secure-development lifecycle. Every role leaves an artifact.
Every gate evaluates inspectable evidence. Your repository remains the system of record.

It is deliberately split into two layers:

- **The firm:** replaceable LLM workers produce requirements, threat models, UX specifications,
  architecture decisions, backlogs, structured file proposals, reviews, and release notes.
- **The ward:** ordinary Python code owns state transitions, context limits, response validation, path
  containment, check execution, budgets, evidence integrity, and human gates.

ForgeWard is not a free-running shell agent, an excuse to skip review, or a claim that several personas
automatically equal a good engineering organization.

## Five-minute quick start

Requirements: Python 3.11+, Git, and [`uv`](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/YesterdaysLemon/forgeward.git
cd forgeward
uv tool install .

cd /path/to/your/project
forgeward init
forgeward doctor
forgeward run "Add passwordless sign-in with recovery codes"
```

The generated configuration uses a deterministic offline demo provider. It lets you inspect the whole
lifecycle without credentials or network access, but its output is not substantive engineering review.

The run stops at the plan gate:

```bash
forgeward inspect fw-20260716-120000-a1b2c3
forgeward approve fw-20260716-120000-a1b2c3 plan
forgeward resume fw-20260716-120000-a1b2c3
```

It then stops at the release gate. Required check failures and high-severity findings produced during
verification block approval.

```bash
forgeward approve fw-20260716-120000-a1b2c3 release
forgeward resume fw-20260716-120000-a1b2c3
forgeward report fw-20260716-120000-a1b2c3
forgeward export fw-20260716-120000-a1b2c3
```

Use `forgeward plan "…"` when you only want the planning bench. Add `--apply` to `forgeward run` only
when you explicitly want validated builder proposals written into a clean Git worktree.

## How an engagement works

```text
CREATED
   │
   ▼
INTAKE ── product brief + acceptance criteria
   │
   ▼
DISCOVERY ── UX specification + threat model
   │
   ▼
DESIGN ── architecture decision + ordered backlog
   │
   ▼
PLAN GATE ◀── explicit human approval by default
   │
   ▼
EXECUTION ── typed, path-scoped file proposals
   │
   ▼
VERIFICATION ── allowlisted checks + independent review + security review
   │
   ▼
RELEASE GATE ◀── blockers fail closed; explicit human approval by default
   │
   ▼
COMPLETE ── release handoff + hash-chained evidence ledger
```

Models may recommend a transition. Only the deterministic engine can apply it. A plan rejection reruns
the complete planning bench from intake; a release rejection reruns build and verification. Neither
path silently downgrades evidence.

### The default firm

| Role | Leaves behind | Repository authority |
|---|---|---|
| Product | Requirements and acceptance criteria | Read-only context |
| Designer | Accessible UX flow and states | Read-only context |
| Security | Threat model and independent findings | Read-only context |
| Architect | Architecture decision | Read-only context |
| Scrum master | Ordered, verifiable backlog | None |
| Builder | Implementation note and typed file proposals | Create/update only with `--apply` |
| Reviewer | Independent code review | Read-only context |
| Tester | Coverage assessment tied to check evidence | Read-only evidence |
| Release | Handoff and rollback notes | Read-only evidence |

The orchestrator is code, not another model persona. No model role can approve a gate.

## One contract. Any model bench.

ForgeWard keeps an OpenAI Chat Completions-compatible wire boundary because it is the broadest common
denominator across current providers and local servers. The internal types stay provider-neutral, and
the roadmap tracks the agentic [Open Responses](https://www.openresponses.org/) specification.

The quick research behind this decision:

| Option | Best use in ForgeWard |
|---|---|
| [LiteLLM](https://docs.litellm.ai/) | Closest thing to an LLM ORM: optional Python dialect layer or self-hosted OpenAI-compatible gateway with routing and fallbacks |
| [Pydantic AI models](https://ai.pydantic.dev/models/overview/) | Strong typed provider/model profiles; more agent-framework opinion than the core requires |
| [Portkey Gateway](https://github.com/Portkey-AI/gateway) | Separate gateway with routing, fallbacks, guardrails, and governance |
| [OpenRouter](https://openrouter.ai/docs/quickstart) | Hosted OpenAI-compatible route with broad model access |
| Ollama, vLLM, LM Studio | Local or self-hosted endpoints when their OpenAI-compatible Chat Completions mode is enabled |

LiteLLM is the recommended optional adapter, not a core dependency. In ORM terms: ForgeWard owns the
domain model, LiteLLM supplies provider dialects, and `base_url` endpoints are interchangeable
connections. From a clone, install the in-process dialect adapter with `uv tool install '.[litellm]'`, or run
LiteLLM as a separate gateway and keep the smaller core installation.

Edit `.forgeward/firm.yaml`:

```yaml
project:
  name: acme-api
  default_provider: gateway

providers:
  gateway:
    adapter: openai-compatible
    base_url: http://localhost:4000/v1
    model: forgeward/default
    api_key_env: FORGEWARD_API_KEY
    timeout_seconds: 120
    max_response_bytes: 1000000
    allow_insecure_http: false
    enabled: true
    capabilities:
      tools: true
      json_schema: true
      streaming: true
      images: false
      reasoning: true
```

Keep the secret in the named environment variable. ForgeWard never prints it, stores it in run state,
or includes it in the evidence pack. The direct `openai-compatible` adapter rejects non-loopback HTTP
unless you set the conspicuous `allow_insecure_http: true` escape hatch, ignores ambient proxy
variables, streams a bounded decoded body, and never surfaces upstream error bodies. Verify the route
explicitly:

```bash
forgeward provider list
forgeward provider test gateway
```

Current v0.1 model calls use text messages plus JSON Schema response formatting. Tool-call parsing,
streaming, automatic capability negotiation, native Responses API transport, and in-process LiteLLM
routing policies are roadmap items—not implied by the capability declarations yet. The optional
LiteLLM adapter does provide direct provider translation with retries explicitly disabled; routing and
fallback strategy belong in a separately configured LiteLLM gateway for now. With in-process
`adapter: litellm` and no explicit `base_url`, LiteLLM owns endpoint, proxy, CA, and response
materialization behavior; ForgeWard applies its text-size check only after the SDK returns. For the
strongest transport boundary, run LiteLLM as a gateway and call it over HTTPS through ForgeWard's
direct adapter. `forgeward doctor` warns when native transport is delegated this way.

## Gates, not vibes

The MVP enforces these controls in code:

- **Capability-bounded context:** only roles granted `repository.read` receive source context; prior
  artifacts, proposed diffs, and check evidence are separately capability-gated. Only Git-tracked files
  are eligible. Common credential/key/state paths are always omitted, known secret shapes are redacted,
  enumeration fails closed, and every decision is recorded in a bounded context manifest. Run
  `forgeward context preview` before using an external provider.
- **Prompt-injection boundary:** repository text, prior model output, issue content, and check output are
  labeled untrusted; system policy remains outside those delimiters.
- **Strict model output:** every worker must satisfy one Pydantic deliverable schema. Only the builder
  may propose repository changes.
- **Safe writes:** relative paths only; traversal, protected paths, symlink/reparse chains, Windows
  aliases and device names, oversized files, inconsistent create/update operations, and writes outside
  the root fail closed.
- **No model shell:** configured checks are argv arrays, use an executable allowlist, and always run with
  `shell=false`. Check subprocesses receive only an explicit environment-variable allowlist, so provider
  keys and unrelated host secrets are withheld. Models cannot add or invoke commands during a run.
  A bare executable that resolves inside the project is rejected; prefer an external runner such as
  `[uv, run, pytest, -q]`, or allowlist an exact absolute tool path deliberately. Stored output is
  bounded and drained in memory; native checks are still not an OS sandbox.
- **Dirty-worktree protection:** `--apply` requires a Git commit and clean worktree. Before release,
  ForgeWard revalidates `HEAD` and every file hash it applied.
- **Independent approval:** plan and release are human gates by default. Model roles have no approval
  capability and blocked releases cannot be approved.
- **Evidence integrity:** every hash-chained event checkpoints the complete semantic run projection.
  Resume and approval verify that checkpoint plus every recorded artifact; gates additionally bind the
  exact artifact, check, and applied-workspace evidence under review.
- **Secret hygiene:** common sensitive filenames are withheld and common key shapes are redacted from
  provider context, check logs, and exported text. Telemetry is off by default and no telemetry client
  ships in v0.1.
- **Budgets:** context, file, output, provider-call, and command-time limits are explicit configuration.

Read the full [threat model](docs/threat-model.md), [architecture](docs/architecture.md), and
[evidence-pack format](docs/evidence-pack.md) before using ForgeWard on sensitive code.

### Honest limitations

- A compromised local process can alter files before ForgeWard verifies them; this is tamper-evidence,
  not a trusted execution environment.
- Native execution does not enforce network isolation. Use a hardened container or sandbox appropriate
  to your project and threat model.
- On POSIX, a timed-out check is started in and terminates its own process group. On Windows, ForgeWard
  can kill only the direct process with portable standard-library primitives; a descendant may survive.
  Use job objects, a container, CI runner limits, or another OS boundary for hostile commands.
- In-process LiteLLM delegates transport/proxy policy and initial response allocation to LiteLLM. Use an
  HTTPS LiteLLM gateway through the direct adapter when those controls must remain inside ForgeWard's
  tested HTTP boundary.
- Sensitive-path filtering and redaction are best-effort controls, not data classification or a
  data-loss-prevention guarantee. Inspect `context preview`, provider policy, and exports.
- v0.1 serializes one builder rather than managing parallel isolated worktrees.
- Builder proposals support create and update only. A correction that needs delete, rename, or rollback
  must abandon the run, clean the worktree deliberately, and start a new engagement; out-of-band edits
  make the current run fail its workspace-integrity check.
- The default 20-call budget fits one full plan correction and one full release correction exactly.
  Further model iterations require a deliberate policy increase or a new run.
- Provider compatibility varies, especially around strict JSON Schema. `provider test` is necessary but
  not a full conformance suite.
- ForgeWard does not install scanners, dependencies, or project commands autonomously.

## Command map

```text
forgeward init [PATH]                  Scaffold firm.yaml and role playbooks
forgeward doctor [--live]             Validate configuration and safety invariants
forgeward context preview             Preview tracked files selected, omitted, or redacted
forgeward plan "OBJECTIVE"            Produce planning evidence and stop at plan gate
forgeward run "OBJECTIVE" [--apply]   Start a full engagement
forgeward resume RUN_ID                Continue from persisted state
forgeward status [RUN_ID] [--json]     Show the run projection
forgeward approve RUN_ID GATE          Record an explicit human approval
forgeward reject RUN_ID GATE --reason  Return work for correction
forgeward inspect RUN_ID               Verify and display artifacts and event ledger
forgeward report RUN_ID                Generate a Markdown engagement report
forgeward export RUN_ID                Create a best-effort redacted evidence ZIP
forgeward provider list|test            Inspect provider routes
forgeward team list|validate            Inspect role boundaries
forgeward policy check                  Evaluate hard policy invariants
```

### Optional Codex team skill

The repository and wheel include `skills/forgeward-team`, a Codex skill that wraps the same CLI
lifecycle without bypassing its gates. From a clone, copy that directory to
`$CODEX_HOME/skills/forgeward-team` (normally `~/.codex/skills/forgeward-team`), restart Codex, and
invoke it explicitly:

```text
Use $forgeward-team to plan this feature, stop at each human gate, and show me the evidence.
```

You can also ask Codex to install the skill directly from the public repository's
`skills/forgeward-team` directory. The skill expects the `forgeward` executable to be installed and
never treats model output as approval.

## Docker

Run the landing page locally:

```bash
docker compose up --build landing
# http://localhost:8080
```

Run the CLI without installing it on the host:

```bash
export FORGEWARD_PROJECT=/absolute/path/to/your/project
export FORGEWARD_UID="$(id -u)" FORGEWARD_GID="$(id -g)"  # Linux bind-mount ownership
docker compose --profile cli run --rm forgeward --help
docker compose --profile cli run --rm forgeward init
docker compose --profile cli run --rm forgeward doctor
```

PowerShell equivalent:

```powershell
$env:FORGEWARD_PROJECT = (Resolve-Path C:\path\to\your\project).Path
docker compose --profile cli run --rm forgeward init
docker compose --profile cli run --rm forgeward doctor
```

On macOS or Windows, set `FORGEWARD_PROJECT` and leave the UID/GID defaults alone. Provider credentials
are not forwarded automatically; pass only the required variable with Compose `-e`. A gateway running
on the host usually needs a `host.docker.internal` base URL from inside the container; because that is
not a loopback hostname, an HTTP-only local gateway also needs explicit `allow_insecure_http: true`.
The stock CLI
image contains ForgeWard, Python, and Git—not your project's scanners or dependencies—so extend the
image or run project checks on the host when they require more tooling.

The bind-mounted CLI is a convenience, not a hardened sandbox. The landing container is read-only,
unprivileged nginx with a health check and security headers.

## Repository map

```text
src/forgeward/                  CLI, provider boundary, policy, state, evidence, orchestration
templates/default/             firm.yaml and role playbooks copied by `forgeward init`
skills/forgeward-team/         reusable Codex skill wrapping the CLI workflow
tests/                         deterministic and adversarial regression tests
docs/                          architecture, threat model, providers, evidence, roadmap
site/                          no-build static landing page and nginx container
.github/workflows/             CI and security automation
```

## Development

```bash
git clone https://github.com/YesterdaysLemon/forgeward.git
cd forgeward
uv sync --extra dev
uv run ruff check .
uv run mypy src/forgeward
uv run pytest --cov=forgeward --cov-report=term-missing
```

The test suite uses a deterministic provider and mocked HTTP. It must not require a real LLM, secret, or
network connection. See [CONTRIBUTING.md](CONTRIBUTING.md) before changing a security boundary.

## Alpha status

The lifecycle, offline demo, OpenAI-compatible text/JSON adapter, safe write broker, checks, gates,
integrity ledger, reports, skill, site, and Docker packaging are usable now. The
[roadmap](docs/roadmap.md) covers SQLite projections, parallel worktrees, SBOM/SARIF integrations,
Open Responses transport, richer tool brokerage, and conformance fixtures.

Please report vulnerabilities privately as described in [SECURITY.md](SECURITY.md). General issues and
pull requests are welcome under the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
