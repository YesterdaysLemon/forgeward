# Evidence pack

> **Status:** alpha format description. Field names and packaging may change before `1.0`. The `0.1` format is tied to the ForgeWard release; an explicit on-disk `schema_version` is roadmap work.

An evidence pack is the local, reviewable record of one ForgeWard engagement. It answers:

- What did the operator ask for?
- Which roles, providers, models, prompts, and policies participated?
- What was proposed and changed?
- Which checks actually ran, and what failed or was skipped?
- What did humans approve or reject?
- Has the recorded history changed since it was written?

An evidence pack is not proof that the software is secure, correct, compliant, or free from model influence. It is evidence about a process, with explicit limits.

## Location and logical contents

Active runs live under `.forgeward/runs/<run-id>/`. The minimum MVP record is:

```text
.forgeward/runs/<run-id>/
├── run.json          # atomically replaced materialized snapshot
├── events.jsonl      # ordered, hash-chained event history
├── artifacts/        # role outputs
└── evidence/         # bounded command/check reports

.forgeward/exports/
└── <run-id>-evidence.zip
```

Reports and exports are derived from that directory. Implementations may add `report.md`, manifests, patches, command-output summaries, or approval views, but they must not create a second contradictory source of truth.

`forgeward inspect RUN_ID` is the detailed local view. `forgeward report RUN_ID` renders a human-oriented summary. `forgeward export RUN_ID` produces a portable ZIP of text records with best-effort secret-pattern redaction; binary files are omitted. That filtering is not data classification and may miss sensitive content. If redaction changes an artifact or event, its original digest or event hash will no longer validate inside the exported derivative. Keep the private run directory as the original record and inspect the ZIP before moving it outside the project's trust boundary. An alpha export is not an integrity attestation.

## `run.json`

`run.json` is a fast, atomically replaced snapshot of the latest engagement state. The `0.1` record contains:

- run identifier, objective, creation/update timestamps, and current lifecycle state;
- selected provider alias and whether applying changes was requested;
- starting Git revision when available;
- provider-call attempt count;
- event count and latest event hash;
- plan and release gate records, including their aggregate evidence digest;
- artifact records, structured findings, human-feedback history, and check results;
- release blockers and the digests of workspace changes applied by the engagement; and
- failure reason when present.

Provider/model-per-artifact provenance, prompt/playbook digests, explicit schema version, and a finding resolution/acceptance model are planned format improvements; consumers must not infer them when absent.

Secrets, authorization headers, plaintext API keys, and unrelated environment variables must never appear. The snapshot is a materialized view: if it disagrees with the event chain or referenced artifact digests, integrity validation fails.

## `events.jsonl`

Each line is one complete JSON object representing a durable event. The `0.1` fields are:

- `seq`, a monotonically increasing sequence number;
- `timestamp`, an ISO-formatted UTC timestamp;
- `type` and `actor` strings;
- `data`, the bounded event-specific object;
- `previous_hash`;
- `projection_sha256`, a checkpoint over the complete semantic `run.json` projection excluding ledger bookkeeping and update time; and
- `hash`.

The run identifier is supplied by the parent directory rather than repeated on every event. State transitions are represented in event data.

The hash is SHA-256 over the UTF-8 JSON representation of the event without its `hash` field, with keys sorted and compact separators. Because `previous_hash` is included, each event binds its predecessor. The reader verifies the sequence, previous hash, claimed hash, final count/head, and latest semantic projection checkpoint against `run.json`.

Typical events include run creation, state transition, role start/finish/failure, artifact recording, provider failure, policy decision, tool result, gate approval/rejection, integrity failure, resume, and completion.

Hash chaining provides tamper evidence for ordinary edits, deletion, reordering, and truncation when a trusted chain head is available. It does not provide immutable storage. Someone who controls every local file can rewrite all events and hashes. The MVP does not remotely anchor the chain or cryptographically sign it.

## Artifacts

Every role output used by a gate is a named artifact. The `0.1` artifact record contains:

- relative `path`;
- SHA-256 digest;
- `author` role;
- `kind`; and
- creation time.

Media type, artifact schema version, provider/model provenance, dependency digests, and explicit artifact status are planned additions. In `0.1`, those properties may be present in artifact content but are not guaranteed by the artifact record.

Expected artifacts include the brief, discovery record, acceptance criteria, UX or architecture design, threat model, plan, proposed patch/change summary, test results, review findings, security findings, release notes, and final handoff.

Do not record “tests passed” as prose alone. A `0.1` check record identifies its name, command argument list, status (`passed`, `failed`, `skipped`, or `error`), exit code when available, duration, output digest, report path, and whether it was required. Tool versions are not yet guaranteed. Missing tools and skipped checks remain visible and cannot be converted to `passed`.

Large raw logs and build products should normally remain outside the pack with a digest and local reference. This limits accidental data exposure and pack growth, but a reference that cannot be resolved later has weaker evidentiary value.

## Approval records

A `0.1` human gate record contains:

- gate ID (`plan` or `release`, corresponding to `PLAN_GATE` and `RELEASE_GATE`);
- decision (`approved` or `rejected`);
- local actor label and decision time;
- reason or comment; and
- `evidence_sha256`, the aggregate recorded evidence digest captured when the gate opens.

A release-role recommendation is a separate artifact and cannot stand in for a human decision. The `0.1` gate digest covers recorded artifact path/SHA/kind entries (excluding reports), check name/status/output SHA/required entries, and applied workspace path/SHA entries. Before approval, ForgeWard verifies the event chain and recomputes every artifact file digest, then recomputes the gate aggregate and rejects stale or tampered evidence. Release approval for an `--apply` engagement also checks Git HEAD and every recorded workspace file digest.

The digest does not yet include the effective policy/configuration, and alpha local files are not immutable. A hostile local writer can replace the executable and rebuild all records. Effective-policy binding and remotely anchored signatures remain hardening work.

In the alpha, the actor label is a local assertion, not a verified human identity or cryptographic signature. Do not use it as a regulated electronic signature.

## Evidence quality

ForgeWard distinguishes these claims:

| Claim | Meaning |
| --- | --- |
| Recorded | The pack contains an artifact or event with a valid digest |
| Executed | A local tool invocation and exit status were recorded |
| Reviewed | A designated role or human produced findings against a bound artifact |
| Approved | A human gate decision exists for the run/gate and matches the gate's aggregate recorded evidence digest |
| Verified | Pack integrity checks and required policy criteria passed |

“Verified” is scoped to declared criteria. It is not a general security guarantee. Model agreement alone cannot upgrade evidence quality.

## Integrity verification

An integrity verifier should:

1. parse every event as a complete JSON object with the required fields;
2. verify order, sequence continuity, previous hash, and event hash;
3. compare the chain count/head and final `projection_sha256` with the complete semantic `run.json` projection;
4. recompute every referenced artifact digest;
5. ensure approvals cover the current dependency digests when the schema supports binding;
6. reject unsupported required-event or schema versions; and
7. surface any failure without attempting model-based repair.

The `0.1` event reader verifies chain hashes, order, final count/head, and the complete semantic projection checkpoint. `resume`, `inspect`, `report`, `export`, and gate decisions also verify every recorded artifact; applied release approval additionally checks Git and workspace digests. Effective-policy binding, event replay into a reconstructed projection, and external anchoring remain hardening targets.

An operator may preserve an exported pack in immutable or access-controlled storage and record its archive digest externally. Signed manifests and provenance attestations are roadmap items.

## Privacy and handling

Packs stay local unless the operator exports or moves them. ForgeWard does not upload packs or send telemetry to its maintainers.

Evidence can still contain confidential code, file names, prompts, model output, vulnerabilities, personal data, and provider identifiers. Secret filtering is best effort and cannot classify all sensitive content. Treat the pack at least as sensitively as the source repository.

Before sharing a pack:

- inspect every included artifact and rendered report;
- remove content only through a recorded, explicit sanitization workflow;
- preserve the original privately if auditability matters;
- never publish live exploit details before coordinated disclosure; and
- state that sanitization changes digests and creates a derivative pack; the `0.1` redacted export does not yet emit a cryptographic redaction manifest.

## Retention and deletion

Retention is operator-controlled. Deleting `.forgeward/runs/<run-id>` deletes the local ForgeWard record but cannot delete copies retained by a model provider, gateway, backup, terminal logger, build tool, or exported archive. Consult those systems independently.

## Schema evolution

The `0.1` files do not yet carry an explicit schema version, so consumers must pin the ForgeWard release that produced the pack. A versioned schema will require readers to reject unsupported required fields or event types and preserve unknown informational fields when copying. Migrations should be explicit and produce a new event or derivative export; they must not silently rewrite historical bytes.

Before `1.0`, breaking alpha migrations are possible and will be called out in release notes. No long-term evidence-format stability is promised yet.
