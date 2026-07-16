# ForgeWard lifecycle reference

The deterministic lifecycle is:

`created → intake → discovery → design → plan gate → execution → verification → release gate → complete`

- Plan rejection returns the engagement to intake and reruns every planning role with the human
  feedback as required evidence.
- Release rejection returns it to execution and then verification.
- Provider errors leave the current phase resumable; investigate the error before retrying.
- A provider-call budget exhaustion is a hard stop until the configuration or objective changes.
- `--apply` proposals may create or update regular files inside the project root only. Protected paths,
  traversal, symlinks/reparse points, canonical aliases, Windows device names, oversized files, and
  operations inconsistent with current file existence fail closed.
- Checks are configured argv arrays, must use an allowlisted executable, and run without a shell.
- The run projection is `.forgeward/runs/<run-id>/run.json`; the append-only hash-chained audit trail is
  `events.jsonl`; role work and evidence live under `artifacts/`.

At each gate, base the summary on those artifacts and deterministic check records—not on a worker's
claim. A completed demo-provider run proves only orchestration behavior.
