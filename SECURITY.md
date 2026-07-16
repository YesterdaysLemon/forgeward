# Security policy

ForgeWard is alpha software. It coordinates probabilistic, potentially adversarial model output and may operate on source code. It has not completed an independent security audit and should not be given production credentials or unsupervised access to sensitive repositories, networks, deployment systems, or data.

## Supported versions

Until the first stable release, security fixes are made on a best-effort basis for the current `main` branch only. There is no long-term support policy yet.

| Version | Supported |
| --- | --- |
| Current `main` | Best effort |
| Tagged alpha releases | Upgrade to current `main` or the latest release |
| Forks and modified distributions | Maintained by their distributors |

## Report a vulnerability privately

Use **Security → Report a vulnerability** in this GitHub repository to open a private vulnerability report. If private vulnerability reporting is not available, contact a maintainer privately through the contact method on their GitHub profile and ask for a secure reporting channel.

Do not include secrets, personal data, exploit payloads against third parties, or sensitive repository contents. Please include:

- the affected commit or release;
- the operating system and installation method;
- a minimal reproduction or proof of concept;
- expected and observed behavior;
- the security impact and required preconditions; and
- any mitigation you have already tested.

Do not open a public issue for an undisclosed vulnerability. We aim to acknowledge a complete report within five business days, but this community project cannot promise a response or remediation SLA.

## In scope

Examples include:

- bypassing a human approval gate or command policy;
- escaping an advertised workspace or process boundary;
- exposing credentials through logs, prompts, evidence packs, or error messages;
- executing model-produced tool calls without the documented validation;
- tampering with an engagement's recorded evidence without detection;
- unsafe defaults that permit an unapproved merge, push, release, or deployment; and
- vulnerabilities in a bundled dependency or container configuration that materially affect ForgeWard users.

Provider outages, provider-side data retention, model behavior by itself, and vulnerabilities in third-party gateways are normally out of scope. A ForgeWard integration flaw that makes one of those issues exploitable is in scope.

## Disclosure process

Maintainers will validate the report, agree on a disclosure plan where practical, develop a fix, and credit the reporter if requested. Please allow a reasonable remediation window before publishing details. If you believe users face active exploitation or immediate harm, say so prominently in the report.

## Security expectations for operators

- Treat every LLM response, retrieved document, issue, test log, and repository file as untrusted input.
- Start in a disposable branch or clone and review all changes before integration.
- Give ForgeWard and each provider the least privilege needed for one engagement.
- Keep deployment credentials and unrelated secrets outside the working process.
- Review the selected provider's retention, training, region, and logging policies before sending code.
- Require human approval for privileged commands and for release. Alpha releases do not support safe unattended deployment.
- Use operating-system or container isolation when handling hostile repositories. ForgeWard policy checks are defense in depth, not a sandbox.

ForgeWard has no telemetry: it does not send product analytics, crash reports, or engagement artifacts to its maintainers. Model requests are intentional outbound network traffic to the endpoint you configure; that provider or gateway may log or retain them. See [the threat model](docs/threat-model.md) for trust boundaries and residual risks.
