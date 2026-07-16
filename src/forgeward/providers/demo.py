"""Deterministic offline provider used for safe evaluation and demonstrations."""

from __future__ import annotations

import json

from forgeward.models import (
    CompletionRequest,
    CompletionResult,
    Deliverable,
    Finding,
    ProviderConfig,
    Severity,
    Usage,
)


class DemoProvider:
    def __init__(self, config: ProviderConfig) -> None:
        self.config = config

    def probe(self) -> tuple[bool, str]:
        return True, "offline deterministic provider ready"

    def complete(self, request: CompletionRequest) -> CompletionResult:
        role = request.metadata.get("role", "worker")
        objective = request.metadata.get("objective", "the requested change")
        artifact = _artifact_for(role, objective)
        findings: list[Finding] = []
        if role == "security":
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    title="Demo provider cannot inspect implementation semantics",
                    detail=(
                        "Replace the demo provider with an OpenAI-compatible endpoint before "
                        "treating this evidence as a substantive security review."
                    ),
                    evidence="provider=demo",
                )
            )
        deliverable = Deliverable(
            summary=f"{role} completed a deterministic demonstration artifact.",
            artifact=artifact,
            acceptance_criteria=(
                [
                    "The requested behavior is documented.",
                    "Security and failure cases have explicit tests.",
                    "Release evidence is traceable to the approved plan.",
                ]
                if role == "product"
                else []
            ),
            findings=findings,
            proposed_transition="continue",
        )
        content = json.dumps(deliverable.model_dump(mode="json"), ensure_ascii=False)
        return CompletionResult(
            content=content,
            model=self.config.model,
            finish_reason="stop",
            usage=Usage(input_tokens=0, output_tokens=0, total_tokens=0),
        )


def _artifact_for(role: str, objective: str) -> str:
    heading = role.replace("-", " ").title()
    sections: dict[str, str] = {
        "product": (
            "## Problem\nDefine the user and measurable outcome.\n\n"
            "## Acceptance criteria\n- Happy path is observable.\n- Error states are explicit.\n"
            "- Security requirements are testable.\n\n## Non-goals\nRecord scope exclusions."
        ),
        "designer": (
            "## Primary flow\nMap the shortest accessible path to completion.\n\n"
            "## States\nDocument loading, empty, success, error, and recovery states.\n\n"
            "## Accessibility\nKeyboard, focus, contrast, and reduced-motion behavior are required."
        ),
        "security": (
            "## Assets and trust boundaries\nIdentify source, credentials, build outputs, and "
            "provider calls.\n\n"
            "## Abuse cases\nConsider prompt injection, path escape, secret disclosure, "
            "arbitrary execution, "
            "supply-chain compromise, and self-approval.\n\n"
            "## Controls\nUse scoped context, typed outputs, allowlisted tools, independent "
            "review, and "
            "human release approval."
        ),
        "architect": (
            "## Decision\nKeep orchestration deterministic and model workers replaceable.\n\n"
            "## Boundaries\nSeparate provider calls, policy decisions, file writes, and "
            "evidence storage.\n\n"
            "## Failure strategy\nFail closed at gates and retain resumable evidence."
        ),
        "scrum-master": (
            "## Sprint goal\nDeliver the smallest secure vertical slice.\n\n"
            "## Backlog\n1. Confirm acceptance criteria.\n2. Implement the slice.\n"
            "3. Review and test independently.\n4. Assemble release evidence."
        ),
        "builder": (
            "## Build note\nThe offline demo provider never proposes repository writes. "
            "Configure a real "
            "OpenAI-compatible provider and start a new engagement to generate an implementation."
        ),
        "reviewer": (
            "## Review\nCheck the diff against acceptance criteria, architecture decisions, "
            "failure handling, compatibility, and maintainability. No executable diff was "
            "produced in demo mode."
        ),
        "tester": (
            "## Verification\nRun deterministic project checks and preserve redacted output. "
            "Map each "
            "acceptance criterion to at least one test."
        ),
        "release": (
            "## Release decision\nConfirm required checks, unresolved findings, rollback steps, "
            "and final human "
            "approval before shipping."
        ),
    }
    body = sections.get(role, "Produce an evidence-backed contribution within the assigned role.")
    return f"# {heading} artifact\n\n**Objective:** {objective}\n\n{body}\n"
