"""Typed domain models shared by the CLI, engine, and providers."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

__version__ = "0.1.0"


def utc_now() -> datetime:
    return datetime.now(UTC)


class RunState(StrEnum):
    CREATED = "created"
    INTAKE = "intake"
    DISCOVERY = "discovery"
    DESIGN = "design"
    PLAN_GATE = "plan_gate"
    EXECUTION = "execution"
    VERIFICATION = "verification"
    RELEASE_GATE = "release_gate"
    COMPLETE = "complete"
    PAUSED = "paused"
    FAILED = "failed"
    CANCELLED = "cancelled"


class GateDecision(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ProviderCapabilities(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tools: bool = False
    json_schema: bool = True
    streaming: bool = False
    images: bool = False
    reasoning: bool = False


class ProviderConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    adapter: Literal["demo", "openai-compatible", "litellm"] = "demo"
    base_url: str | None = Field(default=None, max_length=2_048)
    model: str = Field(default="forgeward-demo", min_length=1, max_length=500)
    api_key_env: str | None = Field(
        default=None,
        max_length=128,
        pattern=r"^[A-Za-z_][A-Za-z0-9_]*$",
    )
    timeout_seconds: float = Field(default=90, ge=1, le=600)
    allow_insecure_http: bool = False
    max_response_bytes: int = Field(default=2_000_000, ge=1, le=20_000_000)
    enabled: bool = True
    capabilities: ProviderCapabilities = Field(default_factory=ProviderCapabilities)

    @model_validator(mode="after")
    def validate_adapter_settings(self) -> ProviderConfig:
        if self.adapter == "openai-compatible" and not self.base_url:
            raise ValueError("openai-compatible providers require base_url")
        return self


class RoleSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z][a-z0-9-]*$")
    mission: str = Field(min_length=8, max_length=500)
    provider: str | None = None
    prompt: str = Field(min_length=1, max_length=500)
    allowed_tools: list[str] = Field(default_factory=list)
    may_approve: list[str] = Field(default_factory=list)

    @field_validator("allowed_tools")
    @classmethod
    def validate_allowed_tools(cls, value: list[str]) -> list[str]:
        supported = {
            "artifact.read",
            "check.read",
            "diff.read",
            "repository.read",
            "workspace.propose",
        }
        unknown = sorted(set(value) - supported)
        if unknown:
            raise ValueError(f"unsupported role capabilities: {', '.join(unknown)}")
        if len(value) != len(set(value)):
            raise ValueError("role capabilities must be unique")
        return value

    @field_validator("may_approve")
    @classmethod
    def reject_model_approval_authority(cls, value: list[str]) -> list[str]:
        if value:
            raise ValueError("model roles cannot approve gates")
        return value


class CheckSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=80)
    command: list[str] = Field(min_length=1)
    timeout_seconds: int = Field(default=300, ge=1, le=3600)
    required: bool = True

    @field_validator("command")
    @classmethod
    def reject_empty_arguments(cls, value: list[str]) -> list[str]:
        if any(not part or "\x00" in part for part in value):
            raise ValueError("command arguments must be non-empty and contain no NUL bytes")
        return value


class PolicyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    human_gates: list[str] = Field(default_factory=lambda: ["plan", "release"])
    denied_paths: list[str] = Field(default_factory=lambda: [".git", ".forgeward", ".env", ".ssh"])
    allowed_executables: list[str] = Field(
        default_factory=lambda: ["python", "python3", "pytest", "ruff", "npm", "pnpm", "uv"]
    )
    check_env_allowlist: list[str] = Field(
        default_factory=lambda: [
            "PATH",
            "SYSTEMROOT",
            "WINDIR",
            "COMSPEC",
            "PATHEXT",
            "TEMP",
            "TMP",
            "TMPDIR",
            "USERPROFILE",
            "HOME",
            "LANG",
            "LC_ALL",
            "TERM",
            "CI",
            "VIRTUAL_ENV",
        ]
    )
    max_context_files: int = Field(default=24, ge=1, le=200)
    max_context_bytes: int = Field(default=120_000, ge=1_000, le=2_000_000)
    max_file_bytes: int = Field(default=250_000, ge=1_000, le=2_000_000)
    max_output_chars: int = Field(default=40_000, ge=1_000, le=1_000_000)
    max_provider_calls: int = Field(default=20, ge=1, le=100)
    fail_on_severity: Severity = Severity.HIGH
    telemetry: bool = False

    @field_validator("human_gates")
    @classmethod
    def validate_human_gates(cls, value: list[str]) -> list[str]:
        unknown = sorted(set(value) - {"plan", "release"})
        if unknown:
            raise ValueError(f"unknown human gates: {', '.join(unknown)}")
        if len(value) != len(set(value)):
            raise ValueError("human gates must be unique")
        return value

    @field_validator("denied_paths")
    @classmethod
    def require_protected_roots(cls, value: list[str]) -> list[str]:
        normalized = {
            "/".join(part for part in item.replace("\\", "/").split("/") if part != ".")
            .strip("/")
            .casefold()
            for item in value
        }
        missing = sorted({".env", ".forgeward", ".git"} - normalized)
        if missing:
            raise ValueError("denied_paths must protect: " + ", ".join(missing))
        return value


class WorkflowConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    plan_roles: list[str] = Field(
        default_factory=lambda: ["product", "designer", "security", "architect", "scrum-master"],
        min_length=1,
    )
    build_role: str = "builder"
    verification_roles: list[str] = Field(
        default_factory=lambda: ["reviewer", "tester", "security"]
    )
    release_role: str = "release"


class ProjectConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = "my-project"
    default_provider: str = "demo"


class ForgeWardConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = 1
    project: ProjectConfig = Field(default_factory=ProjectConfig)
    providers: dict[str, ProviderConfig]
    team: list[RoleSpec]
    workflow: WorkflowConfig = Field(default_factory=WorkflowConfig)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    checks: list[CheckSpec] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_references(self) -> ForgeWardConfig:
        role_ids = [role.id for role in self.team]
        if len(role_ids) != len(set(role_ids)):
            raise ValueError("team role ids must be unique")
        if self.project.default_provider not in self.providers:
            raise ValueError("project.default_provider does not exist in providers")
        for role in self.team:
            if role.provider and role.provider not in self.providers:
                raise ValueError(f"role {role.id!r} references an unknown provider")
        referenced = [
            *self.workflow.plan_roles,
            self.workflow.build_role,
            *self.workflow.verification_roles,
            self.workflow.release_role,
        ]
        missing = sorted(set(referenced) - set(role_ids))
        if missing:
            raise ValueError(f"workflow references missing roles: {', '.join(missing)}")
        for label, roles in (
            ("workflow.plan_roles", self.workflow.plan_roles),
            ("workflow.verification_roles", self.workflow.verification_roles),
        ):
            if len(roles) != len(set(roles)):
                raise ValueError(f"{label} must not contain duplicate roles")
        builder = next(role for role in self.team if role.id == self.workflow.build_role)
        required_builder_capabilities = {"artifact.read", "diff.read", "workspace.propose"}
        missing_builder_capabilities = sorted(
            required_builder_capabilities - set(builder.allowed_tools)
        )
        if missing_builder_capabilities:
            raise ValueError(
                "workflow.build_role lacks required evidence capabilities: "
                + ", ".join(missing_builder_capabilities)
            )
        unauthorized_proposers = sorted(
            role.id
            for role in self.team
            if role.id != builder.id and "workspace.propose" in role.allowed_tools
        )
        if unauthorized_proposers:
            raise ValueError(
                "workspace.propose is reserved for workflow.build_role: "
                + ", ".join(unauthorized_proposers)
            )
        role_map = {role.id: role for role in self.team}
        for role_id in self.workflow.plan_roles:
            if "artifact.read" not in role_map[role_id].allowed_tools:
                raise ValueError(
                    f"planning role {role_id!r} requires artifact.read for corrective feedback"
                )
        required_review_capabilities = {"artifact.read", "check.read", "diff.read"}
        for role_id in [*self.workflow.verification_roles, self.workflow.release_role]:
            missing_capabilities = sorted(
                required_review_capabilities - set(role_map[role_id].allowed_tools)
            )
            if missing_capabilities:
                raise ValueError(
                    f"review role {role_id!r} lacks required evidence capabilities: "
                    + ", ".join(missing_capabilities)
                )
        return self

    def role(self, role_id: str) -> RoleSpec:
        for role in self.team:
            if role.id == role_id:
                return role
        raise KeyError(role_id)


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    severity: Severity
    title: str = Field(min_length=1, max_length=160)
    detail: str = Field(min_length=1, max_length=10_000)
    evidence: str | None = Field(default=None, max_length=2_000)


class RecordedFinding(Finding):
    role: str = Field(min_length=1, max_length=100)
    provider: str = Field(min_length=1, max_length=100)
    model: str = Field(min_length=1, max_length=500)
    artifact_path: str = Field(min_length=1, max_length=1_000)
    recorded_at: datetime = Field(default_factory=utc_now)


class HumanFeedbackRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    gate: str
    reason: str = Field(min_length=1, max_length=4_000)
    actor: str = Field(min_length=1, max_length=200)
    artifact_path: str
    recorded_at: datetime = Field(default_factory=utc_now)


class ProposedChange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operation: Literal["create", "update"]
    path: str = Field(min_length=1, max_length=500)
    content: str = Field(max_length=1_000_000)
    rationale: str = Field(min_length=1, max_length=2_000)

    @field_validator("path")
    @classmethod
    def normalize_path(cls, value: str) -> str:
        normalized = value.replace("\\", "/").strip()
        if normalized.startswith("/") or "\x00" in normalized:
            raise ValueError("change paths must be relative and contain no NUL bytes")
        return normalized


class Deliverable(BaseModel):
    """Strict shape every model worker must return."""

    model_config = ConfigDict(extra="forbid")

    summary: str = Field(min_length=1, max_length=2_000)
    artifact: str = Field(min_length=1, max_length=200_000)
    acceptance_criteria: list[str] = Field(default_factory=list, max_length=50)
    proposed_changes: list[ProposedChange] = Field(default_factory=list, max_length=100)
    findings: list[Finding] = Field(default_factory=list, max_length=100)
    proposed_transition: str | None = Field(default=None, max_length=80)

    @field_validator("acceptance_criteria")
    @classmethod
    def validate_acceptance_criteria(cls, value: list[str]) -> list[str]:
        if any(not item.strip() or len(item) > 2_000 for item in value):
            raise ValueError("acceptance criteria must contain 1 to 2000 non-whitespace characters")
        return value


class Usage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    input_tokens: int = Field(default=0, ge=0, le=1_000_000_000_000_000)
    output_tokens: int = Field(default=0, ge=0, le=1_000_000_000_000_000)
    total_tokens: int = Field(default=0, ge=0, le=1_000_000_000_000_000)


class CompletionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content: str
    model: str = Field(min_length=1, max_length=500)
    finish_reason: str | None = Field(default=None, max_length=100)
    usage: Usage = Field(default_factory=Usage)


class ChatMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Literal["system", "developer", "user", "assistant", "tool"]
    content: str = Field(max_length=3_000_000)


class CompletionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    model: str = Field(min_length=1, max_length=500)
    messages: list[ChatMessage] = Field(max_length=64)
    response_schema: dict[str, Any] | None = None
    temperature: float = Field(default=0.2, ge=0, le=2)
    max_tokens: int = Field(default=4_096, ge=1, le=128_000)
    metadata: dict[str, str] = Field(default_factory=dict, max_length=32)

    @field_validator("metadata")
    @classmethod
    def bound_metadata(cls, value: dict[str, str]) -> dict[str, str]:
        if any(not key or len(key) > 100 for key in value):
            raise ValueError("request metadata keys must contain 1 to 100 characters")
        if any(len(item) > 20_000 for item in value.values()):
            raise ValueError("request metadata values must not exceed 20000 characters")
        return value


class GateRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    decision: GateDecision = GateDecision.PENDING
    actor: str | None = Field(default=None, max_length=200)
    reason: str | None = None
    decided_at: datetime | None = None
    evidence_sha256: str | None = None


class ArtifactRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    sha256: str
    author: str
    kind: str
    created_at: datetime = Field(default_factory=utc_now)


class CheckResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    command: list[str]
    status: Literal["passed", "failed", "skipped", "error"]
    exit_code: int | None = None
    duration_seconds: float = 0
    output_sha256: str | None = None
    report_path: str | None = None
    required: bool = True


class RunRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    objective: str = Field(min_length=1, max_length=20_000)
    state: RunState = RunState.CREATED
    provider: str
    apply_changes: bool = False
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    base_commit: str | None = None
    calls_made: int = 0
    event_count: int = 0
    last_event_hash: str | None = None
    gates: dict[str, GateRecord] = Field(default_factory=dict)
    artifacts: list[ArtifactRecord] = Field(default_factory=list)
    checks: list[CheckResult] = Field(default_factory=list)
    findings: list[RecordedFinding] = Field(default_factory=list)
    feedback: list[HumanFeedbackRecord] = Field(default_factory=list)
    blockers: list[str] = Field(default_factory=list)
    workspace_changes: dict[str, str] = Field(default_factory=dict)
    failure: str | None = None
