"""Synthetic authentication identities and explicit resource/action authorization policy."""

from dataclasses import asdict, dataclass, field
from enum import Enum

from app.reporting.redaction import RedactionEngine


class AuthenticationKind(str, Enum):
    ANONYMOUS = "anonymous"
    TEST_USER = "test_user"
    PRIVILEGED_TEST_USER = "privileged_test_user"


@dataclass(frozen=True)
class Actor:
    id: str
    role: str
    tenant: str


@dataclass
class AuthenticationContext:
    kind: AuthenticationKind = AuthenticationKind.ANONYMOUS
    actor: Actor = field(default_factory=lambda: Actor("anonymous", "anonymous", ""))
    session: str = field(default="", repr=False)
    cookie: dict = field(default_factory=dict, repr=False)
    token: str = field(default="", repr=False)
    owned_resources: tuple[str, ...] = ()

    @property
    def role(self):
        return self.actor.role

    def to_dict(self):
        return RedactionEngine.redact_dict(asdict(self))

    def headers(self):
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}


@dataclass(frozen=True)
class Resource:
    id: str
    owner: str
    tenant: str
    private_marker: str
    required_role: str = ""
    public: bool = False


@dataclass(frozen=True)
class AuthorizationCase:
    actor: Actor
    owner: Actor
    resource: Resource
    action: str = "read"

    @property
    def expected_result(self):
        if self.resource.public:
            return "ALLOW"
        if self.actor.tenant != self.resource.tenant:
            return "DENY"
        if self.resource.required_role:
            return "ALLOW" if self.actor.role == self.resource.required_role else "DENY"
        return "ALLOW" if self.actor.id == self.resource.owner else "DENY"

    def evaluate(self, context):
        from app.validation.evidence.typed_evidence import Evidence, EvidenceType
        from app.validation.validators.collected import Decision, private_content, repeated

        baseline, control, test, repeat = repeated(context)
        owner_identity, actor_identity = context.require("owner_identity", "actor_identity")
        checks = (
            "Owner and actor sessions verified",
            "Resource identity and private marker checked",
            "Explicit action/role/tenant policy compared",
            "Public/self access excluded",
        )
        if self.action != "read":
            return Decision(
                "INCONCLUSIVE", "Mutation actions require a state-change validator", checks
            )
        for exchange, identity in ((owner_identity, self.owner), (actor_identity, self.actor)):
            if exchange.json() != {
                "subject": identity.id,
                "role": identity.role,
                "tenant": identity.tenant,
            }:
                return Decision(
                    "INCONCLUSIVE",
                    "Captured session identity disagrees with configured actor",
                    checks,
                )
        if (
            baseline.actor != self.owner.id
            or test.actor != self.actor.id
            or repeat.actor != self.actor.id
        ):
            return Decision("INCONCLUSIVE", "Actor provenance missing or inconsistent", checks)
        if test.sent_header("authorization") != actor_identity.sent_header("authorization"):
            return Decision(
                "INCONCLUSIVE", "Resource probe does not use the verified actor session", checks
            )
        if baseline.sent_header("authorization") != owner_identity.sent_header("authorization"):
            return Decision(
                "INCONCLUSIVE", "Baseline does not use the verified owner session", checks
            )
        if self.expected_result == "ALLOW":
            return Decision(
                "NOT_VULNERABLE",
                "Access is allowed by the configured public/owner/role policy",
                checks,
            )
        resource = asdict(self.resource)
        if not private_content(baseline, resource) or control.status not in {401, 403}:
            return Decision(
                "INCONCLUSIVE", "Private resource baseline/anonymous control missing", checks
            )
        accessed = private_content(test, resource) and private_content(repeat, resource)
        context.add_observation(
            Evidence(
                EvidenceType.AUTHORIZATION_CONTEXT,
                "Authorization matrix comparison",
                "Expected policy compared with captured resource access",
                data={
                    "actor": self.actor.id,
                    "role": self.actor.role,
                    "tenant": self.actor.tenant,
                    "owner": self.owner.id,
                    "resource": self.resource.id,
                    "action": self.action,
                    "expected_result": self.expected_result,
                    "actual_result": "ACCESS" if accessed else "NO_ACCESS",
                    "evidence_ids": [
                        baseline.id,
                        control.id,
                        test.id,
                        repeat.id,
                        owner_identity.id,
                        actor_identity.id,
                    ],
                },
                asset=context.target,
                relevance=1,
                confidence=1,
            )
        )
        if accessed:
            return Decision(
                "CONFIRMED",
                "Verified non-owner/role/tenant session repeatedly accessed a private resource contrary to policy",
                checks,
            )
        return Decision(
            "NOT_VULNERABLE", "Private resource was not returned to the unauthorized actor", checks
        )
