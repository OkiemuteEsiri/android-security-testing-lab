from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256


@dataclass(frozen=True)
class RemediationEvidence:
    finding_id: str
    owner: str
    change_reference: str
    configuration_before: str
    configuration_after: str
    validation_method: str
    validation_result: str
    release_build_verified: bool

    def __post_init__(self) -> None:
        if not self.finding_id or not self.owner:
            raise ValueError("finding_id and owner are required")

    @property
    def evidence_id(self) -> str:
        material = "|".join((self.finding_id, self.owner, self.change_reference, self.configuration_after, self.validation_result))
        return sha256(material.encode()).hexdigest()[:16]


def validate_remediation(evidence: RemediationEvidence) -> tuple[str, list[str]]:
    missing: list[str] = []
    if not evidence.change_reference.strip():
        missing.append("change_reference")
    if not evidence.configuration_before.strip():
        missing.append("configuration_before")
    if not evidence.configuration_after.strip():
        missing.append("configuration_after")
    if evidence.configuration_before == evidence.configuration_after:
        missing.append("control_state_change")
    if not evidence.validation_method.strip():
        missing.append("validation_method")
    if evidence.validation_result.lower() not in {"pass", "passed", "effective"}:
        missing.append("effective_validation")
    if not evidence.release_build_verified:
        missing.append("release_build_verified")

    if missing:
        return "needs_evidence", missing
    return "validated", []
