from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from ipaddress import ip_address
from typing import Iterable


SEVERITY_WEIGHT = {"low": 10, "medium": 30, "high": 55, "critical": 80}


@dataclass(frozen=True)
class MobileFinding:
    rule_id: str
    title: str
    severity: str
    component: str
    evidence: str
    remediation: str
    validation: str
    masvs: str
    attack_id: str | None = None
    internet_reachable: bool = False
    handles_sensitive_data: bool = False
    privileged_component: bool = False

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_WEIGHT:
            raise ValueError(f"unsupported severity: {self.severity}")
        if not self.rule_id.startswith("MOB-"):
            raise ValueError("rule_id must start with MOB-")
        for field_name in ("title", "component", "evidence", "remediation", "validation", "masvs"):
            if not getattr(self, field_name).strip():
                raise ValueError(f"{field_name} is required")

    @property
    def decision_id(self) -> str:
        canonical = "|".join((self.rule_id, self.component, self.evidence, self.severity))
        return sha256(canonical.encode()).hexdigest()[:16]

    @property
    def risk_score(self) -> int:
        score = SEVERITY_WEIGHT[self.severity]
        score += 10 if self.internet_reachable else 0
        score += 10 if self.handles_sensitive_data else 0
        score += 10 if self.privileged_component else 0
        return min(100, score)

    @property
    def risk_band(self) -> str:
        if self.risk_score >= 85:
            return "critical"
        if self.risk_score >= 60:
            return "high"
        if self.risk_score >= 35:
            return "medium"
        return "low"


def prioritize(findings: Iterable[MobileFinding]) -> list[MobileFinding]:
    return sorted(findings, key=lambda finding: (-finding.risk_score, finding.rule_id, finding.component))


def summarize(findings: Iterable[MobileFinding]) -> dict[str, object]:
    items = list(findings)
    bands = {band: 0 for band in ("critical", "high", "medium", "low")}
    for finding in items:
        bands[finding.risk_band] += 1
    return {
        "total": len(items),
        "risk_bands": bands,
        "internet_reachable": sum(item.internet_reachable for item in items),
        "sensitive_data": sum(item.handles_sensitive_data for item in items),
        "attack_mapped": sum(bool(item.attack_id) for item in items),
        "max_score": max((item.risk_score for item in items), default=0),
    }


def validate_endpoint(host: str) -> str:
    """Normalize literal IP evidence while rejecting malformed values."""
    return str(ip_address(host))
