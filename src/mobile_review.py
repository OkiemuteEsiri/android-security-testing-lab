import json
import sys
from dataclasses import dataclass, asdict
from pathlib import Path

@dataclass
class Finding:
    check_id: str
    title: str
    status: str
    severity: str
    evidence: str
    remediation: str
    validation: str

HIGH_RISK_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
}


def review(app: dict) -> list[Finding]:
    findings: list[Finding] = []

    debuggable = bool(app.get("debuggable"))
    findings.append(Finding(
        "MOB-001", "Release build is not debuggable", "FAIL" if debuggable else "PASS", "high",
        f"debuggable={debuggable}",
        "Disable debuggable for release builds and enforce this in the build pipeline.",
        "Re-read release metadata and confirm debuggable=false."
    ))

    cleartext = bool(app.get("uses_cleartext_traffic"))
    findings.append(Finding(
        "MOB-002", "Cleartext traffic disabled", "FAIL" if cleartext else "PASS", "high",
        f"uses_cleartext_traffic={cleartext}",
        "Disable cleartext traffic and use approved TLS endpoints.",
        "Confirm release configuration rejects cleartext transport."
    ))

    exported_without_reason = [c["name"] for c in app.get("components", []) if c.get("exported") and not c.get("business_required")]
    findings.append(Finding(
        "MOB-003", "Exported components justified", "FAIL" if exported_without_reason else "PASS", "high",
        f"unjustified_exported_components={exported_without_reason}",
        "Set exported=false unless external invocation is required; protect required exported components with appropriate controls.",
        "Re-review the manifest and verify each exported component has an approved requirement."
    ))

    backup = app.get("allow_backup")
    findings.append(Finding(
        "MOB-004", "Backup behavior explicitly controlled", "PASS" if backup is False else "FAIL", "medium",
        f"allow_backup={backup}",
        "Explicitly disable application backup unless the data model and business requirement justify it.",
        "Confirm the release manifest explicitly sets the intended backup policy."
    ))

    target_sdk = int(app.get("target_sdk", 0))
    findings.append(Finding(
        "MOB-005", "Target SDK meets lab baseline", "PASS" if target_sdk >= 35 else "FAIL", "medium",
        f"target_sdk={target_sdk}",
        "Upgrade the target SDK through normal compatibility testing and release governance.",
        "Confirm the built release artifact reports the approved target SDK."
    ))

    declared = set(app.get("permissions", []))
    risky = sorted(declared & HIGH_RISK_PERMISSIONS)
    justified = set(app.get("justified_permissions", []))
    unjustified = [p for p in risky if p not in justified]
    findings.append(Finding(
        "MOB-006", "High-risk permissions justified", "FAIL" if unjustified else "PASS", "medium",
        f"unjustified_high_risk_permissions={unjustified}",
        "Remove unnecessary permissions or document and approve the capability requiring them.",
        "Re-evaluate declared permissions and confirm every high-risk permission maps to an approved feature."
    ))

    return findings


def summarize(findings: list[Finding]) -> dict:
    return {
        "total": len(findings),
        "failed": sum(1 for f in findings if f.status == "FAIL"),
        "high_failed": sum(1 for f in findings if f.status == "FAIL" and f.severity == "high"),
        "findings": [asdict(f) for f in findings]
    }


def main(path: str) -> None:
    app = json.loads(Path(path).read_text())
    print(json.dumps(summarize(review(app)), indent=2))

if __name__ == "__main__":
    main(sys.argv[1])
