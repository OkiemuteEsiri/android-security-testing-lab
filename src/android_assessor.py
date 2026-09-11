from __future__ import annotations

import json
from pathlib import Path

from .risk_engine import MobileFinding


REQUIRED_KEYS = {
    "package",
    "release_build",
    "debuggable",
    "allow_backup",
    "uses_cleartext_traffic",
    "target_sdk",
    "min_target_sdk",
    "exported_components",
    "permissions",
    "network_security_config",
    "signing",
    "data_handling",
}

HIGH_RISK_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.READ_CONTACTS",
}


def load_app(path: str | Path) -> dict:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    missing = REQUIRED_KEYS - raw.keys()
    if missing:
        raise ValueError(f"missing required keys: {sorted(missing)}")
    if not isinstance(raw["exported_components"], list) or not isinstance(raw["permissions"], list):
        raise ValueError("exported_components and permissions must be arrays")
    return raw


def assess_app(app: dict) -> list[MobileFinding]:
    findings: list[MobileFinding] = []

    def add(**kwargs) -> None:
        findings.append(MobileFinding(**kwargs))

    if app["release_build"] and app["debuggable"]:
        add(rule_id="MOB-001", title="Release build is debuggable", severity="high", component="AndroidManifest.xml",
            evidence="android:debuggable=true in release metadata", remediation="Disable debugging for release variants.",
            validation="Rebuild release metadata and confirm debuggable=false.", masvs="MASVS-RESILIENCE", attack_id="T1629")

    if app["uses_cleartext_traffic"]:
        add(rule_id="MOB-002", title="Cleartext transport permitted", severity="high", component="network policy",
            evidence="usesCleartextTraffic=true", remediation="Disable cleartext traffic and explicitly scope any development exceptions.",
            validation="Confirm release policy rejects HTTP endpoints and TLS-only paths remain functional.", masvs="MASVS-NETWORK",
            attack_id="T1439", internet_reachable=True, handles_sensitive_data=bool(app["data_handling"].get("sensitive")))

    for component in app["exported_components"]:
        if component.get("exported") and not component.get("business_required"):
            add(rule_id="MOB-003", title="Unnecessary exported component", severity="high", component=component.get("name", "unknown"),
                evidence="component exported without documented business requirement", remediation="Set exported=false or document and enforce a narrow authorization boundary.",
                validation="Re-run static review and verify external invocation is no longer part of the release contract.", masvs="MASVS-PLATFORM",
                attack_id="T1474", internet_reachable=bool(component.get("deep_link")), privileged_component=bool(component.get("privileged")))

    if app["allow_backup"]:
        add(rule_id="MOB-004", title="Application backup enabled", severity="medium", component="AndroidManifest.xml",
            evidence="allowBackup=true", remediation="Disable backup for sensitive applications or explicitly exclude sensitive data.",
            validation="Inspect release backup policy and confirm sensitive stores are excluded.", masvs="MASVS-STORAGE",
            handles_sensitive_data=bool(app["data_handling"].get("sensitive")))

    if int(app["target_sdk"]) < int(app["min_target_sdk"]):
        add(rule_id="MOB-005", title="Target SDK below security baseline", severity="medium", component="build configuration",
            evidence=f"targetSdk={app['target_sdk']} baseline={app['min_target_sdk']}", remediation="Upgrade target SDK and regression-test platform behavior changes.",
            validation="Confirm target SDK meets the declared baseline in the release artifact.", masvs="MASVS-CODE")

    declared = set(app["permissions"])
    unjustified = sorted(HIGH_RISK_PERMISSIONS & declared - set(app.get("justified_permissions", [])))
    for permission in unjustified:
        add(rule_id="MOB-006", title="High-risk permission lacks justification", severity="medium", component=permission,
            evidence="permission present without mapped capability", remediation="Remove the permission or document least-privilege necessity and runtime controls.",
            validation="Re-run review and confirm the permission is removed or explicitly justified.", masvs="MASVS-PRIVACY")

    net = app["network_security_config"]
    if net.get("trust_user_cas"):
        add(rule_id="MOB-007", title="Release policy trusts user-added CAs", severity="high", component="network-security-config",
            evidence="user certificate authorities trusted", remediation="Restrict release trust anchors to intended CA stores unless the business case requires otherwise.",
            validation="Confirm release trust anchors exclude user CAs and regression-test approved endpoints.", masvs="MASVS-NETWORK",
            attack_id="T1439", handles_sensitive_data=bool(app["data_handling"].get("sensitive")))

    signing = app["signing"]
    if signing.get("algorithm") in {"SHA1withRSA", "MD5withRSA"} or int(signing.get("key_bits", 0)) < 2048:
        add(rule_id="MOB-008", title="Weak signing metadata", severity="high", component="release signing",
            evidence=f"algorithm={signing.get('algorithm')} key_bits={signing.get('key_bits')}", remediation="Use a modern signing algorithm and appropriately sized key under controlled release signing.",
            validation="Verify signing metadata against the release policy without exposing private key material.", masvs="MASVS-RESILIENCE")

    return findings
