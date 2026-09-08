# Android Security Testing Lab

A defensive mobile-application security engineering project focused on **safe static review** of Android application configuration and security posture. The lab evaluates synthetic manifest/configuration data for common weaknesses without interacting with real devices, production applications, credentials, or third-party services.

## Objectives

- Convert mobile security requirements into repeatable checks.
- Identify insecure application configuration before release.
- Produce remediation and validation criteria that developers can act on.
- Demonstrate OWASP MASVS-aligned thinking without unsafe exploitation.

## Architecture

`synthetic app metadata -> static policy checks -> normalized findings -> severity summary -> remediation validation`

## Implemented checks

| ID | Area | Check |
|---|---|---|
| MOB-001 | Platform | Application is not debuggable in release configuration |
| MOB-002 | Network | Cleartext traffic is disabled |
| MOB-003 | Components | Exported components have an explicit business requirement |
| MOB-004 | Backup | Backup behavior is explicitly controlled |
| MOB-005 | SDK | Target SDK meets the lab baseline |
| MOB-006 | Permissions | High-risk permissions are reviewed against declared capabilities |

## Run

```bash
python -m src.mobile_review data/synthetic_app.json
```

## Tests

```bash
python -m unittest discover -s tests -v
```

## Methodology

The lab models a release-gate review. It does not decompile or instrument third-party software. Findings are based solely on synthetic metadata and are treated as **security review signals**, not proof of exploitability.

## Risk model

- **High:** configuration can materially weaken trust boundaries or expose application functionality.
- **Medium:** configuration expands attack surface or weakens platform protections.
- **Low:** hardening or governance gap with limited direct security impact.

## Remediation workflow

Each finding includes affected configuration, rationale, remediation, and validation criteria. A finding is closed only after the configuration is updated and re-evaluated against the same deterministic rule.

## Framework alignment

The project uses concepts consistent with OWASP Mobile Application Security Verification Standard categories such as platform interaction, network communication, storage/privacy, and resilience. It is not represented as formal MASVS certification.

## Skills demonstrated

Mobile application security, Android configuration review, secure SDLC, Python automation, policy-as-code, risk classification, developer remediation guidance, unit testing, and release validation.

## Safety

All application metadata is fictional. No APK exploitation, credential harvesting, bypass instructions, production targets, or confidential data are included.

## Roadmap

- Add Network Security Configuration review.
- Add synthetic signing-policy metadata.
- Add SBOM/dependency risk ingestion.
- Add SARIF-style output for CI integration.
- Add CI workflow and policy regression tests.
