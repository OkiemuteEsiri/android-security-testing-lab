# Android Security Testing Lab

A recruiter-facing **mobile application security engineering** project that turns Android release metadata into deterministic security findings, contextual risk scores, remediation guidance, and evidence-based closure decisions. All data is synthetic and the workflow is deliberately offline and defensive.

## Problem statement

Mobile security reviews often degrade into one-off checklists. This lab demonstrates how a security engineer can convert release requirements into repeatable policy-as-code, preserve evidence, prioritize findings consistently, and validate remediation without claiming exploitability that has not been demonstrated.

## Architecture

```text
synthetic release metadata
        |
        v
fail-closed input validation
        |
        v
Android control assessment
        |
        v
contextual 0-100 risk engine
        |
        +--> prioritized CLI output
        +--> recruiter-readable Markdown report
        |
        v
remediation evidence validator
        |
        v
repeat release-build validation
```

Core modules:

- `src/android_assessor.py` — Android configuration and release-policy checks.
- `src/risk_engine.py` — immutable findings, deterministic IDs, risk scoring and portfolio metrics.
- `src/remediation_validator.py` — evidence requirements for defensible finding closure.
- `src/report.py` — executive and technical Markdown reporting.
- `src/cli.py` — offline command-line entry point.
- `src/mobile_review.py` — original lightweight review engine retained for comparison/regression history.

## Implemented controls

| Rule | Domain | Security intent |
|---|---|---|
| MOB-001 | Release hardening | Debugging disabled in release variants |
| MOB-002 | Network | Cleartext transport prohibited |
| MOB-003 | Platform | Exported components require explicit business justification |
| MOB-004 | Storage | Backup behavior explicitly controlled |
| MOB-005 | Platform | Target SDK meets the declared baseline |
| MOB-006 | Privacy | High-risk permissions mapped to legitimate capabilities |
| MOB-007 | Network | Release trust anchors avoid user-added CAs unless justified |
| MOB-008 | Integrity | Release signing metadata meets minimum policy |

## Risk model

The engine starts with a severity weight and adds contextual modifiers for:

- internet reachability;
- sensitive-data handling;
- privileged Android components.

Scores are capped at **100** and translated to critical/high/medium/low priority bands. The score is transparent and deterministic; it is a triage aid rather than a substitute for CVSS or a formal mobile threat model.

## Run

```bash
python -m src.cli data/synthetic_release_app.json
python -m src.cli data/synthetic_release_app.json --report reports/generated-assessment.md
```

The legacy baseline remains available:

```bash
python -m src.mobile_review data/synthetic_app.json
```

## Tests

```bash
python -m unittest discover -s tests -v
```

The test suite covers release-data validation, cleartext/sensitive-data context, exported privileged components, permission justification, signing posture, deterministic decision IDs, score bounds, prioritization, summary metrics, report rendering, and remediation-evidence validation.

## Remediation and validation workflow

A finding is not considered closed simply because a ticket says "fixed." The validator requires:

1. accountable owner;
2. change reference;
3. before/after control state;
4. an actual state change;
5. repeatable validation method;
6. effective validation result;
7. verification against the release build.

See `docs/architecture-methodology.md` and `docs/remediation-validation.md`.

## Framework mapping

The project uses OWASP MASVS concepts across platform interaction, network communication, storage, privacy, code quality and resilience. It does **not** claim formal MASVS certification.

Relevant MITRE ATT&CK Mobile mappings are used only as threat-model context where helpful. They do not assert that adversary activity occurred.

## Repository structure

```text
.github/workflows/tests.yml
data/
  synthetic_app.json
  synthetic_release_app.json
docs/
  architecture-methodology.md
  remediation-validation.md
reports/
  example-assessment.md
src/
  android_assessor.py
  cli.py
  mobile_review.py
  remediation_validator.py
  report.py
  risk_engine.py
tests/
  test_android_assessor.py
  test_mobile_review.py
```

## Design decisions

- **Offline by default:** no live app, device, account, API, or production access is required.
- **Fail closed:** malformed or incomplete assessment inputs raise errors rather than silently producing misleading results.
- **Deterministic findings:** decision IDs derive from stable finding evidence for auditability.
- **Evidence before closure:** remediation status depends on observable control-state change and validation.
- **No fabricated exploitability:** configuration weaknesses are security-review signals, not proof of compromise.

## Skills demonstrated

Android security review, mobile AppSec, OWASP MASVS interpretation, policy-as-code, Python automation, security data modeling, deterministic risk prioritization, remediation governance, secure SDLC integration, unit testing, CI/CD security controls, technical reporting, and threat-informed analysis.

## Limitations

This project does not decompile APKs, hook processes, intercept traffic, bypass certificate pinning, test authentication, execute payloads, or inspect production applications. Synthetic metadata cannot prove runtime behavior. Runtime authorization, WebView security, cryptographic implementation, native code, dependency risk and device-specific behavior require additional validated approaches.

## CI/CD

GitHub Actions runs the Python unit-test suite using least-privilege `contents: read`. CI results should be treated as authoritative only after the workflow for the specific commit completes successfully.

## Roadmap

- Add SARIF output for code-scanning ingestion.
- Add SBOM/dependency-risk ingestion using synthetic dependency inventories.
- Add WebView and deep-link policy models.
- Add synthetic privacy/data-flow inventory correlation.
- Add policy profiles for different application risk tiers.
- Add release attestation metadata and control-drift comparison.

## Safety

No real credentials, signing keys, private application data, employer/client information, production targets, exploit payloads, bypass instructions, or confidential telemetry are included.
