# Architecture and Methodology

## Purpose

This project models a defensive Android release-security review using synthetic application metadata. It is intentionally offline: no APK decompilation, device interaction, interception, credential use, or third-party targeting is required.

## Data flow

`synthetic release metadata -> fail-closed validation -> deterministic control checks -> contextual risk scoring -> prioritized findings -> remediation evidence -> repeat validation`

## Trust boundaries

1. **Input boundary** — JSON is treated as untrusted until required fields and structures are validated.
2. **Assessment boundary** — rules are deterministic and do not infer compromise or exploitability beyond supplied metadata.
3. **Reporting boundary** — reports distinguish observed configuration from threat-model context.
4. **Closure boundary** — findings remain open until change evidence and release-build validation demonstrate an effective control-state change.

## Control domains

| Control | Security intent | Example evidence | Framework context |
|---|---|---|---|
| Release debugging | Prevent release diagnostic interfaces | `debuggable=false` | MASVS-RESILIENCE |
| Transport security | Prevent unintended cleartext transport | `usesCleartextTraffic=false` | MASVS-NETWORK |
| Exported components | Minimize externally reachable Android components | exported flag + business requirement | MASVS-PLATFORM |
| Backup control | Reduce unintended data extraction paths | backup policy | MASVS-STORAGE |
| SDK baseline | Retain modern platform protections | target SDK | MASVS-CODE |
| Permission governance | Enforce least privilege | declared vs justified permissions | MASVS-PRIVACY |
| Trust anchors | Restrict release CA trust policy | network security config | MASVS-NETWORK |
| Signing posture | Protect release integrity | algorithm/key-size metadata | MASVS-RESILIENCE |

## Risk methodology

The risk engine starts with a severity weight and adds contextual modifiers for internet reachability, sensitive-data handling, and privileged components. Scores are capped at 100 and translated into critical/high/medium/low bands. The model is intentionally transparent and deterministic; it is not a substitute for CVSS, formal mobile threat modeling, or hands-on application testing.

## MITRE ATT&CK context

Mappings are used only to explain defensive relevance. Examples include T1439 (Access Sensitive Data in Device Logs / mobile data exposure context), T1474 (Supply Chain Compromise / application component exposure context), and T1629 (Impair Defenses / weakened release protections context). A mapping never means the technique occurred.

## Remediation lifecycle

1. Assign an accountable owner.
2. Record the affected configuration and intended secure state.
3. Implement the change through normal source-control/release governance.
4. Re-run the same deterministic assessment against release metadata.
5. Capture validation method and result.
6. Verify the actual release build, not only a development variant.
7. Close only when evidence shows the control state changed and the validation passed.

## Limitations

- Synthetic metadata cannot prove runtime behavior.
- Certificate pinning effectiveness, storage implementation, WebView behavior, native-code protections, and runtime authorization require additional testing approaches.
- ATT&CK mappings are contextual rather than incident evidence.
- The project does not claim OWASP MASVS certification.
