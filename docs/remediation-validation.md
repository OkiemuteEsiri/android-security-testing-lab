# Mobile Remediation and Validation

## Finding lifecycle

1. Confirm the release configuration that produced the finding.
2. Identify the feature owner and security impact.
3. Implement the least-privilege configuration change.
4. Rebuild the release artifact.
5. Re-run the deterministic check against release metadata.
6. Record PASS evidence or a time-bound approved exception.

## Validation examples

- **Debuggable:** confirm release metadata resolves to `false`.
- **Cleartext:** confirm the effective network policy prevents unapproved cleartext traffic.
- **Exported components:** verify every exported component has a documented requirement and appropriate authorization boundary.
- **Backup:** confirm the intended backup policy is explicit in release configuration.
- **Target SDK:** confirm the built artifact reports the approved target SDK after compatibility testing.
- **Permissions:** map each high-risk permission to a documented product capability and remove unused permissions.

## Strategic considerations

Security checks should run before release and should be paired with dependency scanning, secure code review, runtime testing in an authorized lab, privacy assessment, and signing/release governance. Static configuration review alone does not establish that an application is secure.
