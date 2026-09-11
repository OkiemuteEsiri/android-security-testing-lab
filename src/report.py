from __future__ import annotations

from pathlib import Path

from .risk_engine import MobileFinding, prioritize, summarize


def render_markdown(package: str, findings: list[MobileFinding]) -> str:
    metrics = summarize(findings)
    lines = [
        f"# Android Security Assessment — `{package}`",
        "",
        "> Synthetic defensive assessment. No production application or device was tested.",
        "",
        "## Executive summary",
        "",
        f"- Findings: **{metrics['total']}**",
        f"- Maximum contextual risk score: **{metrics['max_score']}/100**",
        f"- Internet-reachable findings: **{metrics['internet_reachable']}**",
        f"- Findings involving sensitive-data context: **{metrics['sensitive_data']}**",
        f"- ATT&CK-mapped findings: **{metrics['attack_mapped']}**",
        "",
        "## Prioritized findings",
        "",
        "| Score | ID | Severity | Finding | Component | MASVS | ATT&CK |",
        "|---:|---|---|---|---|---|---|",
    ]
    for item in prioritize(findings):
        lines.append(
            f"| {item.risk_score} | {item.rule_id} | {item.risk_band} | {item.title} | `{item.component}` | {item.masvs} | {item.attack_id or '—'} |"
        )

    lines.extend(["", "## Remediation and validation", ""])
    for item in prioritize(findings):
        lines.extend([
            f"### {item.rule_id} — {item.title}",
            "",
            f"**Evidence:** {item.evidence}",
            "",
            f"**Remediation:** {item.remediation}",
            "",
            f"**Validation:** {item.validation}",
            "",
            f"Decision ID: `{item.decision_id}`",
            "",
        ])
    return "\n".join(lines).rstrip() + "\n"


def write_report(path: str | Path, package: str, findings: list[MobileFinding]) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_markdown(package, findings), encoding="utf-8")
    return target
