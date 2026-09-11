from __future__ import annotations

import argparse
from pathlib import Path

from .android_assessor import assess_app, load_app
from .report import render_markdown, write_report
from .risk_engine import prioritize


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline Android release security assessment")
    parser.add_argument("input", type=Path, help="Synthetic Android release metadata JSON")
    parser.add_argument("--report", type=Path, help="Optional Markdown report path")
    args = parser.parse_args()

    app = load_app(args.input)
    findings = assess_app(app)
    for finding in prioritize(findings):
        print(f"{finding.risk_score:03d} {finding.risk_band.upper():8} {finding.rule_id} {finding.title} [{finding.component}]")

    if args.report:
        write_report(args.report, app["package"], findings)
        print(f"report={args.report}")
    else:
        print(render_markdown(app["package"], findings))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
