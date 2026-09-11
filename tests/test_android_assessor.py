import json
import tempfile
import unittest
from pathlib import Path

from src.android_assessor import assess_app, load_app
from src.remediation_validator import RemediationEvidence, validate_remediation
from src.report import render_markdown
from src.risk_engine import MobileFinding, prioritize, summarize


FIXTURE = Path("data/synthetic_release_app.json")


class AndroidAssessorTests(unittest.TestCase):
    def test_fixture_loads_and_produces_multiple_findings(self):
        app = load_app(FIXTURE)
        findings = assess_app(app)
        self.assertGreaterEqual(len(findings), 7)

    def test_cleartext_sensitive_context_scores_high(self):
        finding = next(item for item in assess_app(load_app(FIXTURE)) if item.rule_id == "MOB-002")
        self.assertGreaterEqual(finding.risk_score, 75)
        self.assertTrue(finding.handles_sensitive_data)

    def test_unnecessary_privileged_export_is_prioritized(self):
        findings = assess_app(load_app(FIXTURE))
        exported = next(item for item in findings if item.rule_id == "MOB-003")
        self.assertTrue(exported.privileged_component)
        self.assertEqual(prioritize(findings)[0].risk_score, max(item.risk_score for item in findings))

    def test_high_risk_permission_requires_justification(self):
        findings = assess_app(load_app(FIXTURE))
        components = {item.component for item in findings if item.rule_id == "MOB-006"}
        self.assertIn("android.permission.RECORD_AUDIO", components)
        self.assertNotIn("android.permission.ACCESS_FINE_LOCATION", components)

    def test_weak_signing_metadata_detected(self):
        finding = next(item for item in assess_app(load_app(FIXTURE)) if item.rule_id == "MOB-008")
        self.assertIn("SHA1withRSA", finding.evidence)

    def test_decision_ids_are_deterministic(self):
        app = load_app(FIXTURE)
        first = assess_app(app)[0].decision_id
        second = assess_app(app)[0].decision_id
        self.assertEqual(first, second)

    def test_risk_score_is_bounded(self):
        finding = MobileFinding(
            rule_id="MOB-999", title="Synthetic", severity="critical", component="x", evidence="e",
            remediation="r", validation="v", masvs="MASVS-PLATFORM", internet_reachable=True,
            handles_sensitive_data=True, privileged_component=True,
        )
        self.assertEqual(finding.risk_score, 100)

    def test_loader_rejects_missing_required_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            path.write_text(json.dumps({"package": "x"}), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_app(path)

    def test_summary_counts_context(self):
        metrics = summarize(assess_app(load_app(FIXTURE)))
        self.assertGreater(metrics["sensitive_data"], 0)
        self.assertGreater(metrics["attack_mapped"], 0)

    def test_report_contains_masvs_and_validation(self):
        app = load_app(FIXTURE)
        report = render_markdown(app["package"], assess_app(app))
        self.assertIn("MASVS", report)
        self.assertIn("Remediation and validation", report)
        self.assertIn("Decision ID", report)

    def test_complete_remediation_evidence_validates(self):
        evidence = RemediationEvidence(
            finding_id="abc", owner="mobile-team", change_reference="PR-42",
            configuration_before="usesCleartextTraffic=true", configuration_after="usesCleartextTraffic=false",
            validation_method="release metadata regression review", validation_result="passed",
            release_build_verified=True,
        )
        self.assertEqual(validate_remediation(evidence), ("validated", []))

    def test_incomplete_remediation_evidence_stays_open(self):
        evidence = RemediationEvidence(
            finding_id="abc", owner="mobile-team", change_reference="",
            configuration_before="true", configuration_after="true", validation_method="",
            validation_result="pending", release_build_verified=False,
        )
        status, missing = validate_remediation(evidence)
        self.assertEqual(status, "needs_evidence")
        self.assertIn("control_state_change", missing)
        self.assertIn("release_build_verified", missing)


if __name__ == "__main__":
    unittest.main()
