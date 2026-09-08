import unittest
from src.mobile_review import review

class MobileReviewTests(unittest.TestCase):
    def test_debuggable_release_fails(self):
        app = {"debuggable": True, "uses_cleartext_traffic": False, "allow_backup": False, "target_sdk": 35, "permissions": [], "justified_permissions": [], "components": []}
        finding = next(f for f in review(app) if f.check_id == "MOB-001")
        self.assertEqual(finding.status, "FAIL")

    def test_unjustified_exported_component_fails(self):
        app = {"debuggable": False, "uses_cleartext_traffic": False, "allow_backup": False, "target_sdk": 35, "permissions": [], "justified_permissions": [], "components": [{"name": ".Receiver", "exported": True, "business_required": False}]}
        finding = next(f for f in review(app) if f.check_id == "MOB-003")
        self.assertEqual(finding.status, "FAIL")

    def test_hardened_configuration_passes_core_checks(self):
        app = {"debuggable": False, "uses_cleartext_traffic": False, "allow_backup": False, "target_sdk": 35, "permissions": [], "justified_permissions": [], "components": []}
        self.assertTrue(all(f.status == "PASS" for f in review(app)))

if __name__ == "__main__":
    unittest.main()
