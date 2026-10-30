"""Offline contract for the sacrificial gate graph, not platform enforcement proof."""

from __future__ import annotations

import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
REVIEWED_SCANPROOF_SHA = "b13f39808d3d23c4a68755544bef468addc3e507"


class GateDefinitionContract(unittest.TestCase):
    def setUp(self):
        self.workflow_text = (ROOT / ".github/workflows/scanproof-gate.yml").read_text()
        self.workflow = yaml.safe_load(self.workflow_text)
        self.policy = yaml.safe_load((ROOT / ".scanproof/policy.yaml").read_text())

    def test_stable_gate_job_is_not_optional_or_continue_on_error(self):
        gate = self.workflow["jobs"]["scanproof-verification"]
        self.assertEqual(gate["name"], "ScanProof verification")
        self.assertEqual(gate["needs"], ["scan-semgrep"])
        self.assertEqual(gate["if"], "${{ always() }}")
        self.assertNotIn("continue-on-error", self.workflow_text)
        self.assertIn("b13f39808d3d23c4a68755544bef468addc3e507", self.workflow_text)
        self.assertIn("--pipeline \"$GITHUB_RUN_ID\"", self.workflow_text)
        self.assertIn("-p \"$GITHUB_REPOSITORY\"", self.workflow_text)
        self.assertEqual(len(REVIEWED_SCANPROOF_SHA), 40)

    def test_real_scanner_job_and_artifact_are_required(self):
        scan = self.workflow["jobs"]["scan-semgrep"]
        # ScanProof matches the provider-reported job name, not the YAML job ID.
        # An explicit display name would silently change the provider's name.
        self.assertNotIn("name", scan)
        self.assertIn("semgrep/semgrep:", scan["container"])
        self.assertIn("semgrep scan", self.workflow_text)
        self.assertIn("gate-lab-semgrep", self.workflow_text)
        required = self.policy["requirements"]
        self.assertEqual(len(required), 1)
        self.assertEqual(required[0]["tool"], "semgrep")
        self.assertEqual(required[0]["job_name"], "scan-semgrep")
        self.assertEqual(required[0]["artifact_name"], "gate-lab-semgrep")
        self.assertEqual(required[0]["checks"]["scanner_errors_allowed"], 0)
        self.assertGreaterEqual(required[0]["checks"]["minimum_scanned_files"], 1)

    def test_policy_fails_closed_on_unknown_or_missing_evidence(self):
        self.assertEqual(self.policy["enforcement"]["on_unknown"], "block")
        self.assertEqual(self.policy["enforcement"]["on_nothing_applicable"], "block")
        self.assertEqual(
            self.policy["project"], {
                "provider": "github",
                "id": "abdelrahman-eladwy/scanproof-gate-lab",
            }
        )

    def test_staging_marker_requires_success_and_is_nonproduction(self):
        stage = self.workflow["jobs"]["staging-marker"]
        self.assertEqual(stage["needs"], ["scanproof-verification"])
        self.assertEqual(stage["environment"], "staging")
        self.assertIn("needs.scanproof-verification.result == 'success'", stage["if"])
        self.assertIn("github.event_name == 'push'", stage["if"])
        self.assertEqual(stage["permissions"], {"contents": "read"})
        self.assertNotIn("production", stage["environment"])

    def test_codeowners_propose_separate_review_without_claiming_enforcement(self):
        codeowners = (ROOT / ".github/CODEOWNERS").read_text()
        self.assertIn("/.github/workflows/ @eladwy22", codeowners)
        self.assertIn("/.scanproof/ @eladwy22", codeowners)
        self.assertIn("/.github/CODEOWNERS @eladwy22", codeowners)
        self.assertIn("does not enforce approvals", codeowners)


if __name__ == "__main__":
    unittest.main()
