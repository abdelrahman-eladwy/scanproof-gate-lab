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
        self.assertEqual(
            sorted(gate["needs"]), sorted(r["job_name"] for r in self.policy["requirements"])
        )
        self.assertEqual(gate["if"], "${{ always() }}")
        self.assertNotIn("continue-on-error", self.workflow_text)
        self.assertIn("b13f39808d3d23c4a68755544bef468addc3e507", self.workflow_text)
        self.assertIn("--pipeline \"$GITHUB_RUN_ID\"", self.workflow_text)
        self.assertIn("-p \"$GITHUB_REPOSITORY\"", self.workflow_text)
        self.assertEqual(len(REVIEWED_SCANPROOF_SHA), 40)

    def test_real_scanner_job_and_artifact_are_required(self):
        # Every policy requirement must be backed by a real scanner job of the same
        # name that uploads the named artifact. Two scanners prove the gate is not
        # Semgrep-specific (scanproof#123).
        required = {r["id"]: r for r in self.policy["requirements"]}
        self.assertEqual(set(required), {"SAST", "SCA"})
        expected = {
            "SAST": ("semgrep", "semgrep/semgrep:", "semgrep scan", "gate-lab-semgrep"),
            "SCA": ("trivy", "aquasec/trivy:", "trivy fs --scanners vuln", "gate-lab-trivy"),
        }
        for rid, (tool, image, command, artifact) in expected.items():
            req = required[rid]
            job = self.workflow["jobs"][req["job_name"]]
            # ScanProof matches the provider-reported job name, not the YAML job ID.
            # An explicit display name would silently change the provider's name.
            self.assertNotIn("name", job)
            self.assertEqual(req["tool"], tool)
            self.assertIn(image, job["container"])
            self.assertIn(command, yaml.safe_dump(job))
            self.assertEqual(req["artifact_name"], artifact)
            self.assertIn(artifact, yaml.safe_dump(job))
            self.assertGreaterEqual(req["checks"]["minimum_scanned_files"], 1)
        self.assertEqual(required["SAST"]["checks"]["scanner_errors_allowed"], 0)

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
