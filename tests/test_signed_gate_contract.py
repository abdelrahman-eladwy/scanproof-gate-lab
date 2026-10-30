"""Offline contract for the App-signed gate design (gate-lab#13 F1).

Structure only: it cannot prove GitHub attaches the App's check to the PR head or
that the environment withholds the key. Those need live trials after owner setup.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WF = ROOT / ".github/workflows/scanproof-signed-gate.yml"
PINNED = re.compile(r"uses:\s*[\w.-]+/[\w.-]+@[0-9a-f]{40}\b")


class SignedGateContract(unittest.TestCase):
    def setUp(self):
        self.text = WF.read_text()
        self.wf = yaml.safe_load(self.text)
        # PyYAML parses the bare key `on` as True.
        self.on = self.wf.get("on", self.wf.get(True))
        self.jobs = self.wf["jobs"]

    def test_runs_only_from_the_base_branch_definition(self):
        self.assertEqual(list(self.on), ["pull_request_target"])
        self.assertEqual(self.wf["permissions"], {})

    def test_pr_code_is_checked_out_only_in_the_secretless_scan_job(self):
        head_ref = "github.event.pull_request.head.sha"
        for name, job in self.jobs.items():
            steps = yaml.safe_dump(job.get("steps", []))
            if name == "scan-semgrep":
                self.assertIn(head_ref, steps)
                self.assertNotIn("environment", job)
                self.assertEqual(job["permissions"], {"contents": "read"})
                self.assertNotIn("secrets.", steps)
            else:
                # The PR SHA may be *named* (the check's head_sha) but never checked out.
                for step in job.get("steps", []):
                    if str(step.get("uses", "")).startswith("actions/checkout@"):
                        self.assertNotIn("ref", step.get("with", {}))

    def test_nothing_from_the_pr_is_executed(self):
        scan = self.jobs["scan-semgrep"]
        runs = [s["run"] for s in scan["steps"] if "run" in s]
        self.assertEqual(len(runs), 1)
        self.assertTrue(runs[0].startswith("semgrep scan --config .semgrep/rules.yml"))
        self.assertIn(" pr/demo/", runs[0])
        for step in scan["steps"]:
            self.assertFalse(str(step.get("uses", "")).startswith("./"))

    def test_key_is_only_reachable_in_the_main_restricted_signer(self):
        users = [n for n, j in self.jobs.items() if "GATE_APP_PRIVATE_KEY" in yaml.safe_dump(j)]
        self.assertEqual(users, ["sign"])
        sign = self.jobs["sign"]
        self.assertEqual(sign["environment"], "gate-signer")
        self.assertEqual(sign["permissions"], {})
        self.assertNotIn("actions/checkout", yaml.safe_dump(sign))

    def test_signer_fails_closed_and_uses_a_distinct_check_name(self):
        sign_text = yaml.safe_dump(self.jobs["sign"])
        self.assertIn('if [ "$VERIFY_RESULT" = "success" ]; then conclusion=success; else conclusion=failure; fi', self.text)
        self.assertIn("ScanProof signed verification", sign_text)
        self.assertEqual(self.jobs["sign"]["needs"], ["verify"])
        self.assertEqual(self.jobs["sign"]["if"], "${{ always() }}")
        self.assertNotIn("continue-on-error", self.text)

    def test_every_action_is_pinned_by_full_sha(self):
        uses = re.findall(r"uses:\s*\S+", self.text)
        self.assertTrue(uses)
        for line in uses:
            self.assertRegex(line, PINNED)

    def test_trusted_policy_binds_the_scan_job_by_name(self):
        policy = yaml.safe_load((ROOT / ".scanproof/policy.yaml").read_text())
        self.assertEqual(policy["requirements"][0]["job_name"], "scan-semgrep")
        self.assertIn("scan-semgrep", self.jobs)
        self.assertNotIn("name", self.jobs["scan-semgrep"])


if __name__ == "__main__":
    unittest.main()
