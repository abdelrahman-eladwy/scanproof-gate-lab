# ScanProof gate-lab: staging acceptance (NOT YET ENFORCED)

This is a sacrificial repository with no production deploy, credentials or secrets.
Successful workflow runs alone cannot prove an independently enforced release gate.

## Bootstrap sequence

1. Merge the tested bootstrap PR **before** enabling a mandatory status check.
2. Inspect the actual check-run name `ScanProof verification` in GitHub Actions.
   Confirm a real Semgrep JSON artifact and ScanProof decision were produced on
   the *same run*, tied to the actual commit. A green workflow contract alone
   is insufficient.
3. Confirm `eladwy22` has active write access and is a separately controlled
   identity. CODEOWNERS is merely a proposal until an administrator enables
   required CODEOWNER review. A second account controlled by the same person
   does not establish independent security ownership.
4. In Settings > Rules > Rulesets, target `main`: require PRs, at least one
   approving review, required code-owner review, dismiss stale approvals or
   require last-push review; require the **exact** `ScanProof verification`
   status context from trusted GitHub Actions integration, with strict
   up-to-date checks. Prohibit force push/deletion and broad bypass permissions.
   Protect the gate workflow, CODEOWNERS, policy, and Semgrep rules from
   unreviewed changes. Do not select an unobserved or missing check name.
5. In Settings > Environments > staging, require an independent reviewer,
   enable prevent self-review, restrict to protected branches only, disable
   administrator bypass where supported, and use no real deployment secrets.
   The dry-run marker executes only on a push to `main` after a green gate.
6. From the *reviewed* E2E checkout, execute the read-only
   `github-protection-preflight` manually against this repository and staging
   environment. Save both JSON results; a green offline self-test does not
   mean the target audit ran.

## Distinct live negative trials (after platform protection)

- Positive PR: real Semgrep artifact and ScanProof VERIFIED; record check run,
  approved merge and staging marker.
- Missing check: contributor removes the gate workflow; merger is denied.
- Failed check: contributor changes the scan to yield unreadable/invalid
  evidence; gate is red and merger is denied.
- Skipped check: contributor disables the gate job; merger is denied.
- Weakened policy, changed required context, removed staging dependency and
  forged/replayed reports: require independent review or reject by independent
  control. Test each separately, with negative PRs **never merged**.

Capture actual refused merge attempts performed by an account without bypass
rights, and verify that a staging deployment cannot run for those attempts.
The read-only PR observer is advisory and cannot prove denial on its own.

GitLab centrally managed pipeline execution policy and actual denied staging
trials are separate Phase 2 requirements. NO-GO until evidenced.
