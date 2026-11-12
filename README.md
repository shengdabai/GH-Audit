# gh-audit

GitHub repository security audit tool. Scans for secrets, PII, code vulnerabilities, dependency risks, IaC misconfigurations, and governance gaps.

## Install

```bash
pipx install gh-audit
# or
pip install gh-audit
```

## Quick Start

```bash
export GITHUB_TOKEN=ghp_yourtoken

# Scan a repo
gh-audit scan owner/repo

# Scan an org, output HTML + JSON
gh-audit scan --org myorg --output terminal,json,html

# Check tool availability
gh-audit doctor
```

## Detection Modules

| Module | Built-in | Enhanced with |
|--------|---------|---------------|
| secrets | ✓ entropy + regex | gitleaks, trufflehog |
| pii | ✓ CN phone/ID/bank + email | presidio |
| governance | ✓ GitHub API | - |
| sast | - | semgrep, bandit |
| sca | ✓ OSV API fallback | osv-scanner |
| iac | - | trivy, checkov |

SAST reports include rule IDs and checkout-relative locations. They omit
source snippets, tool messages, and tool-provided URLs. Where available, the
scanner computes a keyed content ID from the full match, scoped to this
installation, repository, branch, scanner, and rule. The scanner verifies
selected checkout bytes against the scanned Git commit before assigning an ID.
Keep the owner-only key
in the local gh-audit configuration directory. A change to the matched source
creates a new ID, and moving an identical match within the same scope keeps
the ID.

When source or secure key storage is unavailable, the JSON content ID is null.
Diff and suppression filters keep those findings visible. Older SAST fingerprints and
suppressions must be replaced with IDs from a new scan. Generate a local JSON
report before suppressing a SAST finding. Deleting the local key also
invalidates earlier SAST IDs.

## Optional Tools

```bash
pip install semgrep bandit       # SAST
brew install osv-scanner trivy   # SCA + IaC
```

## CLI Reference

```bash
gh-audit scan owner/repo [--branch main] [--modules secrets,pii] [--output terminal,json,html] [--min-severity high] [--diff]
gh-audit scan --org myorg
gh-audit doctor
gh-audit history owner/repo
gh-audit suppress <content_fingerprint> --reason "false positive" --expires 30d
gh-audit config set token ghp_xxx
```
