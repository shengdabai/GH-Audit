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
gh-audit suppress <finding_id> --reason "false positive" --expires 30d
gh-audit config set token ghp_xxx
```
