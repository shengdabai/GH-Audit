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
| sca | OSV API fallback for online scans | osv-scanner |
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

### Comparing scans

`--diff` compares against the last complete scan of the same repository,
branch, selected modules, and SCA networking mode when enabled. After report
delivery, a complete scan saves
a private snapshot of fingerprint counts collected before display filters.
This works with terminal, HTML, and JSON output. The snapshot contains counts
and fingerprint IDs.
Reports and their history keep their existing format.

If an identical SAST match appears more times than before, the diff shows all
current locations for that match. Counts establish that the group grew. They
cannot establish which location is new. Moving an identical match without
changing the count keeps it out of the diff.

The first scan in a scope shows current findings. Earlier JSON reports may
contain only filtered results, so they cannot establish a complete baseline.
Incomplete scans preserve the previous snapshot and show the findings from
modules that finished. Report delivery failures also preserve the previous
snapshot. If the CLI cannot read a snapshot, it shows current findings.
If it cannot save a snapshot, it warns that the next diff may repeat findings.
On Windows, the snapshot inherits access permissions from the per-user results
directory. The CLI rejects links and reparse points in the snapshot path.

### Dependency scan networking

Dependency scans use `--sca-network auto` by default. Public repositories
can use online OSV lookups. Private, internal, and unknown-visibility
repositories use offline OSV-Scanner v2. Prepare the
[local advisory database](https://google.github.io/osv-scanner/usage/offline-mode/)
separately. If the tool or database is unavailable, SCA reports an incomplete
scan. Offline mode disables call graph analysis and uses the existing local
database without downloading or falling back to online lookups.

Use `--sca-network offline` to restrict SCA lookups for any repository.
Use `--sca-network online` only if you want to allow SCA to send dependency
coordinates from the selected repositories to external advisory services.
These options apply to SCA only. Repository discovery and cloning still
contact GitHub.

The built-in online fallback submits exact npm and PyPI registry coordinates
to the OSV API. For npm, it uses entries with an official registry resolution
or no resolution field. It skips mirrors, ranges, direct URLs, local sources,
and Git references.

## Optional Tools

```bash
pip install semgrep bandit       # SAST
brew install osv-scanner trivy   # SCA + IaC
```

## CLI Reference

```bash
gh-audit scan owner/repo [--branch main] [--modules secrets,pii] [--output terminal,json,html] [--min-severity high] [--diff]
gh-audit scan --org myorg
gh-audit scan owner/repo --modules sca --sca-network offline
gh-audit doctor
gh-audit history owner/repo
gh-audit suppress <content_fingerprint> --reason "false positive" --expires 30d
gh-audit config set token ghp_xxx
```
