# GitHubReconScanner

Ethical GitHub reconnaissance scanner for identifying potentially sensitive data in public repositories.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## PAT Scopes

Use a GitHub Personal Access Token with scopes aligned to your use case:

- `repo`
- `read:org`
- Search permissions as applicable to your token type

Pass token via `--token` or export and pass from shell:

```bash
export GITHUB_TOKEN="YOUR_TOKEN"
python github_recon_scanner.py --token "$GITHUB_TOKEN" --repo owner/repo --verbose
```

## Usage

```bash
python github_recon_scanner.py --target example.com --type domain --output results.json
python github_recon_scanner.py --user bugbuster --patterns custom_patterns.json --verbose
python github_recon_scanner.py --org some-org --output findings.csv
python github_recon_scanner.py --org some-org --output findings.json --csv-output findings.csv
python github_recon_scanner.py --org some-org --output findings.txt
python github_recon_scanner.py --org some-org --output findings.html
python github_recon_scanner.py --repo owner/repo --concurrency 1 --requests-per-minute 30
python github_recon_scanner.py --repo owner/repo --no-regex-grep  # disable grep-style regex extraction
python github_recon_scanner.py --repo owner/repo --max-commits-per-repo 50
python github_recon_scanner.py --repo owner/repo --max-prs-per-repo 50
python github_recon_scanner.py --repo owner/repo --fresh-days 7
python github_recon_scanner.py --repo owner/repo --fresh-since 2026-02-01T00:00:00Z
python github_recon_scanner.py --repo owner/repo --fresh-days 7 --latest-only
python github_recon_scanner.py --domain google.com --discover-subdomains --output subdomains.json
python github_recon_scanner.py --domain example.com --discover-subdomains --output subdomains.csv
python github_recon_scanner.py --org my-org --resume --progress-file .scan_progress.json
python github_recon_scanner.py --repo owner/repo --custom-pattern MyToken 'mytok_[A-Za-z0-9]{32}'
python github_recon_scanner.py --org my-org --flush  # start fresh for this target
python github_recon_scanner.py --org my-org --scan-all-files --max-files-per-repo 20000
python github_recon_scanner.py --org my-org --tokens "$TOKEN1,$TOKEN2"
python github_recon_scanner.py --org my-org --token TOKEN1 --token TOKEN2
python github_recon_scanner.py --org my-org --tokens-file tokens.txt
```

Shortcuts:

- `--domain example.com`
- `--user bugbuster`
- `--org my-org`
- `--repo owner/repo`

## Features

- Rate-limit aware requests using `/rate_limit`
- Conservative built-in pacing for both core API calls and stricter search API calls
- Sleep until reset when `X-RateLimit-Remaining` is exhausted
- Exponential backoff for 403/429 and secondary limits
- Search query pacing (`--requests-per-minute`) is safety-capped to reduce throttling risk
- `--no-rate-limit` is kept only for CLI compatibility and does not disable pacing
- Progress save/resume checkpoints (`--resume`, `--progress-file`, `--clear-progress`)
- Automatic target-based cache resume (`.scan_cache/<type>_<target>.json`)
- `Ctrl+C` saves cache immediately and exits; rerun same target to continue
- `--flush` clears cache for the selected target and starts from scratch
- Multi-token input (`--token` repeatable, `--tokens`, `--tokens-file`) with auto failover if active token becomes invalid
- Repo/org/user/domain target support
- Global subdomain and sub-subdomain discovery for `--domain` targets with `--discover-subdomains`
- Code search qualifiers (`repo:`, `filename:`) and optional regex queries (`--use-regex-query`)
- Client-side regex grep over GitHub file contents with matched-value extraction and confidence scoring
- Commit history scanning (recent commit patches) to catch secrets that were committed and later removed
- Pull request patch scanning (recent PR diffs)
- Collaboration text scanning (recent PR descriptions/comments, issue descriptions/comments, release notes)
- Freshness filtering (`--fresh-days`, `--fresh-since`) so results stay current and relevant
- `--latest-only` to keep only findings from the most recent observed activity per repo
- Optional full repository file scan (`--scan-all-files`) to enumerate and scan all files in each repo
- TXT/JSON/HTML/CSV output inferred from `--output` file extension
- Optional parallel CSV export with `--csv-output findings.csv`
- Prints full finding URLs to console by default (repo/org/user/domain scans)
- `--verbose` prints detailed per-finding context and debug logs

## Subdomain Discovery

- Use `--discover-subdomains` together with `--domain example.com`.
- The scanner searches GitHub code globally for the base domain, then regex-extracts hostnames such as `api.example.com` and `a.b.example.com`.
- Bare apex domains like `example.com` are excluded; only deeper hostnames are reported.
- Output works with the normal formats: JSON, CSV, TXT, and HTML.

## Commit Scanning

- Enabled by default.
- Scans added lines in recent commit patches and applies the same regex rules.
- Control volume with `--max-commits-per-repo` (default: `30`).
- Disable with `--no-scan-commits` if you need to reduce API load.

## Pull Request and Discussion Scanning

- Pull request patch scanning is enabled by default.
- Scans added lines in PR diffs plus PR text/comment threads.
- Scans issue text/comment threads and release notes for leaked secrets.
- Controls:
  - `--max-prs-per-repo` (default: `20`)
  - `--max-issues-per-repo` (default: `30`)
  - `--max-releases-per-repo` (default: `20`)
  - `--no-scan-prs`
  - `--no-scan-collab-text`

## Fresh Data Filters

- Default behavior scans only recent activity from the last `30` days.
- Use `--fresh-days N` to adjust recency window.
- Use `--fresh-since 2026-02-01T00:00:00Z` for a fixed UTC cutoff.
- Use `--fresh-days 0` to disable freshness filtering.

## Custom Patterns File

Create a JSON list:

```json
[
  {
    "name": "My Internal Token",
    "regex": "mytok_[A-Za-z0-9]{32}",
    "literals": ["mytok_"],
    "severity": 90,
    "description": "Internal API token format"
  }
]
```

Alternate config format (compatible with `--config`):

```json
{
  "custom_patterns": {
    "My Internal Token": "mytok_[A-Za-z0-9]{32}",
    "Legacy Key": "legacy_[0-9A-F]{40}"
  }
}
```

## Ethical Use

- Scan only authorized targets and public data.
- Follow bug bounty scope and GitHub Terms of Service.
- Keep concurrency and RPM low to avoid abuse flags.
