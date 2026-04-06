# Github Recon Scanner

GitHub reconnaissance scanner for identifying potentially sensitive data in public repositories.

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

Pass token via `--token` / `-t` or export and pass from shell:

```bash
export GITHUB_TOKEN="YOUR_TOKEN"
python github_scanner.py -t "$GITHUB_TOKEN" -r owner/repo -v
```

If you do not provide a token, the scanner still runs with public unauthenticated GitHub API access, but you should expect stricter rate limits, slower scans, and lower coverage on larger targets.

If you provide `--token`, `--tokens`, or `--tokens-file` or their short forms `-t`, `-T`, or `-F`, and none of the supplied tokens are valid, the scanner exits immediately and shows an invalid token response instead of silently falling back to unauthenticated mode.

## Features

- Rate-limit aware requests using `/rate_limit`
- Conservative built-in pacing for both core API calls and stricter search API calls
- Sleep until reset when `X-RateLimit-Remaining` is exhausted
- Exponential backoff for 403/429 and secondary limits
- Search query pacing (`--requests-per-minute` / `-R`) is safety-capped to reduce throttling risk
- `--no-rate-limit` / `-N` is kept only for CLI compatibility and does not disable pacing
- Progress save/resume checkpoints (`--resume` / `-e`, `--progress-file` / `-J`, `--clear-progress` / `-K`)
- Automatic target-based cache resume (`.scan_cache/<type>_<target>.json`)
- `Ctrl+C` saves cache immediately and exits; rerun same target to continue
- `--flush` / `-U` clears cache for the selected target and starts from scratch
- Multi-token input (`--token` / `-t` repeatable, `--tokens` / `-T`, `--tokens-file` / `-F`) with auto failover if active token becomes invalid
- Repo/org/user/domain target support
- Global subdomain and sub-subdomain discovery for any `--domain` / `-d` target with `--discover-subdomains` / `-D`
- Subdomain discovery now combines multiple GitHub sources: global code search, repo-scoped code search, repository metadata, small text files, recent commit patches, PR patches, issue/PR comments, and release notes
- Code search qualifiers (`repo:`, `filename:`) and optional regex queries (`--use-regex-query` / `-q`)
- Client-side regex grep over GitHub file contents with matched-value extraction and confidence scoring
- Commit history scanning (recent commit patches) to catch secrets that were committed and later removed
- Pull request patch scanning (recent PR diffs)
- Collaboration text scanning (recent PR descriptions/comments, issue descriptions/comments, release notes)
- Freshness filtering (`--fresh-days` / `-w`, `--fresh-since` / `-S`) so results stay current and relevant
- `--latest-only` / `-y` to keep only findings from the most recent observed activity per repo
- Optional full repository file scan (`--scan-all-files` / `-A`) to enumerate and scan all files in each repo
- TXT/JSON/HTML/CSV output inferred from `--output` / `-O` file extension
- Optional parallel CSV export with `--csv-output` / `-V`
- Prints full finding URLs to console by default (repo/org/user/domain scans)
- `--verbose` / `-v` prints detailed per-finding context and debug logs

## Subdomain Discovery

- Use `--discover-subdomains` / `-D` together with `--domain example.com` / `-d example.com`.
- The scanner regex-extracts hostnames such as `api.example.com` and `a.b.example.com` from multiple GitHub sources.
- Sources include global code search, repo-scoped code search, repository metadata, repository text files, commit patches, pull request patches, issue and PR discussion text, and release notes.
- Bare apex domains like `example.com` are excluded; only deeper hostnames are reported.
- This works for any domain you provide, such as `example.com`, `acme.co.uk`, or `my-company.io`.
- Output works with the normal formats: JSON, CSV, TXT, and HTML.
- Subdomain discovery does not save a file by default; add `--output` / `-O` if you want to persist the results.

## Commit Scanning

- Enabled by default.
- Scans added lines in recent commit patches and applies the same regex rules.
- Control volume with `--max-commits-per-repo` / `-c` (default: `30`).
- Disable with `--no-scan-commits` / `-m` if you need to reduce API load.

## Pull Request and Discussion Scanning

- Pull request patch scanning is enabled by default.
- Scans added lines in PR diffs plus PR text/comment threads.
- Scans issue text/comment threads and release notes for leaked secrets.
- Controls:
  - `--max-prs-per-repo` / `-j` (default: `20`)
  - `--max-issues-per-repo` / `-i` (default: `30`)
  - `--max-releases-per-repo` / `-l` (default: `20`)
  - `--no-scan-prs` / `-s`
  - `--no-scan-collab-text` / `-I`

## Fresh Data Filters

- Default behavior scans only recent activity from the last `30` days.
- Use `--fresh-days N` / `-w N` to adjust recency window.
- Use `--fresh-since 2026-02-01T00:00:00Z` / `-S 2026-02-01T00:00:00Z` for a fixed UTC cutoff.
- Use `--fresh-days 0` / `-w 0` to disable freshness filtering.

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

Alternate config format (compatible with `--config` / `-f`):

```json
{
  "custom_patterns": {
    "My Internal Token": "mytok_[A-Za-z0-9]{32}",
    "Legacy Key": "legacy_[0-9A-F]{40}"
  }
}
```

## Responsible Use

- Scan only authorized targets. 
- Follow GitHub Terms of Service.
- Keep concurrency and RPM low to avoid abuse flags.
