  # GitHub Security Scanner

`github_scanner.py` is a Python recon and secret-scanning script for public GitHub targets. It can scan:

- A GitHub organization
- A GitHub user account
- A single repository

It walks repository contents through the GitHub REST API, downloads text files, and searches them for common sensitive-data patterns such as API keys, tokens, passwords, and private keys.

## Features

- Scan all repos in an organization with `--org`
- Scan all repos for a user with `--user`
- Scan one repo with `--repo`
- Built-in regex signatures for common secrets
- Add custom regex rules from CLI
- Load custom regex rules from a JSON config file
- Optional JSON report output
- Optional GitHub token support to improve API limits

## Built-In Detection Patterns

The scanner currently includes patterns for:

- AWS access keys and secret keys
- GitHub tokens
- Generic API keys and secrets
- Password assignments
- Private keys
- Slack, Stripe, Google, Firebase, Heroku, MailChimp, Mailgun, Telegram, Twilio, PayPal/Braintree, Square, NPM, and Docker Hub tokens
- JWTs

## Requirements

- Python 3.8+
- `requests`

## Installation

```bash
git clone <your-repo-url>
cd latest_scanner
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

### Scan an organization

```bash
python3 github_scanner.py --org microsoft
```

### Scan a user

```bash
python3 github_scanner.py --user torvalds
```

### Scan a single repository

```bash
python3 github_scanner.py --repo owner/repo
```

You can also pass a GitHub URL:

```bash
python3 github_scanner.py --repo https://github.com/owner/repo
```

### Use a GitHub token

Using a personal access token is recommended to reduce API rate-limit issues.

```bash
python3 github_scanner.py --org microsoft --token YOUR_GITHUB_TOKEN
```

### Save results to JSON

```bash
python3 github_scanner.py --repo owner/repo --output report.json
```

### Load custom patterns from config

```bash
python3 github_scanner.py --org target-org --config patterns_config.example.json
```

### Add custom patterns from the command line

```bash
python3 github_scanner.py \
  --repo owner/repo \
  --custom-pattern "Internal Token" "INT_[A-Z0-9]{24}"
```

### Disable built-in delays

```bash
python3 github_scanner.py --user someuser --no-rate-limit
```

Use `--no-rate-limit` carefully. It disables the script's sleep intervals and may cause GitHub API throttling.

## CLI Reference

```bash
python3 github_scanner.py [-h] [--org ORG] [--user USER] [--repo REPO]
                         [--token TOKEN] [--output OUTPUT] [--config CONFIG]
                         [--no-rate-limit] [--custom-pattern NAME PATTERN]
```

Options:

- `--org`: organization name to scan
- `--user`: GitHub username to scan
- `--repo`: single repository to scan in `owner/repo` format or full GitHub URL
- `--token`: GitHub personal access token
- `--output`, `-o`: save findings as JSON
- `--config`, `-c`: load custom patterns from a JSON file
- `--no-rate-limit`: disable built-in delays
- `--custom-pattern NAME PATTERN`: add one custom regex rule; may be used multiple times

## Config File Format

The config file must be JSON and contain a `custom_patterns` object:

```json
{
  "custom_patterns": {
    "Internal Token": "INT_[A-Z0-9]{24}",
    "Example Secret": "SECRET_[A-Za-z0-9_-]{16,}"
  }
}
```

A sample file is included at `patterns_config.example.json`.

## Output

When matches are found, the script prints a summary grouped by finding type and can optionally save a JSON report with:

- Scan timestamp
- Total findings
- Full findings list
- Summary count by finding type

Each finding includes:

- Detection type
- Repository name
- File path
- Line number
- Matched value preview
- Timestamp

## Notes and Limitations

- This scanner relies on the GitHub API and is affected by API rate limits.
- It skips files larger than 1 MB.
- It only scans files that can be downloaded as text content.
- Regex-based matching may produce false positives.
- Very large orgs may take time to scan.

## Responsible Use

Use this tool only on targets you are authorized to assess. If you discover exposed secrets, handle them responsibly and report them through the appropriate disclosure process.

## Project Files

- `github_scanner.py`: main scanner
- `requirements.txt`: Python dependency list
- `patterns_config.example.json`: sample custom-pattern config
