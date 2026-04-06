#!/usr/bin/env python3
"""
Github Recon Scanner

GitHub reconnaissance scanner for public repositories.
Uses GitHub REST APIs with rate-limit-aware pacing and client-side pattern validation.
"""

from __future__ import annotations

import argparse
import base64
import csv
import html
import json
import logging
import os
import random
import re
import signal
import threading
import time
import base64 as b64
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests

try:
    import regex as re2
except Exception:  # pragma: no cover
    re2 = None


LOG = logging.getLogger("Github Recon Scanner")

SAFE_CORE_RPM_AUTHENTICATED = 15
SAFE_CORE_RPM_UNAUTHENTICATED = 6
SAFE_SEARCH_RPM_AUTHENTICATED = 6
SAFE_SEARCH_RPM_UNAUTHENTICATED = 3


class GitHubScannerError(RuntimeError):
    """Base exception for user-facing scanner failures."""


class GitHubApiError(GitHubScannerError):
    """GitHub API request failed with a handled response."""


class GitHubTargetNotFoundError(GitHubApiError):
    """Requested GitHub org/user/repo does not exist or is inaccessible."""


class ScannerNetworkError(GitHubScannerError):
    """Scanner could not reach a remote service."""


class ScannerOutputError(GitHubScannerError):
    """Scanner could not write or send output."""


@dataclass
class PatternRule:
    name: str
    regex: Optional[str] = None
    literals: List[str] = field(default_factory=list)
    severity: int = 50
    description: str = ""

    def compile(self) -> Any:
        if not self.regex:
            return None
        engine = re2 if re2 is not None else re
        return engine.compile(self.regex)


def default_rules() -> List[PatternRule]:
    return [
        PatternRule("AWS Access Key ID", r"AKIA[0-9A-Z]{16}", ["AKIA"], 95),
        PatternRule(
            "AWS Secret Access Key",
            r"(?<![A-Z0-9])[A-Za-z0-9/+=]{40}(?![A-Z0-9])",
            ["aws_secret_access_key", "AWS_SECRET_ACCESS_KEY"],
            88,
        ),
        PatternRule("GitHub PAT", r"gh[pousr]_[A-Za-z0-9_]{36}", ["ghp_", "github_pat"], 95),
        PatternRule("Stripe Live Key", r"sk_live_[0-9a-zA-Z]{24}", ["sk_live_"], 90),
        PatternRule(
            "Slack Webhook",
            r"https://hooks\.slack\.com/services/[A-Za-z0-9_/]+",
            ["hooks.slack.com/services"],
            90,
        ),
        PatternRule("Google API Key", r"AIza[0-9A-Za-z\-_]{35}", ["AIza"], 88),
        PatternRule(
            "JWT",
            r"[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_+/=]*",
            ["Bearer ", "jwt", "authorization"],
            70,
        ),
        PatternRule(
            "SSH Private Key Header",
            r"-----BEGIN (RSA|OPENSSH|DSA|EC) PRIVATE KEY-----",
            ["PRIVATE KEY"],
            98,
        ),
        PatternRule(
            "Database Credential Indicators",
            r"(postgres|mysql|mongodb|redis)://[^:\s]+:[^@\s]+@",
            ["db_password", "database_url", "connection_string"],
            80,
        ),
        PatternRule(
            "Common Secret Assignment",
            r"(api[_-]?key|secret[_-]?key|private[_-]?key|auth[_-]?token|db[_-]?password|password)\s*[:=]\s*['\"][^'\"]{6,}['\"]",
            ["api_key", "secret_key", "auth_token", "db_password", "password="],
            65,
        ),
    ]


COMMON_FILENAME_INDICATORS = [
    ".env",
    ".aws/credentials",
    "config.json",
    "secrets.yml",
    ".htpasswd",
]

TEXT_LIKE_FILE_EXTENSIONS = {
    ".txt", ".md", ".rst", ".adoc", ".env", ".cfg", ".conf", ".config", ".ini",
    ".json", ".jsonl", ".yaml", ".yml", ".toml", ".properties", ".xml", ".html",
    ".htm", ".xhtml", ".svg", ".css", ".scss", ".less", ".js", ".mjs", ".cjs",
    ".ts", ".tsx", ".jsx", ".py", ".rb", ".php", ".java", ".kt", ".kts", ".go",
    ".rs", ".c", ".cc", ".cpp", ".h", ".hpp", ".cs", ".swift", ".sql", ".sh",
    ".bash", ".zsh", ".ps1", ".bat", ".cmd", ".dockerfile",
}

TEXT_LIKE_FILENAMES = {
    "readme", "license", "notice", "changelog", "changes", "hosts", "cname",
    ".gitignore", ".env", ".npmrc", "dockerfile", "compose.yml", "compose.yaml",
}


class RateLimiter:
    def __init__(self, min_interval_seconds: float):
        self.min_interval_seconds = min_interval_seconds
        self._lock = threading.Lock()
        self._last_request_at = 0.0

    def wait_for_slot(self) -> None:
        with self._lock:
            now = time.time()
            delta = now - self._last_request_at
            wait = self.min_interval_seconds - delta
            if wait > 0:
                time.sleep(wait)
            self._last_request_at = time.time()


class GitHubApiClient:
    def __init__(
        self,
        token: Optional[str] = None,
        timeout: int = 25,
        requests_per_minute: Optional[int] = None,
        max_retries: int = 6,
    ):
        self.base_url = "https://api.github.com"
        self.session = requests.Session()
        self.timeout = timeout
        self.max_retries = max_retries
        self.authenticated = bool(token)
        self.secondary_limit_cooldown_until = 0.0

        headers = {
            "Accept": "application/vnd.github+json, application/vnd.github.text-match+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "Github Recon Scanner/1.0",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self.session.headers.update(headers)

        self.core_rpm = self._resolve_safe_rpm(
            requested_rpm=requests_per_minute,
            safe_default=(SAFE_CORE_RPM_AUTHENTICATED if self.authenticated else SAFE_CORE_RPM_UNAUTHENTICATED),
            label="core",
        )
        self.search_rpm = self._resolve_safe_rpm(
            requested_rpm=requests_per_minute,
            safe_default=(SAFE_SEARCH_RPM_AUTHENTICATED if self.authenticated else SAFE_SEARCH_RPM_UNAUTHENTICATED),
            label="search",
        )
        self.rate_limiter = RateLimiter(min_interval_seconds=max(0.05, 60.0 / max(1, self.core_rpm)))
        self.search_rate_limiter = RateLimiter(min_interval_seconds=max(0.05, 60.0 / max(1, self.search_rpm)))

    def _resolve_safe_rpm(self, requested_rpm: Optional[int], safe_default: int, label: str) -> int:
        if requested_rpm is None:
            return safe_default
        rpm = max(1, int(requested_rpm))
        if rpm > safe_default:
            LOG.warning(
                "Requested %s rpm=%s exceeds the safe cap of %s for %s API calls. "
                "Clamping to %s to reduce GitHub throttling risk.",
                label,
                rpm,
                safe_default,
                "authenticated" if self.authenticated else "unauthenticated",
                safe_default,
            )
            return safe_default
        return rpm

    def _selected_limiter(self, path: str) -> RateLimiter:
        return self.search_rate_limiter if path.startswith("/search/") else self.rate_limiter

    def _wait_for_secondary_limit_cooldown(self) -> None:
        wait_for = self.secondary_limit_cooldown_until - time.time()
        if wait_for > 0:
            LOG.warning("Cooling down for %.2fs after GitHub secondary throttling.", wait_for)
            time.sleep(wait_for)

    def get_rate_limit(self) -> Dict[str, Any]:
        return self._request("GET", "/rate_limit")

    def get_token_scopes(self) -> List[str]:
        if not self.authenticated:
            return []
        self.rate_limiter.wait_for_slot()
        resp = self.session.get(f"{self.base_url}/rate_limit", timeout=self.timeout)
        scopes_header = resp.headers.get("X-OAuth-Scopes", "")
        scopes = [s.strip() for s in scopes_header.split(",") if s.strip()]
        return scopes

    def _sleep_until_reset(self, reset_epoch: int) -> None:
        now = int(time.time())
        wait_for = max(0, reset_epoch - now + 1)
        if wait_for > 0:
            reset_dt = datetime.fromtimestamp(reset_epoch, tz=timezone.utc).isoformat()
            LOG.warning("Rate limit exhausted. Sleeping %ss until reset at %s", wait_for, reset_dt)
            time.sleep(wait_for)

    def _request(self, method: str, path: str, **kwargs) -> Dict[str, Any]:
        url = path if path.startswith("http") else f"{self.base_url}{path}"
        limiter = self._selected_limiter(path)
        for attempt in range(self.max_retries + 1):
            self._wait_for_secondary_limit_cooldown()
            limiter.wait_for_slot()
            try:
                resp = self.session.request(method, url, timeout=self.timeout, **kwargs)
            except requests.RequestException as exc:
                raise ScannerNetworkError(
                    f"Unable to reach the GitHub API while requesting '{path}'. "
                    "Check network connectivity and try again."
                ) from exc
            remaining = resp.headers.get("X-RateLimit-Remaining")
            reset_at = resp.headers.get("X-RateLimit-Reset")
            if remaining == "0" and reset_at:
                self._sleep_until_reset(int(reset_at))
                continue

            if resp.status_code in (403, 429):
                msg = ""
                try:
                    payload = resp.json()
                    msg = (payload.get("message") or "").lower()
                except Exception:
                    pass
                retry_after = int(resp.headers.get("Retry-After", "0") or 0)
                if "secondary rate limit" in msg or resp.status_code == 429 or retry_after:
                    sleep_s = retry_after or min(120, (2**attempt) + random.uniform(0.0, 1.5))
                    self.secondary_limit_cooldown_until = max(self.secondary_limit_cooldown_until, time.time() + sleep_s)
                    LOG.warning(
                        "Secondary/abuse throttling received (status=%s). Backing off %.2fs (attempt %s/%s)",
                        resp.status_code,
                        sleep_s,
                        attempt + 1,
                        self.max_retries + 1,
                    )
                    time.sleep(sleep_s)
                    continue

            if 200 <= resp.status_code < 300:
                if resp.content:
                    return resp.json()
                return {}

            if resp.status_code == 401:
                raise GitHubApiError(
                    "Authentication failed (401 Bad credentials). "
                    "Check your GitHub token or run without --token."
                )

            if resp.status_code >= 500 and attempt < self.max_retries:
                sleep_s = min(60, (2**attempt) + random.uniform(0.0, 1.0))
                LOG.warning("GitHub server error %s. Retrying in %.2fs", resp.status_code, sleep_s)
                time.sleep(sleep_s)
                continue

            try:
                err_payload = resp.json()
            except Exception:
                err_payload = {"message": resp.text[:300]}
            raise self._build_api_error(path, resp.status_code, err_payload)

        raise GitHubApiError("GitHub API request failed after multiple retries. Please try again later.")

    def _build_api_error(self, path: str, status_code: int, err_payload: Dict[str, Any]) -> GitHubApiError:
        message = str(err_payload.get("message") or "").strip()

        if status_code == 404:
            if path.startswith("/orgs/") and path.endswith("/repos"):
                org = path[len("/orgs/") : -len("/repos")].strip("/")
                return GitHubTargetNotFoundError(
                    f"GitHub organization '{org}' was not found or is not accessible."
                )
            if path.startswith("/users/") and path.endswith("/repos"):
                user = path[len("/users/") : -len("/repos")].strip("/")
                return GitHubTargetNotFoundError(
                    f"GitHub user '{user}' was not found or has no accessible public repositories."
                )
            if "/repos/" in path:
                repo = path.split("/repos/", 1)[1].strip("/")
                return GitHubTargetNotFoundError(
                    f"GitHub repository '{repo}' was not found or is not accessible."
                )

        if status_code == 403 and message:
            return GitHubApiError(f"GitHub API access denied (403): {message}")

        if message:
            return GitHubApiError(f"GitHub API error {status_code}: {message}")
        return GitHubApiError(f"GitHub API error {status_code}.")

    def list_org_repos(self, org: str) -> List[str]:
        return self._paginate_repo_names(f"/orgs/{org}/repos", params={"type": "public", "per_page": 100})

    def list_user_repos(self, user: str) -> List[str]:
        return self._paginate_repo_names(f"/users/{user}/repos", params={"type": "owner", "per_page": 100})

    def _paginate_repo_names(self, path: str, params: Dict[str, Any]) -> List[str]:
        page = 1
        repos: List[str] = []
        while True:
            p = dict(params)
            p["page"] = page
            data = self._request("GET", path, params=p)
            if not isinstance(data, list) or not data:
                break
            repos.extend([r["full_name"] for r in data if "full_name" in r])
            page += 1
        return repos

    def search_repos_by_domain(self, domain: str, limit: int = 100) -> List[str]:
        repos: List[str] = []
        page = 1
        while len(repos) < limit:
            q = f'"{domain}" in:name,description,readme'
            data = self._request("GET", "/search/repositories", params={"q": q, "per_page": 100, "page": page})
            items = data.get("items", [])
            if not items:
                break
            repos.extend([it["full_name"] for it in items if "full_name" in it])
            if len(items) < 100:
                break
            page += 1
        return list(dict.fromkeys(repos))[:limit]

    def search_code(self, query: str, per_page: int = 50, page: int = 1) -> Dict[str, Any]:
        return self._request(
            "GET",
            "/search/code",
            params={"q": query, "per_page": per_page, "page": page},
        )

    def get_file_content(self, repo_full_name: str, path: str, ref: Optional[str] = None) -> str:
        params = {"ref": ref} if ref else {}
        data = self._request("GET", f"/repos/{repo_full_name}/contents/{path}", params=params)
        content = data.get("content")
        if not content:
            return ""
        encoding = data.get("encoding")
        if encoding == "base64":
            return base64.b64decode(content).decode("utf-8", errors="replace")
        return str(content)

    def get_repo(self, repo_full_name: str) -> Dict[str, Any]:
        return self._request("GET", f"/repos/{repo_full_name}")

    def get_branch(self, repo_full_name: str, branch: str) -> Dict[str, Any]:
        return self._request("GET", f"/repos/{repo_full_name}/branches/{branch}")

    def get_repo_tree(self, repo_full_name: str, recursive: bool = True) -> List[Dict[str, Any]]:
        repo = self.get_repo(repo_full_name)
        default_branch = repo.get("default_branch") or "HEAD"
        branch_data = self.get_branch(repo_full_name, default_branch)
        tree_sha = (((branch_data.get("commit") or {}).get("commit") or {}).get("tree") or {}).get("sha")
        if not tree_sha:
            return []
        params = {"recursive": 1} if recursive else {}
        tree_data = self._request("GET", f"/repos/{repo_full_name}/git/trees/{tree_sha}", params=params)
        return tree_data.get("tree", []) or []

    def list_repo_commits(
        self,
        repo_full_name: str,
        per_page: int = 100,
        page: int = 1,
        since: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {"per_page": per_page, "page": page}
        if since:
            params["since"] = since
        return self._request(
            "GET",
            f"/repos/{repo_full_name}/commits",
            params=params,
        )

    def get_commit(self, repo_full_name: str, sha: str) -> Dict[str, Any]:
        return self._request("GET", f"/repos/{repo_full_name}/commits/{sha}")

    def list_repo_pull_requests(
        self,
        repo_full_name: str,
        state: str = "all",
        sort: str = "updated",
        direction: str = "desc",
        per_page: int = 100,
        page: int = 1,
    ) -> List[Dict[str, Any]]:
        return self._request(
            "GET",
            f"/repos/{repo_full_name}/pulls",
            params={
                "state": state,
                "sort": sort,
                "direction": direction,
                "per_page": per_page,
                "page": page,
            },
        )

    def list_pull_request_files(
        self,
        repo_full_name: str,
        pull_number: int,
        per_page: int = 100,
    ) -> List[Dict[str, Any]]:
        page = 1
        files: List[Dict[str, Any]] = []
        while True:
            batch = self._request(
                "GET",
                f"/repos/{repo_full_name}/pulls/{pull_number}/files",
                params={"per_page": per_page, "page": page},
            )
            if not isinstance(batch, list) or not batch:
                break
            files.extend(batch)
            if len(batch) < per_page:
                break
            page += 1
        return files

    def list_repo_issues(
        self,
        repo_full_name: str,
        state: str = "all",
        sort: str = "updated",
        direction: str = "desc",
        per_page: int = 100,
        page: int = 1,
    ) -> List[Dict[str, Any]]:
        return self._request(
            "GET",
            f"/repos/{repo_full_name}/issues",
            params={
                "state": state,
                "sort": sort,
                "direction": direction,
                "per_page": per_page,
                "page": page,
            },
        )

    def list_issue_comments(
        self,
        repo_full_name: str,
        issue_number: int,
        per_page: int = 100,
        page: int = 1,
    ) -> List[Dict[str, Any]]:
        return self._request(
            "GET",
            f"/repos/{repo_full_name}/issues/{issue_number}/comments",
            params={"per_page": per_page, "page": page},
        )

    def list_pull_request_review_comments(
        self,
        repo_full_name: str,
        pull_number: int,
        per_page: int = 100,
        page: int = 1,
    ) -> List[Dict[str, Any]]:
        return self._request(
            "GET",
            f"/repos/{repo_full_name}/pulls/{pull_number}/comments",
            params={"per_page": per_page, "page": page},
        )

    def list_repo_releases(
        self,
        repo_full_name: str,
        per_page: int = 100,
        page: int = 1,
    ) -> List[Dict[str, Any]]:
        return self._request(
            "GET",
            f"/repos/{repo_full_name}/releases",
            params={"per_page": per_page, "page": page},
        )


def parse_github_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def normalize_domain(value: str) -> str:
    domain = str(value or "").strip().lower()
    if domain.startswith("*."):
        domain = domain[2:]
    return domain.strip(".")


def build_subdomain_regex(domain: str) -> Any:
    escaped_domain = re.escape(normalize_domain(domain))
    return re.compile(
        rf"(?i)\b((?:[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?\.)+{escaped_domain})\b"
    )


def extract_subdomains_from_text(text: str, domain: str) -> List[str]:
    normalized_domain = normalize_domain(domain)
    if not normalized_domain:
        return []
    regex = build_subdomain_regex(normalized_domain)
    matches = {m.group(1).lower().rstrip(".") for m in regex.finditer(str(text or ""))}
    return sorted([m for m in matches if m != normalized_domain])


def is_probably_text_path(path: str) -> bool:
    p = Path(str(path or ""))
    suffix = p.suffix.lower()
    if suffix in TEXT_LIKE_FILE_EXTENSIONS:
        return True
    name = p.name.lower()
    stem = p.stem.lower()
    if name in TEXT_LIKE_FILENAMES or stem in TEXT_LIKE_FILENAMES:
        return True
    return "." not in name


def finding_sort_key(finding: Dict[str, Any]) -> Tuple[float, int]:
    observed_at = parse_github_datetime(finding.get("observed_at"))
    timestamp = observed_at.timestamp() if observed_at else 0.0
    score = int(finding.get("score", 0))
    return (timestamp, score)


class GithubReconScanner:
    def __init__(
        self,
        client: GitHubApiClient,
        rules: List[PatternRule],
        use_regex_query: bool = False,
        regex_grep: bool = True,
        scan_commits: bool = True,
        scan_all_files: bool = False,
        max_files_per_repo: int = 5000,
        max_file_size_bytes: int = 1000000,
        max_commits_per_repo: int = 30,
        scan_pull_requests: bool = True,
        max_pull_requests_per_repo: int = 20,
        scan_collaboration_text: bool = True,
        max_issues_per_repo: int = 30,
        max_releases_per_repo: int = 20,
        max_results_per_query: int = 100,
        max_file_fetches: int = 40,
        stream_to_stdout: bool = True,
        min_score: int = 75,
        strict_mode: bool = True,
        fresh_since: Optional[datetime] = None,
    ):
        self.client = client
        self.rules = rules
        self.compiled_rules: List[Tuple[PatternRule, Any]] = [(r, r.compile()) for r in rules]
        self.use_regex_query = use_regex_query
        self.regex_grep = regex_grep
        self.scan_commits = scan_commits
        self.scan_all_files = scan_all_files
        self.max_files_per_repo = max_files_per_repo
        self.max_file_size_bytes = max_file_size_bytes
        self.max_commits_per_repo = max_commits_per_repo
        self.scan_pull_requests = scan_pull_requests
        self.max_pull_requests_per_repo = max_pull_requests_per_repo
        self.scan_collaboration_text = scan_collaboration_text
        self.max_issues_per_repo = max_issues_per_repo
        self.max_releases_per_repo = max_releases_per_repo
        self.max_results_per_query = max_results_per_query
        self.max_file_fetches = max_file_fetches
        self.stream_to_stdout = stream_to_stdout
        self.min_score = min_score
        self.strict_mode = strict_mode
        self.fresh_since = fresh_since.astimezone(timezone.utc) if fresh_since else None
        self._stream_seen_urls: set = set()
        self._seen_finding_keys: set = set()
        self._last_subdomain_results: List[Dict[str, Any]] = []

    def _is_fresh(self, dt_value: Optional[str]) -> bool:
        if not self.fresh_since:
            return True
        dt = parse_github_datetime(dt_value)
        if not dt:
            return False
        return dt >= self.fresh_since

    def _normalize_match(self, value: Any) -> str:
        return re.sub(r"\s+", "", str(value or "").strip().lower())

    def _possible_contains(self, rule_name: str) -> str:
        mapping = {
            "AWS Access Key ID": "AWS access identifier",
            "AWS Secret Access Key": "AWS secret access key",
            "GitHub PAT": "GitHub personal access token",
            "Stripe Live Key": "Stripe live secret key",
            "Slack Webhook": "Slack incoming webhook URL",
            "Google API Key": "Google API key",
            "JWT": "Bearer/JWT authentication token",
            "SSH Private Key Header": "Private SSH key material",
            "Database Credential Indicators": "Database credentials/connection secret",
            "Common Secret Assignment": "Hardcoded secret/password/token value",
        }
        return mapping.get(rule_name, "Potential credential or secret")

    def _likely_false_positive(self, finding: Dict[str, Any]) -> bool:
        rule = str(finding.get("rule", ""))
        line = str(finding.get("matched_line", "")).lower()
        value = str(finding.get("matched_value", ""))
        path = str(finding.get("path", "")).lower()

        noisy_terms = ("example", "dummy", "sample", "fake", "placeholder", "changeme", "test", "mock")
        high_conf_rules = {
            "AWS Access Key ID",
            "GitHub PAT",
            "Stripe Live Key",
            "Slack Webhook",
            "Google API Key",
            "SSH Private Key Header",
        }
        if rule not in high_conf_rules and any(t in line for t in noisy_terms):
            return True

        if rule == "JWT":
            if value.count(".") != 2 or len(value) < 30:
                return True
            # Try to decode header to reduce random token-like strings.
            try:
                header = value.split(".")[0]
                pad = "=" * ((4 - len(header) % 4) % 4)
                decoded = b64.urlsafe_b64decode((header + pad).encode("utf-8")).decode("utf-8", errors="ignore").lower()
                if "alg" not in decoded and "typ" not in decoded:
                    return True
            except Exception:
                return True

        if rule == "Common Secret Assignment":
            raw = value.strip("'\" ")
            if len(raw) < 12:
                return True
            if raw.lower() in {"password", "secret", "token", "apikey"}:
                return True
            has_alpha = any(c.isalpha() for c in raw)
            has_digit = any(c.isdigit() for c in raw)
            if not (has_alpha and has_digit):
                return True
            if re.fullmatch(r"[a-f0-9]{12,}", raw.lower()):
                return True

        if rule == "Database Credential Indicators":
            if "://" not in value or "@" not in value:
                return True
            if "localhost" in value.lower() or "127.0.0.1" in value:
                return True

        if rule == "AWS Access Key ID":
            if "AKIAIOSFODNN7EXAMPLE" in value:
                return True

        if rule == "AWS Secret Access Key":
            if "example" in line or "sample" in line:
                return True
            # Generic 40-char base64-like strings need AWS context in strict mode.
            aws_context = ("aws", "access_key", "secret_key", "credentials")
            if self.strict_mode and not any(ctx in line for ctx in aws_context):
                return True

        if rule == "Google API Key":
            if "example" in line or "your_key_here" in line:
                return True

        if rule == "Slack Webhook":
            if value.endswith("/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"):
                return True

        # Ignore obvious docs/examples locations unless high-confidence rule.
        if rule not in high_conf_rules and any(p in path for p in ("/docs/", "/examples/", "/test/", "/tests/")):
            return True

        return False

    def _build_finding_key(self, finding: Dict[str, Any]) -> str:
        url = build_finding_url(finding)
        normalized = self._normalize_match(finding.get("matched_value"))
        return f'{finding.get("rule")}|{url}|{normalized}'

    def _emit_finding(self, findings: List[Dict[str, Any]], finding: Dict[str, Any]) -> None:
        finding["possible_contains"] = self._possible_contains(str(finding.get("rule", "")))
        finding["why_flagged"] = (
            f"Matched {finding.get('rule')} pattern with score {finding.get('score')}"
        )
        score = int(finding.get("score", 0))
        if score < self.min_score:
            return
        if self._likely_false_positive(finding):
            return
        dedup_key = self._build_finding_key(finding)
        if dedup_key in self._seen_finding_keys:
            return
        self._seen_finding_keys.add(dedup_key)
        findings.append(finding)
        if not self.stream_to_stdout:
            return
        url = build_finding_url(finding)
        if not url or url in self._stream_seen_urls:
            return
        self._stream_seen_urls.add(url)
        print(url, flush=True)

    def build_queries_for_repo(self, repo_full_name: str) -> List[Tuple[str, PatternRule]]:
        queries: List[Tuple[str, PatternRule]] = []
        for rule in self.rules:
            for lit in rule.literals[:2]:
                query = f'repo:{repo_full_name} "{lit}"'
                queries.append((query, rule))
            if self.use_regex_query and rule.regex:
                query = f"repo:{repo_full_name} /{rule.regex}/"
                queries.append((query, rule))

        for indicator in COMMON_FILENAME_INDICATORS:
            q = f'repo:{repo_full_name} filename:"{indicator.split("/")[-1]}"'
            queries.append((q, PatternRule(name="Filename Indicator", literals=[indicator], severity=45)))

        unique: Dict[str, PatternRule] = {}
        for q, r in queries:
            unique.setdefault(q, r)
        return list(unique.items())

    def score_match(self, rule: PatternRule, line: str) -> int:
        score = rule.severity
        lowered = line.lower()
        boost_terms = ["secret", "token", "password", "private", "key", "authorization"]
        for term in boost_terms:
            if term in lowered:
                score += 4
        if "example" in lowered or "dummy" in lowered or "test" in lowered:
            score -= 18
        return max(1, min(100, score))

    def extract_candidate_lines(self, item: Dict[str, Any], repo: str) -> List[str]:
        fragments: List[str] = []
        for tm in item.get("text_matches", []):
            frag = tm.get("fragment")
            if frag:
                fragments.extend(frag.splitlines())
        if fragments and not self.regex_grep:
            return fragments

        if self.max_file_fetches <= 0:
            return fragments
        try:
            text = self.client.get_file_content(repo, item.get("path", ""))
            self.max_file_fetches -= 1
            return text.splitlines() if text else fragments
        except Exception as exc:
            LOG.debug("Unable to fetch file content for %s/%s: %s", repo, item.get("path"), exc)
            return fragments

    def grep_matches(self, line: str, rule: PatternRule, compiled: Any) -> List[str]:
        if compiled:
            matches: List[str] = []
            try:
                for m in compiled.finditer(line):
                    matches.append(m.group(0))
            except Exception:
                if compiled.search(line):
                    matches.append(line.strip())
            return matches
        if any(l in line for l in rule.literals):
            return [line.strip()]
        return []

    def _scan_commit_history(self, repo_full_name: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if self.max_commits_per_repo <= 0:
            return findings

        commits_processed = 0
        page = 1
        since_iso = self.fresh_since.isoformat() if self.fresh_since else None
        while commits_processed < self.max_commits_per_repo:
            commits = self.client.list_repo_commits(repo_full_name, per_page=100, page=page, since=since_iso)
            if not commits:
                break
            stop_early = False
            for commit_stub in commits:
                if commits_processed >= self.max_commits_per_repo:
                    break
                commit_date = (((commit_stub.get("commit") or {}).get("committer") or {}).get("date")
                               or ((commit_stub.get("commit") or {}).get("author") or {}).get("date"))
                if self.fresh_since and not self._is_fresh(commit_date):
                    stop_early = True
                    break
                sha = commit_stub.get("sha")
                if not sha:
                    continue
                commits_processed += 1
                try:
                    commit_data = self.client.get_commit(repo_full_name, sha)
                except Exception as exc:
                    LOG.debug("Commit fetch failed for %s@%s: %s", repo_full_name, sha, exc)
                    continue

                commit_html_url = commit_data.get("html_url")
                commit_message = (commit_data.get("commit", {}) or {}).get("message", "")
                commit_observed_at = (((commit_data.get("commit") or {}).get("committer") or {}).get("date")
                                      or ((commit_data.get("commit") or {}).get("author") or {}).get("date")
                                      or commit_date)
                if self.fresh_since and not self._is_fresh(commit_observed_at):
                    continue
                files = commit_data.get("files", []) or []

                for file_obj in files:
                    patch = file_obj.get("patch") or ""
                    if not patch:
                        continue
                    path = file_obj.get("filename", "")
                    for patch_line_no, patch_line in enumerate(patch.splitlines(), start=1):
                        # Grep only added lines and ignore diff metadata lines like +++
                        if not patch_line.startswith("+") or patch_line.startswith("+++"):
                            continue
                        line = patch_line[1:]
                        for rule, compiled in self.compiled_rules:
                            matched_values = self.grep_matches(line, rule, compiled)
                            for matched_value in matched_values:
                                self._emit_finding(findings, {
                                        "repo": repo_full_name,
                                        "path": path,
                                        "blob_sha": file_obj.get("sha"),
                                        "commit_sha": sha,
                                        "rule": rule.name,
                                        "query_rule": "Commit Patch Regex Grep",
                                        "score": self.score_match(rule, line),
                                        "line_number": None,
                                        "patch_line_number": patch_line_no,
                                        "matched_line": line.strip()[:500],
                                        "matched_value": matched_value[:300],
                                        "query": "commit_patch",
                                        "html_url": commit_html_url,
                                        "commit_message": commit_message[:500],
                                        "observed_at": commit_observed_at,
                                    })
            if stop_early:
                break
            if len(commits) < 100:
                break
            page += 1
        return findings

    def _scan_pull_requests(self, repo_full_name: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if self.max_pull_requests_per_repo <= 0:
            return findings

        prs_processed = 0
        page = 1
        while prs_processed < self.max_pull_requests_per_repo:
            prs = self.client.list_repo_pull_requests(
                repo_full_name,
                state="all",
                sort="updated",
                direction="desc",
                per_page=100,
                page=page,
            )
            if not prs:
                break
            stop_early = False
            for pr in prs:
                if prs_processed >= self.max_pull_requests_per_repo:
                    break
                pr_updated_at = pr.get("updated_at") or pr.get("created_at")
                if self.fresh_since and not self._is_fresh(pr_updated_at):
                    stop_early = True
                    break
                pull_number = pr.get("number")
                if not pull_number:
                    continue
                prs_processed += 1
                try:
                    files = self.client.list_pull_request_files(repo_full_name, int(pull_number))
                except Exception as exc:
                    LOG.debug("Pull request files fetch failed for %s#%s: %s", repo_full_name, pull_number, exc)
                    continue

                pr_html_url = pr.get("html_url")
                pr_title = str(pr.get("title") or "")
                for file_obj in files:
                    patch = file_obj.get("patch") or ""
                    if not patch:
                        continue
                    path = file_obj.get("filename", "")
                    for patch_line_no, patch_line in enumerate(patch.splitlines(), start=1):
                        if not patch_line.startswith("+") or patch_line.startswith("+++"):
                            continue
                        line = patch_line[1:]
                        for rule, compiled in self.compiled_rules:
                            matched_values = self.grep_matches(line, rule, compiled)
                            for matched_value in matched_values:
                                self._emit_finding(findings, {
                                        "repo": repo_full_name,
                                        "path": path,
                                        "blob_sha": file_obj.get("sha"),
                                        "commit_sha": (pr.get("head") or {}).get("sha"),
                                        "pr_number": pull_number,
                                        "rule": rule.name,
                                        "query_rule": "Pull Request Patch Regex Grep",
                                        "score": self.score_match(rule, line),
                                        "line_number": None,
                                        "patch_line_number": patch_line_no,
                                        "matched_line": line.strip()[:500],
                                        "matched_value": matched_value[:300],
                                        "query": "pull_request_patch",
                                        "html_url": pr_html_url,
                                        "pr_title": pr_title[:500],
                                        "observed_at": pr_updated_at,
                                    })
            if stop_early:
                break
            if len(prs) < 100:
                break
            page += 1
        return findings

    def _scan_text_lines(
        self,
        findings: List[Dict[str, Any]],
        repo_full_name: str,
        path: str,
        text: str,
        query_rule: str,
        html_url: str,
        observed_at: Optional[str],
        commit_sha: Optional[str] = None,
        pr_number: Optional[int] = None,
        issue_number: Optional[int] = None,
    ) -> None:
        if not text:
            return
        for line_no, line in enumerate(str(text).splitlines(), start=1):
            for rule, compiled in self.compiled_rules:
                matched_values = self.grep_matches(line, rule, compiled)
                for matched_value in matched_values:
                    self._emit_finding(findings, {
                            "repo": repo_full_name,
                            "path": path,
                            "blob_sha": None,
                            "commit_sha": commit_sha,
                            "pr_number": pr_number,
                            "issue_number": issue_number,
                            "rule": rule.name,
                            "query_rule": query_rule,
                            "score": self.score_match(rule, line),
                            "line_number": line_no,
                            "patch_line_number": None,
                            "matched_line": line.strip()[:500],
                            "matched_value": matched_value[:300],
                            "query": "collaboration_text",
                            "html_url": html_url,
                            "observed_at": observed_at,
                        })

    def _scan_pull_request_text(self, repo_full_name: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if self.max_pull_requests_per_repo <= 0:
            return findings
        prs_processed = 0
        page = 1
        while prs_processed < self.max_pull_requests_per_repo:
            prs = self.client.list_repo_pull_requests(
                repo_full_name,
                state="all",
                sort="updated",
                direction="desc",
                per_page=100,
                page=page,
            )
            if not prs:
                break
            stop_early = False
            for pr in prs:
                if prs_processed >= self.max_pull_requests_per_repo:
                    break
                pr_updated_at = pr.get("updated_at") or pr.get("created_at")
                if self.fresh_since and not self._is_fresh(pr_updated_at):
                    stop_early = True
                    break
                pull_number = pr.get("number")
                if not pull_number:
                    continue
                prs_processed += 1
                pr_html_url = pr.get("html_url") or ""
                self._scan_text_lines(
                    findings,
                    repo_full_name,
                    f"PR#{pull_number}:title",
                    str(pr.get("title") or ""),
                    "Pull Request Title",
                    pr_html_url,
                    pr_updated_at,
                    commit_sha=(pr.get("head") or {}).get("sha"),
                    pr_number=pull_number,
                )
                self._scan_text_lines(
                    findings,
                    repo_full_name,
                    f"PR#{pull_number}:body",
                    str(pr.get("body") or ""),
                    "Pull Request Description",
                    pr_html_url,
                    pr_updated_at,
                    commit_sha=(pr.get("head") or {}).get("sha"),
                    pr_number=pull_number,
                )
                comment_page = 1
                while True:
                    comments = self.client.list_issue_comments(
                        repo_full_name,
                        int(pull_number),
                        per_page=100,
                        page=comment_page,
                    )
                    if not comments:
                        break
                    for comment in comments:
                        comment_updated = comment.get("updated_at") or comment.get("created_at") or pr_updated_at
                        if self.fresh_since and not self._is_fresh(comment_updated):
                            continue
                        self._scan_text_lines(
                            findings,
                            repo_full_name,
                            f"PR#{pull_number}:conversation-comment",
                            str(comment.get("body") or ""),
                            "Pull Request Conversation Comment",
                            str(comment.get("html_url") or pr_html_url),
                            comment_updated,
                            commit_sha=(pr.get("head") or {}).get("sha"),
                            pr_number=pull_number,
                        )
                    if len(comments) < 100:
                        break
                    comment_page += 1

                review_page = 1
                while True:
                    comments = self.client.list_pull_request_review_comments(
                        repo_full_name,
                        int(pull_number),
                        per_page=100,
                        page=review_page,
                    )
                    if not comments:
                        break
                    for comment in comments:
                        comment_updated = comment.get("updated_at") or comment.get("created_at") or pr_updated_at
                        if self.fresh_since and not self._is_fresh(comment_updated):
                            continue
                        self._scan_text_lines(
                            findings,
                            repo_full_name,
                            f"PR#{pull_number}:review-comment",
                            str(comment.get("body") or ""),
                            "Pull Request Review Comment",
                            str(comment.get("html_url") or pr_html_url),
                            comment_updated,
                            commit_sha=(pr.get("commit_id") or (pr.get("head") or {}).get("sha")),
                            pr_number=pull_number,
                        )
                    if len(comments) < 100:
                        break
                    review_page += 1
            if stop_early:
                break
            if len(prs) < 100:
                break
            page += 1
        return findings

    def _scan_issue_text(self, repo_full_name: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if self.max_issues_per_repo <= 0:
            return findings
        issues_processed = 0
        page = 1
        while issues_processed < self.max_issues_per_repo:
            issues = self.client.list_repo_issues(
                repo_full_name,
                state="all",
                sort="updated",
                direction="desc",
                per_page=100,
                page=page,
            )
            if not issues:
                break
            stop_early = False
            for issue in issues:
                if issues_processed >= self.max_issues_per_repo:
                    break
                # /issues endpoint includes PRs; skip those here.
                if issue.get("pull_request"):
                    continue
                issue_updated = issue.get("updated_at") or issue.get("created_at")
                if self.fresh_since and not self._is_fresh(issue_updated):
                    stop_early = True
                    break
                issue_number = issue.get("number")
                if not issue_number:
                    continue
                issues_processed += 1
                issue_html_url = issue.get("html_url") or ""
                self._scan_text_lines(
                    findings,
                    repo_full_name,
                    f"Issue#{issue_number}:title",
                    str(issue.get("title") or ""),
                    "Issue Title",
                    issue_html_url,
                    issue_updated,
                    issue_number=issue_number,
                )
                self._scan_text_lines(
                    findings,
                    repo_full_name,
                    f"Issue#{issue_number}:body",
                    str(issue.get("body") or ""),
                    "Issue Description",
                    issue_html_url,
                    issue_updated,
                    issue_number=issue_number,
                )
                comment_page = 1
                while True:
                    comments = self.client.list_issue_comments(
                        repo_full_name,
                        int(issue_number),
                        per_page=100,
                        page=comment_page,
                    )
                    if not comments:
                        break
                    for comment in comments:
                        comment_updated = comment.get("updated_at") or comment.get("created_at") or issue_updated
                        if self.fresh_since and not self._is_fresh(comment_updated):
                            continue
                        self._scan_text_lines(
                            findings,
                            repo_full_name,
                            f"Issue#{issue_number}:comment",
                            str(comment.get("body") or ""),
                            "Issue Comment",
                            str(comment.get("html_url") or issue_html_url),
                            comment_updated,
                            issue_number=issue_number,
                        )
                    if len(comments) < 100:
                        break
                    comment_page += 1
            if stop_early:
                break
            if len(issues) < 100:
                break
            page += 1
        return findings

    def _scan_release_notes(self, repo_full_name: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if self.max_releases_per_repo <= 0:
            return findings
        releases_processed = 0
        page = 1
        while releases_processed < self.max_releases_per_repo:
            releases = self.client.list_repo_releases(repo_full_name, per_page=100, page=page)
            if not releases:
                break
            for release in releases:
                if releases_processed >= self.max_releases_per_repo:
                    break
                release_date = release.get("published_at") or release.get("created_at")
                if self.fresh_since and not self._is_fresh(release_date):
                    continue
                releases_processed += 1
                release_html_url = release.get("html_url") or ""
                release_name = str(release.get("name") or release.get("tag_name") or "")
                self._scan_text_lines(
                    findings,
                    repo_full_name,
                    f"Release:{release_name or 'untitled'}:name",
                    release_name,
                    "Release Name",
                    release_html_url,
                    release_date,
                )
                self._scan_text_lines(
                    findings,
                    repo_full_name,
                    f"Release:{release_name or 'untitled'}:notes",
                    str(release.get("body") or ""),
                    "Release Notes",
                    release_html_url,
                    release_date,
                )
            if len(releases) < 100:
                break
            page += 1
        return findings

    def _scan_all_files(self, repo_full_name: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        try:
            repo_meta = self.client.get_repo(repo_full_name)
            default_branch = repo_meta.get("default_branch") or "HEAD"
            tree = self.client.get_repo_tree(repo_full_name, recursive=True)
        except Exception as exc:
            LOG.error("Failed to enumerate repository tree for %s: %s", repo_full_name, exc)
            return findings

        blobs = [n for n in tree if n.get("type") == "blob"]
        if self.max_files_per_repo > 0:
            blobs = blobs[: self.max_files_per_repo]

        LOG.info("Scanning full file set for %s: %d files", repo_full_name, len(blobs))
        for file_obj in blobs:
            path = file_obj.get("path", "")
            size = int(file_obj.get("size") or 0)
            if size > self.max_file_size_bytes:
                continue
            try:
                content = self.client.get_file_content(repo_full_name, path, ref=default_branch)
            except Exception as exc:
                LOG.debug("Skipping unreadable file %s/%s: %s", repo_full_name, path, exc)
                continue
            if not content:
                continue
            for line_no, line in enumerate(content.splitlines(), start=1):
                for rule, compiled in self.compiled_rules:
                    matched_values = self.grep_matches(line, rule, compiled)
                    for matched_value in matched_values:
                        self._emit_finding(findings, {
                                "repo": repo_full_name,
                                "path": path,
                                "blob_sha": file_obj.get("sha"),
                                "commit_sha": None,
                                "rule": rule.name,
                                "query_rule": "Full Repository File Scan",
                                "score": self.score_match(rule, line),
                                "line_number": line_no,
                                "patch_line_number": None,
                                "matched_line": line.strip()[:500],
                                "matched_value": matched_value[:300],
                                "query": "full_file_scan",
                                "html_url": f"https://github.com/{repo_full_name}/blob/{default_branch}/{path}",
                            })
        return findings

    def scan_repo(self, repo_full_name: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if self.scan_all_files:
            findings.extend(self._scan_all_files(repo_full_name))
        else:
            queries = self.build_queries_for_repo(repo_full_name)
            LOG.info("Scanning repo %s with %d search queries", repo_full_name, len(queries))

            for query, query_rule in queries:
                page = 1
                seen_item_keys = set()
                while True:
                    data = self.client.search_code(query, per_page=50, page=page)
                    items = data.get("items", [])
                    if not items:
                        break
                    for item in items:
                        item_key = f'{item.get("repository", {}).get("full_name","")}|{item.get("path","")}|{item.get("sha","")}'
                        if item_key in seen_item_keys:
                            continue
                        seen_item_keys.add(item_key)

                        repo = item.get("repository", {}).get("full_name", repo_full_name)
                        path = item.get("path", "")
                        lines = self.extract_candidate_lines(item, repo)
                        if not lines:
                            continue

                        for line_no, line in enumerate(lines, start=1):
                            for rule, compiled in self.compiled_rules:
                                matched_values = self.grep_matches(line, rule, compiled)
                                for matched_value in matched_values:
                                    self._emit_finding(findings, {
                                            "repo": repo,
                                            "path": path,
                                            "blob_sha": item.get("sha"),
                                            "commit_sha": None,
                                            "rule": rule.name,
                                            "query_rule": query_rule.name,
                                            "score": self.score_match(rule, line),
                                            "line_number": line_no,
                                            "matched_line": line.strip()[:500],
                                            "matched_value": matched_value[:300],
                                            "query": query,
                                            "html_url": item.get("html_url"),
                                        })
                    if len(items) < 50 or (page * 50) >= self.max_results_per_query:
                        break
                    page += 1

        if self.scan_commits:
            LOG.info(
                "Scanning recent commit history for %s (max_commits_per_repo=%s)",
                repo_full_name,
                self.max_commits_per_repo,
            )
            findings.extend(self._scan_commit_history(repo_full_name))
        if self.scan_pull_requests:
            LOG.info(
                "Scanning recent pull request patches for %s (max_pull_requests_per_repo=%s)",
                repo_full_name,
                self.max_pull_requests_per_repo,
            )
            findings.extend(self._scan_pull_requests(repo_full_name))
        if self.scan_collaboration_text:
            LOG.info(
                "Scanning fresh collaboration text for %s (PRs/issues/releases)",
                repo_full_name,
            )
            findings.extend(self._scan_pull_request_text(repo_full_name))
            findings.extend(self._scan_issue_text(repo_full_name))
            findings.extend(self._scan_release_notes(repo_full_name))

        dedup: Dict[str, Dict[str, Any]] = {}
        for f in findings:
            k = (
                f'{f["repo"]}|{f["path"]}|{f["rule"]}|'
                f'{f.get("commit_sha")}|{f.get("line_number")}|'
                f'{f.get("patch_line_number")}|{f["matched_value"]}'
            )
            existing = dedup.get(k)
            if not existing or f["score"] > existing["score"]:
                dedup[k] = f
        return sorted(dedup.values(), key=finding_sort_key, reverse=True)

    def scan_repos(self, repos: Iterable[str], concurrency: int = 1) -> List[Dict[str, Any]]:
        repos = list(dict.fromkeys([r for r in repos if r]))
        if not repos:
            return []

        if concurrency <= 1:
            all_findings: List[Dict[str, Any]] = []
            for repo in repos:
                all_findings.extend(self.scan_repo(repo))
            return sorted(all_findings, key=finding_sort_key, reverse=True)

        # Shared client + rate limiter keeps aggregate pacing safe across threads.
        from concurrent.futures import ThreadPoolExecutor, as_completed

        findings: List[Dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=concurrency) as ex:
            futures = {ex.submit(self.scan_repo, repo): repo for repo in repos}
            for future in as_completed(futures):
                repo = futures[future]
                try:
                    findings.extend(future.result())
                except Exception as exc:
                    LOG.error("Repo scan failed for %s: %s", repo, exc)
        return sorted(findings, key=finding_sort_key, reverse=True)

    def _add_subdomain_finding(
        self,
        findings_by_host: Dict[str, Dict[str, Any]],
        domain: str,
        hostname: str,
        repo: str,
        path: str,
        line_number: Optional[int],
        matched_line: str,
        html_url: str,
        query_rule: str,
        query: str,
        observed_at: Optional[str] = None,
        commit_sha: Optional[str] = None,
        pr_number: Optional[int] = None,
        issue_number: Optional[int] = None,
    ) -> None:
        existing = findings_by_host.get(hostname)
        if existing:
            existing["occurrences"] = int(existing.get("occurrences", 1)) + 1
            if not existing.get("observed_at") and observed_at:
                existing["observed_at"] = observed_at
            self._last_subdomain_results = sorted(
                findings_by_host.values(),
                key=lambda item: str(item.get("matched_value", "")),
            )
            return

        finding = {
            "type": "subdomain",
            "rule": "Discovered Subdomain",
            "score": 100,
            "repo": repo,
            "path": path,
            "line_number": line_number,
            "commit_sha": commit_sha,
            "pr_number": pr_number,
            "issue_number": issue_number,
            "matched_value": hostname,
            "matched_line": matched_line.strip()[:500],
            "query_rule": query_rule,
            "query": query,
            "html_url": html_url,
            "possible_contains": f"Subdomain of {domain}",
            "why_flagged": f"Discovered hostname ending in {domain} from GitHub data",
            "observed_at": observed_at,
            "occurrences": 1,
        }
        findings_by_host[hostname] = finding
        self._last_subdomain_results = sorted(
            findings_by_host.values(),
            key=lambda item: str(item.get("matched_value", "")),
        )
        if self.stream_to_stdout:
            print(hostname, flush=True)

    def _record_subdomains_from_text(
        self,
        findings_by_host: Dict[str, Dict[str, Any]],
        domain: str,
        repo: str,
        path: str,
        text: str,
        html_url: str,
        query_rule: str,
        query: str,
        observed_at: Optional[str] = None,
        commit_sha: Optional[str] = None,
        pr_number: Optional[int] = None,
        issue_number: Optional[int] = None,
    ) -> None:
        if not text:
            return
        for line_no, line in enumerate(str(text).splitlines(), start=1):
            for hostname in extract_subdomains_from_text(line, domain):
                self._add_subdomain_finding(
                    findings_by_host=findings_by_host,
                    domain=domain,
                    hostname=hostname,
                    repo=repo,
                    path=path,
                    line_number=line_no,
                    matched_line=line,
                    html_url=html_url,
                    query_rule=query_rule,
                    query=query,
                    observed_at=observed_at,
                    commit_sha=commit_sha,
                    pr_number=pr_number,
                    issue_number=issue_number,
                )

    def _discover_subdomains_via_code_search(
        self,
        domain: str,
        findings_by_host: Dict[str, Dict[str, Any]],
        query_prefix: str = "",
    ) -> None:
        remaining_fetches = max(0, self.max_file_fetches)
        query_terms = [
            f'"{domain}"',
            f'"https://{domain}"',
            f'"http://{domain}"',
            f'".{domain}"',
            f'"*.{domain}"',
        ]
        queries = [f"{query_prefix}{term}".strip() for term in query_terms]

        for query in dict.fromkeys(queries):
            page = 1
            seen_item_keys = set()
            while True:
                data = self.client.search_code(query, per_page=50, page=page)
                items = data.get("items", [])
                if not items:
                    break
                for item in items:
                    item_key = f'{item.get("repository", {}).get("full_name","")}|{item.get("path","")}|{item.get("sha","")}'
                    if item_key in seen_item_keys:
                        continue
                    seen_item_keys.add(item_key)

                    repo = item.get("repository", {}).get("full_name", "")
                    path = item.get("path", "")
                    lines: List[str] = []
                    for tm in item.get("text_matches", []):
                        frag = tm.get("fragment")
                        if frag:
                            lines.extend(frag.splitlines())
                    if not lines and remaining_fetches > 0:
                        try:
                            text = self.client.get_file_content(repo, path)
                            remaining_fetches -= 1
                            if text:
                                lines = text.splitlines()
                        except Exception as exc:
                            LOG.debug("Unable to fetch file content for %s/%s during subdomain discovery: %s", repo, path, exc)
                    if not lines:
                        continue

                    html_url = item.get("html_url") or ""
                    for line_no, line in enumerate(lines, start=1):
                        for hostname in extract_subdomains_from_text(line, domain):
                            self._add_subdomain_finding(
                                findings_by_host=findings_by_host,
                                domain=domain,
                                hostname=hostname,
                                repo=repo,
                                path=path,
                                line_number=line_no,
                                matched_line=line,
                                html_url=html_url,
                                query_rule="Global Domain Code Search" if not query_prefix else "Repository Domain Code Search",
                                query=query,
                            )
                if len(items) < 50 or (page * 50) >= self.max_results_per_query:
                    break
                page += 1

    def _discover_subdomains_in_repo_metadata(
        self,
        repo_full_name: str,
        domain: str,
        findings_by_host: Dict[str, Dict[str, Any]],
    ) -> None:
        try:
            repo_meta = self.client.get_repo(repo_full_name)
        except Exception as exc:
            LOG.debug("Repo metadata fetch failed for %s during subdomain discovery: %s", repo_full_name, exc)
            return

        repo_url = str(repo_meta.get("html_url") or f"https://github.com/{repo_full_name}")
        metadata_fields = [
            ("repo:full_name", str(repo_meta.get("full_name") or "")),
            ("repo:name", str(repo_meta.get("name") or "")),
            ("repo:description", str(repo_meta.get("description") or "")),
            ("repo:homepage", str(repo_meta.get("homepage") or "")),
        ]
        owner = repo_meta.get("owner") or {}
        metadata_fields.append(("repo:owner", str(owner.get("login") or "")))

        for path, text in metadata_fields:
            self._record_subdomains_from_text(
                findings_by_host,
                domain,
                repo_full_name,
                path,
                text,
                repo_url,
                "Repository Metadata",
                "repo_metadata",
                observed_at=str(repo_meta.get("updated_at") or repo_meta.get("pushed_at") or ""),
            )

    def _discover_subdomains_in_repo_tree(
        self,
        repo_full_name: str,
        domain: str,
        findings_by_host: Dict[str, Dict[str, Any]],
    ) -> None:
        fetch_budget = max(0, self.max_file_fetches)
        if fetch_budget <= 0:
            return
        try:
            repo_meta = self.client.get_repo(repo_full_name)
            default_branch = repo_meta.get("default_branch") or "HEAD"
            tree = self.client.get_repo_tree(repo_full_name, recursive=True)
        except Exception as exc:
            LOG.debug("Repo tree fetch failed for %s during subdomain discovery: %s", repo_full_name, exc)
            return

        blobs = [n for n in tree if n.get("type") == "blob"]
        prioritized = sorted(
            blobs,
            key=lambda item: (
                0 if str(item.get("path", "")).lower().startswith("readme") else 1,
                0 if is_probably_text_path(str(item.get("path", ""))) else 1,
                int(item.get("size") or 0),
            ),
        )
        for file_obj in prioritized:
            if fetch_budget <= 0:
                break
            path = str(file_obj.get("path") or "")
            size = int(file_obj.get("size") or 0)
            if size <= 0 or size > self.max_file_size_bytes or not is_probably_text_path(path):
                continue
            try:
                text = self.client.get_file_content(repo_full_name, path, ref=default_branch)
            except Exception as exc:
                LOG.debug("Skipping unreadable file %s/%s during subdomain discovery: %s", repo_full_name, path, exc)
                continue
            fetch_budget -= 1
            if not text:
                continue
            self._record_subdomains_from_text(
                findings_by_host,
                domain,
                repo_full_name,
                path,
                text,
                f"https://github.com/{repo_full_name}/blob/{default_branch}/{path}",
                "Repository File Content",
                "repo_tree_content",
                observed_at=str(repo_meta.get("pushed_at") or repo_meta.get("updated_at") or ""),
            )

    def _discover_subdomains_in_commit_history(
        self,
        repo_full_name: str,
        domain: str,
        findings_by_host: Dict[str, Dict[str, Any]],
    ) -> None:
        if self.max_commits_per_repo <= 0:
            return
        commits_processed = 0
        page = 1
        since_iso = self.fresh_since.isoformat() if self.fresh_since else None
        while commits_processed < self.max_commits_per_repo:
            commits = self.client.list_repo_commits(repo_full_name, per_page=100, page=page, since=since_iso)
            if not commits:
                break
            stop_early = False
            for commit_stub in commits:
                if commits_processed >= self.max_commits_per_repo:
                    break
                commit_date = (((commit_stub.get("commit") or {}).get("committer") or {}).get("date")
                               or ((commit_stub.get("commit") or {}).get("author") or {}).get("date"))
                if self.fresh_since and not self._is_fresh(commit_date):
                    stop_early = True
                    break
                sha = commit_stub.get("sha")
                if not sha:
                    continue
                commits_processed += 1
                try:
                    commit_data = self.client.get_commit(repo_full_name, sha)
                except Exception as exc:
                    LOG.debug("Commit fetch failed for %s@%s during subdomain discovery: %s", repo_full_name, sha, exc)
                    continue
                commit_html_url = str(commit_data.get("html_url") or "")
                commit_message = str((commit_data.get("commit", {}) or {}).get("message") or "")
                observed_at = (((commit_data.get("commit") or {}).get("committer") or {}).get("date")
                               or ((commit_data.get("commit") or {}).get("author") or {}).get("date")
                               or commit_date)
                self._record_subdomains_from_text(
                    findings_by_host,
                    domain,
                    repo_full_name,
                    "commit:message",
                    commit_message,
                    commit_html_url,
                    "Commit Message",
                    "commit_message",
                    observed_at=observed_at,
                    commit_sha=sha,
                )
                for file_obj in commit_data.get("files", []) or []:
                    path = str(file_obj.get("filename") or "")
                    patch = str(file_obj.get("patch") or "")
                    if not patch:
                        continue
                    for patch_line_no, patch_line in enumerate(patch.splitlines(), start=1):
                        if not patch_line.startswith("+") or patch_line.startswith("+++"):
                            continue
                        self._record_subdomains_from_text(
                            findings_by_host,
                            domain,
                            repo_full_name,
                            path,
                            patch_line[1:],
                            commit_html_url,
                            "Commit Patch",
                            "commit_patch",
                            observed_at=observed_at,
                            commit_sha=sha,
                        )
            if stop_early or len(commits) < 100:
                break
            page += 1

    def _discover_subdomains_in_pull_requests(
        self,
        repo_full_name: str,
        domain: str,
        findings_by_host: Dict[str, Dict[str, Any]],
    ) -> None:
        if self.max_pull_requests_per_repo <= 0:
            return
        prs_processed = 0
        page = 1
        while prs_processed < self.max_pull_requests_per_repo:
            prs = self.client.list_repo_pull_requests(
                repo_full_name,
                state="all",
                sort="updated",
                direction="desc",
                per_page=100,
                page=page,
            )
            if not prs:
                break
            stop_early = False
            for pr in prs:
                if prs_processed >= self.max_pull_requests_per_repo:
                    break
                pr_updated_at = pr.get("updated_at") or pr.get("created_at")
                if self.fresh_since and not self._is_fresh(pr_updated_at):
                    stop_early = True
                    break
                pull_number = pr.get("number")
                if not pull_number:
                    continue
                prs_processed += 1
                pr_html_url = str(pr.get("html_url") or "")
                pr_title = str(pr.get("title") or "")
                pr_body = str(pr.get("body") or "")
                head_sha = (pr.get("head") or {}).get("sha")
                self._record_subdomains_from_text(findings_by_host, domain, repo_full_name, f"PR#{pull_number}:title", pr_title, pr_html_url, "Pull Request Title", "pull_request_title", pr_updated_at, head_sha, int(pull_number))
                self._record_subdomains_from_text(findings_by_host, domain, repo_full_name, f"PR#{pull_number}:body", pr_body, pr_html_url, "Pull Request Description", "pull_request_body", pr_updated_at, head_sha, int(pull_number))
                try:
                    files = self.client.list_pull_request_files(repo_full_name, int(pull_number))
                except Exception as exc:
                    LOG.debug("PR files fetch failed for %s#%s during subdomain discovery: %s", repo_full_name, pull_number, exc)
                    files = []
                for file_obj in files:
                    path = str(file_obj.get("filename") or "")
                    patch = str(file_obj.get("patch") or "")
                    if not patch:
                        continue
                    for patch_line in patch.splitlines():
                        if not patch_line.startswith("+") or patch_line.startswith("+++"):
                            continue
                        self._record_subdomains_from_text(
                            findings_by_host,
                            domain,
                            repo_full_name,
                            path,
                            patch_line[1:],
                            pr_html_url,
                            "Pull Request Patch",
                            "pull_request_patch",
                            observed_at=pr_updated_at,
                            commit_sha=head_sha,
                            pr_number=int(pull_number),
                        )
                comment_page = 1
                while True:
                    comments = self.client.list_issue_comments(repo_full_name, int(pull_number), per_page=100, page=comment_page)
                    if not comments:
                        break
                    for comment in comments:
                        comment_updated = comment.get("updated_at") or comment.get("created_at") or pr_updated_at
                        self._record_subdomains_from_text(
                            findings_by_host,
                            domain,
                            repo_full_name,
                            f"PR#{pull_number}:conversation-comment",
                            str(comment.get("body") or ""),
                            str(comment.get("html_url") or pr_html_url),
                            "Pull Request Conversation Comment",
                            "pull_request_comment",
                            observed_at=comment_updated,
                            commit_sha=head_sha,
                            pr_number=int(pull_number),
                        )
                    if len(comments) < 100:
                        break
                    comment_page += 1
                review_page = 1
                while True:
                    comments = self.client.list_pull_request_review_comments(repo_full_name, int(pull_number), per_page=100, page=review_page)
                    if not comments:
                        break
                    for comment in comments:
                        comment_updated = comment.get("updated_at") or comment.get("created_at") or pr_updated_at
                        self._record_subdomains_from_text(
                            findings_by_host,
                            domain,
                            repo_full_name,
                            f"PR#{pull_number}:review-comment",
                            str(comment.get("body") or ""),
                            str(comment.get("html_url") or pr_html_url),
                            "Pull Request Review Comment",
                            "pull_request_review_comment",
                            observed_at=comment_updated,
                            commit_sha=str(comment.get("commit_id") or head_sha or ""),
                            pr_number=int(pull_number),
                        )
                    if len(comments) < 100:
                        break
                    review_page += 1
            if stop_early or len(prs) < 100:
                break
            page += 1

    def _discover_subdomains_in_issues_and_releases(
        self,
        repo_full_name: str,
        domain: str,
        findings_by_host: Dict[str, Dict[str, Any]],
    ) -> None:
        if self.max_issues_per_repo > 0:
            issues_processed = 0
            page = 1
            while issues_processed < self.max_issues_per_repo:
                issues = self.client.list_repo_issues(
                    repo_full_name,
                    state="all",
                    sort="updated",
                    direction="desc",
                    per_page=100,
                    page=page,
                )
                if not issues:
                    break
                stop_early = False
                for issue in issues:
                    if issues_processed >= self.max_issues_per_repo:
                        break
                    if issue.get("pull_request"):
                        continue
                    issue_updated = issue.get("updated_at") or issue.get("created_at")
                    if self.fresh_since and not self._is_fresh(issue_updated):
                        stop_early = True
                        break
                    issue_number = issue.get("number")
                    if not issue_number:
                        continue
                    issues_processed += 1
                    issue_html_url = str(issue.get("html_url") or "")
                    self._record_subdomains_from_text(findings_by_host, domain, repo_full_name, f"Issue#{issue_number}:title", str(issue.get("title") or ""), issue_html_url, "Issue Title", "issue_title", issue_updated, issue_number=int(issue_number))
                    self._record_subdomains_from_text(findings_by_host, domain, repo_full_name, f"Issue#{issue_number}:body", str(issue.get("body") or ""), issue_html_url, "Issue Description", "issue_body", issue_updated, issue_number=int(issue_number))
                    comment_page = 1
                    while True:
                        comments = self.client.list_issue_comments(repo_full_name, int(issue_number), per_page=100, page=comment_page)
                        if not comments:
                            break
                        for comment in comments:
                            comment_updated = comment.get("updated_at") or comment.get("created_at") or issue_updated
                            self._record_subdomains_from_text(
                                findings_by_host,
                                domain,
                                repo_full_name,
                                f"Issue#{issue_number}:comment",
                                str(comment.get("body") or ""),
                                str(comment.get("html_url") or issue_html_url),
                                "Issue Comment",
                                "issue_comment",
                                observed_at=comment_updated,
                                issue_number=int(issue_number),
                            )
                        if len(comments) < 100:
                            break
                        comment_page += 1
                if stop_early or len(issues) < 100:
                    break
                page += 1

        if self.max_releases_per_repo <= 0:
            return
        releases_processed = 0
        page = 1
        while releases_processed < self.max_releases_per_repo:
            releases = self.client.list_repo_releases(repo_full_name, per_page=100, page=page)
            if not releases:
                break
            for release in releases:
                if releases_processed >= self.max_releases_per_repo:
                    break
                release_date = release.get("published_at") or release.get("created_at")
                if self.fresh_since and not self._is_fresh(release_date):
                    continue
                releases_processed += 1
                release_html_url = str(release.get("html_url") or "")
                release_name = str(release.get("name") or release.get("tag_name") or "")
                self._record_subdomains_from_text(findings_by_host, domain, repo_full_name, f"Release:{release_name or 'untitled'}:name", release_name, release_html_url, "Release Name", "release_name", release_date)
                self._record_subdomains_from_text(findings_by_host, domain, repo_full_name, f"Release:{release_name or 'untitled'}:notes", str(release.get("body") or ""), release_html_url, "Release Notes", "release_notes", release_date)
            if len(releases) < 100:
                break
            page += 1

    def _discover_subdomains_in_repo(
        self,
        repo_full_name: str,
        domain: str,
        findings_by_host: Dict[str, Dict[str, Any]],
    ) -> None:
        self._discover_subdomains_in_repo_metadata(repo_full_name, domain, findings_by_host)
        self._discover_subdomains_via_code_search(domain, findings_by_host, query_prefix=f'repo:{repo_full_name} ')
        self._discover_subdomains_in_repo_tree(repo_full_name, domain, findings_by_host)
        self._discover_subdomains_in_commit_history(repo_full_name, domain, findings_by_host)
        self._discover_subdomains_in_pull_requests(repo_full_name, domain, findings_by_host)
        self._discover_subdomains_in_issues_and_releases(repo_full_name, domain, findings_by_host)

    def discover_subdomains(self, domain: str) -> List[Dict[str, Any]]:
        normalized_domain = normalize_domain(domain)
        if not normalized_domain:
            return []

        findings_by_host: Dict[str, Dict[str, Any]] = {}
        self._discover_subdomains_via_code_search(normalized_domain, findings_by_host)

        repos = self.client.search_repos_by_domain(normalized_domain, limit=self.max_results_per_query)
        for repo_full_name in repos:
            try:
                self._discover_subdomains_in_repo(repo_full_name, normalized_domain, findings_by_host)
            except Exception as exc:
                LOG.debug("Expanded subdomain discovery failed for %s: %s", repo_full_name, exc)
        self._last_subdomain_results = sorted(
            findings_by_host.values(),
            key=lambda item: str(item.get("matched_value", "")),
        )
        return self._last_subdomain_results


def load_rules_file(path: Optional[str]) -> List[PatternRule]:
    rules = default_rules()
    if not path:
        return rules

    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Patterns file not found: {path}")
    data = json.loads(p.read_text(encoding="utf-8"))
    # Supports both:
    # 1) List[{"name":..., "regex":..., "literals":[...]}]
    # 2) {"custom_patterns": {"Name": "regex", ...}}
    if isinstance(data, dict):
        custom = data.get("custom_patterns", {})
        if not isinstance(custom, dict):
            raise ValueError("Config JSON object must contain 'custom_patterns' as an object")
        for name, pattern in custom.items():
            rules.append(
                PatternRule(
                    name=str(name),
                    regex=str(pattern),
                    literals=[],
                    severity=70,
                    description="Loaded from config.custom_patterns",
                )
            )
        return rules

    if isinstance(data, list):
        for entry in data:
            rules.append(
                PatternRule(
                    name=entry.get("name", "Custom Rule"),
                    regex=entry.get("regex"),
                    literals=entry.get("literals", []) or [],
                    severity=int(entry.get("severity", 50)),
                    description=entry.get("description", ""),
                )
            )
        return rules

    raise ValueError("Patterns file must be either a JSON list or object with custom_patterns")


def save_progress(progress_file: str, findings: List[Dict[str, Any]], completed_repos: Iterable[str]) -> None:
    payload = {
        "timestamp_utc": datetime.now(tz=timezone.utc).isoformat(),
        "completed_repos": sorted(list(set(completed_repos))),
        "findings": findings,
    }
    p = Path(progress_file)
    p.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_progress(progress_file: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    p = Path(progress_file)
    if not p.exists():
        return [], []
    data = json.loads(p.read_text(encoding="utf-8"))
    return data.get("findings", []) or [], data.get("completed_repos", []) or []


def target_cache_path(target_type: str, target_value: str, cache_dir: str = ".scan_cache") -> str:
    safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", f"{target_type}_{target_value}")
    return str(Path(cache_dir) / f"{safe}.json")


def collect_candidate_tokens(args: argparse.Namespace) -> List[str]:
    tokens: List[str] = []
    token_arg = getattr(args, "token", None)
    if isinstance(token_arg, list):
        tokens.extend([t.strip() for t in token_arg if t and t.strip()])
    elif isinstance(token_arg, str) and token_arg.strip():
        tokens.append(token_arg.strip())
    if getattr(args, "tokens", None):
        tokens.extend([t.strip() for t in args.tokens.split(",") if t.strip()])
    if getattr(args, "tokens_file", None):
        p = Path(args.tokens_file)
        if p.exists():
            for line in p.read_text(encoding="utf-8").splitlines():
                token = line.strip()
                if token and not token.startswith("#"):
                    tokens.append(token)
    seen = set()
    unique_tokens: List[str] = []
    for t in tokens:
        if t not in seen:
            seen.add(t)
            unique_tokens.append(t)
    return unique_tokens


def save_json(findings: List[Dict[str, Any]], output_path: str) -> None:
    Path(output_path).write_text(json.dumps(findings, indent=2), encoding="utf-8")


def save_csv(findings: List[Dict[str, Any]], output_path: str) -> None:
    if not findings:
        Path(output_path).write_text("", encoding="utf-8")
        return
    keys = list(findings[0].keys())
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(findings)


def save_txt(findings: List[Dict[str, Any]], output_path: str) -> None:
    lines: List[str] = []
    lines.append(f"Github Recon Scanner Findings: {len(findings)}")
    lines.append("")
    for i, f in enumerate(findings, start=1):
        lines.append(f"[{i}] {f.get('rule')} (score={f.get('score')})")
        lines.append(f"repo: {f.get('repo')}")
        lines.append(f"path: {f.get('path')}")
        lines.append(f"url: {build_finding_url(f)}")
        lines.append(f"line: {f.get('line_number')}")
        lines.append(f"commit: {f.get('commit_sha')}")
        lines.append(f"match: {f.get('matched_value')}")
        lines.append(f"context: {f.get('matched_line')}")
        lines.append("")
    Path(output_path).write_text("\n".join(lines), encoding="utf-8")


def save_html(findings: List[Dict[str, Any]], output_path: str) -> None:
    rows = []
    for f in findings:
        url = html.escape(build_finding_url(f) or "")
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(f.get('score', '')))}</td>"
            f"<td>{html.escape(str(f.get('rule', '')))}</td>"
            f"<td>{html.escape(str(f.get('repo', '')))}</td>"
            f"<td>{html.escape(str(f.get('path', '')))}</td>"
            f"<td>{html.escape(str(f.get('line_number', '')))}</td>"
            f"<td>{html.escape(str(f.get('commit_sha', '')))}</td>"
            f"<td>{html.escape(str(f.get('matched_value', '')))}</td>"
            f"<td><a href=\"{url}\">{url}</a></td>"
            "</tr>"
        )
    body = (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>Github Recon Scanner Results</title>"
        "<style>body{font-family:Arial,sans-serif;padding:16px;}table{border-collapse:collapse;width:100%;}"
        "th,td{border:1px solid #ddd;padding:8px;vertical-align:top;}th{background:#f4f4f4;text-align:left;}</style>"
        "</head><body>"
        f"<h1>Github Recon Scanner Findings ({len(findings)})</h1>"
        "<table><thead><tr><th>Score</th><th>Rule</th><th>Repo</th><th>Path</th><th>Line</th>"
        "<th>Commit</th><th>Matched Value</th><th>URL</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></body></html>"
    )
    Path(output_path).write_text(body, encoding="utf-8")


def save_output_by_extension(findings: List[Dict[str, Any]], output_path: str) -> None:
    ext = Path(output_path).suffix.lower()
    if ext == ".txt":
        save_txt(findings, output_path)
    elif ext == ".html":
        save_html(findings, output_path)
    elif ext == ".csv":
        save_csv(findings, output_path)
    else:
        save_json(findings, output_path)


def save_requested_outputs(
    findings: List[Dict[str, Any]],
    output_path: Optional[str] = None,
    csv_output_path: Optional[str] = None,
) -> None:
    if output_path:
        save_output_by_extension(findings, output_path)
    if csv_output_path:
        save_csv(findings, csv_output_path)


def filter_latest_only_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    newest_by_repo: Dict[str, float] = {}
    for f in findings:
        repo = str(f.get("repo") or "")
        observed = parse_github_datetime(f.get("observed_at"))
        if not repo or not observed:
            continue
        ts = observed.timestamp()
        if repo not in newest_by_repo or ts > newest_by_repo[repo]:
            newest_by_repo[repo] = ts

    if not newest_by_repo:
        return []

    filtered: List[Dict[str, Any]] = []
    for f in findings:
        repo = str(f.get("repo") or "")
        observed = parse_github_datetime(f.get("observed_at"))
        if not repo or not observed:
            continue
        if observed.timestamp() == newest_by_repo.get(repo):
            filtered.append(f)
    return filtered


def dedup_findings(findings: List[Dict[str, Any]], latest_only: bool = False) -> List[Dict[str, Any]]:
    dedup: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        norm_match = re.sub(r"\s+", "", str(f.get("matched_value", "")).strip().lower())
        url = build_finding_url(f)
        key = (
            f'{f.get("rule")}|{url}|{norm_match}|'
            f'{f.get("repo")}|{f.get("path")}'
        )
        existing = dedup.get(key)
        if not existing or int(f.get("score", 0)) > int(existing.get("score", 0)):
            dedup[key] = f
    ordered = sorted(dedup.values(), key=finding_sort_key, reverse=True)
    if latest_only:
        ordered = filter_latest_only_findings(ordered)
    return ordered


def send_alerts(webhook_url: str, findings: List[Dict[str, Any]], top_n: int = 10) -> None:
    payload = {
        "scanner": "Github Recon Scanner",
        "total_findings": len(findings),
        "top_findings": findings[:top_n],
        "generated_at_utc": datetime.now(tz=timezone.utc).isoformat(),
    }
    try:
        resp = requests.post(webhook_url, json=payload, timeout=20)
    except requests.RequestException as exc:
        raise ScannerOutputError(
            "Alert delivery failed because the webhook endpoint could not be reached."
        ) from exc
    if resp.status_code >= 300:
        raise ScannerOutputError(
            f"Alert delivery failed because the webhook returned HTTP {resp.status_code}."
        )


def build_parser() -> argparse.ArgumentParser:
    class CleanHelpFormatter(argparse.RawDescriptionHelpFormatter, argparse.ArgumentDefaultsHelpFormatter):
        pass

    parser = argparse.ArgumentParser(
        description=(
            "Github Recon Scanner\n"
            "Scanner for finding exposed secrets in public GitHub data.\n"
            "Tip: run with --examples for a guided command list."
        ),
        formatter_class=CleanHelpFormatter,
        epilog=(
            "Important Commands:\n"
            "  1) Scan one repository:\n"
            "     python github_recon_scanner.py --repo owner/repo --token TOKEN\n"
            "  2) Discover subdomains across GitHub sources:\n"
            "     python github_recon_scanner.py --domain example.com --discover-subdomains\n"
            "  3) Scan all repos in an org:\n"
            "     python github_recon_scanner.py --org my-org --token TOKEN\n"
            "  4) Deep scan all files in org repos:\n"
            "     python github_recon_scanner.py --org my-org --scan-all-files --max-files-per-repo 20000\n"
            "  5) Resume previous run:\n"
            "     python github_recon_scanner.py --org my-org --resume\n"
            "  6) Start fresh for a target:\n"
            "     python github_recon_scanner.py --org my-org --flush\n"
            "  7) View extra examples:\n"
            "     python github_recon_scanner.py --examples\n"
        ),
    )

    misc_group = parser.add_argument_group("General")
    misc_group.add_argument(
        "-x",
        "--examples",
        action="store_true",
        help="Show a clean command cookbook and exit.",
    )
    misc_group.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed logs and extra finding context.",
    )
    misc_group.add_argument("-C", "--concurrency", type=int, default=1, help="Concurrent repo scans (keep low).")
    misc_group.add_argument("-R", "--requests-per-minute", type=int, default=None, help="Global request pacing cap.")
    misc_group.add_argument("-L", "--rate-limit-threshold", type=int, default=30, help="Warn when Search API remaining requests are low.")
    misc_group.add_argument(
        "-N",
        "--no-rate-limit",
        action="store_true",
        help="Deprecated compatibility flag. Pacing stays enabled to protect users from GitHub throttling.",
    )

    auth_group = parser.add_argument_group("Authentication")
    auth_group.add_argument(
        "-t",
        "--token",
        action="append",
        help="GitHub PAT (repeatable). Recommended scopes: repo, read:org, and search permissions.",
    )
    auth_group.add_argument("-T", "--tokens", help="Comma-separated GitHub PATs (alternative input).")
    auth_group.add_argument("-F", "--tokens-file", help="File with one GitHub PAT per line.")

    target_group = parser.add_argument_group("Target Selection")
    target_group.add_argument("-a", "--target", help="Target value (domain, user, org, or repo).")
    target_group.add_argument("-Y", "--type", choices=["domain", "user", "org", "repo"], help="Target type for --target.")
    target_group.add_argument("-d", "--domain", help="Domain shortcut (example.com).")
    target_group.add_argument("-u", "--user", help="GitHub username shortcut.")
    target_group.add_argument("-o", "--org", help="GitHub org shortcut.")
    target_group.add_argument("-r", "--repo", help="Repository shortcut (owner/repo).")

    rules_group = parser.add_argument_group("Rules and Patterns")
    rules_group.add_argument("-p", "--patterns", help="Path to JSON file with additional pattern rules.")
    rules_group.add_argument("-f", "--config", help="Alias for --patterns; also supports {custom_patterns:{name:regex}} format.")
    rules_group.add_argument(
        "-P",
        "--custom-pattern",
        nargs=2,
        action="append",
        metavar=("NAME", "REGEX"),
        help="Add custom regex pattern (can be provided multiple times).",
    )

    scan_group = parser.add_argument_group("Scan Behavior")
    scan_group.add_argument("-q", "--use-regex-query", action="store_true", help="Try regex-based code search query syntax when supported.")
    scan_group.add_argument(
        "-G",
        "--no-regex-grep",
        action="store_true",
        help="Disable client-side regex grep over GitHub file contents.",
    )
    scan_group.add_argument("-m", "--no-scan-commits", action="store_true", help="Disable scanning recent commit patches.")
    scan_group.add_argument("-s", "--no-scan-prs", action="store_true", help="Disable scanning pull request patches.")
    scan_group.add_argument("-A", "--scan-all-files", action="store_true", help="Enumerate and scan all files in each repository.")
    scan_group.add_argument(
        "-D",
        "--discover-subdomains",
        action="store_true",
        help="For --domain targets, discover subdomains from GitHub code, metadata, patches, discussions, and release text.",
    )
    scan_group.add_argument("-M", "--max-files-per-repo", type=int, default=5000, help="Max files to scan per repository in --scan-all-files mode.")
    scan_group.add_argument("-B", "--max-file-size-bytes", type=int, default=1000000, help="Skip files larger than this size in bytes.")
    scan_group.add_argument(
        "-c",
        "--max-commits-per-repo",
        type=int,
        default=30,
        help="Maximum recent commits to inspect per repo for patch-based secret leaks.",
    )
    scan_group.add_argument(
        "-j",
        "--max-prs-per-repo",
        type=int,
        default=20,
        help="Maximum recent pull requests to inspect per repo for patch-based secret leaks.",
    )
    scan_group.add_argument("-I", "--no-scan-collab-text", action="store_true", help="Disable scanning PR/issue comments and release notes.")
    scan_group.add_argument("-i", "--max-issues-per-repo", type=int, default=30, help="Maximum recent issues to inspect for text-based leaks.")
    scan_group.add_argument("-l", "--max-releases-per-repo", type=int, default=20, help="Maximum recent releases to inspect for text-based leaks.")
    scan_group.add_argument(
        "-w",
        "--fresh-days",
        type=int,
        default=30,
        help="Only scan activity updated in the last N days. Set to 0 to disable freshness filtering.",
    )
    scan_group.add_argument(
        "-S",
        "--fresh-since",
        help="Only scan activity updated on/after this UTC timestamp (ISO-8601), e.g. 2026-02-01T00:00:00Z.",
    )
    scan_group.add_argument(
        "-y",
        "--latest-only",
        action="store_true",
        help="Keep only findings from each repo's most recent observed activity timestamp.",
    )
    scan_group.add_argument("-Q", "--max-results-per-query", type=int, default=100, help="Max search results to process per query.")
    scan_group.add_argument("-X", "--max-file-fetches", type=int, default=40, help="Fallback file-content API calls if text-matches missing.")
    scan_group.add_argument("-E", "--max-domain-repos", type=int, default=100, help="Max repositories inferred from domain search.")
    scan_group.add_argument("-n", "--min-score", type=int, default=75, help="Minimum confidence score required to keep a finding.")
    scan_group.add_argument("-z", "--relaxed", action="store_true", help="Relax strict false-positive filters.")

    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "-O",
        "--output",
        help="Output file path. Default is results.json for normal scans; subdomain discovery writes no file unless you set this.",
    )
    output_group.add_argument("-V", "--csv-output", help="Optional additional CSV output file path.")
    output_group.add_argument("-H", "--alert-webhook", help="Optional webhook URL for summarized alerts.")

    progress_group = parser.add_argument_group("Progress and Cache")
    progress_group.add_argument("-e", "--resume", action="store_true", help="Resume from saved progress file.")
    progress_group.add_argument("-K", "--clear-progress", action="store_true", help="Delete progress file before scanning.")
    progress_group.add_argument("-J", "--progress-file", default=".scan_progress.json", help="Progress state file path.")
    progress_group.add_argument("-U", "--flush", action="store_true", help="Delete cached progress for this target and start from scratch.")

    return parser


def parse_args() -> argparse.Namespace:
    return build_parser().parse_args()


def resolve_target(args: argparse.Namespace) -> Tuple[str, str]:
    def _normalize_github_value(target_type: str, value: str) -> str:
        raw = str(value or "").strip()
        if not raw:
            return raw
        if "github.com" not in raw:
            return raw.strip("/")
        m = re.match(r"^https?://github\.com/([^?#]+)", raw, flags=re.IGNORECASE)
        if not m:
            return raw.strip("/")
        parts = [p for p in m.group(1).strip("/").split("/") if p]
        if not parts:
            return raw.strip("/")
        if target_type in {"user", "org"}:
            return parts[0]
        if target_type == "repo" and len(parts) >= 2:
            return f"{parts[0]}/{parts[1]}"
        return raw.strip("/")

    if args.domain:
        return "domain", args.domain
    if args.user:
        return "user", _normalize_github_value("user", args.user)
    if args.org:
        return "org", _normalize_github_value("org", args.org)
    if args.repo:
        return "repo", _normalize_github_value("repo", args.repo)
    if args.target and args.type:
        return args.type, _normalize_github_value(args.type, args.target)
    raise ValueError("Provide a target using --target + --type, or one of --domain/--user/--org/--repo.")


def warn_if_high_volume(target_type: str, concurrency: int, rpm: int) -> None:
    if concurrency > 1 or rpm > SAFE_CORE_RPM_AUTHENTICATED:
        LOG.warning(
            "High-volume settings detected (concurrency=%s, rpm=%s). "
            "Reduce values to avoid abuse detection and comply with GitHub ToS.",
            concurrency,
            rpm,
        )
    if target_type in {"domain", "org", "user"}:
        LOG.warning(
            "Ensure you are authorized to scan this target scope. "
            "This scanner is for public-data recon only."
        )


def print_unauthenticated_restrictions() -> None:
    print(
        "No GitHub token provided. Continuing with unauthenticated API access.\n"
        "Restrictions:\n"
        "- Lower GitHub API and search rate limits\n"
        "- Slower scans due to stricter pacing\n"
        "- Reduced coverage on larger domains/orgs/users before throttling\n"
        "- Higher chance of incomplete subdomain discovery or fewer findings\n"
        "Use --token, --tokens, or --tokens-file for better coverage."
    )


def print_invalid_token_response() -> None:
    print(
        "Invalid GitHub token provided.\n"
        "Check your GitHub token and try again."
    )


def format_cli_error(exc: Exception, fallback: str = "Scanner operation failed.") -> str:
    if isinstance(exc, GitHubScannerError):
        return str(exc)
    if isinstance(exc, requests.RequestException):
        return "A network error occurred while contacting a remote service."
    return fallback


def build_finding_url(finding: Dict[str, Any]) -> str:
    base = finding.get("html_url") or ""
    repo = finding.get("repo") or ""
    path = finding.get("path") or ""
    line_number = finding.get("line_number")
    commit_sha = finding.get("commit_sha")
    blob_sha = finding.get("blob_sha")

    if not base and repo and commit_sha:
        base = f"https://github.com/{repo}/commit/{commit_sha}"
    elif not base and repo and path and blob_sha:
        base = f"https://github.com/{repo}/blob/{blob_sha}/{path}"
    elif not base and repo and path:
        base = f"https://github.com/{repo}/blob/HEAD/{path}"
    elif not base and repo:
        base = f"https://github.com/{repo}"

    if base and line_number and "github.com" in base and "#L" not in base and "/blob/" in base:
        return f"{base}#L{line_number}"
    return base


def print_findings_to_console(findings: List[Dict[str, Any]], verbose: bool = False) -> None:
    if not findings:
        print("\nNo findings detected.")
        return

    if all(str(f.get("type", "")) == "subdomain" for f in findings):
        print(f"\nDiscovered subdomains: {len(findings)}")
        for finding in findings:
            print(str(finding.get("matched_value") or "N/A"))
            if verbose:
                print(
                    "   "
                    f"repo={finding.get('repo')} "
                    f"path={finding.get('path')} "
                    f"line={finding.get('line_number')} "
                    f"occurrences={finding.get('occurrences')} "
                    f"url={build_finding_url(finding)}"
                )
        return

    print(f"\nFindings: {len(findings)}")
    print("Full GitHub URLs (copy/paste):")
    for finding in findings:
        url = build_finding_url(finding) or "N/A"
        print(url)
        if verbose:
            print(
                "   "
                f"repo={finding.get('repo')} "
                f"path={finding.get('path')} "
                f"rule={finding.get('rule')} "
                f"score={finding.get('score')} "
                f"line={finding.get('line_number')} "
                f"commit={finding.get('commit_sha')} "
                f"pr={finding.get('pr_number')} "
                f"observed_at={finding.get('observed_at')}"
            )
            print(f"   contains={finding.get('possible_contains')}")
            print(f"   reason={finding.get('why_flagged')}")
            print(f"   match={finding.get('matched_value')}")


def print_examples() -> None:
    print(
        "\nGithub Recon Scanner Command Guide\n"
        "================================\n"
        "Step 1: Pick one target option\n"
        "  --repo owner/repo\n"
        "  --org orgname\n"
        "  --user username\n"
        "  --target VALUE --type domain|user|org|repo\n"
        "\nStep 2: Add auth (optional, recommended)\n"
        "  --token TOKEN\n"
        "  --token TOKEN1 --token TOKEN2\n"
        "  --tokens-file tokens.txt\n"
        "\nStep 3: Choose scan depth\n"
        "  default: code-search + regex validation + commit scan + PR scan + fresh discussion scan\n"
        "  deep:    add --scan-all-files\n"
        "  inventory subdomains: add --discover-subdomains with --domain example.com\n"
        "\nStep 4: Choose output\n"
        "  --output results.json\n"
        "  --output results.txt\n"
        "  --output results.html\n"
        "\nImportant Commands:\n"
        "  python github_recon_scanner.py --repo owner/repo --token TOKEN\n"
        "  python github_recon_scanner.py --domain example.com --discover-subdomains --output subdomains.json\n"
        "  python github_recon_scanner.py --repo owner/repo --fresh-days 7 --max-prs-per-repo 50\n"
        "  python github_recon_scanner.py --repo owner/repo --fresh-days 14 --max-issues-per-repo 40\n"
        "  python github_recon_scanner.py --org my-org --scan-all-files --max-files-per-repo 20000\n"
        "  python github_recon_scanner.py --org my-org --resume\n"
        "  python github_recon_scanner.py --org my-org --flush\n"
    )


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.CRITICAL,
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
    )

    if args.examples:
        print_examples()
        return 0

    if args.no_rate_limit:
        print(
            "Ignoring --no-rate-limit to keep GitHub pacing protections enabled "
            "and reduce the chance of rate limiting."
        )
        args.no_rate_limit = False

    try:
        target_type, target_value = resolve_target(args)
    except ValueError as exc:
        print(f"{exc}\n")
        parser.print_help()
        return 2

    patterns_source = args.patterns or args.config
    rules = load_rules_file(patterns_source)
    if args.custom_pattern:
        for name, regex_pattern in args.custom_pattern:
            rules.append(
                PatternRule(
                    name=name,
                    regex=regex_pattern,
                    literals=[],
                    severity=70,
                    description="Loaded from --custom-pattern",
                )
            )

    # Resolve per-target cache path so repeated scans can resume automatically.
    auto_progress_file = target_cache_path(target_type, target_value)
    progress_file = args.progress_file or auto_progress_file
    if args.progress_file == ".scan_progress.json":
        # Preserve backwards-compatible default behavior while enabling per-target cache.
        progress_file = auto_progress_file
    try:
        Path(progress_file).parent.mkdir(parents=True, exist_ok=True)

        if args.flush and os.path.exists(progress_file):
            os.remove(progress_file)
            LOG.info("Flushed cache file: %s", progress_file)

        if args.clear_progress and os.path.exists(progress_file):
            os.remove(progress_file)
            LOG.info("Cleared progress file: %s", progress_file)
    except OSError as exc:
        print(f"Progress file setup failed: {exc}")
        return 1

    candidate_tokens = collect_candidate_tokens(args)
    client: Optional[GitHubApiClient] = None
    rate: Dict[str, Any] = {}
    auth_mode = "unauthenticated"
    selected_token = None
    valid_tokens: List[str] = []
    invalid_token_count = 0
    try:
        for token in candidate_tokens:
            probe = GitHubApiClient(
                token=token,
                requests_per_minute=args.requests_per_minute,
            )
            try:
                rate = probe.get_rate_limit()
                scopes = probe.get_token_scopes()
                if scopes:
                    LOG.info("Token scopes detected: %s", ", ".join(scopes))
                    missing = [s for s in ("repo", "read:org") if s not in scopes]
                    if missing:
                        LOG.warning("Token appears to miss recommended scopes: %s", ", ".join(missing))
                else:
                    LOG.warning("Unable to read token scopes from API headers.")
                client = probe
                selected_token = token
                valid_tokens.append(token)
                auth_mode = "authenticated"
                break
            except GitHubScannerError as exc:
                if "401" in str(exc):
                    LOG.error("Skipping invalid/expired token.")
                    invalid_token_count += 1
                    continue
                LOG.error("Token probe failed: %s", exc)
                continue

        if client is None:
            if candidate_tokens and invalid_token_count == len(candidate_tokens):
                print_invalid_token_response()
                return 1
            client = GitHubApiClient(
                token=None,
                requests_per_minute=args.requests_per_minute,
            )
            try:
                rate = client.get_rate_limit()
            except GitHubScannerError as exc:
                LOG.error("Failed to access GitHub API: %s", exc)
                print(f"Failed to access GitHub API: {format_cli_error(exc, 'GitHub API access failed.')}")
                return 1
        else:
            # Keep all valid tokens for runtime failover.
            for token in candidate_tokens:
                if token == selected_token:
                    continue
                probe = GitHubApiClient(
                    token=token,
                    requests_per_minute=args.requests_per_minute,
                )
                try:
                    probe.get_rate_limit()
                    valid_tokens.append(token)
                except GitHubScannerError:
                    continue
    except KeyboardInterrupt:
        print("Scan interrupted by user (Ctrl+C). Exiting safely.")
        return 130

    rpm = client.core_rpm
    warn_if_high_volume(target_type, args.concurrency, rpm)
    LOG.info("API mode: %s", auth_mode)
    if auth_mode == "unauthenticated" and (args.discover_subdomains or target_type in {"domain", "org", "user"}):
        print_unauthenticated_restrictions()
    core = rate.get("resources", {}).get("core", {})
    search = rate.get("resources", {}).get("search", {})
    LOG.info(
        "Rate limits: core remaining=%s reset=%s | search remaining=%s reset=%s",
        core.get("remaining"),
        core.get("reset"),
        search.get("remaining"),
        search.get("reset"),
    )
    if search.get("remaining") is not None and int(search["remaining"]) <= int(args.rate_limit_threshold):
        LOG.warning(
            "Search API remaining requests (%s) are below threshold (%s). Expect slower scans.",
            search["remaining"],
            args.rate_limit_threshold,
        )

    scanner = GithubReconScanner(
        client=client,
        rules=rules,
        use_regex_query=args.use_regex_query,
        regex_grep=not args.no_regex_grep,
        scan_commits=not args.no_scan_commits,
        scan_pull_requests=not args.no_scan_prs,
        scan_collaboration_text=not args.no_scan_collab_text,
        scan_all_files=args.scan_all_files,
        max_files_per_repo=max(0, args.max_files_per_repo),
        max_file_size_bytes=max(1, args.max_file_size_bytes),
        max_commits_per_repo=max(0, args.max_commits_per_repo),
        max_pull_requests_per_repo=max(0, args.max_prs_per_repo),
        max_issues_per_repo=max(0, args.max_issues_per_repo),
        max_releases_per_repo=max(0, args.max_releases_per_repo),
        max_results_per_query=args.max_results_per_query,
        max_file_fetches=args.max_file_fetches,
        stream_to_stdout=not args.verbose,
        min_score=max(1, min(100, args.min_score)),
        strict_mode=not args.relaxed,
        fresh_since=(
            parse_github_datetime(args.fresh_since)
            if args.fresh_since
            else (
                datetime.now(tz=timezone.utc) - timedelta(days=max(0, args.fresh_days))
                if args.fresh_days > 0
                else None
            )
        ),
    )

    output_path = args.output or ("results.json" if not args.discover_subdomains else None)
    should_save_subdomain_cache = args.discover_subdomains and (
        bool(args.output) or bool(args.csv_output) or bool(args.resume) or args.progress_file != ".scan_progress.json"
    )

    if args.discover_subdomains:
        if target_type != "domain":
            print("--discover-subdomains requires a domain target. Use --domain example.com or --target example.com --type domain.")
            return 2
        findings: List[Dict[str, Any]] = []
        try:
            findings = scanner.discover_subdomains(target_value)
            if should_save_subdomain_cache:
                save_progress(progress_file, findings, [])
            save_requested_outputs(findings, output_path, args.csv_output)
        except KeyboardInterrupt:
            print("Subdomain discovery interrupted by user (Ctrl+C). Saving partial results and cache now...")
            partial = scanner._last_subdomain_results or findings
            if should_save_subdomain_cache:
                save_progress(progress_file, partial, [])
            save_requested_outputs(partial, output_path, args.csv_output)
            return 130
        except GitHubScannerError as exc:
            partial = scanner._last_subdomain_results or findings
            if partial:
                if should_save_subdomain_cache:
                    save_progress(progress_file, partial, [])
                save_requested_outputs(partial, output_path, args.csv_output)
            if "Authentication failed" in str(exc) or "401" in str(exc):
                if auth_mode == "authenticated":
                    print("Bad credentials. Check your GitHub token or run without --token.")
                else:
                    print(
                        "GitHub rejected the unauthenticated request. "
                        "Retry later or use --token, --tokens, or --tokens-file for higher limits."
                    )
            else:
                print(f"Subdomain discovery failed: {format_cli_error(exc, 'The scanner could not complete subdomain discovery.')}")
            return 1
        if args.verbose:
            print_findings_to_console(findings, verbose=True)
        elif not findings:
            print("No subdomains detected.")
        return 0

    repos: List[str]
    try:
        if target_type == "repo":
            repos = [target_value]
        elif target_type == "org":
            repos = client.list_org_repos(target_value)
        elif target_type == "user":
            repos = client.list_user_repos(target_value)
        elif target_type == "domain":
            repos = client.search_repos_by_domain(target_value, limit=args.max_domain_repos)
        else:
            raise ValueError(f"Unsupported target type: {target_type}")
    except GitHubScannerError as exc:
        print(f"Target resolution failed: {exc}")
        return 1

    if not repos:
        LOG.warning("No repositories found for target %s (%s)", target_value, target_type)
        print(f"No accessible repositories found for {target_type} '{target_value}'.")
        return 0

    LOG.info("Resolved %d repositories for scan", len(repos))
    all_findings: List[Dict[str, Any]] = []
    completed_repos: List[str] = []

    # Auto-resume cached progress for the same target unless flushed.
    prev_findings, prev_completed = load_progress(progress_file)
    if prev_findings or prev_completed:
        all_findings.extend(prev_findings)
        completed_repos.extend(prev_completed)
        LOG.info(
            "Loaded cache: %d previous findings, %d completed repos from %s",
            len(prev_findings),
            len(prev_completed),
            progress_file,
        )

    remaining_repos = [r for r in repos if r not in set(completed_repos)]
    LOG.info("Repositories remaining to scan: %d", len(remaining_repos))

    # Use sequential mode for robust checkpoint/resume semantics.
    interrupted = {"value": False}

    def _mark_interrupted(signum: int, frame: Any) -> None:
        interrupted["value"] = True
        raise KeyboardInterrupt

    previous_sigint = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, _mark_interrupted)
    try:
        for idx, repo in enumerate(remaining_repos, start=1):
            LOG.info("Scanning repository %d/%d: %s", idx, len(remaining_repos), repo)
            try:
                repo_findings = scanner.scan_repo(repo)
            except GitHubScannerError as exc:
                # Safe token failover for invalid/failed credentials. Not used to evade rate limits.
                if "401" in str(exc) or "Authentication failed" in str(exc):
                    LOG.warning("Active token failed; attempting failover to next valid token.")
                    switched = False
                    while valid_tokens:
                        next_token = valid_tokens.pop(0)
                        if next_token == selected_token:
                            continue
                        fallback_client = GitHubApiClient(
                            token=next_token,
                            requests_per_minute=args.requests_per_minute,
                        )
                        try:
                            fallback_client.get_rate_limit()
                            scanner.client = fallback_client
                            selected_token = next_token
                            switched = True
                            LOG.info("Token failover successful. Retrying repo: %s", repo)
                            break
                        except GitHubScannerError:
                            continue
                    if not switched:
                        # Fallback to unauthenticated mode rather than crashing with traceback.
                        fallback_client = GitHubApiClient(
                            token=None,
                            requests_per_minute=args.requests_per_minute,
                        )
                        scanner.client = fallback_client
                        selected_token = None
                        switched = True
                        LOG.warning("No valid token available. Falling back to unauthenticated mode.")
                    try:
                        repo_findings = scanner.scan_repo(repo)
                    except GitHubScannerError as retry_exc:
                        print(
                            f"Failed scanning {repo}: "
                            f"{format_cli_error(retry_exc, 'The repository scan could not be completed.')}"
                        )
                        partial = dedup_findings(all_findings, latest_only=args.latest_only)
                        save_progress(progress_file, partial, completed_repos)
                        save_requested_outputs(partial, args.output, args.csv_output)
                        return 1
                else:
                    print(
                        f"Failed scanning {repo}: "
                        f"{format_cli_error(exc, 'The repository scan could not be completed.')}"
                    )
                    partial = dedup_findings(all_findings, latest_only=args.latest_only)
                    save_progress(progress_file, partial, completed_repos)
                    save_requested_outputs(partial, args.output, args.csv_output)
                    return 1
            all_findings.extend(repo_findings)
            completed_repos.append(repo)
            save_progress(progress_file, all_findings, completed_repos)
    except KeyboardInterrupt:
        print("Scan interrupted by user (Ctrl+C). Saving partial results and cache now...")
        partial = dedup_findings(all_findings, latest_only=args.latest_only)
        save_progress(progress_file, partial, completed_repos)
        save_requested_outputs(partial, args.output, args.csv_output)
        return 130
    except Exception as exc:
        print(
            "Scan stopped due to an internal scanner error. "
            "Saving partial results and cache..."
        )
        LOG.exception("Unhandled scanner failure during repository scan: %s", exc)
        partial = dedup_findings(all_findings, latest_only=args.latest_only)
        save_progress(progress_file, partial, completed_repos)
        save_requested_outputs(partial, args.output, args.csv_output)
        return 1
    finally:
        signal.signal(signal.SIGINT, previous_sigint)

    findings = dedup_findings(all_findings, latest_only=args.latest_only)
    save_requested_outputs(findings, args.output, args.csv_output)

    LOG.info("Scan complete. Findings: %d. Output: %s", len(findings), args.output)
    save_progress(progress_file, findings, repos)
    if args.verbose:
        print_findings_to_console(findings, verbose=True)
    elif not findings:
        print("No findings detected.")
    if args.alert_webhook:
        try:
            send_alerts(args.alert_webhook, findings)
            LOG.info("Alert webhook sent to %s", args.alert_webhook)
        except GitHubScannerError as exc:
            print(f"Scan completed, but alert delivery failed: {format_cli_error(exc, 'Unable to send the alert webhook.')}")
            return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nScan interrupted by user (Ctrl+C). Exiting safely.")
        raise SystemExit(130)
    except GitHubScannerError as exc:
        print(f"Scanner error: {exc}")
        raise SystemExit(1)
    except Exception as exc:
        LOG.exception("Unexpected top-level scanner failure: %s", exc)
        print("Unexpected scanner error. Run with --verbose for more details.")
        raise SystemExit(1)
