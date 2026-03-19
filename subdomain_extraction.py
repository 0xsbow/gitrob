#!/usr/bin/env python3

import pytest

from github_recon_scanner import extract_subdomains_from_text


@pytest.mark.parametrize(
    ("text", "domain", "expected"),
    [
        ("api.example.com", "example.com", ["api.example.com"]),
        ("x.y.z.abc.example.com", "example.com", ["x.y.z.abc.example.com"]),
        ("Visit https://x.y.z.abc.example.com/path for details", "example.com", ["x.y.z.abc.example.com"]),
        ("google.com", "google.com", []),
        ("b.example.com a.example.com b.example.com x.y.example.com", "example.com", ["a.example.com", "b.example.com", "x.y.example.com"]),
        ("login.internal.acme.co.uk", "acme.co.uk", ["login.internal.acme.co.uk"]),
        ("api.service.my-company.io", "my-company.io", ["api.service.my-company.io"]),
    ],
)
def test_extract_subdomains_from_text_supports_arbitrary_domains(text, domain, expected):
    result = extract_subdomains_from_text(text, domain)
    assert result == expected


def test_normalizes_wildcard_domain_input():
    result = extract_subdomains_from_text("api.example.com", "*.example.com")
    assert result == ["api.example.com"]
