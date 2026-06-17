"""Tests for validate_email_authenticity orchestration and allowlisting."""

import pytest

import emaillm
from emaillm import validate_email_authenticity, InboxConfig


@pytest.fixture
def email(make_email):
    raw = (
        b"From: sender@example.com\n"
        b"To: me@example.com\n"
        b"Subject: Hi\n\n"
        b"Body.\n"
    )
    return make_email(raw)


def _patch_checks(monkeypatch, dkim=True, spf=(True, "ok"), headers=True):
    monkeypatch.setattr(
        emaillm, "validate_dkim",
        lambda e: (dkim, "dkim reason"),
    )
    monkeypatch.setattr(
        emaillm, "validate_spf",
        lambda e: spf,
    )
    monkeypatch.setattr(
        emaillm, "validate_headers_match_from",
        lambda e, mailer_domains=None: (headers, "header reason"),
    )


class TestAllowlisting:
    def test_email_address_allowlisted(self, email, folder_configs):
        cls, reason = validate_email_authenticity(
            email, InboxConfig("i", "e", "h"),
            ["sender@example.com"], [], folder_configs,
        )
        assert cls.category == "allowlisted"
        assert cls.target_folder == "Regular"
        assert "allowlisted" in reason.lower()

    def test_domain_allowlisted_exact(self, email, folder_configs):
        # from_domain collapses to the registered domain (example.com)
        cls, reason = validate_email_authenticity(
            email, InboxConfig("i", "e", "h"),
            [], ["example.com"], folder_configs,
        )
        assert cls.category == "allowlisted"
        assert "example.com" in reason

    def test_domain_wildcard_does_not_match_apex(self, email, folder_configs, monkeypatch):
        """'*.example.com' must NOT match the apex 'example.com' -> not allowlisted."""
        _patch_checks(monkeypatch)
        cls, _ = validate_email_authenticity(
            email, InboxConfig("i", "e", "h"),
            [], ["*.example.com"], folder_configs,
        )
        assert cls.category == "regular"

    def test_inbox_level_allowlist(self, email, folder_configs):
        inbox = InboxConfig("i", "e", "h", allowlist_emails=["sender@example.com"])
        cls, _ = validate_email_authenticity(
            email, inbox, [], [], folder_configs,
        )
        assert cls.category == "allowlisted"


class TestAuthChecks:
    def test_all_pass_returns_regular(self, email, folder_configs, monkeypatch):
        _patch_checks(monkeypatch)
        cls, reason = validate_email_authenticity(
            email, InboxConfig("i", "e", "h"), [], [], folder_configs,
        )
        assert cls.category == "regular"
        assert "passed" in reason.lower()

    def test_dkim_fail_marks_spoofed(self, email, folder_configs, monkeypatch):
        _patch_checks(monkeypatch, dkim=False)
        cls, reason = validate_email_authenticity(
            email, InboxConfig("i", "e", "h"), [], [], folder_configs,
        )
        assert cls.category == "spoofed"
        assert cls.target_folder == "Spam"
        assert "DKIM" in reason

    def test_spf_hardfail_marks_spoofed(self, email, folder_configs, monkeypatch):
        _patch_checks(monkeypatch, spf=(False, "SPF failed"))
        cls, _ = validate_email_authenticity(
            email, InboxConfig("i", "e", "h"), [], [], folder_configs,
        )
        assert cls.category == "spoofed"

    def test_spf_softfail_not_spoofed(self, email, folder_configs, monkeypatch):
        """softfail in the reason must not trigger the spoofed branch."""
        _patch_checks(monkeypatch, spf=(False, "SPF softfail - lenient"))
        cls, _ = validate_email_authenticity(
            email, InboxConfig("i", "e", "h"), [], [], folder_configs,
        )
        assert cls.category == "regular"

    def test_header_fail_marks_spoofed(self, email, folder_configs, monkeypatch):
        _patch_checks(monkeypatch, headers=False)
        cls, _ = validate_email_authenticity(
            email, InboxConfig("i", "e", "h"), [], [], folder_configs,
        )
        assert cls.category == "spoofed"

    def test_allowlisted_email_survives_dkim_failure(self, email, folder_configs, monkeypatch):
        """An allowlisted address that fails DKIM is still treated as allowlisted."""
        _patch_checks(monkeypatch, dkim=False)
        cls, _ = validate_email_authenticity(
            email, InboxConfig("i", "e", "h"),
            ["sender@example.com"], [], folder_configs,
        )
        # Allowlist check returns before validation runs at all
        assert cls.category == "allowlisted"
