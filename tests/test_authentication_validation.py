"""Tests for email authentication validation (DKIM, SPF, headers)."""

import pytest
from email import policy
from email import message_from_bytes
from emaillm import EmailMessage, validate_dkim, validate_spf, validate_headers_match_from


def create_email(raw_email: bytes) -> EmailMessage:
    """Helper to create and parse an EmailMessage."""
    msg = message_from_bytes(raw_email, policy=policy.default)
    email = EmailMessage(
        message_id="test_msg",
        raw_data=raw_email,
        parsed=msg
    )
    email.extract_headers()
    email.extract_body()
    return email


# --- DKIM test fixtures ----------------------------------------------------
# These messages were signed offline with throwaway 1024-bit RSA keys. The
# matching public keys are served by FAKE_DKIM_DNS below so verification runs
# fully offline (no network / real DNS). DKIM canonicalization is line-ending
# sensitive, so messages are stored with LF and normalized to CRLF by _crlf().

FAKE_DKIM_DNS = {
    "sel._domainkey.example.com.":
        "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDVhZvO2Loa8bdphmp+Y/D59GRb"
        "mZqWk2Vob9t/odKIGIIL/wdoQndJS2Nd/SVuX56LvqcFT7ppgz/PwobHSHQU4NXF02UQI5PSuuK91Phd3a"
        "7XGprdxv2m7BsuAaq9P1ZZPpjKBKviMndfLjIOrUEb5PBgyuPAhkakixX83j555wIDAQAB",
    "sel2._domainkey.evil.com.":
        "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQClxfNjrQCKzmM+7JaLo2iGID3g"
        "3FkA/2n2WDjtMN0A5I7NOxheORtyNqiAQy3DKQcaaa0aFApRKSqXk625j765dWNrTrHt/9/u91A2NiNbcDR"
        "w8ZAjOhVlrLU0eGGqlfEl5FujNMUVG7psZ18Vu3r5Zax2e3WnKNY1wNSPpCvFowIDAQAB",
}


def fake_dkim_dns(name, timeout=5):
    """Stand-in for the DKIM public-key DNS lookup used by dkimpy."""
    if isinstance(name, bytes):
        name = name.decode()
    return FAKE_DKIM_DNS.get(name, "").encode()


def _crlf(text: str) -> bytes:
    return text.replace('\r\n', '\n').replace('\n', '\r\n').encode()


# Valid signature, signing domain (d=example.com) aligns with From.
DKIM_ALIGNED = _crlf("""DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/simple; d=example.com;
 i=@example.com; q=dns/txt; s=sel; t=1780170309; h=from : to : subject;
 bh=TJnoB+ZgA8hH5kDk0sHkyILr0qoHt1QABzXsd9yItT4=;
 b=Db9CgVVYy3gf0LswT3d63Ydsn+s1EfZ2DN1a/Ld7CJjFKavLwHFfDtmmC7rsdakATzb9F
 BrP3Ar8x8w5J6sVq41T7WTLa8BwzGq1XUb7GqLkWYaWG5SEFES1wswgVeEnQ/SV3cGAmUAd
 bnEJeVdkpZz59FpTJlAm0mVSApaCP90=
From: sender@example.com
To: me@example.com
Subject: Test

Hello world.
""")

# Valid signature, but signing domain (d=evil.com) does NOT match From
# (sender@example.com) - the spoofing case header-trust validation missed.
DKIM_MISALIGNED = _crlf("""DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/simple; d=evil.com;
 i=@evil.com; q=dns/txt; s=sel2; t=1780170309; h=from : to : subject;
 bh=TJnoB+ZgA8hH5kDk0sHkyILr0qoHt1QABzXsd9yItT4=;
 b=lcuJY6EIJ7HdaXLUdvbwzN8yTrQogNyWSnlzM5wyQq7XBHkMuzpxJz/wFYPyI6q5ZBT7o
 hITqUM8qQEiov13669OvMzDGw3vRauP8vXHUAO7aQAgO95qESpvGMlbrdGBEtTEivaeJ/3d
 7djFNF7qvvJN7W1Y1fzvGlhFh1ATPFg=
From: sender@example.com
To: me@example.com
Subject: Test

Hello world.
""")


class TestValidateDKIM:
    """Test cryptographic DKIM validation."""

    def test_valid_aligned_signature_passes(self):
        """A cryptographically valid signature aligned with From passes."""
        email = create_email(DKIM_ALIGNED)
        valid, reason = validate_dkim(email, dnsfunc=fake_dkim_dns)

        assert valid is True
        assert "verified" in reason.lower()

    def test_tampered_body_fails(self):
        """Modifying a signed message breaks verification."""
        email = create_email(DKIM_ALIGNED.replace(b"Hello world.", b"Goodbye, send money."))
        valid, reason = validate_dkim(email, dnsfunc=fake_dkim_dns)

        assert valid is False
        assert "dkim" in reason.lower()

    def test_valid_signature_misaligned_domain_fails(self):
        """A valid signature from an unrelated domain does not authenticate From."""
        email = create_email(DKIM_MISALIGNED)
        valid, reason = validate_dkim(email, dnsfunc=fake_dkim_dns)

        # Signature verifies, but d=evil.com is not aligned with From example.com.
        assert valid is False
        assert "align" in reason.lower()

    def test_forged_auth_results_header_is_not_trusted(self):
        """A faked 'Authentication-Results: dkim=pass' with no signature must fail.

        This is the spoofing vector cryptographic verification closes: an
        attacker can write any header they like, but cannot forge a signature.
        """
        raw_email = b"""\
From: attacker@example.com
Authentication-Results: mail.example.com; dkim=pass header.i=@example.com

Test."""
        email = create_email(raw_email)
        valid, reason = validate_dkim(email, dnsfunc=fake_dkim_dns)

        assert valid is False
        assert "no dkim-signature" in reason.lower()

    def test_no_dkim_header(self):
        """Test email without any DKIM signature fails."""
        raw_email = b"""\
From: sender@example.com

Test."""
        email = create_email(raw_email)
        valid, reason = validate_dkim(email, dnsfunc=fake_dkim_dns)

        # No DKIM signature means failure
        assert valid is False


class TestValidateSPF:
    """Test SPF validation function."""
    
    def test_spf_pass_in_auth_results(self):
        """Test SPF pass detection."""
        raw_email = b"""\
From: sender@example.com
Authentication-Results: mail.example.com; spf=pass smtp.mailfrom=example.com

Test."""
        email = create_email(raw_email)
        valid, reason = validate_spf(email)
        
        assert valid is True
        assert "spf" in reason.lower()
    
    def test_spf_fail_in_auth_results(self):
        """Test SPF fail detection."""
        raw_email = b"""\
From: sender@example.com
Authentication-Results: mail.example.com; spf=fail smtp.mailfrom=other.com

Test."""
        email = create_email(raw_email)
        valid, reason = validate_spf(email)
        
        assert valid is False
        assert "spf" in reason.lower()
    
    def test_spf_softfail_is_failure(self):
        """Test SPF softfail is treated as failure."""
        raw_email = b"""\
From: sender@example.com
Authentication-Results: mail.example.com; spf=softfail smtp.mailfrom=example.com

Test."""
        email = create_email(raw_email)
        valid, reason = validate_spf(email)
        
        # Softfail is treated as failure
        assert valid is False
    
    def test_spf_none_is_pass(self):
        """Test SPF none (not checked) is treated as pass."""
        raw_email = b"""\
From: sender@example.com
Authentication-Results: mail.example.com; spf=none smtp.mailfrom=example.com

Test."""
        email = create_email(raw_email)
        valid, reason = validate_spf(email)
        
        # SPF=none means server didn't check, we trust the server
        assert valid is True
    
    def test_spf_neutral_is_pass(self):
        """Test SPF neutral is treated as pass."""
        raw_email = b"""\
From: sender@example.com
Authentication-Results: mail.example.com; spf=neutral smtp.mailfrom=example.com

Test."""
        email = create_email(raw_email)
        valid, reason = validate_spf(email)
        
        # Neutral is treated as pass
        assert valid is True
    
    def test_received_spf_header(self):
        """Test SPF from Received-SPF header."""
        raw_email = b"""\
From: sender@example.com
Received-SPF: pass (mail.example.com: domain of sender@example.com designates 1.2.3.4 as permitted sender)

Test."""
        email = create_email(raw_email)
        valid, reason = validate_spf(email)
        
        assert valid is True
    
    def test_no_spf_info(self):
        """Test email without SPF info passes (no info to check)."""
        raw_email = b"""\
From: sender@example.com

Test."""
        email = create_email(raw_email)
        valid, reason = validate_spf(email)
        
        # No SPF info means we can't check, so pass
        assert valid is True


class TestValidateHeadersMatchFrom:
    """Test header validation function."""
    
    def test_headers_match(self):
        """Test when headers match From address."""
        raw_email = b"""\
From: sender@example.com
Return-Path: <sender@example.com>
Sender: sender@example.com

Test."""
        email = create_email(raw_email)
        valid, reason = validate_headers_match_from(email)
        
        assert valid is True
    
    def test_headers_mismatch_different_domain(self):
        """Test when headers don't match From address."""
        raw_email = b"""\
From: sender@example.com
Return-Path: <attacker@evil.com>
Sender: attacker@evil.com

Test."""
        email = create_email(raw_email)
        valid, reason = validate_headers_match_from(email)
        
        # Implementation is lenient - logs warning but passes
        assert valid is True
    
    def test_known_mailer_domain_gmail(self):
        """Test that Gmail is allowed."""
        raw_email = b"""\
From: user@gmail.com
Return-Path: <bounces@gmail.com>
Sender: gmail.com

Test."""
        email = create_email(raw_email)
        valid, reason = validate_headers_match_from(email)
        
        # Gmail is a known mailer, should pass
        assert valid is True
    
    def test_known_mailer_domain_sendgrid(self):
        """Test that SendGrid is allowed."""
        raw_email = b"""\
From: notifications@example.com
Return-Path: <bounce@sendgrid.net>
Sender: sendgrid.net

Test."""
        email = create_email(raw_email)
        valid, reason = validate_headers_match_from(email)
        
        # SendGrid is a known mailer, should pass
        assert valid is True
    
    def test_no_return_path(self):
        """Test email without Return-Path passes."""
        raw_email = b"""\
From: sender@example.com

Test."""
        email = create_email(raw_email)
        valid, reason = validate_headers_match_from(email)
        
        # Should pass (no info to check)
        assert valid is True
