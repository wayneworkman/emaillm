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


class TestValidateDKIM:
    """Test DKIM validation function."""
    
    def test_dkim_pass_in_auth_results(self):
        """Test DKIM pass detection."""
        raw_email = b"""\
From: sender@example.com
Authentication-Results: mail.example.com; dkim=pass header.i=@example.com

Test."""
        email = create_email(raw_email)
        valid, reason = validate_dkim(email)
        
        assert valid is True
        assert "dkim" in reason.lower()
    
    def test_dkim_fail_in_auth_results(self):
        """Test DKIM fail detection."""
        raw_email = b"""\
From: sender@example.com
Authentication-Results: mail.example.com; dkim=fail header.i=@example.com

Test."""
        email = create_email(raw_email)
        valid, reason = validate_dkim(email)
        
        assert valid is False
        assert "dkim" in reason.lower()
    
    def test_dkim_none_in_auth_results(self):
        """Test DKIM none is treated as failure."""
        raw_email = b"""\
From: sender@example.com
Authentication-Results: mail.example.com; dkim=none

Test."""
        email = create_email(raw_email)
        valid, reason = validate_dkim(email)
        
        # DKIM=none is treated as failure
        assert valid is False
        assert "dkim" in reason.lower()
    
    def test_no_authentication_results_no_dkim_header(self):
        """Test email without any DKIM info fails."""
        raw_email = b"""\
From: sender@example.com

Test."""
        email = create_email(raw_email)
        valid, reason = validate_dkim(email)
        
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
