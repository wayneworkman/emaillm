"""Tests for email parsing and message handling."""

import pytest
from email import policy
from email import message_from_bytes
from emaillm import EmailMessage


class TestEmailMessage:
    """Test EmailMessage dataclass parsing."""
    
    def test_parse_simple_email(self):
        """Test parsing a simple email."""
        raw_email = b"""\
From: sender@example.com
To: recipient@example.com
Subject: Test Subject
Date: Mon, 01 Jan 2024 12:00:00 +0000
Message-ID: <test123@example.com>

Hello, this is a test email."""
        
        msg = message_from_bytes(raw_email, policy=policy.default)
        email = EmailMessage(
            message_id="msg001",
            raw_data=raw_email,
            parsed=msg
        )
        email.extract_headers()
        email.extract_body()
        
        assert email.from_address == "sender@example.com"
        assert email.subject == "Test Subject"
        assert "Hello, this is a test email" in email.body_text
    
    def test_parse_email_with_encoded_subject(self):
        """Test parsing email with encoded subject."""
        raw_email = b"""\
From: sender@example.com
To: recipient@example.com
Subject: =?utf-8?B?SGVsbG8gV29ybGQ=?=
Message-ID: <test456@example.com>

Test content."""
        
        msg = message_from_bytes(raw_email, policy=policy.default)
        email = EmailMessage(
            message_id="msg002",
            raw_data=raw_email,
            parsed=msg
        )
        email.extract_headers()
        
        assert email.subject == "Hello World"
    
    def test_parse_email_with_mime(self):
        """Test parsing MIME multipart email."""
        raw_email = b"""\
From: sender@example.com
To: recipient@example.com
Subject: MIME Test
Message-ID: <mime789@example.com>
Content-Type: multipart/alternative; boundary="boundary123"

--boundary123
Content-Type: text/plain; charset="utf-8"

Plain text version.
--boundary123
Content-Type: text/html; charset="utf-8"

<html><body>HTML version.</body></html>
--boundary123--"""
        
        msg = message_from_bytes(raw_email, policy=policy.default)
        email = EmailMessage(
            message_id="msg003",
            raw_data=raw_email,
            parsed=msg
        )
        email.extract_headers()
        email.extract_body()
        
        assert email.subject == "MIME Test"
        assert "Plain text version" in email.body_text
        assert "HTML version" in email.body_html
    
    def test_parse_email_with_authentication_results(self):
        """Test parsing email with authentication headers."""
        raw_email = b"""\
From: sender@example.com
To: recipient@example.com
Subject: Auth Test
Message-ID: <auth456@example.com>
Authentication-Results: mail.example.com;
    dkim=pass header.i=@example.com;
    spf=pass (sender IP is 1.2.3.4) smtp.mailfrom=example.com;
    dmarc=pass action=none header.from=example.com

Test content."""
        
        msg = message_from_bytes(raw_email, policy=policy.default)
        email = EmailMessage(
            message_id="msg004",
            raw_data=raw_email,
            parsed=msg
        )
        email.extract_headers()
        
        assert "dkim=pass" in email.headers['authentication_results']
        assert "spf=pass" in email.headers['authentication_results']
    
    def test_parse_email_with_in_reply_to(self):
        """Test parsing email with In-Reply-To header."""
        raw_email = b"""\
From: sender@example.com
To: recipient@example.com
Subject: Re: Original Subject
Message-ID: <reply123@example.com>
In-Reply-To: <original456@example.com>
References: <original456@example.com> <another789@example.com>

Reply content."""
        
        msg = message_from_bytes(raw_email, policy=policy.default)
        email = EmailMessage(
            message_id="msg005",
            raw_data=raw_email,
            parsed=msg
        )
        email.extract_headers()
        
        assert email.headers['in_reply_to'] == "<original456@example.com>"
        assert "<original456@example.com>" in email.headers['references']
    
    def test_parse_email_with_missing_headers(self):
        """Test parsing email with minimal headers."""
        raw_email = b"""\
From: sender@example.com

Minimal email."""
        
        msg = message_from_bytes(raw_email, policy=policy.default)
        email = EmailMessage(
            message_id="msg006",
            raw_data=raw_email,
            parsed=msg
        )
        email.extract_headers()
        email.extract_body()
        
        assert email.from_address == "sender@example.com"
        assert email.subject == ""
    
    def test_get_text_content_plain_text(self):
        """Test extracting text from plain text email."""
        raw_email = b"""\
From: sender@example.com
Content-Type: text/plain; charset="utf-8"

Plain text content."""
        
        msg = message_from_bytes(raw_email, policy=policy.default)
        email = EmailMessage(
            message_id="msg007",
            raw_data=raw_email,
            parsed=msg
        )
        email.extract_headers()
        email.extract_body()
        
        assert "Plain text content" in email.body_text
    
    def test_get_text_content_from_html(self):
        """Test extracting text from HTML email."""
        raw_email = b"""\
From: sender@example.com
Content-Type: text/html; charset="utf-8"

<html><body><p>HTML content</p></body></html>"""
        
        msg = message_from_bytes(raw_email, policy=policy.default)
        email = EmailMessage(
            message_id="msg008",
            raw_data=raw_email,
            parsed=msg
        )
        email.extract_headers()
        email.extract_body()
        
        # HTML content should be extracted and converted to text
        assert "HTML content" in email.body_text
    
    def test_from_address_parsing_with_name(self):
        """Test parsing From address with display name."""
        raw_email = b"""\
From: "John Doe" <john@example.com>
To: recipient@example.com

Test."""
        
        msg = message_from_bytes(raw_email, policy=policy.default)
        email = EmailMessage(
            message_id="msg009",
            raw_data=raw_email,
            parsed=msg
        )
        email.extract_headers()
        
        # Should extract just the email address
        assert email.from_address == "john@example.com"
    
    def test_from_domain_extraction(self):
        """Test domain extraction from From address."""
        raw_email = b"""\
From: sender@example.com
To: recipient@example.com

Test."""
        
        msg = message_from_bytes(raw_email, policy=policy.default)
        email = EmailMessage(
            message_id="msg010",
            raw_data=raw_email,
            parsed=msg
        )
        email.extract_headers()
        
        assert email.from_domain == "example.com"
    
    def test_from_domain_extraction_with_subdomain(self):
        """Test domain extraction with subdomain."""
        raw_email = b"""\
From: sender@mail.example.com
To: recipient@example.com

Test."""
        
        msg = message_from_bytes(raw_email, policy=policy.default)
        email = EmailMessage(
            message_id="msg011",
            raw_data=raw_email,
            parsed=msg
        )
        email.extract_headers()
        
        assert email.from_domain == "example.com"
