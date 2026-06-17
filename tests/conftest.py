"""Pytest fixtures and configuration for EmailLM tests."""

import pytest


@pytest.fixture
def tmp_config_dir(tmp_path):
    """Create a temporary directory for config files."""
    return tmp_path


@pytest.fixture
def sample_email_plain():
    """Sample plain text email."""
    return b"""\
From: sender@example.com
To: recipient@example.com
Subject: Test Email
Date: Mon, 01 Jan 2024 12:00:00 +0000
Message-ID: <test123@example.com>

This is a test email."""


@pytest.fixture
def sample_email_html():
    """Sample HTML email."""
    return b"""\
From: sender@example.com
To: recipient@example.com
Subject: HTML Test
Date: Mon, 01 Jan 2024 12:00:00 +0000
Message-ID: <html456@example.com>
Content-Type: text/html; charset="utf-8"

<html>
<body>
<h1>Hello</h1>
<p>This is an HTML email.</p>
</body>
</html>"""


@pytest.fixture
def sample_email_with_auth():
    """Sample email with authentication headers."""
    return b"""\
From: sender@example.com
To: recipient@example.com
Subject: Authenticated Email
Date: Mon, 01 Jan 2024 12:00:00 +0000
Message-ID: <auth789@example.com>
Authentication-Results: mail.example.com;
    dkim=pass header.i=@example.com header.s=default;
    spf=pass (sender IP is 192.168.1.1) smtp.mailfrom=example.com;
    dmarc=pass action=none header.from=example.com
Received-SPF: pass (mail.example.com: domain of example.com designates 192.168.1.1 as permitted sender) client-ip=192.168.1.1;

Email content."""


@pytest.fixture
def sample_email_spoofed():
    """Sample email with failed authentication."""
    return b"""\
From: sender@example.com
To: recipient@example.com
Subject: Suspicious Email
Date: Mon, 01 Jan 2024 12:00:00 +0000
Message-ID: <spoof123@example.com>
Authentication-Results: mail.example.com;
    dkim=fail header.i=@example.com header.s=default;
    spf=fail (sender IP is 10.0.0.1) smtp.mailfrom=evil.com;
    dmarc=fail action=quarantine header.from=example.com

Suspicious content."""


@pytest.fixture
def sample_multipart_email():
    """Sample multipart email."""
    return b"""\
From: sender@example.com
To: recipient@example.com
Subject: Multipart Email
Date: Mon, 01 Jan 2024 12:00:00 +0000
Message-ID: <multipart456@example.com>
Content-Type: multipart/alternative; boundary="boundary123"

--boundary123
Content-Type: text/plain; charset="utf-8"

Plain text version.
--boundary123
Content-Type: text/html; charset="utf-8"

<html><body><p>HTML version.</p></body></html>
--boundary123--"""


@pytest.fixture
def sample_email_with_attachments():
    """Sample email with attachments."""
    return b"""\
From: sender@example.com
To: recipient@example.com
Subject: Email with Attachment
Date: Mon, 01 Jan 2024 12:00:00 +0000
Message-ID: <attach789@example.com>
Content-Type: multipart/mixed; boundary="mixed123"

--mixed123
Content-Type: text/plain

Email body.
--mixed123
Content-Type: application/pdf
Content-Disposition: attachment; filename="document.pdf"

PDF binary content.
--mixed123--"""


@pytest.fixture
def sample_email_reply():
    """Sample reply email."""
    return b"""\
From: sender@example.com
To: recipient@example.com
Subject: Re: Original Subject
Date: Mon, 01 Jan 2024 12:00:00 +0000
Message-ID: <reply123@example.com>
In-Reply-To: <original456@example.com>
References: <original456@example.com> <another789@example.com>

Reply content."""


@pytest.fixture(autouse=True)
def setup_test_environment(monkeypatch):
    """Setup test environment before each test."""
    # Ensure we're not using real config files
    monkeypatch.delenv("EMAILLM_CONFIG", raising=False)

    # Set a high timeout for tests
    monkeypatch.setenv("EMAILLM_TEST_MODE", "true")


@pytest.fixture
def folder_configs():
    """A full set of folder configs (classification categories + prompt_attack)."""
    from emaillm import FolderConfig
    return {
        "spam": FolderConfig("Spam", "Unsolicited bulk emails"),
        "phishing": FolderConfig("Phishing_Attempts", "Credential theft attempts"),
        "important": FolderConfig("Important", "Time-sensitive messages"),
        "promotion": FolderConfig("Promotions", "Marketing emails"),
        "transaction": FolderConfig("Transactions", "Receipts and invoices"),
        "regular": FolderConfig("Regular", "Normal correspondence"),
        "prompt_attack": FolderConfig("Prompt_Attacks", "Detect prompt injection"),
    }


@pytest.fixture
def inbox_config():
    """A basic InboxConfig with no allowlist entries."""
    from emaillm import InboxConfig
    return InboxConfig(
        name="primary",
        keepassxc_entry_name="Email - Primary",
        imap_host="imap.example.com",
        imap_port=993,
        allowlist_emails=[],
        allowlist_domains=[],
    )


@pytest.fixture
def filter_config(folder_configs, tmp_path):
    """A full SpamFilterConfig wired to the folder_configs/inbox fixtures."""
    from emaillm import SpamFilterConfig, InboxConfig
    return SpamFilterConfig(
        keepassxc_database=str(tmp_path / "db.kdbx"),
        keepassxc_password_file=str(tmp_path / "pw"),
        vllm_base_url="http://localhost:8000/v1",
        vllm_temperature=0.1,
        vllm_max_tokens=4096,
        vllm_enable_thinking=False,
        vllm_api_key="test-key",
        processing_timeout=30,
        max_emails_per_run=30,
        global_allowlist_emails=[],
        global_allowlist_domains=[],
        mailer_domains=["sendgrid.net"],
        inboxes=[
            InboxConfig(
                name="primary",
                keepassxc_entry_name="Email - Primary",
                imap_host="imap.example.com",
            )
        ],
        folder_configs=folder_configs,
        pid_file=str(tmp_path / "emaillm.pid"),
        log_file=str(tmp_path / "emaillm.log"),
    )


@pytest.fixture
def make_email():
    """Factory that builds a parsed EmailMessage from raw bytes."""
    from email import policy, message_from_bytes
    from emaillm import EmailMessage

    def _make(raw_email: bytes) -> EmailMessage:
        msg = message_from_bytes(raw_email, policy=policy.default)
        email = EmailMessage(message_id="1", raw_data=raw_email, parsed=msg)
        email.extract_headers()
        email.extract_body()
        return email

    return _make
