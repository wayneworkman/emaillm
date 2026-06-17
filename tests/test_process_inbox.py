"""Tests for process_inbox end-to-end flow with mocked IMAP and vLLM."""

from unittest.mock import MagicMock

import pytest

import emaillm
from emaillm import process_inbox, EmailClassification


CREDS = {"username": "me@example.com", "password": "pw", "host": "imap.example.com"}


def build_email(from_addr="sender@example.com", subject="Hi", extra_headers="", body="Body"):
    headers = f"From: {from_addr}\r\nTo: me@example.com\r\nSubject: {subject}\r\n"
    if extra_headers:
        headers += extra_headers
        if not extra_headers.endswith("\r\n"):
            headers += "\r\n"
    return (headers + "\r\n" + body).encode()


@pytest.fixture
def harness(monkeypatch, filter_config, inbox_config):
    """Wire up mocked credentials, IMAP connection and sent-folder scan.

    Returns an object exposing knobs to configure the run.
    """
    class Harness:
        def __init__(self):
            self.imap = MagicMock()
            self.imap.select.return_value = ("OK", [b"1"])
            self.emails = []
            self.sent_recipients = set()
            self.sent_message_ids = set()
            self.move_calls = []
            self.move_result = True

        def set_emails(self, emails):
            self.emails = emails
            ids = " ".join(str(i + 1) for i in range(len(emails))).encode()
            self.imap.search.return_value = ("OK", [ids])

            def fetch(mail_id, spec):
                idx = int(mail_id) - 1
                if idx < 0 or idx >= len(emails):
                    return ("NO", [None])
                return ("OK", [(f"{mail_id} (RFC822)".encode(), emails[idx])])

            self.imap.fetch.side_effect = fetch

        def install(self):
            monkeypatch.setattr(emaillm, "get_keepassxc_credential", lambda *a, **k: CREDS)
            monkeypatch.setattr(emaillm.imaplib, "IMAP4_SSL", lambda *a, **k: self.imap)
            monkeypatch.setattr(emaillm, "ensure_all_folders_exist", lambda *a, **k: True)
            monkeypatch.setattr(
                emaillm, "extract_sent_data_from_sent_folder",
                lambda *a, **k: (self.sent_recipients, self.sent_message_ids),
            )

            def move(imap, mail_id, folder):
                self.move_calls.append((mail_id, folder))
                return self.move_result

            monkeypatch.setattr(emaillm, "move_to_folder", move)

        def run(self):
            return process_inbox(inbox_config, filter_config, "model")

    h = Harness()
    return h


class TestProcessInboxEarlyExits:
    def test_credential_failure_returns_stats(self, monkeypatch, filter_config, inbox_config):
        def boom(*a, **k):
            raise Exception("no creds")

        monkeypatch.setattr(emaillm, "get_keepassxc_credential", boom)
        stats = process_inbox(inbox_config, filter_config, "model")
        assert stats["processed"] == 0

    def test_imap_connect_failure_returns_stats(self, monkeypatch, filter_config, inbox_config):
        monkeypatch.setattr(emaillm, "get_keepassxc_credential", lambda *a, **k: CREDS)

        def boom(*a, **k):
            raise OSError("connection refused")

        monkeypatch.setattr(emaillm.imaplib, "IMAP4_SSL", boom)
        stats = process_inbox(inbox_config, filter_config, "model")
        assert stats["processed"] == 0

    def test_select_inbox_failure(self, harness):
        harness.install()
        harness.imap.select.return_value = ("NO", [b"cannot select"])
        stats = harness.run()
        assert stats["processed"] == 0

    def test_folder_creation_failure(self, harness, monkeypatch):
        harness.install()
        monkeypatch.setattr(emaillm, "ensure_all_folders_exist", lambda *a, **k: False)
        stats = harness.run()
        assert stats["processed"] == 0

    def test_search_failure(self, harness):
        harness.install()
        harness.imap.search.return_value = ("NO", [b"search failed"])
        stats = harness.run()
        assert stats["processed"] == 0


class TestProcessInboxRouting:
    def test_own_email_to_important(self, harness):
        harness.set_emails([build_email(from_addr="me@example.com")])
        harness.install()
        stats = harness.run()
        assert stats["important"] == 1
        assert harness.move_calls == [("1", "Important")]

    def test_spoofed_to_spam(self, harness, monkeypatch):
        harness.set_emails([build_email()])
        harness.install()
        monkeypatch.setattr(
            emaillm, "validate_email_authenticity",
            lambda *a, **k: (EmailClassification("spoofed", "Spam"), "bad dkim"),
        )
        stats = harness.run()
        assert stats["spoofed"] == 1
        assert harness.move_calls == [("1", "Spam")]

    def test_allowlisted_to_regular(self, harness, monkeypatch):
        harness.set_emails([build_email()])
        harness.install()
        monkeypatch.setattr(
            emaillm, "validate_email_authenticity",
            lambda *a, **k: (EmailClassification("allowlisted", "Regular"), "allowed"),
        )
        stats = harness.run()
        assert stats["allowlisted"] == 1
        assert harness.move_calls == [("1", "Regular")]

    def test_previously_contacted_to_important(self, harness, monkeypatch):
        harness.set_emails([build_email(from_addr="friend@example.com")])
        harness.sent_recipients = {"friend@example.com"}
        harness.install()
        monkeypatch.setattr(
            emaillm, "validate_email_authenticity",
            lambda *a, **k: (EmailClassification("regular", "Regular"), "ok"),
        )
        stats = harness.run()
        assert stats["important"] == 1
        assert harness.move_calls == [("1", "Important")]

    def test_conversation_in_reply_to(self, harness, monkeypatch):
        email = build_email(extra_headers="In-Reply-To: <our-msg@example.com>\r\n")
        harness.set_emails([email])
        harness.sent_message_ids = {"our-msg@example.com"}
        harness.install()
        monkeypatch.setattr(
            emaillm, "validate_email_authenticity",
            lambda *a, **k: (EmailClassification("regular", "Regular"), "ok"),
        )
        stats = harness.run()
        assert stats["important"] == 1

    def test_conversation_references(self, harness, monkeypatch):
        email = build_email(
            extra_headers="References: <a@example.com> <our-msg@example.com>\r\n"
        )
        harness.set_emails([email])
        harness.sent_message_ids = {"our-msg@example.com"}
        harness.install()
        monkeypatch.setattr(
            emaillm, "validate_email_authenticity",
            lambda *a, **k: (EmailClassification("regular", "Regular"), "ok"),
        )
        stats = harness.run()
        assert stats["important"] == 1

    def test_prompt_attack_detected(self, harness, monkeypatch):
        harness.set_emails([build_email()])
        harness.install()
        monkeypatch.setattr(
            emaillm, "validate_email_authenticity",
            lambda *a, **k: (EmailClassification("regular", "Regular"), "ok"),
        )
        monkeypatch.setattr(
            emaillm, "detect_prompt_injection",
            lambda *a, **k: (False, "injection!"),
        )
        stats = harness.run()
        assert stats["prompt_injection"] == 1
        assert harness.move_calls == [("1", "Prompt_Attacks")]

    def test_normal_classification(self, harness, monkeypatch):
        harness.set_emails([build_email()])
        harness.install()
        monkeypatch.setattr(
            emaillm, "validate_email_authenticity",
            lambda *a, **k: (EmailClassification("regular", "Regular"), "ok"),
        )
        monkeypatch.setattr(emaillm, "detect_prompt_injection", lambda *a, **k: (True, "safe"))
        monkeypatch.setattr(
            emaillm, "classify_email_vllm",
            lambda *a, **k: (EmailClassification("promotion", "Promotions"), "marketing"),
        )
        stats = harness.run()
        assert stats["promotion"] == 1
        assert harness.move_calls == [("1", "Promotions")]

    def test_classification_without_prompt_attack_config(self, harness, monkeypatch, filter_config):
        """When prompt_attack folder is absent, injection detection is skipped."""
        del filter_config.folder_configs["prompt_attack"]
        harness.set_emails([build_email()])
        harness.install()
        called = {"injection": False}

        def injection(*a, **k):
            called["injection"] = True
            return (True, "safe")

        monkeypatch.setattr(emaillm, "detect_prompt_injection", injection)
        monkeypatch.setattr(
            emaillm, "validate_email_authenticity",
            lambda *a, **k: (EmailClassification("regular", "Regular"), "ok"),
        )
        monkeypatch.setattr(
            emaillm, "classify_email_vllm",
            lambda *a, **k: (EmailClassification("regular", "Regular"), "ok"),
        )
        stats = harness.run()
        assert called["injection"] is False
        assert stats["regular"] == 1


class TestProcessInboxErrors:
    def test_fetch_failure_counts_error(self, harness):
        harness.set_emails([build_email()])
        harness.install()
        harness.imap.fetch.side_effect = None
        harness.imap.fetch.return_value = ("NO", [None])
        stats = harness.run()
        assert stats["errors"] == 1

    def test_classification_error_counts_error(self, harness, monkeypatch):
        harness.set_emails([build_email()])
        harness.install()
        monkeypatch.setattr(
            emaillm, "validate_email_authenticity",
            lambda *a, **k: (EmailClassification("regular", "Regular"), "ok"),
        )
        monkeypatch.setattr(emaillm, "detect_prompt_injection", lambda *a, **k: (True, "safe"))
        monkeypatch.setattr(
            emaillm, "classify_email_vllm",
            lambda *a, **k: (EmailClassification("error", None), "boom"),
        )
        stats = harness.run()
        assert stats["errors"] == 1

    def test_move_failure_counts_error(self, harness, monkeypatch):
        harness.set_emails([build_email(from_addr="me@example.com")])
        harness.install()
        harness.move_result = False
        stats = harness.run()
        assert stats["errors"] == 1
        assert stats["important"] == 0

    def test_exception_during_processing_counts_error(self, harness, monkeypatch):
        harness.set_emails([build_email()])
        harness.install()

        def boom(*a, **k):
            raise RuntimeError("unexpected")

        monkeypatch.setattr(emaillm, "validate_email_authenticity", boom)
        stats = harness.run()
        assert stats["errors"] == 1

    def test_max_emails_per_run_limits(self, harness, filter_config, monkeypatch):
        filter_config.max_emails_per_run = 2
        harness.set_emails([build_email(from_addr="me@example.com") for _ in range(5)])
        harness.install()
        stats = harness.run()
        # Only the 2 newest are processed
        assert stats["processed"] == 2

    def test_expunge_failure_is_swallowed(self, harness):
        harness.set_emails([build_email(from_addr="me@example.com")])
        harness.install()
        harness.imap.expunge.side_effect = Exception("expunge failed")
        # Should still complete and return stats
        stats = harness.run()
        assert stats["important"] == 1

    def test_spoofed_move_failure_counts_error(self, harness, monkeypatch):
        harness.set_emails([build_email()])
        harness.install()
        harness.move_result = False
        monkeypatch.setattr(
            emaillm, "validate_email_authenticity",
            lambda *a, **k: (EmailClassification("spoofed", "Spam"), "bad"),
        )
        stats = harness.run()
        assert stats["errors"] == 1
        assert stats["spoofed"] == 0

    def test_allowlisted_move_failure_counts_error(self, harness, monkeypatch):
        harness.set_emails([build_email()])
        harness.install()
        harness.move_result = False
        monkeypatch.setattr(
            emaillm, "validate_email_authenticity",
            lambda *a, **k: (EmailClassification("allowlisted", "Regular"), "ok"),
        )
        stats = harness.run()
        assert stats["errors"] == 1

    def test_previously_contacted_move_failure_counts_error(self, harness, monkeypatch):
        harness.set_emails([build_email(from_addr="friend@example.com")])
        harness.sent_recipients = {"friend@example.com"}
        harness.install()
        harness.move_result = False
        monkeypatch.setattr(
            emaillm, "validate_email_authenticity",
            lambda *a, **k: (EmailClassification("regular", "Regular"), "ok"),
        )
        stats = harness.run()
        assert stats["errors"] == 1

    def test_conversation_move_failure_counts_error(self, harness, monkeypatch):
        email = build_email(extra_headers="In-Reply-To: <our-msg@example.com>\r\n")
        harness.set_emails([email])
        harness.sent_message_ids = {"our-msg@example.com"}
        harness.install()
        harness.move_result = False
        monkeypatch.setattr(
            emaillm, "validate_email_authenticity",
            lambda *a, **k: (EmailClassification("regular", "Regular"), "ok"),
        )
        stats = harness.run()
        assert stats["errors"] == 1

    def test_prompt_attack_move_failure_counts_error(self, harness, monkeypatch):
        harness.set_emails([build_email()])
        harness.install()
        harness.move_result = False
        monkeypatch.setattr(
            emaillm, "validate_email_authenticity",
            lambda *a, **k: (EmailClassification("regular", "Regular"), "ok"),
        )
        monkeypatch.setattr(emaillm, "detect_prompt_injection", lambda *a, **k: (False, "bad"))
        stats = harness.run()
        assert stats["errors"] == 1

    def test_classified_move_failure_counts_error(self, harness, monkeypatch):
        harness.set_emails([build_email()])
        harness.install()
        harness.move_result = False
        monkeypatch.setattr(
            emaillm, "validate_email_authenticity",
            lambda *a, **k: (EmailClassification("regular", "Regular"), "ok"),
        )
        monkeypatch.setattr(emaillm, "detect_prompt_injection", lambda *a, **k: (True, "safe"))
        monkeypatch.setattr(
            emaillm, "classify_email_vllm",
            lambda *a, **k: (EmailClassification("spam", "Spam"), "spammy"),
        )
        stats = harness.run()
        assert stats["errors"] == 1

    def test_non_matching_references_proceeds_to_classification(self, harness, monkeypatch):
        email = build_email(extra_headers="References: <unrelated@x.com>\r\n")
        harness.set_emails([email])
        harness.sent_message_ids = {"different@example.com"}
        harness.install()
        monkeypatch.setattr(
            emaillm, "validate_email_authenticity",
            lambda *a, **k: (EmailClassification("regular", "Regular"), "ok"),
        )
        monkeypatch.setattr(emaillm, "detect_prompt_injection", lambda *a, **k: (True, "safe"))
        monkeypatch.setattr(
            emaillm, "classify_email_vllm",
            lambda *a, **k: (EmailClassification("spam", "Spam"), "spammy"),
        )
        stats = harness.run()
        # Not routed as a conversation -> classified normally
        assert stats["spam"] == 1
        assert harness.move_calls == [("1", "Spam")]

    def test_classification_with_no_target_folder_counts_error(self, harness, monkeypatch):
        harness.set_emails([build_email()])
        harness.install()
        monkeypatch.setattr(
            emaillm, "validate_email_authenticity",
            lambda *a, **k: (EmailClassification("regular", "Regular"), "ok"),
        )
        monkeypatch.setattr(emaillm, "detect_prompt_injection", lambda *a, **k: (True, "safe"))
        # Non-error category but a missing folder name -> no target folder
        monkeypatch.setattr(
            emaillm, "classify_email_vllm",
            lambda *a, **k: (EmailClassification("regular", None), "weird"),
        )
        stats = harness.run()
        assert stats["errors"] == 1
        assert harness.move_calls == []

    def test_custom_category_stats_initialized(self, harness, monkeypatch, filter_config):
        from emaillm import FolderConfig
        filter_config.folder_configs["interviews"] = FolderConfig("Interviews", "jobs")
        harness.set_emails([build_email()])
        harness.install()
        monkeypatch.setattr(
            emaillm, "validate_email_authenticity",
            lambda *a, **k: (EmailClassification("regular", "Regular"), "ok"),
        )
        monkeypatch.setattr(emaillm, "detect_prompt_injection", lambda *a, **k: (True, "safe"))
        monkeypatch.setattr(
            emaillm, "classify_email_vllm",
            lambda *a, **k: (EmailClassification("interviews", "Interviews"), "job"),
        )
        stats = harness.run()
        assert stats["interviews"] == 1
        assert harness.move_calls == [("1", "Interviews")]
