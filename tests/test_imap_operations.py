"""Tests for IMAP folder/move/sent-scan helpers using a mocked IMAP connection."""

import imaplib
from unittest.mock import MagicMock


from emaillm import (
    FolderConfig,
    ensure_folder_exists,
    ensure_all_folders_exist,
    move_to_folder,
    extract_sent_data_from_sent_folder,
    extract_recipients_from_sent_folder,
)


class TestEnsureFolderExists:
    def test_folder_already_listed(self):
        imap = MagicMock()
        imap.list.return_value = ("OK", [b'(\\HasNoChildren) "/" INBOX/Spam'])
        assert ensure_folder_exists(imap, "Spam") is True
        imap.create.assert_not_called()

    def test_folder_created(self):
        imap = MagicMock()
        imap.list.return_value = ("OK", [b'(\\HasNoChildren) "/" INBOX/Other'])
        imap.create.return_value = ("OK", [b"created"])
        assert ensure_folder_exists(imap, "Spam") is True
        imap.create.assert_called_once_with("INBOX/Spam")

    def test_create_reports_alreadyexists(self):
        imap = MagicMock()
        imap.list.return_value = ("OK", [])
        imap.create.return_value = ("NO", [b"[ALREADYEXISTS] Mailbox exists"])
        assert ensure_folder_exists(imap, "Spam") is True

    def test_create_failure_returns_false(self):
        imap = MagicMock()
        imap.list.return_value = ("OK", [])
        imap.create.return_value = ("NO", [b"permission denied"])
        assert ensure_folder_exists(imap, "Spam") is False

    def test_exception_returns_false(self):
        imap = MagicMock()
        imap.list.side_effect = imaplib.IMAP4.error("boom")
        assert ensure_folder_exists(imap, "Spam") is False


class TestEnsureAllFoldersExist:
    def test_all_present(self):
        imap = MagicMock()
        imap.list.return_value = ("OK", [
            b'(\\HasNoChildren) "/" INBOX/Spam',
            b'(\\HasNoChildren) "/" INBOX/Regular',
        ])
        configs = {
            "spam": FolderConfig("Spam", "d"),
            "regular": FolderConfig("Regular", "d"),
        }
        assert ensure_all_folders_exist(imap, configs) is True

    def test_one_failure_returns_false(self):
        imap = MagicMock()
        imap.list.return_value = ("OK", [])
        imap.create.return_value = ("NO", [b"denied"])
        configs = {"spam": FolderConfig("Spam", "d")}
        assert ensure_all_folders_exist(imap, configs) is False


class TestMoveToFolder:
    def test_successful_move(self):
        imap = MagicMock()
        imap.copy.return_value = ("OK", [b"copied"])
        imap.store.return_value = ("OK", [b"stored"])
        assert move_to_folder(imap, "5", "Spam") is True
        imap.copy.assert_called_once_with("5", "INBOX/Spam")
        imap.store.assert_called_once_with("5", "+FLAGS", "\\Deleted")

    def test_copy_failure_does_not_delete(self):
        imap = MagicMock()
        imap.copy.return_value = ("NO", [b"quota exceeded"])
        assert move_to_folder(imap, "5", "Spam") is False
        imap.store.assert_not_called()

    def test_delete_flag_failure_returns_false(self):
        imap = MagicMock()
        imap.copy.return_value = ("OK", [b"copied"])
        imap.store.return_value = ("NO", [b"failed"])
        assert move_to_folder(imap, "5", "Spam") is False

    def test_exception_returns_false(self):
        imap = MagicMock()
        imap.copy.side_effect = imaplib.IMAP4.error("connection lost")
        assert move_to_folder(imap, "5", "Spam") is False


SENT_EMAIL = (
    b"From: me@example.com\r\n"
    b"To: Alice <alice@example.com>, bob@example.com\r\n"
    b"Cc: carol@example.com\r\n"
    b"Subject: Hello\r\n"
    b"Message-ID: <sent-123@example.com>\r\n\r\n"
    b"Body"
)


class TestExtractSentData:
    def test_extracts_recipients_and_message_ids(self):
        imap = MagicMock()
        imap.select.return_value = ("OK", [b"1"])
        imap.search.return_value = ("OK", [b"1"])
        imap.fetch.return_value = ("OK", [(b"1 (RFC822.HEADER)", SENT_EMAIL)])

        recipients, message_ids = extract_sent_data_from_sent_folder(imap)
        assert recipients == {"alice@example.com", "bob@example.com", "carol@example.com"}
        assert message_ids == {"sent-123@example.com"}

    def test_no_sent_folder_returns_empty_tuple(self):
        """Regression: must return a 2-tuple even when Sent is unavailable."""
        imap = MagicMock()
        imap.select.return_value = ("NO", [b"no such folder"])

        result = extract_sent_data_from_sent_folder(imap)
        assert result == (set(), set())

    def test_empty_sent_folder_returns_empty_tuple(self):
        imap = MagicMock()
        imap.select.return_value = ("OK", [b"0"])
        imap.search.return_value = ("OK", [b""])

        recipients, message_ids = extract_sent_data_from_sent_folder(imap)
        assert recipients == set()
        assert message_ids == set()

    def test_fetch_error_skipped(self):
        imap = MagicMock()
        imap.select.return_value = ("OK", [b"1"])
        imap.search.return_value = ("OK", [b"1 2"])

        def fetch(mail_id, spec):
            if mail_id == "1":
                return ("NO", [None])
            return ("OK", [(b"2 (RFC822.HEADER)", SENT_EMAIL)])

        imap.fetch.side_effect = fetch
        recipients, message_ids = extract_sent_data_from_sent_folder(imap)
        assert "alice@example.com" in recipients

    def test_parse_exception_skipped(self):
        imap = MagicMock()
        imap.select.return_value = ("OK", [b"1"])
        imap.search.return_value = ("OK", [b"1"])
        # Malformed fetch payload triggers the per-message except branch
        imap.fetch.return_value = ("OK", [None])

        recipients, message_ids = extract_sent_data_from_sent_folder(imap)
        assert recipients == set()
        assert message_ids == set()

    def test_outer_exception_handled(self):
        imap = MagicMock()
        imap.select.side_effect = imaplib.IMAP4.error("broken")
        # Outer try/except swallows; finally re-selects Inbox
        recipients, message_ids = extract_sent_data_from_sent_folder(imap)
        assert recipients == set()

    def test_empty_folder_reselect_imapabort_swallowed(self):
        imap = MagicMock()
        # First select picks the Sent folder, later Inbox re-select aborts
        imap.select.side_effect = [("OK", [b"1"]), imaplib.IMAP4.abort("aborted"),
                                   ("OK", [b"1"])]
        imap.search.return_value = ("OK", [b""])
        recipients, message_ids = extract_sent_data_from_sent_folder(imap)
        assert recipients == set()

    def test_email_without_cc_and_without_message_id(self):
        imap = MagicMock()
        imap.select.return_value = ("OK", [b"1"])
        imap.search.return_value = ("OK", [b"1"])
        # The 'undisclosed-recipients' part has no @ and must be skipped
        raw = (
            b"From: me@example.com\r\n"
            b"To: alice@example.com, undisclosed-recipients\r\n"
            b"Subject: Hi\r\n\r\nBody"
        )
        imap.fetch.return_value = ("OK", [(b"1 (RFC822.HEADER)", raw)])
        recipients, message_ids = extract_sent_data_from_sent_folder(imap)
        assert recipients == {"alice@example.com"}
        assert message_ids == set()

    def test_deprecated_wrapper_returns_recipients_only(self):
        imap = MagicMock()
        imap.select.return_value = ("OK", [b"1"])
        imap.search.return_value = ("OK", [b"1"])
        imap.fetch.return_value = ("OK", [(b"1 (RFC822.HEADER)", SENT_EMAIL)])

        recipients = extract_recipients_from_sent_folder(imap)
        assert isinstance(recipients, set)
        assert "bob@example.com" in recipients
