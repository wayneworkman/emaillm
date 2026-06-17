"""Edge-case coverage for parsing, validators, and load_config error paths."""

import json
from pathlib import Path

import pytest

import emaillm
from emaillm import (
    load_config,
    validate_config_path,
    validate_dkim,
    validate_spf,
    validate_headers_match_from,
    parse_keepassxc_show_output,
    classify_email_vllm,
)


# --------------------------------------------------------------------------
# load_config error / branch coverage
# --------------------------------------------------------------------------

def _base_config(tmp_path):
    return {
        "keepassxc": {
            "database_path": str(tmp_path / "db.kdbx"),
            "password_file": str(tmp_path / "pw"),
        },
        "vllm": {"base_url": "http://localhost:8000/v1"},
        "spam": {"processing_timeout_seconds": 30, "max_emails_per_run": 30},
        "mailers": {"domains": []},
        "folders": {
            "spam": {"folder_name": "Spam", "description": "Spam"},
            "phishing": {"folder_name": "Phishing", "description": "Phishing"},
            "important": {"folder_name": "Important", "description": "Important"},
            "promotion": {"folder_name": "Promotions", "description": "Promo"},
            "transaction": {"folder_name": "Transactions", "description": "Txn"},
            "regular": {"folder_name": "Regular", "description": "Regular"},
        },
        "global_allowlist": {"email_addresses": [], "domains": []},
        "inboxes": [],
        "runtime": {
            "pid_file": str(tmp_path / "emaillm.pid"),
            "log_file": str(tmp_path / "emaillm.log"),
        },
    }


def _write_and_load(tmp_path, monkeypatch, config):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config))
    return load_config(str(path))


class TestValidateConfigPath:
    def test_malformed_path_raises(self):
        # Embedded null byte makes abspath/resolve raise -> wrapped ValueError
        with pytest.raises(ValueError, match="Invalid config path"):
            validate_config_path("\x00not-a-path")


class TestLoadConfigErrors:
    def test_invalid_path_raises(self):
        with pytest.raises(ValueError, match="Invalid configuration path"):
            load_config("/etc/../../../tmp/evil.json")

    def test_folder_file_is_directory_ioerror(self, tmp_path, monkeypatch):
        a_dir = tmp_path / "a_directory"
        a_dir.mkdir()
        cfg = _base_config(tmp_path)
        cfg["folders"]["prompt_attack"] = {
            "folder_name": "Prompt_Attacks", "file": str(a_dir)
        }
        with pytest.raises(ValueError, match="cannot read file"):
            _write_and_load(tmp_path, monkeypatch, cfg)

    def test_folder_not_a_dict(self, tmp_path, monkeypatch):
        cfg = _base_config(tmp_path)
        cfg["folders"]["spam"] = "not-a-dict"
        with pytest.raises(ValueError, match="must be a dictionary"):
            _write_and_load(tmp_path, monkeypatch, cfg)

    def test_folder_missing_folder_name(self, tmp_path, monkeypatch):
        cfg = _base_config(tmp_path)
        cfg["folders"]["spam"] = {"description": "Spam"}
        with pytest.raises(ValueError, match="missing 'folder_name'"):
            _write_and_load(tmp_path, monkeypatch, cfg)

    def test_folder_both_description_and_file(self, tmp_path, monkeypatch):
        cfg = _base_config(tmp_path)
        cfg["folders"]["spam"] = {
            "folder_name": "Spam", "description": "x", "file": "y.txt"
        }
        with pytest.raises(ValueError, match="cannot have both"):
            _write_and_load(tmp_path, monkeypatch, cfg)

    def test_folder_neither_description_nor_file(self, tmp_path, monkeypatch):
        cfg = _base_config(tmp_path)
        cfg["folders"]["spam"] = {"folder_name": "Spam"}
        with pytest.raises(ValueError, match="must have either"):
            _write_and_load(tmp_path, monkeypatch, cfg)

    def test_folder_invalid_name(self, tmp_path, monkeypatch):
        cfg = _base_config(tmp_path)
        cfg["folders"]["spam"] = {"folder_name": "Bad Name!", "description": "x"}
        with pytest.raises(ValueError, match="Invalid folder name"):
            _write_and_load(tmp_path, monkeypatch, cfg)

    def test_folder_file_not_found(self, tmp_path, monkeypatch):
        cfg = _base_config(tmp_path)
        cfg["folders"]["prompt_attack"] = {
            "folder_name": "Prompt_Attacks", "file": str(tmp_path / "missing.txt")
        }
        with pytest.raises(ValueError, match="file not found"):
            _write_and_load(tmp_path, monkeypatch, cfg)

    def test_folder_file_is_loaded(self, tmp_path, monkeypatch):
        prompt = tmp_path / "p.txt"
        prompt.write_text("  detect injection  ")
        cfg = _base_config(tmp_path)
        cfg["folders"]["prompt_attack"] = {
            "folder_name": "Prompt_Attacks", "file": str(prompt)
        }
        config = _write_and_load(tmp_path, monkeypatch, cfg)
        assert config.folder_configs["prompt_attack"].description == "detect injection"

    def test_inboxes_are_built(self, tmp_path, monkeypatch):
        cfg = _base_config(tmp_path)
        cfg["inboxes"] = [{
            "name": "work",
            "keepassxc_entry_name": "Work",
            "imap": {"host": "imap.work.com", "port": 1993},
            "allowlist": {"email_addresses": ["a@b.com"], "domains": ["b.com"]},
        }]
        config = _write_and_load(tmp_path, monkeypatch, cfg)
        assert config.inboxes[0].imap_host == "imap.work.com"
        assert config.inboxes[0].imap_port == 1993
        assert config.inboxes[0].allowlist_emails == ["a@b.com"]


# --------------------------------------------------------------------------
# DKIM branch coverage
# --------------------------------------------------------------------------

def _email_with_dkim(make_email, d="example.com", from_addr="sender@example.com"):
    raw = (
        f"From: {from_addr}\r\n"
        f"DKIM-Signature: v=1; a=rsa-sha256; d={d}; s=sel; b=abc\r\n"
        "Subject: Hi\r\n\r\nBody"
    ).encode()
    return make_email(raw)


class TestValidateDkimBranches:
    def test_dkim_exception(self, make_email, monkeypatch):
        email = _email_with_dkim(make_email)

        def boom(raw):
            raise emaillm.dkim.DKIMException("bad sig")

        monkeypatch.setattr(emaillm.dkim, "verify", boom)
        valid, reason = validate_dkim(email)
        assert valid is False
        assert "DKIM verification failed" in reason

    def test_dkim_generic_exception(self, make_email, monkeypatch):
        email = _email_with_dkim(make_email)
        monkeypatch.setattr(
            emaillm.dkim, "verify",
            lambda raw: (_ for _ in ()).throw(OSError("dns down")),
        )
        valid, reason = validate_dkim(email)
        assert valid is False
        assert "could not be verified" in reason

    def test_dkim_valid_and_aligned(self, make_email, monkeypatch):
        email = _email_with_dkim(make_email, d="example.com")
        monkeypatch.setattr(emaillm.dkim, "verify", lambda raw: True)
        valid, reason = validate_dkim(email)
        assert valid is True
        assert "aligned" in reason

    def test_dkim_valid_but_misaligned(self, make_email, monkeypatch):
        email = _email_with_dkim(make_email, d="evil.com")
        monkeypatch.setattr(emaillm.dkim, "verify", lambda raw: True)
        valid, reason = validate_dkim(email)
        assert valid is False
        assert "not aligned" in reason

    def test_dkim_verify_returns_false(self, make_email, monkeypatch):
        email = _email_with_dkim(make_email)
        monkeypatch.setattr(emaillm.dkim, "verify", lambda raw: False)
        valid, reason = validate_dkim(email)
        assert valid is False
        assert "verification failed" in reason


# --------------------------------------------------------------------------
# SPF branch coverage
# --------------------------------------------------------------------------

class TestValidateSpfBranches:
    def _email(self, make_email, headers):
        raw = ("From: sender@example.com\r\n" + headers + "\r\nBody").encode()
        return make_email(raw)

    def test_received_spf_pass(self, make_email):
        email = self._email(make_email, "Received-SPF: status=pass\r\n")
        assert validate_spf(email)[0] is True

    def test_received_spf_fail(self, make_email):
        email = self._email(make_email, "Received-SPF: status=fail\r\n")
        assert validate_spf(email)[0] is False

    def test_received_spf_softfail_is_lenient(self, make_email):
        email = self._email(make_email, "Received-SPF: status=softfail\r\n")
        assert validate_spf(email)[0] is True

    def test_authresults_inconclusive_trusts_server(self, make_email):
        email = self._email(
            make_email, "Authentication-Results: mx; spf=temperror\r\n"
        )
        valid, reason = validate_spf(email)
        assert valid is True
        assert "inconclusive" in reason

    def test_manual_spf_pass(self, make_email, monkeypatch):
        email = self._email(
            make_email,
            "Return-Path: <sender@example.com>\r\n"
            "Received: from mx (1.2.3.4)\r\n",
        )
        monkeypatch.setattr(emaillm.spf, "check2", lambda i, s, h: ("pass", "ok"))
        valid, reason = validate_spf(email)
        assert valid is True
        assert "manual check" in reason

    def test_manual_spf_fail(self, make_email, monkeypatch):
        email = self._email(
            make_email,
            "Return-Path: <sender@example.com>\r\n"
            "Received: from mx [5.6.7.8]\r\n",
        )
        monkeypatch.setattr(emaillm.spf, "check2", lambda i, s, h: ("fail", "no"))
        assert validate_spf(email)[0] is False

    def test_manual_spf_softfail_lenient(self, make_email, monkeypatch):
        email = self._email(
            make_email,
            "Return-Path: <sender@example.com>\r\n"
            "Received: from mx [5.6.7.8]\r\n",
        )
        monkeypatch.setattr(emaillm.spf, "check2", lambda i, s, h: ("softfail", "m"))
        assert validate_spf(email)[0] is True

    def test_manual_spf_neutral_lenient(self, make_email, monkeypatch):
        email = self._email(
            make_email,
            "Return-Path: <sender@example.com>\r\n"
            "Received: from mx [5.6.7.8]\r\n",
        )
        monkeypatch.setattr(emaillm.spf, "check2", lambda i, s, h: ("neutral", "m"))
        assert validate_spf(email)[0] is True

    def test_manual_spf_exception_lenient(self, make_email, monkeypatch):
        email = self._email(
            make_email,
            "Return-Path: <sender@example.com>\r\n"
            "Received: from mx [5.6.7.8]\r\n",
        )
        monkeypatch.setattr(
            emaillm.spf, "check2",
            lambda i, s, h: (_ for _ in ()).throw(RuntimeError("dns")),
        )
        assert validate_spf(email)[0] is True

    def test_no_info_is_lenient(self, make_email):
        email = self._email(make_email, "Subject: x\r\n")
        valid, reason = validate_spf(email)
        assert valid is True


# --------------------------------------------------------------------------
# Header validation branch coverage
# --------------------------------------------------------------------------

class TestValidateHeaders:
    def test_return_path_and_sender_differ_still_valid(self, make_email):
        raw = (
            "From: a@example.com\r\n"
            "Return-Path: <b@other.com>\r\n"
            "Sender: c@example.com\r\n"
            "Subject: x\r\n\r\nBody"
        ).encode()
        email = make_email(raw)
        valid, reason = validate_headers_match_from(email)
        assert valid is True
        assert "consistent" in reason

    def test_known_mailer_domain_allowed(self, make_email):
        raw = (
            "From: a@example.com\r\n"
            "Return-Path: <bounce@sendgrid.net>\r\n"
            "Subject: x\r\n\r\nBody"
        ).encode()
        email = make_email(raw)
        valid, _ = validate_headers_match_from(email, mailer_domains=["sendgrid.net"])
        assert valid is True


# --------------------------------------------------------------------------
# Email parsing edge cases
# --------------------------------------------------------------------------

class TestEmailParsingEdges:
    def test_from_without_at_sign(self, make_email):
        email = make_email(b"From: garbagevalue\r\nSubject: x\r\n\r\nBody")
        assert email.from_domain == ""

    def test_no_from_header(self, make_email):
        email = make_email(b"Subject: x\r\n\r\nBody")
        assert email.from_address == ""

    def test_attachment_is_skipped(self, sample_email_with_attachments, make_email):
        email = make_email(sample_email_with_attachments)
        assert "Email body" in email.body_text
        assert "PDF binary" not in email.body_text

    def test_non_text_single_part_has_empty_body(self, make_email):
        raw = (
            b"From: a@example.com\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"Subject: x\r\n\r\n\x00\x01binary"
        )
        email = make_email(raw)
        assert email.body_text == ""

    def test_html_only_multipart_converted_to_text(self, make_email):
        raw = (
            b'From: a@example.com\r\n'
            b'Subject: x\r\n'
            b'Content-Type: multipart/alternative; boundary="b"\r\n\r\n'
            b'--b\r\n'
            b'Content-Type: text/html; charset="utf-8"\r\n\r\n'
            b'<p>Hello &amp; welcome</p>\r\n'
            b'--b--\r\n'
        )
        email = make_email(raw)
        assert "Hello" in email.body_text
        assert "&" in email.body_text  # entity unescaped
        assert "<p>" not in email.body_text

    def test_bad_charset_falls_back_to_utf8(self, make_email):
        raw = (
            b"From: a@example.com\r\n"
            b'Content-Type: text/plain; charset="not-a-real-charset"\r\n'
            b"Subject: x\r\n\r\nHello body"
        )
        email = make_email(raw)
        assert "Hello body" in email.body_text


# --------------------------------------------------------------------------
# KeePassXC parser edge cases
# --------------------------------------------------------------------------

class TestKeepassxcParserEdges:
    def test_json_attributes_as_json_string(self):
        output = json.dumps({
            "username": "u@e.com",
            "password": "pw",
            "attributes": json.dumps({"host": "imap.e.com"}),
        })
        username, password, host = parse_keepassxc_show_output(output)
        assert host == "imap.e.com"

    def test_json_attributes_list_without_host(self):
        output = json.dumps({
            "username": "u@e.com",
            "password": "pw",
            "attributes": [{"key": "other", "value": "x"}],
        })
        username, password, host = parse_keepassxc_show_output(output)
        assert username == "u@e.com"
        assert host == ""

    def test_invalid_json_falls_back_to_plaintext(self):
        # Starts with '{' but is not valid JSON -> plain-text parser runs
        output = "{not valid json\nUserName: u@e.com\nPassword: pw\nhost: h.com\n"
        username, password, host = parse_keepassxc_show_output(output)
        assert username == "u@e.com"
        assert host == "h.com"

    def test_json_attributes_neither_dict_nor_list(self):
        output = json.dumps({
            "username": "u@e.com", "password": "pw", "attributes": 42,
        })
        username, password, host = parse_keepassxc_show_output(output)
        assert username == "u@e.com"
        assert host == ""


class TestDkimNoSigningDomain:
    def test_valid_signature_without_d_tag(self, make_email, monkeypatch):
        raw = (
            "From: sender@example.com\r\n"
            "DKIM-Signature: v=1; a=rsa-sha256; s=sel; b=abc\r\n"
            "Subject: Hi\r\n\r\nBody"
        ).encode()
        email = make_email(raw)
        monkeypatch.setattr(emaillm.dkim, "verify", lambda r: True)
        valid, reason = validate_dkim(email)
        # No d= to align against -> treated as not aligned
        assert valid is False


class TestSpfManualNoSender:
    def test_return_path_without_at_sign(self, make_email, monkeypatch):
        raw = (
            "From: sender@example.com\r\n"
            "Return-Path: <garbage>\r\n"
            "Received: from mx [5.6.7.8]\r\n"
            "Subject: x\r\n\r\nBody"
        ).encode()
        email = make_email(raw)
        # check2 should never be reached; falls through to lenient default
        called = {"hit": False}
        monkeypatch.setattr(
            emaillm.spf, "check2",
            lambda *a: called.__setitem__("hit", True) or ("pass", "x"),
        )
        valid, reason = validate_spf(email)
        assert valid is True
        assert called["hit"] is False

    def test_sender_domain_unresolvable(self, make_email, monkeypatch):
        # sender has '@' but 'localhost' has no registered domain -> skip check2
        raw = (
            "From: sender@example.com\r\n"
            "Return-Path: <user@localhost>\r\n"
            "Received: from mx [5.6.7.8]\r\n"
            "Subject: x\r\n\r\nBody"
        ).encode()
        email = make_email(raw)
        called = {"hit": False}
        monkeypatch.setattr(
            emaillm.spf, "check2",
            lambda *a: called.__setitem__("hit", True) or ("pass", "x"),
        )
        valid, _ = validate_spf(email)
        assert valid is True
        assert called["hit"] is False


class TestHeadersReturnPathNoAt:
    def test_return_path_without_at_sign(self, make_email):
        raw = (
            "From: a@example.com\r\n"
            "Return-Path: <garbage>\r\n"
            "Subject: x\r\n\r\nBody"
        ).encode()
        email = make_email(raw)
        valid, _ = validate_headers_match_from(email)
        assert valid is True

    def test_return_path_domain_unresolvable(self, make_email):
        raw = (
            "From: a@example.com\r\n"
            "Return-Path: <user@localhost>\r\n"
            "Subject: x\r\n\r\nBody"
        ).encode()
        email = make_email(raw)
        valid, _ = validate_headers_match_from(email)
        assert valid is True


class TestClassifyThinkingEnabled:
    def test_thinking_enabled_omits_kwargs(self, make_email, folder_configs, monkeypatch):
        from types import SimpleNamespace
        email = make_email(b"From: a@example.com\r\nSubject: x\r\n\r\nBody")
        captured = {}

        def fake_post(url, headers=None, json=None, timeout=None):
            captured["payload"] = json
            return SimpleNamespace(
                json=lambda: {"choices": [{"message": {"content": "x\n##### spam"}}]},
                raise_for_status=lambda: None,
            )

        monkeypatch.setattr(emaillm.requests, "post", fake_post)
        classify_email_vllm(
            "http://x/v1", "model", email, 0.1, 4096, folder_configs,
            enable_thinking=True,
        )
        assert "chat_template_kwargs" not in captured["payload"]
