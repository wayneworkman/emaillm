"""Tests for get_keepassxc_credential (subprocess-driven credential retrieval)."""

import subprocess
from types import SimpleNamespace

import pytest

from emaillm import get_keepassxc_credential


def _password_file(tmp_path, content="db-password"):
    pw = tmp_path / "kpx_pw"
    pw.write_text(content)
    return str(pw)


def _completed(returncode=0, stdout=b"", stderr=b""):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


class TestGetKeepassxcCredential:
    def test_success_plaintext(self, tmp_path, monkeypatch):
        pw_file = _password_file(tmp_path)
        stdout = (
            b"UserName: user@example.com\n"
            b"Password: app-pw\n"
            b"host: imap.example.com\n"
        )
        monkeypatch.setattr(subprocess, "run", lambda *a, **k: _completed(stdout=stdout))

        creds = get_keepassxc_credential("db.kdbx", "entry", pw_file)
        assert creds == {
            "username": "user@example.com",
            "password": "app-pw",
            "host": "imap.example.com",
        }

    def test_password_file_missing(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            get_keepassxc_credential("db.kdbx", "entry", str(tmp_path / "nope"))

    def test_password_file_permission_error(self, tmp_path, monkeypatch):
        pw_file = _password_file(tmp_path)
        real_open = open

        def fake_open(path, *args, **kwargs):
            if str(path) == pw_file:
                raise PermissionError()
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr("builtins.open", fake_open)
        with pytest.raises(PermissionError):
            get_keepassxc_credential("db.kdbx", "entry", pw_file)

    def test_empty_password_file(self, tmp_path):
        pw_file = _password_file(tmp_path, content="   \n")
        with pytest.raises(ValueError, match="empty"):
            get_keepassxc_credential("db.kdbx", "entry", pw_file)

    def test_nonzero_returncode_raises(self, tmp_path, monkeypatch):
        pw_file = _password_file(tmp_path)
        monkeypatch.setattr(
            subprocess, "run",
            lambda *a, **k: _completed(returncode=2, stderr=b"bad password"),
        )
        with pytest.raises(Exception, match="Failed to retrieve credentials"):
            get_keepassxc_credential("db.kdbx", "entry", pw_file)

    def test_missing_fields_raises(self, tmp_path, monkeypatch):
        pw_file = _password_file(tmp_path)
        # No host field -> incomplete entry
        stdout = b"UserName: user@example.com\nPassword: app-pw\n"
        monkeypatch.setattr(subprocess, "run", lambda *a, **k: _completed(stdout=stdout))
        with pytest.raises(Exception, match="Missing required fields"):
            get_keepassxc_credential("db.kdbx", "entry", pw_file)

    def test_timeout_raises(self, tmp_path, monkeypatch):
        pw_file = _password_file(tmp_path)

        def fake_run(*a, **k):
            raise subprocess.TimeoutExpired(cmd="keepassxc-cli", timeout=30)

        monkeypatch.setattr(subprocess, "run", fake_run)
        with pytest.raises(Exception, match="Timeout"):
            get_keepassxc_credential("db.kdbx", "entry", pw_file)

    def test_password_passed_to_subprocess_stdin(self, tmp_path, monkeypatch):
        """The DB password is fed to keepassxc-cli via stdin, not argv."""
        pw_file = _password_file(tmp_path, content="db-secret")
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            captured["input"] = kwargs.get("input")
            return _completed(
                stdout=b"UserName: u@e.com\nPassword: p\nhost: h.example.com\n"
            )

        monkeypatch.setattr(subprocess, "run", fake_run)
        get_keepassxc_credential("db.kdbx", "entry-name", pw_file)

        assert captured["input"] == b"db-secret"
        assert "keepassxc-cli" in captured["cmd"]
        assert "db.kdbx" in captured["cmd"]
        assert "entry-name" in captured["cmd"]
        # DB password must never appear on the command line
        assert "db-secret" not in captured["cmd"]
