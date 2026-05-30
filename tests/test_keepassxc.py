"""Tests for parsing `keepassxc-cli show --all` output."""

from emaillm import parse_keepassxc_show_output


class TestParseKeepassxcShowOutput:
    """Test extraction of username, password, and host from a single call."""

    def test_plaintext_format(self):
        """Parse the standard 'Key: value' plain-text output."""
        output = (
            "Title: personal\n"
            "UserName: wayne@example.com\n"
            "Password: s3cr3t-app-pw\n"
            "URL: \n"
            "Notes: \n"
            "host: imap.example.com\n"
        )
        username, password, host = parse_keepassxc_show_output(output)

        assert username == "wayne@example.com"
        assert password == "s3cr3t-app-pw"
        assert host == "imap.example.com"

    def test_password_with_colon_and_special_chars(self):
        """A password containing ':' is preserved (split on first ':' only)."""
        output = (
            "UserName: user@example.com\n"
            "Password: a:b:c=https://x\n"
            "host: mail.example.com\n"
        )
        _, password, _ = parse_keepassxc_show_output(output)

        assert password == "a:b:c=https://x"

    def test_host_is_case_sensitive(self):
        """The custom 'host' attribute must match exactly (not 'Host')."""
        output = (
            "UserName: user@example.com\n"
            "Password: pw\n"
            "Host: wrong.example.com\n"
        )
        _, _, host = parse_keepassxc_show_output(output)

        assert host == ""

    def test_missing_fields_return_empty(self):
        """Absent fields come back as empty strings, not errors."""
        username, password, host = parse_keepassxc_show_output("Title: only\n")

        assert username == ""
        assert password == ""
        assert host == ""

    def test_json_format(self):
        """A JSON object is parsed when keepassxc-cli emits one."""
        output = (
            '{"username": "user@example.com", "password": "pw", '
            '"attributes": {"host": "imap.example.com"}}'
        )
        username, password, host = parse_keepassxc_show_output(output)

        assert username == "user@example.com"
        assert password == "pw"
        assert host == "imap.example.com"

    def test_json_attributes_as_list(self):
        """JSON attributes given as a list of key/value pairs are handled."""
        output = (
            '{"UserName": "user@example.com", "Password": "pw", '
            '"attributes": [{"key": "host", "value": "mail.example.com"}]}'
        )
        username, password, host = parse_keepassxc_show_output(output)

        assert username == "user@example.com"
        assert host == "mail.example.com"
