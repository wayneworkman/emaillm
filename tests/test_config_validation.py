"""Tests for configuration validation functions."""

import pytest
from pathlib import Path
from emaillm import validate_config_path, validate_folder_name


class TestValidateConfigPath:
    """Test validate_config_path function."""
    
    def test_valid_home_path(self, monkeypatch, tmp_path):
        """Test valid path in home directory."""
        # Mock home directory
        monkeypatch.setattr(Path, 'home', lambda: tmp_path)
        
        config_path = tmp_path / ".emaillm.json"
        result = validate_config_path(str(config_path))
        
        assert result == config_path
    
    def test_valid_etc_path(self):
        """Test valid path in /etc."""
        result = validate_config_path("/etc/emaillm/config.json")
        assert result == Path("/etc/emaillm/config.json")
    
    def test_valid_opt_path(self):
        """Test valid path in /opt."""
        result = validate_config_path("/opt/emaillm/config.json")
        assert result == Path("/opt/emaillm/config.json")
    
    def test_expand_tilde(self, monkeypatch, tmp_path):
        """Test that ~ is expanded to home directory."""
        # Mock os.path.expanduser to return our tmp_path
        original_expanduser = __import__('os').path.expanduser
        monkeypatch.setattr(__import__('os').path, 'expanduser', 
                           lambda path: str(tmp_path / ".emaillm.json") if path == "~/.emaillm.json" else original_expanduser(path))
        
        # Also need to mock Path.home() for the validation check
        monkeypatch.setattr(Path, 'home', lambda: tmp_path)
        
        result = validate_config_path("~/.emaillm.json")
        assert result == tmp_path / ".emaillm.json"
    
    def test_empty_path_raises_error(self):
        """Test that empty path raises ValueError."""
        with pytest.raises(ValueError, match="cannot be empty"):
            validate_config_path("")
    
    def test_path_traversal_blocked(self, monkeypatch, tmp_path):
        """Test that paths outside allowed directories are blocked."""
        monkeypatch.setattr(Path, 'home', lambda: tmp_path)
        
        # Try to access /tmp which is outside home, /etc, /opt
        with pytest.raises(ValueError, match="must be within"):
            validate_config_path("/tmp/emaillm.json")
    
    def test_no_extension_warning(self, monkeypatch, tmp_path, caplog):
        """Test warning when config has no extension."""
        monkeypatch.setattr(Path, 'home', lambda: tmp_path)
        
        config_path = tmp_path / ".emaillm"
        validate_config_path(str(config_path))
        
        assert "no extension" in caplog.text.lower()


class TestValidateFolderName:
    """Test validate_folder_name function."""
    
    def test_valid_folder_name(self):
        """Test valid folder names."""
        assert validate_folder_name("Spam") == "Spam"
        assert validate_folder_name("Phishing_Attempts") == "Phishing_Attempts"
        assert validate_folder_name("Important") == "Important"
        assert validate_folder_name("Sub.Folder") == "Sub.Folder"
        assert validate_folder_name("Folder-123") == "Folder-123"
    
    def test_empty_folder_name_raises_error(self):
        """Test that empty folder name raises ValueError."""
        with pytest.raises(ValueError, match="cannot be empty"):
            validate_folder_name("")
    
    def test_invalid_characters_raise_error(self):
        """Test that invalid characters raise ValueError."""
        invalid_names = [
            "Spam;rm -rf /",  # Command injection attempt
            "Folder<script>",  # Script injection
            "Folder|bad",  # Pipe character
            "Folder&bad",  # Ampersand
            "Folder$bad",  # Dollar sign
            "Folder`bad",  # Backtick
            "Folder(bad)",  # Parentheses
            "Folder{bad}",  # Braces
        ]
        
        for name in invalid_names:
            with pytest.raises(ValueError):
                validate_folder_name(name)
    
    def test_folder_name_too_long_raises_error(self):
        """Test that folder names over 255 characters raise error."""
        long_name = "A" * 256
        with pytest.raises(ValueError, match="too long"):
            validate_folder_name(long_name)
    
    def test_folder_name_starting_with_slash_raises_error(self):
        """Test that folder names starting with / raise error."""
        with pytest.raises(ValueError, match="cannot start or end with"):
            validate_folder_name("/Spam")
    
    def test_folder_name_ending_with_slash_raises_error(self):
        """Test that folder names ending with / raise error."""
        with pytest.raises(ValueError, match="cannot start or end with"):
            validate_folder_name("Spam/")
    
    def test_folder_name_with_double_dot_raises_error(self):
        """Test that folder names with .. raise error."""
        with pytest.raises(ValueError, match="cannot contain '\.\.'"):
            validate_folder_name("Spam/../Inbox")


class TestSanitizeEmailContent:
    """Test email content sanitization."""
    
    def test_truncation(self):
        """Test that long content is truncated."""
        from emaillm import sanitize_email_content_for_prompt
        
        long_content = "A" * 15000
        result = sanitize_email_content_for_prompt(long_content, max_length=10000)
        
        # Result should be truncated (max_length + "\n... [truncated]" = 10000 + 16 = 10016)
        assert len(result) <= 10020  # Allow some buffer
        assert "truncated" in result
    
    def test_control_character_removal(self):
        """Test that control characters are removed."""
        from emaillm import sanitize_email_content_for_prompt
        
        content = "Hello\x00World\x01\x02\x03"
        result = sanitize_email_content_for_prompt(content)
        
        assert "\x00" not in result
        assert "\x01" not in result
    
    def test_excessive_whitespace_limiting(self):
        """Test that excessive whitespace is limited."""
        from emaillm import sanitize_email_content_for_prompt
        
        content = "Line1\n\n\n\n\n\n\n\nLine2"
        result = sanitize_email_content_for_prompt(content)
        
        assert "excessive whitespace removed" in result
    
    def test_empty_content(self):
        """Test handling of empty content."""
        from emaillm import sanitize_email_content_for_prompt
        
        assert sanitize_email_content_for_prompt("") == ""
        assert sanitize_email_content_for_prompt(None) == ""
