"""Tests for dataclasses and configuration structures."""

import pytest
import json
from pathlib import Path
from emaillm import (
    FolderConfig,
    EmailClassification,
    InboxConfig,
    SpamFilterConfig,
    load_config,
)


class TestFolderConfig:
    """Test FolderConfig dataclass."""
    
    def test_folder_config_creation(self):
        """Test creating a FolderConfig."""
        folder = FolderConfig(
            folder_name="Spam",
            description="Spam emails"
        )
        
        assert folder.folder_name == "Spam"
        assert folder.description == "Spam emails"
    
    def test_folder_config_all_categories(self):
        """Test creating FolderConfig for all default categories."""
        categories = {
            "spam": ("Spam", "Unsolicited bulk emails"),
            "phishing": ("Phishing_Attempts", "Credential theft attempts"),
            "important": ("Important", "Critical communications"),
            "promotion": ("Promotions", "Marketing emails"),
            "transaction": ("Transactions", "Orders and receipts"),
            "regular": ("Regular", "Normal correspondence"),
        }
        
        for category, (name, desc) in categories.items():
            folder = FolderConfig(folder_name=name, description=desc)
            assert folder.folder_name == name
            assert folder.description == desc


class TestEmailClassification:
    """Test EmailClassification dataclass."""
    
    def test_classification_creation(self):
        """Test creating an EmailClassification."""
        classification = EmailClassification(
            category="spam",
            folder_name="Spam"
        )
        
        assert classification.category == "spam"
        assert classification.folder_name == "Spam"
        assert classification.code == "spam"  # Backward compatibility
        assert classification.target_folder == "Spam"
    
    def test_classification_from_category(self):
        """Test creating classification from category code."""
        folder_configs = {
            "spam": FolderConfig("Spam", "Spam emails"),
            "important": FolderConfig("Important", "Important emails"),
        }
        
        classification = EmailClassification.from_category("spam", folder_configs)
        
        assert classification.category == "spam"
        assert classification.folder_name == "Spam"
    
    def test_classification_from_unknown_category(self):
        """Test that unknown category raises error."""
        folder_configs = {"spam": FolderConfig("Spam", "Spam emails")}
        
        with pytest.raises(ValueError, match="Unknown category"):
            EmailClassification.from_category("unknown", folder_configs)
    
    def test_classification_error(self):
        """Test creating error classification."""
        classification = EmailClassification.error("Test error")
        
        assert classification.category == "error"
        assert classification.folder_name is None
    
    def test_classification_error_class_attribute(self):
        """Test ERROR class attribute exists."""
        assert EmailClassification.ERROR is not None
        assert EmailClassification.ERROR.category == "error"


class TestInboxConfig:
    """Test InboxConfig dataclass."""
    
    def test_inbox_config_creation(self):
        """Test creating an InboxConfig."""
        inbox = InboxConfig(
            name="primary",
            keepassxc_entry_name="Email - Primary",
            imap_host="imap.example.com",
            imap_port=993,
            allowlist_emails=["boss@company.com"],
            allowlist_domains=["company.com"]
        )
        
        assert inbox.name == "primary"
        assert inbox.keepassxc_entry_name == "Email - Primary"
        assert inbox.imap_host == "imap.example.com"
        assert inbox.imap_port == 993
        assert inbox.allowlist_emails == ["boss@company.com"]
        assert inbox.allowlist_domains == ["company.com"]
    
    def test_default_allowlists(self):
        """Test default empty allowlists."""
        inbox = InboxConfig(
            name="secondary",
            keepassxc_entry_name="Email - Secondary",
            imap_host="imap.example.com",
            imap_port=993
        )
        
        assert inbox.allowlist_emails == []
        assert inbox.allowlist_domains == []
    
    def test_default_port(self):
        """Test default IMAP port."""
        inbox = InboxConfig(
            name="test",
            keepassxc_entry_name="Test",
            imap_host="imap.example.com"
        )
        
        assert inbox.imap_port == 993


class TestSpamFilterConfig:
    """Test SpamFilterConfig dataclass."""
    
    def test_config_creation(self):
        """Test creating a SpamFilterConfig."""
        config = SpamFilterConfig(
            keepassxc_database="/path/to/database.kdbx",
            keepassxc_password_file="/path/to/password",
            vllm_base_url="http://localhost:8000/v1",
            vllm_temperature=0.5,
            vllm_max_tokens=4096,
            vllm_enable_thinking=False,
            vllm_api_key=None,
            processing_timeout=30,
            max_emails_per_run=30,
            mailer_domains=["gmail.com"],
            folder_configs={"spam": FolderConfig("Spam", "Spam emails")},
            global_allowlist_emails=["trusted@example.com"],
            global_allowlist_domains=["trusted.com"],
            inboxes=[],
            pid_file="/tmp/emaillm.pid",
            log_file="/tmp/emaillm.log"
        )
        
        assert config.keepassxc_database == "/path/to/database.kdbx"
        assert config.vllm_base_url == "http://localhost:8000/v1"
        assert config.processing_timeout == 30
        assert config.max_emails_per_run == 30
    
    def test_default_values(self):
        """Test default configuration values."""
        config = SpamFilterConfig(
            keepassxc_database="/path/to/database.kdbx",
            keepassxc_password_file="/path/to/password",
            vllm_base_url="http://localhost:8000/v1",
            folder_configs={},
            inboxes=[]
        )
        
        assert config.vllm_temperature == 0.1  # Default
        assert config.vllm_max_tokens == 4096  # Default
        assert config.vllm_enable_thinking is False  # Default
        assert config.processing_timeout == 30  # Default
        assert config.max_emails_per_run == 30  # Default


class TestLoadConfig:
    """Test configuration loading."""
    
    def test_load_valid_config(self, tmp_path, monkeypatch):
        """Test loading a valid configuration file."""
        # Monkeypatch home directory to include tmp_path
        monkeypatch.setattr(Path, 'home', lambda: tmp_path)
        
        config_data = {
            "keepassxc": {
                "database_path": str(tmp_path / "database.kdbx"),
                "password_file": str(tmp_path / "password")
            },
            "vllm": {
                "base_url": "http://localhost:8000/v1",
                "temperature": 0.5,
                "max_tokens": 4096,
                "enable_thinking": False,
                "api_key": None
            },
            "spam": {
                "processing_timeout_seconds": 30,
                "max_emails_per_run": 30
            },
            "mailers": {
                "domains": ["gmail.com"]
            },
            "folders": {
                "spam": {
                    "folder_name": "Spam",
                    "description": "Spam emails"
                },
                "phishing": {
                    "folder_name": "Phishing",
                    "description": "Phishing emails"
                },
                "important": {
                    "folder_name": "Important",
                    "description": "Important emails"
                },
                "promotion": {
                    "folder_name": "Promotions",
                    "description": "Promotion emails"
                },
                "transaction": {
                    "folder_name": "Transactions",
                    "description": "Transaction emails"
                },
                "regular": {
                    "folder_name": "Regular",
                    "description": "Regular emails"
                }
            },
            "global_allowlist": {
                "email_addresses": ["trusted@example.com"],
                "domains": ["trusted.com"]
            },
            "inboxes": [
                {
                    "name": "primary",
                    "keepassxc_entry_name": "Email - Primary",
                    "imap": {
                        "host": "imap.example.com",
                        "port": 993
                    },
                    "allowlist": {
                        "email_addresses": [],
                        "domains": []
                    }
                }
            ],
            "runtime": {
                "pid_file": str(tmp_path / "emaillm.pid"),
                "log_file": str(tmp_path / "emaillm.log")
            }
        }
        
        config_path = tmp_path / "config.json"
        with open(config_path, 'w') as f:
            json.dump(config_data, f)
        
        config = load_config(str(config_path))
        
        assert config is not None
        assert config.keepassxc_database == str(tmp_path / "database.kdbx")
        assert config.vllm_base_url == "http://localhost:8000/v1"
        assert len(config.inboxes) == 1
        assert config.inboxes[0].name == "primary"
    
    def test_load_config_with_prompt_attack_file(self, tmp_path, monkeypatch):
        """Test loading config with prompt attack file."""
        monkeypatch.setattr(Path, 'home', lambda: tmp_path)
        
        config_data = {
            "keepassxc": {
                "database_path": str(tmp_path / "database.kdbx"),
                "password_file": str(tmp_path / "password")
            },
            "vllm": {
                "base_url": "http://localhost:8000/v1",
                "temperature": 0.5,
                "max_tokens": 4096,
                "enable_thinking": False,
                "api_key": None
            },
            "spam": {
                "processing_timeout_seconds": 30,
                "max_emails_per_run": 30
            },
            "mailers": {"domains": []},
            "folders": {
                "spam": {"folder_name": "Spam", "description": "Spam"},
                "phishing": {"folder_name": "Phishing", "description": "Phishing"},
                "important": {"folder_name": "Important", "description": "Important"},
                "promotion": {"folder_name": "Promotions", "description": "Promotions"},
                "transaction": {"folder_name": "Transactions", "description": "Transactions"},
                "regular": {"folder_name": "Regular", "description": "Regular"},
                "prompt_attack": {
                    "folder_name": "Prompt_Attacks",
                    "description": "Prompt attack detection"
                }
            },
            "global_allowlist": {
                "email_addresses": [],
                "domains": []
            },
            "inboxes": [],
            "runtime": {
                "pid_file": str(tmp_path / "emaillm.pid"),
                "log_file": str(tmp_path / "emaillm.log")
            }
        }
        
        config_path = tmp_path / "config.json"
        with open(config_path, 'w') as f:
            json.dump(config_data, f)
        
        config = load_config(str(config_path))
        
        assert "prompt_attack" in config.folder_configs
        assert config.folder_configs["prompt_attack"].folder_name == "Prompt_Attacks"
    
    def test_load_nonexistent_config_raises_error(self, monkeypatch, tmp_path):
        """Test that loading nonexistent config raises error."""
        monkeypatch.setattr(Path, 'home', lambda: tmp_path)
        
        with pytest.raises((FileNotFoundError, ValueError)):
            load_config(str(tmp_path / "nonexistent.json"))
    
    def test_load_invalid_json_raises_error(self, tmp_path, monkeypatch):
        """Test that loading invalid JSON raises error."""
        monkeypatch.setattr(Path, 'home', lambda: tmp_path)
        
        config_path = tmp_path / "invalid.json"
        with open(config_path, 'w') as f:
            f.write("not valid json {")
        
        with pytest.raises((json.JSONDecodeError, ValueError)):
            load_config(str(config_path))
    
    def test_load_config_with_missing_optional_fields(self, tmp_path, monkeypatch):
        """Test loading config with missing optional fields."""
        monkeypatch.setattr(Path, 'home', lambda: tmp_path)
        
        config_data = {
            "keepassxc": {
                "database_path": str(tmp_path / "database.kdbx"),
                "password_file": str(tmp_path / "password")
            },
            "vllm": {
                "base_url": "http://localhost:8000/v1"
            },
            "spam": {},
            "mailers": {"domains": []},
            "folders": {
                "spam": {"folder_name": "Spam", "description": "Spam"},
                "phishing": {"folder_name": "Phishing", "description": "Phishing"},
                "important": {"folder_name": "Important", "description": "Important"},
                "promotion": {"folder_name": "Promotions", "description": "Promotions"},
                "transaction": {"folder_name": "Transactions", "description": "Transactions"},
                "regular": {"folder_name": "Regular", "description": "Regular"}
            },
            "global_allowlist": {
                "email_addresses": [],
                "domains": []
            },
            "inboxes": [],
            "runtime": {}
        }
        
        config_path = tmp_path / "config.json"
        with open(config_path, 'w') as f:
            json.dump(config_data, f)
        
        # Should use defaults for missing fields
        config = load_config(str(config_path))
        
        assert config.vllm_temperature == 0.1  # Default
        assert config.vllm_max_tokens == 500  # Default (from config loading)
        assert config.processing_timeout == 30  # Default
        assert config.max_emails_per_run == 30  # Default
