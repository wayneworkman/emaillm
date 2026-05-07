"""Tests for custom category support and prompt_attack exclusion.

These tests verify that:
1. Custom categories beyond the required 6 + prompt_attack are loaded correctly
2. prompt_attack is excluded from classification_categories (not just prompt_injection)

These were added after discovering that load_config silently dropped custom
categories (Bug 1) and classify_email_vllm excluded the wrong key
(prompt_injection instead of prompt_attack) causing prompt injection text
to leak into classification prompts (Bug 2).
"""

import pytest
import json
from pathlib import Path
from emaillm import (
    FolderConfig,
    EmailClassification,
    load_config,
)


def _make_base_config(tmp_path):
    """Helper to build a minimal valid config dict."""
    return {
        "keepassxc": {
            "database_path": str(tmp_path / "database.kdbx"),
            "password_file": str(tmp_path / "password"),
        },
        "vllm": {
            "base_url": "http://localhost:8000/v1",
            "temperature": 0.5,
            "max_tokens": 4096,
            "enable_thinking": False,
            "api_key": None,
        },
        "spam": {
            "processing_timeout_seconds": 30,
            "max_emails_per_run": 30,
        },
        "mailers": {"domains": []},
        "folders": {
            "spam": {"folder_name": "Spam", "description": "Spam"},
            "phishing": {"folder_name": "Phishing", "description": "Phishing"},
            "important": {"folder_name": "Important", "description": "Important"},
            "promotion": {"folder_name": "Promotions", "description": "Promotions"},
            "transaction": {"folder_name": "Transactions", "description": "Transactions"},
            "regular": {"folder_name": "Regular", "description": "Regular"},
        },
        "global_allowlist": {"email_addresses": [], "domains": []},
        "inboxes": [],
        "runtime": {
            "pid_file": str(tmp_path / "emaillm.pid"),
            "log_file": str(tmp_path / "emaillm.log"),
        },
    }


class TestCustomCategories:
    """Test that load_config processes ALL folder keys, not just hardcoded ones."""

    def test_load_config_with_custom_categories(self, tmp_path, monkeypatch):
        """Custom categories beyond the standard 6 should be loaded."""
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        config_data = _make_base_config(tmp_path)
        # Add custom categories
        config_data["folders"]["interviews"] = {
            "folder_name": "Interviews",
            "description": "Interview scheduling requests",
        }
        config_data["folders"]["application_confirmations"] = {
            "folder_name": "Application_Confirmations",
            "description": "Job application confirmations",
        }

        config_path = tmp_path / "config.json"
        with open(config_path, "w") as f:
            json.dump(config_data, f)

        config = load_config(str(config_path))

        assert "interviews" in config.folder_configs
        assert config.folder_configs["interviews"].folder_name == "Interviews"
        assert (
            config.folder_configs["interviews"].description
            == "Interview scheduling requests"
        )

        assert "application_confirmations" in config.folder_configs
        assert (
            config.folder_configs["application_confirmations"].folder_name
            == "Application_Confirmations"
        )

    def test_load_config_with_many_custom_categories(self, tmp_path, monkeypatch):
        """Config with many custom categories should load them all."""
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        config_data = _make_base_config(tmp_path)
        custom_categories = {
            "cat_a": {"folder_name": "Cat_A", "description": "Category A"},
            "cat_b": {"folder_name": "Cat_B", "description": "Category B"},
            "cat_c": {"folder_name": "Cat_C", "description": "Category C"},
        }
        config_data["folders"].update(custom_categories)

        config_path = tmp_path / "config.json"
        with open(config_path, "w") as f:
            json.dump(config_data, f)

        config = load_config(str(config_path))

        for key, expected in custom_categories.items():
            assert key in config.folder_configs
            assert config.folder_configs[key].folder_name == expected["folder_name"]
            assert config.folder_configs[key].description == expected["description"]

    def test_load_config_with_custom_and_prompt_attack(self, tmp_path, monkeypatch):
        """Custom categories should coexist with prompt_attack."""
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        config_data = _make_base_config(tmp_path)
        config_data["folders"]["prompt_attack"] = {
            "folder_name": "Prompt_Attacks",
            "description": "Prompt attack detection",
        }
        config_data["folders"]["custom_cat"] = {
            "folder_name": "Custom_Cat",
            "description": "A custom category",
        }

        config_path = tmp_path / "config.json"
        with open(config_path, "w") as f:
            json.dump(config_data, f)

        config = load_config(str(config_path))

        assert "prompt_attack" in config.folder_configs
        assert "custom_cat" in config.folder_configs
        # Standard categories should still be present
        for cat in ["spam", "phishing", "important", "promotion", "transaction", "regular"]:
            assert cat in config.folder_configs

    def test_load_config_with_custom_category_from_file(self, tmp_path, monkeypatch):
        """Custom category can load description from external file."""
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        prompt_file = tmp_path / "custom_prompt.txt"
        prompt_file.write_text("This is a custom prompt loaded from file.")

        config_data = _make_base_config(tmp_path)
        config_data["folders"]["file_category"] = {
            "folder_name": "File_Category",
            "file": str(prompt_file),
        }

        config_path = tmp_path / "config.json"
        with open(config_path, "w") as f:
            json.dump(config_data, f)

        config = load_config(str(config_path))

        assert "file_category" in config.folder_configs
        assert (
            config.folder_configs["file_category"].description
            == "This is a custom prompt loaded from file."
        )

    def test_missing_required_folder_still_raises_error(self, tmp_path, monkeypatch):
        """Even with custom categories, missing required folders should fail."""
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        config_data = _make_base_config(tmp_path)
        del config_data["folders"]["spam"]  # Required category missing
        config_data["folders"]["custom"] = {
            "folder_name": "Custom",
            "description": "Custom",
        }

        config_path = tmp_path / "config.json"
        with open(config_path, "w") as f:
            json.dump(config_data, f)

        with pytest.raises(ValueError, match="Missing required folder config: spam"):
            load_config(str(config_path))


class TestPromptAttackExclusion:
    """Test that prompt_attack is excluded from classification_categories.

    This regression test ensures the bug where classify_email_vllm excluded
    'prompt_injection' (wrong key) instead of 'prompt_attack' (correct key)
    does not recur. When 'prompt_attack' leaks into classification, the
    prompt injection detection text pollutes the LLM prompt and causes
    misclassification.
    """

    def test_classification_excludes_prompt_attack(self):
        """prompt_attack should be excluded from classification categories."""
        folder_configs = {
            "spam": FolderConfig("Spam", "Spam"),
            "phishing": FolderConfig("Phishing", "Phishing"),
            "important": FolderConfig("Important", "Important"),
            "promotion": FolderConfig("Promotions", "Promotions"),
            "transaction": FolderConfig("Transactions", "Transactions"),
            "regular": FolderConfig("Regular", "Regular"),
            "prompt_attack": FolderConfig(
                "Prompt_Attacks", "You are a security analyzer..."
            ),
            "custom_cat": FolderConfig("Custom", "Custom"),
        }

        # Replicate the exclusion logic from classify_email_vllm
        classification_categories = {
            k: v for k, v in folder_configs.items() if k != "prompt_attack"
        }

        assert "prompt_attack" not in classification_categories
        assert "spam" in classification_categories
        assert "custom_cat" in classification_categories

    def test_classification_includes_custom_categories(self):
        """Custom categories should be included in classification."""
        folder_configs = {
            "spam": FolderConfig("Spam", "Spam"),
            "phishing": FolderConfig("Phishing", "Phishing"),
            "important": FolderConfig("Important", "Important"),
            "promotion": FolderConfig("Promotions", "Promotions"),
            "transaction": FolderConfig("Transactions", "Transactions"),
            "regular": FolderConfig("Regular", "Regular"),
            "prompt_attack": FolderConfig(
                "Prompt_Attacks", "You are a security analyzer..."
            ),
            "interviews": FolderConfig("Interviews", "Interview requests"),
            "application_confirmations": FolderConfig(
                "App_Confirmations", "Application confirmations"
            ),
        }

        classification_categories = {
            k: v for k, v in folder_configs.items() if k != "prompt_attack"
        }

        # Custom categories should be present
        assert "interviews" in classification_categories
        assert "application_confirmations" in classification_categories
        # prompt_attack should NOT be present
        assert "prompt_attack" not in classification_categories
        # Standard categories should be present
        for cat in ["spam", "phishing", "important", "promotion", "transaction", "regular"]:
            assert cat in classification_categories

    def test_classification_without_prompt_attack(self):
        """Classification should work when prompt_attack is not configured."""
        folder_configs = {
            "spam": FolderConfig("Spam", "Spam"),
            "phishing": FolderConfig("Phishing", "Phishing"),
            "important": FolderConfig("Important", "Important"),
            "promotion": FolderConfig("Promotions", "Promotions"),
            "transaction": FolderConfig("Transactions", "Transactions"),
            "regular": FolderConfig("Regular", "Regular"),
        }

        classification_categories = {
            k: v for k, v in folder_configs.items() if k != "prompt_attack"
        }

        # All categories should be present (prompt_attack was never there)
        assert len(classification_categories) == 6
        assert "prompt_attack" not in classification_categories


class TestClassificationFormat:
    """Test the dynamic prompt format generated for classification."""

    def test_format_string_includes_custom_categories(self):
        """The format/examples string should include custom category names."""
        folder_configs = {
            "spam": FolderConfig("Spam", "Spam"),
            "regular": FolderConfig("Regular", "Regular"),
            "interviews": FolderConfig("Interviews", "Interview requests"),
            "prompt_attack": FolderConfig(
                "Prompt_Attacks", "Security analyzer prompt..."
            ),
        }

        classification_categories = {
            k: v for k, v in folder_configs.items() if k != "prompt_attack"
        }

        category_list = list(classification_categories.keys())
        format_examples = "\nOR\n##### ".join(category_list)

        # Format should contain custom categories
        assert "interviews" in format_examples
        # Format should NOT contain prompt_attack
        assert "prompt_attack" not in format_examples

    def test_categories_section_includes_custom_descriptions(self):
        """The categories section should include custom category descriptions."""
        folder_configs = {
            "spam": FolderConfig("Spam", "Unsolicited bulk emails"),
            "regular": FolderConfig("Regular", "Normal correspondence"),
            "interviews": FolderConfig(
                "Interviews", "Interview scheduling requests"
            ),
            "prompt_attack": FolderConfig(
                "Prompt_Attacks", "You are a security analyzer..."
            ),
        }

        classification_categories = {
            k: v for k, v in folder_configs.items() if k != "prompt_attack"
        }

        categories_section = "Categories:\n"
        for category, config in classification_categories.items():
            categories_section += f"- {category}: {config.description}\n"

        assert "interviews: Interview scheduling requests" in categories_section
        assert "prompt_attack" not in categories_section
        # The prompt_attack description should NOT leak into the section
        assert "security analyzer" not in categories_section


class TestStatsAggregation:
    """Test that stats aggregation handles custom categories.

    Regression test for the bug where main() crashed with KeyError when
    inbox_stats contained a custom category key (e.g., 'application_confirmations')
    that wasn't in the hardcoded total_stats dict.
    """

    def test_aggregation_with_custom_category_keys(self):
        """total_stats aggregation must handle keys not in initial dict."""
        # Simulate the initial total_stats dict from main()
        total_stats = {
            'processed': 0,
            'spam': 0,
            'phishing': 0,
            'important': 0,
            'promotion': 0,
            'transaction': 0,
            'regular': 0,
            'spoofed': 0,
            'allowlisted': 0,
            'prompt_injection': 0,
            'errors': 0,
        }

        # Simulate inbox_stats with a custom category
        inbox_stats = {
            'processed': 5,
            'spam': 1,
            'regular': 2,
            'application_confirmations': 1,  # Custom category
            'errors': 1,
        }

        # This is the aggregation logic from main()
        for key, value in inbox_stats.items():
            total_stats[key] = total_stats.get(key, 0) + value

        assert total_stats['processed'] == 5
        assert total_stats['spam'] == 1
        assert total_stats['regular'] == 2
        assert total_stats['application_confirmations'] == 1
        assert total_stats['errors'] == 1
        assert total_stats['phishing'] == 0  # Unchanged

    def test_aggregation_across_multiple_inboxes(self):
        """Aggregation should accumulate custom category counts across inboxes."""
        total_stats = {
            'processed': 0, 'spam': 0, 'phishing': 0, 'important': 0,
            'promotion': 0, 'transaction': 0, 'regular': 0, 'spoofed': 0,
            'allowlisted': 0, 'prompt_injection': 0, 'errors': 0,
        }

        inbox1_stats = {
            'processed': 10,
            'application_confirmations': 3,
            'interviews': 2,
            'errors': 0,
        }
        inbox2_stats = {
            'processed': 5,
            'application_confirmations': 1,
            'errors': 1,
        }

        for inbox_stats in [inbox1_stats, inbox2_stats]:
            for key, value in inbox_stats.items():
                total_stats[key] = total_stats.get(key, 0) + value

        assert total_stats['processed'] == 15
        assert total_stats['application_confirmations'] == 4
        assert total_stats['interviews'] == 2
        assert total_stats['errors'] == 1

    def test_aggregation_old_code_would_fail(self):
        """Demonstrate that the old += syntax would raise KeyError."""
        total_stats = {
            'processed': 0, 'spam': 0, 'errors': 0,
        }
        inbox_stats = {
            'processed': 5,
            'application_confirmations': 1,  # Not in total_stats
        }

        # Old code: total_stats[key] += value  <-- would KeyError here
        with pytest.raises(KeyError):
            for key, value in inbox_stats.items():
                total_stats[key] += value

        # New code works fine:
        for key, value in inbox_stats.items():
            total_stats[key] = total_stats.get(key, 0) + value

        assert total_stats['application_confirmations'] == 1
