"""Tests for the main() entry point and argument handling."""

import sys

import pytest

import emaillm
from emaillm import main, InboxConfig


@pytest.fixture
def main_env(monkeypatch, filter_config):
    """Patch all of main()'s collaborators; return a control object."""
    state = {
        "pid_ok": True,
        "model": "test-model",
        "process_calls": [],
        "removed_pid": False,
        "stats": {"processed": 1, "spam": 1, "errors": 0},
    }

    monkeypatch.setattr(emaillm, "load_config", lambda path: filter_config)
    monkeypatch.setattr(emaillm, "configure_logging", lambda *a, **k: None)
    monkeypatch.setattr(emaillm, "check_and_create_pid_file", lambda p: state["pid_ok"])
    monkeypatch.setattr(emaillm, "setup_signal_handlers", lambda p: None)
    monkeypatch.setattr(emaillm, "get_vllm_model", lambda *a, **k: state["model"])

    def fake_process(inbox_config, config, model):
        state["process_calls"].append(inbox_config.name)
        return dict(state["stats"])

    monkeypatch.setattr(emaillm, "process_inbox", fake_process)

    def fake_remove(p):
        state["removed_pid"] = True

    monkeypatch.setattr(emaillm, "remove_pid_file", fake_remove)
    monkeypatch.setattr(sys, "argv", ["emaillm.py"])
    return state, filter_config


class TestMain:
    def test_happy_path_processes_inboxes(self, main_env):
        state, _ = main_env
        main()
        assert state["process_calls"] == ["primary"]
        assert state["removed_pid"] is True

    def test_config_load_failure_exits(self, main_env, monkeypatch):
        state, _ = main_env

        def boom(path):
            raise ValueError("bad config")

        monkeypatch.setattr(emaillm, "load_config", boom)
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 1

    def test_pid_lock_held_exits(self, main_env):
        state, _ = main_env
        state["pid_ok"] = False
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 1

    def test_vllm_model_failure_exits_and_cleans_pid(self, main_env, monkeypatch):
        state, _ = main_env

        def boom(*a, **k):
            raise ConnectionError("vllm down")

        monkeypatch.setattr(emaillm, "get_vllm_model", boom)
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 1
        # finally block still removes the PID file
        assert state["removed_pid"] is True

    def test_inbox_filter_selects_one(self, main_env, monkeypatch):
        state, config = main_env
        config.inboxes = [
            InboxConfig("primary", "e1", "h1"),
            InboxConfig("secondary", "e2", "h2"),
        ]
        monkeypatch.setattr(sys, "argv", ["emaillm.py", "--inbox", "secondary"])
        main()
        assert state["process_calls"] == ["secondary"]

    def test_processes_all_inboxes_by_default(self, main_env, monkeypatch):
        state, config = main_env
        config.inboxes = [
            InboxConfig("primary", "e1", "h1"),
            InboxConfig("secondary", "e2", "h2"),
        ]
        main()
        assert state["process_calls"] == ["primary", "secondary"]

    def test_verbose_flag_accepted(self, main_env, monkeypatch):
        state, _ = main_env
        monkeypatch.setattr(sys, "argv", ["emaillm.py", "-v"])
        main()
        assert state["process_calls"] == ["primary"]

    def test_custom_category_in_summary(self, main_env, monkeypatch):
        """Custom categories not in the standard set are summarized too."""
        state, _ = main_env
        state["stats"] = {"processed": 1, "interviews": 1, "errors": 0}
        # Should run without error and aggregate the custom key
        main()
        assert state["process_calls"] == ["primary"]
