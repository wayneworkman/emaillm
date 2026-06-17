"""Tests for logging configuration, PID file management, and signal handlers."""

import logging
import os
import signal
from pathlib import Path

import pytest

import emaillm
from emaillm import (
    configure_logging,
    check_and_create_pid_file,
    remove_pid_file,
    setup_signal_handlers,
)


@pytest.fixture(autouse=True)
def restore_logger():
    """Snapshot/restore the module logger so tests don't leak handlers."""
    original = list(emaillm.logger.handlers)
    original_level = emaillm.logger.level
    yield
    emaillm.logger.handlers.clear()
    emaillm.logger.handlers.extend(original)
    emaillm.logger.setLevel(original_level)


class TestConfigureLogging:
    def test_console_only_when_no_file(self):
        configure_logging("", verbose=False)
        handlers = emaillm.logger.handlers
        assert any(isinstance(h, logging.StreamHandler) for h in handlers)
        assert not any(isinstance(h, logging.FileHandler) for h in handlers)
        assert emaillm.logger.level == logging.INFO

    def test_verbose_sets_debug_level(self):
        configure_logging("", verbose=True)
        assert emaillm.logger.level == logging.DEBUG

    def test_creates_file_handler_and_parent_dir(self, tmp_path):
        log_path = tmp_path / "nested" / "dir" / "emaillm.log"
        configure_logging(str(log_path), verbose=False)
        assert log_path.parent.is_dir()
        assert any(isinstance(h, logging.FileHandler) for h in emaillm.logger.handlers)

    def test_clears_existing_handlers(self, tmp_path):
        configure_logging(str(tmp_path / "a.log"))
        first_count = len(emaillm.logger.handlers)
        configure_logging(str(tmp_path / "b.log"))
        # Reconfiguring shouldn't accumulate handlers
        assert len(emaillm.logger.handlers) == first_count

    def test_file_logging_failure_falls_back_to_console(self, monkeypatch, tmp_path):
        """If the FileHandler can't be created, console logging still works."""
        def boom(*args, **kwargs):
            raise OSError("disk full")

        real_file_handler = logging.FileHandler
        monkeypatch.setattr(logging, "FileHandler", boom)
        # Should not raise
        configure_logging(str(tmp_path / "x.log"))
        handlers = emaillm.logger.handlers
        # Only the console handler survives; file handler creation failed
        assert len(handlers) == 1
        assert not any(isinstance(h, real_file_handler) for h in handlers)


class TestPidFile:
    def test_creates_pid_file_with_current_pid(self, tmp_path):
        pid_file = tmp_path / "emaillm.pid"
        assert check_and_create_pid_file(pid_file) is True
        assert pid_file.read_text().strip() == str(os.getpid())

    def test_running_instance_blocks(self, tmp_path, monkeypatch):
        pid_file = tmp_path / "emaillm.pid"
        pid_file.write_text("4242")
        # os.kill(pid, 0) succeeds => process "exists" => blocked
        monkeypatch.setattr(os, "kill", lambda pid, sig: None)
        assert check_and_create_pid_file(pid_file) is False
        # The existing PID file is left untouched
        assert pid_file.read_text().strip() == "4242"

    def test_stale_pid_file_is_replaced(self, tmp_path, monkeypatch):
        pid_file = tmp_path / "emaillm.pid"
        pid_file.write_text("4242")

        def fake_kill(pid, sig):
            raise ProcessLookupError()

        monkeypatch.setattr(os, "kill", fake_kill)
        assert check_and_create_pid_file(pid_file) is True
        assert pid_file.read_text().strip() == str(os.getpid())

    def test_invalid_pid_file_is_replaced(self, tmp_path):
        pid_file = tmp_path / "emaillm.pid"
        pid_file.write_text("not-a-number")
        assert check_and_create_pid_file(pid_file) is True
        assert pid_file.read_text().strip() == str(os.getpid())

    def test_remove_pid_file(self, tmp_path):
        pid_file = tmp_path / "emaillm.pid"
        pid_file.write_text("123")
        remove_pid_file(pid_file)
        assert not pid_file.exists()

    def test_remove_missing_pid_file_is_noop(self, tmp_path):
        # Should not raise even when the file is absent
        remove_pid_file(tmp_path / "does-not-exist.pid")

    def test_remove_pid_file_handles_unlink_error(self, tmp_path, monkeypatch):
        pid_file = tmp_path / "emaillm.pid"
        pid_file.write_text("123")

        def boom(self):
            raise OSError("permission denied")

        monkeypatch.setattr(Path, "unlink", boom)
        # Swallows the error and logs a warning
        remove_pid_file(pid_file)


class TestSignalHandlers:
    def test_registers_handlers_and_cleans_up(self, tmp_path, monkeypatch):
        pid_file = tmp_path / "emaillm.pid"
        pid_file.write_text("123")

        registered = {}

        def fake_signal(signum, handler):
            registered[signum] = handler

        monkeypatch.setattr(signal, "signal", fake_signal)
        setup_signal_handlers(pid_file)

        assert signal.SIGTERM in registered
        assert signal.SIGINT in registered

        # Invoking the handler should remove the PID file and exit(1)
        with pytest.raises(SystemExit) as exc:
            registered[signal.SIGTERM](signal.SIGTERM, None)
        assert exc.value.code == 1
        assert not pid_file.exists()
