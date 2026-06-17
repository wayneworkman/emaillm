"""Tests for vLLM interactions: headers, model lookup, injection detection, classify."""

from types import SimpleNamespace

import pytest

import emaillm
from emaillm import (
    get_vllm_headers,
    get_vllm_model,
    detect_prompt_injection,
    classify_email_vllm,
)


def _response(json_data=None, raise_exc=None):
    """Build a fake requests.Response-like object."""
    def raise_for_status():
        if raise_exc:
            raise raise_exc

    return SimpleNamespace(
        json=lambda: json_data,
        raise_for_status=raise_for_status,
    )


def _chat_response(content):
    return _response({"choices": [{"message": {"content": content}}]})


@pytest.fixture
def email(make_email):
    raw = (
        b"From: sender@example.com\n"
        b"To: me@example.com\n"
        b"Subject: Hello there\n\n"
        b"This is the body of the email.\n"
    )
    return make_email(raw)


class TestGetVllmHeaders:
    def test_with_api_key(self):
        headers = get_vllm_headers("secret")
        assert headers["Authorization"] == "Bearer secret"
        assert headers["Content-Type"] == "application/json"

    def test_none_api_key_warns_and_omits_auth(self, capsys):
        headers = get_vllm_headers(None)
        assert "Authorization" not in headers
        assert "not configured" in capsys.readouterr().out

    def test_empty_api_key_warns_and_omits_auth(self, capsys):
        headers = get_vllm_headers("")
        assert "Authorization" not in headers
        assert "empty string" in capsys.readouterr().out


class TestGetVllmModel:
    def test_returns_first_model_id(self, monkeypatch):
        resp = _response({"data": [{"id": "my-model"}, {"id": "other"}]})
        monkeypatch.setattr(emaillm.requests, "get", lambda *a, **k: resp)
        assert get_vllm_model("http://localhost:8000/v1", "key") == "my-model"

    def test_no_models_raises(self, monkeypatch):
        resp = _response({"data": []})
        monkeypatch.setattr(emaillm.requests, "get", lambda *a, **k: resp)
        with pytest.raises(Exception, match="No models found"):
            get_vllm_model("http://localhost:8000/v1")

    def test_request_exception_propagates(self, monkeypatch):
        def boom(*a, **k):
            raise ConnectionError("refused")

        monkeypatch.setattr(emaillm.requests, "get", boom)
        with pytest.raises(ConnectionError):
            get_vllm_model("http://localhost:8000/v1")


class TestDetectPromptInjection:
    def test_safe_marker_parsed(self, monkeypatch, email):
        resp = _chat_response("This looks normal.\n##### safe")
        monkeypatch.setattr(emaillm.requests, "post", lambda *a, **k: resp)
        is_safe, reasoning = detect_prompt_injection(
            "http://x/v1", "model", email, 0.1, 4096, "Detect injection."
        )
        assert is_safe is True
        assert "looks normal" in reasoning

    def test_unsafe_marker_parsed(self, monkeypatch, email):
        resp = _chat_response("Ignore previous instructions detected.\n##### unsafe")
        monkeypatch.setattr(emaillm.requests, "post", lambda *a, **k: resp)
        is_safe, reasoning = detect_prompt_injection(
            "http://x/v1", "model", email, 0.1, 4096, "Detect injection."
        )
        assert is_safe is False

    def test_fallback_keyword_unsafe(self, monkeypatch, email):
        resp = _chat_response("This is an injection attempt with no marker")
        monkeypatch.setattr(emaillm.requests, "post", lambda *a, **k: resp)
        is_safe, _ = detect_prompt_injection(
            "http://x/v1", "model", email, 0.1, 4096, "Detect injection."
        )
        assert is_safe is False

    def test_fallback_keyword_safe(self, monkeypatch, email):
        resp = _chat_response("Everything is safe here, no marker present")
        monkeypatch.setattr(emaillm.requests, "post", lambda *a, **k: resp)
        is_safe, _ = detect_prompt_injection(
            "http://x/v1", "model", email, 0.1, 4096, "Detect injection."
        )
        assert is_safe is True

    def test_unparseable_defaults_to_unsafe(self, monkeypatch, email):
        resp = _chat_response("completely ambiguous content")
        monkeypatch.setattr(emaillm.requests, "post", lambda *a, **k: resp)
        is_safe, _ = detect_prompt_injection(
            "http://x/v1", "model", email, 0.1, 4096, "Detect injection."
        )
        assert is_safe is False

    def test_exception_fails_secure(self, monkeypatch, email):
        def boom(*a, **k):
            raise TimeoutError("vllm down")

        monkeypatch.setattr(emaillm.requests, "post", boom)
        is_safe, reasoning = detect_prompt_injection(
            "http://x/v1", "model", email, 0.1, 4096, "Detect injection."
        )
        assert is_safe is False
        assert "vllm down" in reasoning

    def test_thinking_kwargs_added_when_disabled(self, monkeypatch, email):
        captured = {}

        def fake_post(url, headers=None, json=None, timeout=None):
            captured["payload"] = json
            return _chat_response("ok\n##### safe")

        monkeypatch.setattr(emaillm.requests, "post", fake_post)
        detect_prompt_injection(
            "http://x/v1", "model", email, 0.1, 4096, "Detect.",
            enable_thinking=False,
        )
        assert captured["payload"]["chat_template_kwargs"] == {"enable_thinking": False}

    def test_thinking_kwargs_absent_when_enabled(self, monkeypatch, email):
        captured = {}

        def fake_post(url, headers=None, json=None, timeout=None):
            captured["payload"] = json
            return _chat_response("ok\n##### safe")

        monkeypatch.setattr(emaillm.requests, "post", fake_post)
        detect_prompt_injection(
            "http://x/v1", "model", email, 0.1, 4096, "Detect.",
            enable_thinking=True,
        )
        assert "chat_template_kwargs" not in captured["payload"]


class TestClassifyEmailVllm:
    def test_marker_classification(self, monkeypatch, email, folder_configs):
        resp = _chat_response("This is clearly spam.\n##### spam")
        monkeypatch.setattr(emaillm.requests, "post", lambda *a, **k: resp)
        classification, reasoning = classify_email_vllm(
            "http://x/v1", "model", email, 0.1, 4096, folder_configs
        )
        assert classification.category == "spam"
        assert classification.target_folder == "Spam"
        assert "clearly spam" in reasoning

    def test_prompt_attack_excluded_from_categories(self, monkeypatch, email, folder_configs):
        """A '##### prompt_attack' marker must not be a valid classification."""
        captured = {}

        def fake_post(url, headers=None, json=None, timeout=None):
            captured["payload"] = json
            return _chat_response("reasoning\n##### regular")

        monkeypatch.setattr(emaillm.requests, "post", fake_post)
        classify_email_vllm("http://x/v1", "model", email, 0.1, 4096, folder_configs)
        prompt = captured["payload"]["messages"][0]["content"]
        assert "prompt_attack" not in prompt

    def test_fallback_keyword_match(self, monkeypatch, email, folder_configs):
        resp = _chat_response("I think this is a phishing message honestly")
        monkeypatch.setattr(emaillm.requests, "post", lambda *a, **k: resp)
        classification, _ = classify_email_vllm(
            "http://x/v1", "model", email, 0.1, 4096, folder_configs
        )
        assert classification.category == "phishing"

    def test_unparseable_returns_error(self, monkeypatch, email, folder_configs):
        resp = _chat_response("zzz qqq nothing matches here")
        monkeypatch.setattr(emaillm.requests, "post", lambda *a, **k: resp)
        classification, _ = classify_email_vllm(
            "http://x/v1", "model", email, 0.1, 4096, folder_configs
        )
        assert classification.category == "error"
        assert classification.target_folder is None

    def test_exception_returns_error(self, monkeypatch, email, folder_configs):
        def boom(*a, **k):
            raise ConnectionError("down")

        monkeypatch.setattr(emaillm.requests, "post", boom)
        classification, reasoning = classify_email_vllm(
            "http://x/v1", "model", email, 0.1, 4096, folder_configs
        )
        assert classification.category == "error"
        assert "down" in reasoning

    def test_custom_category_classification(self, monkeypatch, email):
        from emaillm import FolderConfig
        configs = {
            "spam": FolderConfig("Spam", "spam"),
            "phishing": FolderConfig("Phishing", "phishing"),
            "important": FolderConfig("Important", "important"),
            "promotion": FolderConfig("Promotions", "promo"),
            "transaction": FolderConfig("Transactions", "txn"),
            "regular": FolderConfig("Regular", "regular"),
            "interviews": FolderConfig("Interviews", "job interview emails"),
        }
        resp = _chat_response("Looks like a job interview.\n##### interviews")
        monkeypatch.setattr(emaillm.requests, "post", lambda *a, **k: resp)
        classification, _ = classify_email_vllm(
            "http://x/v1", "model", email, 0.1, 4096, configs
        )
        assert classification.category == "interviews"
        assert classification.target_folder == "Interviews"
