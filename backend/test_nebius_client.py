"""
Unit tests for backend/nebius_client.py

These tests run fully offline — no Nebius API calls are made.
They cover:
  - is_configured() with and without the env var
  - get_model() explicit configuration requirements
  - call_nebius() raises NebiusError when no API key is set
  - Response normalisation (valid JSON from LLM, bad JSON, missing fields, out-of-range scores)
"""

import asyncio
import json
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nebius_client import (
    NebiusError,
    REQUEST_TIMEOUT_SECONDS,
    _build_user_prompt,
    get_model,
    is_configured,
    call_nebius,
)


# ---------------------------------------------------------------------------
# Minimal async runner — same sandbox-compatible loop as test_api_route_integration
# ---------------------------------------------------------------------------
class _InMemorySelector:
    def __init__(self):
        self._readers = {}
        self._writers = {}
    def register(self, fileobj, events, data=None): pass
    def unregister(self, fileobj): pass
    def select(self, timeout=None): return []
    def close(self): pass


class _InMemorySelectorLoop(asyncio.SelectorEventLoop):
    def __init__(self):
        super().__init__(selector=_InMemorySelector())
    def _make_self_pipe(self): pass
    def _close_self_pipe(self): pass
    def _write_to_self(self): pass
    def _read_from_self(self): pass
    def _add_reader(self, fd, callback, *args): pass
    def _remove_reader(self, fd): pass


def run_async(coro):
    loop = _InMemorySelectorLoop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
class TestNebiusConfiguration(unittest.TestCase):

    def test_not_configured_when_key_missing(self):
        original = os.environ.pop("NEBIUS_API_KEY", None)
        try:
            self.assertFalse(is_configured())
        finally:
            if original is not None:
                os.environ["NEBIUS_API_KEY"] = original

    def test_configured_when_key_and_model_are_present(self):
        with patch.dict(os.environ, {
            "NEBIUS_API_KEY": "test-key-abc123",
            "NEBIUS_MODEL": "configured-model-id",
        }):
            self.assertTrue(is_configured())

    def test_not_configured_when_model_is_missing(self):
        with patch.dict(os.environ, {"NEBIUS_API_KEY": "test-key-abc123"}):
            os.environ.pop("NEBIUS_MODEL", None)
            self.assertFalse(is_configured())

    def test_not_configured_when_key_is_whitespace(self):
        original = os.environ.get("NEBIUS_API_KEY")
        os.environ["NEBIUS_API_KEY"] = "   "
        try:
            self.assertFalse(is_configured())
        finally:
            if original is None:
                del os.environ["NEBIUS_API_KEY"]
            else:
                os.environ["NEBIUS_API_KEY"] = original

    def test_get_model_requires_explicit_configuration(self):
        original = os.environ.pop("NEBIUS_MODEL", None)
        try:
            with self.assertRaises(NebiusError) as ctx:
                get_model()
            self.assertIn("NEBIUS_MODEL", str(ctx.exception))
        finally:
            if original is not None:
                os.environ["NEBIUS_MODEL"] = original

    def test_get_model_override(self):
        original = os.environ.get("NEBIUS_MODEL")
        os.environ["NEBIUS_MODEL"] = "configured-model-id"
        try:
            self.assertEqual(get_model(), "configured-model-id")
        finally:
            if original is None:
                del os.environ["NEBIUS_MODEL"]
            else:
                os.environ["NEBIUS_MODEL"] = original

    def test_get_model_rejects_whitespace(self):
        original = os.environ.get("NEBIUS_MODEL")
        os.environ["NEBIUS_MODEL"] = "   "
        try:
            with self.assertRaises(NebiusError):
                get_model()
        finally:
            if original is None:
                del os.environ["NEBIUS_MODEL"]
            else:
                os.environ["NEBIUS_MODEL"] = original


class TestBuildUserPrompt(unittest.TestCase):

    def test_message_only(self):
        prompt = _build_user_prompt("Hello there", None)
        self.assertIn("Hello there", prompt)
        self.assertNotIn("URL:", prompt)

    def test_url_only(self):
        prompt = _build_user_prompt(None, "http://evil.xyz/login")
        self.assertIn("http://evil.xyz/login", prompt)
        self.assertNotIn("Message:", prompt)

    def test_both(self):
        prompt = _build_user_prompt("Click here", "http://evil.xyz")
        self.assertIn("Message: Click here", prompt)
        self.assertIn("URL: http://evil.xyz", prompt)


class TestCallNebiusNoKey(unittest.TestCase):

    def test_raises_without_api_key(self):
        original = os.environ.pop("NEBIUS_API_KEY", None)
        try:
            with self.assertRaises(NebiusError) as ctx:
                run_async(call_nebius("test message", None))
            self.assertIn("NEBIUS_API_KEY", str(ctx.exception))
        finally:
            if original is not None:
                os.environ["NEBIUS_API_KEY"] = original


class TestCallNebiusWithMockedHTTP(unittest.TestCase):
    """
    Mock httpx.AsyncClient to verify response parsing without network calls.
    """

    def _run_with_mock_response(self, api_key: str, status_code: int, body: dict | str | bytes):
        """Patch httpx.AsyncClient inside nebius_client and run call_nebius."""
        import nebius_client as nc

        class MockResponse:
            def __init__(self):
                self.status_code = status_code
                self._body = body if isinstance(body, (str, bytes)) else json.dumps(body)
                self.text = self._body
            def json(self):
                return json.loads(self._body)

        client_options = {}
        request_options = {}

        class MockAsyncClient:
            def __init__(self, **kwargs):
                client_options.update(kwargs)
            async def __aenter__(self): return self
            async def __aexit__(self, *a): pass
            async def post(self, path, **kwargs):
                request_options.update({"path": path, **kwargs})
                return MockResponse()

        original_async_client = nc.httpx.AsyncClient
        nc.httpx.AsyncClient = MockAsyncClient
        original_key = os.environ.get("NEBIUS_API_KEY")
        original_model = os.environ.get("NEBIUS_MODEL")
        os.environ["NEBIUS_API_KEY"] = api_key
        os.environ["NEBIUS_MODEL"] = "test-model"
        try:
            result = run_async(nc.call_nebius("Buy cheap pills now", None))
            self.assertEqual(client_options["timeout"], REQUEST_TIMEOUT_SECONDS)
            self.assertEqual(request_options["path"], "/chat/completions")
            self.assertEqual(request_options["headers"]["Authorization"], f"Bearer {api_key}")
            self.assertEqual(request_options["json"]["model"], "test-model")
            return result
        finally:
            nc.httpx.AsyncClient = original_async_client
            if original_key is None:
                os.environ.pop("NEBIUS_API_KEY", None)
            else:
                os.environ["NEBIUS_API_KEY"] = original_key
            if original_model is None:
                os.environ.pop("NEBIUS_MODEL", None)
            else:
                os.environ["NEBIUS_MODEL"] = original_model

    def test_valid_response_parsed_correctly(self):
        llm_json = {
            "risk_score": 75,
            "risk_level": "High",
            "indicators": ["pharmaceutical spam", "urgent tone"],
            "recommendation": "Do not click any links.",
        }
        api_response = {
            "choices": [{"message": {"content": json.dumps(llm_json)}}]
        }
        result = self._run_with_mock_response("valid-key", 200, api_response)

        self.assertEqual(result["risk_score"], 75)
        self.assertEqual(result["risk_level"], "High")
        self.assertIn("pharmaceutical spam", result["indicators"])
        self.assertIn("analysis_method", result)
        self.assertEqual(result["analysis_method"], "Nebius AI LLM (test-model)")

    def test_score_clamped_to_100(self):
        llm_json = {"risk_score": 999, "risk_level": "High", "indicators": [], "recommendation": ""}
        api_response = {"choices": [{"message": {"content": json.dumps(llm_json)}}]}
        result = self._run_with_mock_response("valid-key", 200, api_response)
        self.assertEqual(result["risk_score"], 100)

    def test_score_clamped_to_0(self):
        llm_json = {"risk_score": -50, "risk_level": "Low", "indicators": [], "recommendation": ""}
        api_response = {"choices": [{"message": {"content": json.dumps(llm_json)}}]}
        result = self._run_with_mock_response("valid-key", 200, api_response)
        self.assertEqual(result["risk_score"], 0)

    def test_invalid_risk_level_inferred_from_score(self):
        llm_json = {"risk_score": 65, "risk_level": "UNKNOWN", "indicators": [], "recommendation": ""}
        api_response = {"choices": [{"message": {"content": json.dumps(llm_json)}}]}
        result = self._run_with_mock_response("valid-key", 200, api_response)
        self.assertEqual(result["risk_level"], "High")

    def test_risk_level_is_consistent_with_score(self):
        llm_json = {"risk_score": 75, "risk_level": "Low", "indicators": [], "recommendation": ""}
        api_response = {"choices": [{"message": {"content": json.dumps(llm_json)}}]}
        result = self._run_with_mock_response("valid-key", 200, api_response)
        self.assertEqual(result["risk_level"], "High")

    def test_401_raises_nebius_error(self):
        with self.assertRaises(NebiusError) as ctx:
            self._run_with_mock_response("bad-key", 401, {"error": "unauthorized"})
        self.assertIn("401", str(ctx.exception))

    def test_404_raises_nebius_error(self):
        with self.assertRaises(NebiusError) as ctx:
            self._run_with_mock_response("valid-key", 404, {"error": "not found"})
        self.assertIn("404", str(ctx.exception))

    def test_bad_json_content_raises_nebius_error(self):
        api_response = {"choices": [{"message": {"content": "not json!"}}]}
        with self.assertRaises(NebiusError) as ctx:
            self._run_with_mock_response("valid-key", 200, api_response)
        self.assertIn("parse", str(ctx.exception).lower())

    def test_missing_choices_raises_nebius_error(self):
        api_response = {"result": "unexpected_structure"}
        with self.assertRaises(NebiusError) as ctx:
            self._run_with_mock_response("valid-key", 200, api_response)
        self.assertIn("parse", str(ctx.exception).lower())

    def test_non_object_response_raises_nebius_error(self):
        with self.assertRaises(NebiusError) as ctx:
            self._run_with_mock_response("valid-key", 200, [])
        self.assertIn("parse", str(ctx.exception).lower())

    def test_non_utf8_response_raises_nebius_error(self):
        with self.assertRaises(NebiusError) as ctx:
            self._run_with_mock_response("valid-key", 200, b"\xff")
        self.assertIn("parse", str(ctx.exception).lower())

    def test_non_object_model_content_raises_nebius_error(self):
        api_response = {"choices": [{"message": {"content": "[]"}}]}
        with self.assertRaises(NebiusError) as ctx:
            self._run_with_mock_response("valid-key", 200, api_response)
        self.assertIn("json object", str(ctx.exception).lower())

    def test_http_error_does_not_include_response_body(self):
        with self.assertRaises(NebiusError) as ctx:
            self._run_with_mock_response("valid-key", 500, {"error": "private message"})
        self.assertNotIn("private message", str(ctx.exception))

    def test_invalid_response_field_does_not_leak_content(self):
        private_content = "PRIVATE_MESSAGE_CONTENT"
        llm_json = {
            "risk_score": private_content,
            "risk_level": "Low",
            "indicators": [],
            "recommendation": "",
        }
        api_response = {"choices": [{"message": {"content": json.dumps(llm_json)}}]}
        with self.assertRaises(NebiusError) as ctx:
            self._run_with_mock_response("valid-key", 200, api_response)
        self.assertNotIn(private_content, str(ctx.exception))

    def test_invalid_indicator_and_recommendation_types_fall_back(self):
        invalid_fields = (
            {"risk_score": 20, "indicators": "not-a-list", "recommendation": ""},
            {"risk_score": 20, "indicators": [], "recommendation": {"private": "content"}},
            {"risk_score": True, "indicators": [], "recommendation": ""},
        )
        for llm_json in invalid_fields:
            with self.subTest(llm_json=llm_json):
                api_response = {
                    "choices": [{"message": {"content": json.dumps(llm_json)}}]
                }
                with self.assertRaises(NebiusError) as ctx:
                    self._run_with_mock_response("valid-key", 200, api_response)
                self.assertIn("invalid field types", str(ctx.exception))

    def test_timeout_raises_nebius_error(self):
        import nebius_client as nc

        class TimeoutClient:
            def __init__(self, **kwargs): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *args): pass
            async def post(self, *args, **kwargs):
                raise nc.httpx.TimeoutException("request timed out")

        original_key = os.environ.get("NEBIUS_API_KEY")
        original_model = os.environ.get("NEBIUS_MODEL")
        with patch.object(nc.httpx, "AsyncClient", TimeoutClient):
            os.environ["NEBIUS_API_KEY"] = "test-key"
            os.environ["NEBIUS_MODEL"] = "test-model"
            try:
                with self.assertRaises(NebiusError) as ctx:
                    run_async(nc.call_nebius("message", None))
                self.assertIn("TimeoutException", str(ctx.exception))
            finally:
                if original_key is None:
                    os.environ.pop("NEBIUS_API_KEY", None)
                else:
                    os.environ["NEBIUS_API_KEY"] = original_key
                if original_model is None:
                    os.environ.pop("NEBIUS_MODEL", None)
                else:
                    os.environ["NEBIUS_MODEL"] = original_model

    def test_missing_fields_default_to_empty(self):
        # LLM response with only risk_score — other fields should default gracefully
        llm_json = {"risk_score": 50}
        api_response = {"choices": [{"message": {"content": json.dumps(llm_json)}}]}
        result = self._run_with_mock_response("valid-key", 200, api_response)
        self.assertEqual(result["risk_score"], 50)
        self.assertIsInstance(result["indicators"], list)
        self.assertIsInstance(result["recommendation"], str)

    def test_missing_risk_score_is_rejected(self):
        api_response = {
            "choices": [{"message": {"content": json.dumps({"indicators": [], "recommendation": ""})}}]
        }
        with self.assertRaises(NebiusError) as ctx:
            self._run_with_mock_response("valid-key", 200, api_response)
        self.assertIn("risk score", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
