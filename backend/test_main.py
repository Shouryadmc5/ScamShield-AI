import unittest
import sys
import os
import asyncio
import json
from unittest.mock import patch

# Add backend directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from main import evaluate_rules, safe_parse_url, app, AnalyzeRequest, AnalyzeResponse, health
from pydantic import ValidationError
from nebius_client import NebiusError
import main


class TestScamShieldRuleAudit(unittest.TestCase):
    # -------------------------------------------------------------
    # 1. Benign Messages & Legitimate URLs (Low False Positives)
    # -------------------------------------------------------------
    def test_benign_ordinary_conversation(self):
        msg = "Hey are we still meeting for lunch today at 1pm? Let me know."
        result = evaluate_rules(msg, None)
        self.assertEqual(result["risk_level"], "Low")
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(len(result["indicators"]), 0)

    def test_mild_urgency_without_credentials_does_not_trigger_high_risk(self):
        # A message saying urgent without asking for money or passwords should be Low risk
        msg = "Urgent: please remember to pick up the groceries on your way home."
        result = evaluate_rules(msg, None)
        self.assertEqual(result["risk_level"], "Low")
        self.assertLess(result["risk_score"], 30)
        self.assertTrue(any("urgency" in ind.lower() for ind in result["indicators"]))

    def test_urgent_personal_message_and_legitimate_financial_alert_stay_low(self):
        benign_messages = (
            "Urgent: the school office closes at 4, so please bring the signed form before pickup.",
            "Your card was used for $18.42 at Market Street Cafe. If this was not you, call the number on your card.",
            "Your payment of $68.40 to City Utilities was received. No further action is needed.",
        )
        for message in benign_messages:
            with self.subTest(message=message):
                result = evaluate_rules(message, None)
                self.assertLess(result["risk_score"], 30)
                self.assertEqual(result["risk_level"], "Low")

    def test_legitimate_brand_url_not_flagged_as_spoofing(self):
        result = evaluate_rules(None, "https://www.paypal.com/signin")
        self.assertEqual(result["risk_level"], "Low")
        self.assertLess(result["risk_score"], 30)
        # Should not flag brand spoofing for official domain
        self.assertFalse(any("spoofing" in ind.lower() for ind in result["indicators"]))

    def test_legitimate_apple_subdomain(self):
        result = evaluate_rules(None, "https://developer.apple.com/documentation")
        self.assertEqual(result["risk_level"], "Low")
        self.assertFalse(any("spoofing" in ind.lower() for ind in result["indicators"]))

    # -------------------------------------------------------------
    # 2. Urgent Credential / Payment Requests (True Positives)
    # -------------------------------------------------------------
    def test_urgent_credential_harvesting(self):
        msg = "URGENT: Your account has been suspended! Verify your password within 24 hours to restore access."
        result = evaluate_rules(msg, None)
        self.assertGreaterEqual(result["risk_score"], 60)
        self.assertEqual(result["risk_level"], "High")
        combined_inds = " ".join(result["indicators"]).lower()
        self.assertTrue("urgency" in combined_inds)
        self.assertTrue("credentials" in combined_inds or "verification" in combined_inds)

    def test_financial_lottery_and_crypto_scams(self):
        msg = "Congratulations! You have won $5,000 in unclaimed funds. Send wire transfer fee or gift card to claim."
        result = evaluate_rules(msg, None)
        self.assertGreaterEqual(result["risk_score"], 25)
        self.assertIn(result["risk_level"], ["Medium", "High"])
        combined_inds = " ".join(result["indicators"]).lower()
        self.assertTrue("prizes" in combined_inds or "wire transfer" in combined_inds)

    # -------------------------------------------------------------
    # 3. Brand Impersonation & Deceptive Subdomains
    # -------------------------------------------------------------
    def test_brand_in_domain_stem_phishing(self):
        result = evaluate_rules(None, "http://paypal-security-update.xyz/login")
        self.assertGreaterEqual(result["risk_score"], 60)
        self.assertEqual(result["risk_level"], "High")
        combined_inds = " ".join(result["indicators"]).lower()
        self.assertTrue("spoofing" in combined_inds)
        self.assertTrue("xyz" in combined_inds)

    def test_brand_in_subdomain_phishing(self):
        result = evaluate_rules(None, "https://chase.com.security-alert-verify.com/login")
        self.assertGreaterEqual(result["risk_score"], 35)
        combined_inds = " ".join(result["indicators"]).lower()
        self.assertTrue("spoofing" in combined_inds)

    def test_brand_lookalike_domain_is_flagged(self):
        result = evaluate_rules(None, "https://paypa1-security.example/login")
        self.assertGreaterEqual(result["risk_score"], 30)
        self.assertTrue(any("lookalike spelling" in item.lower() for item in result["indicators"]))

    def test_lookalike_rule_does_not_match_substrings_or_legitimate_brand_url(self):
        for url in (
            "https://pineapple.com/recipes",
            "https://developer.apple.com/documentation",
        ):
            with self.subTest(url=url):
                result = evaluate_rules(None, url)
                self.assertFalse(
                    any("lookalike spelling" in item.lower() for item in result["indicators"])
                )

    def test_internationalized_domain_is_reported_as_a_caution(self):
        result = evaluate_rules(None, "https://раypal.example/login")
        self.assertTrue(
            any("internationalized characters" in item.lower() for item in result["indicators"])
        )
        self.assertLess(result["risk_score"], 60)

    def test_ipv6_host_is_parsed_as_an_ip_address(self):
        result = evaluate_rules(None, "http://[2001:db8::1]/account")
        self.assertTrue(any("raw ip address" in item.lower() for item in result["indicators"]))

    def test_payment_method_requires_payment_context(self):
        benign_mentions = (
            "I bought a gift card for my niece's birthday.",
            "We discussed Bitcoin during the economics lecture.",
        )
        for message in benign_mentions:
            with self.subTest(message=message):
                result = evaluate_rules(message, None)
                self.assertLess(result["risk_score"], 30)
                self.assertFalse(
                    any("hard-to-reverse method" in item.lower() for item in result["indicators"])
                )

        scam_request = "Please buy gift cards to verify the account and read me the codes."
        result = evaluate_rules(scam_request, None)
        self.assertTrue(any("demands payment" in item.lower() for item in result["indicators"]))

    def test_explicit_payment_app_request_and_neutral_receipt(self):
        scam_request = "Send payment through Cash App today to avoid collection."
        result = evaluate_rules(scam_request, None)
        self.assertTrue(any("demands payment" in item.lower() for item in result["indicators"]))
        self.assertGreaterEqual(result["risk_score"], 30)

        benign_receipt = "I received the payment through Cash App yesterday. Thank you."
        result = evaluate_rules(benign_receipt, None)
        self.assertLess(result["risk_score"], 30)
        self.assertFalse(any("demands payment" in item.lower() for item in result["indicators"]))

    # -------------------------------------------------------------
    # 4. Malformed URLs, Deceptive Formats & Dangerous Schemes
    # -------------------------------------------------------------
    def test_javascript_and_data_schemes(self):
        result = evaluate_rules(None, "javascript:alert(document.cookie)")
        self.assertGreaterEqual(result["risk_score"], 45)
        self.assertTrue(any("javascript" in ind.lower() for ind in result["indicators"]))

        result_data = evaluate_rules(None, "data:text/html;base64,PHNjcmlwdD4=")
        self.assertTrue(any("dangerous executable url scheme" in ind.lower() for ind in result_data["indicators"]))

    def test_user_info_at_symbol_obfuscation(self):
        result = evaluate_rules(None, "https://google.com@attacker-site.com/fake-login")
        self.assertGreaterEqual(result["risk_score"], 30)
        self.assertTrue(any("@" in ind for ind in result["indicators"]))

    def test_email_address_in_url_query_is_not_user_info_obfuscation(self):
        result = evaluate_rules(
            None,
            "https://example.org/contact?email=support@example.org",
        )
        self.assertLess(result["risk_score"], 30)
        self.assertFalse(any("user-info notation" in item.lower() for item in result["indicators"]))

    def test_raw_ip_address_host(self):
        result = evaluate_rules(None, "http://192.168.1.100/account-verify")
        self.assertGreaterEqual(result["risk_score"], 45)
        self.assertTrue(any("raw ip address" in ind.lower() for ind in result["indicators"]))

    def test_punycode_homograph_domain(self):
        result = evaluate_rules(None, "https://xn--pypal-4ve.com/account")
        self.assertTrue(any("punycode" in ind.lower() for ind in result["indicators"]))

    def test_link_shortener_detection(self):
        result = evaluate_rules(None, "https://bit.ly/secure-account")
        self.assertTrue(any("link shortener" in ind.lower() or "bit.ly" in ind.lower() for ind in result["indicators"]))

    # -------------------------------------------------------------
    # 5. Repeated Signals, Score Bounding & Deduplication
    # -------------------------------------------------------------
    def test_score_strictly_bounded_at_100(self):
        # Accumulate many extreme signals simultaneously
        extreme_msg = "URGENT ACTION REQUIRED: YOUR ACCOUNT IS SUSPENDED! VERIFY PASSWORD IMMEDIATELY OR TERMINATED WITHIN 24 HOURS! YOU HAVE WON $10,000 SEND WIRE TRANSFER OR GIFT CARD NOW!"
        extreme_url = "http://paypal-security-alert.xyz@192.168.1.1/update"
        result = evaluate_rules(extreme_msg, extreme_url)
        self.assertLessEqual(result["risk_score"], 100)
        self.assertEqual(result["risk_score"], 100)
        self.assertEqual(result["risk_level"], "High")

    def test_no_duplicate_indicators(self):
        # Repeat the same shortener or urgency multiple times in message
        msg = "Urgent: urgent action required immediately! Check https://bit.ly/123 and https://bit.ly/456"
        result = evaluate_rules(msg, None)
        # Indicators list should have unique items
        self.assertEqual(len(result["indicators"]), len(set(result["indicators"])))

    # -------------------------------------------------------------
    # 6. Input Validation & API Contract
    # -------------------------------------------------------------
    def test_empty_input_rejected_by_pydantic(self):
        with self.assertRaises(ValidationError):
            AnalyzeRequest()

        with self.assertRaises(ValidationError):
            AnalyzeRequest(message="   ", url="")

    def test_valid_input_schemas(self):
        req1 = AnalyzeRequest(message="Valid text")
        self.assertEqual(req1.message, "Valid text")

        req2 = AnalyzeRequest(url="https://valid.org")
        self.assertEqual(req2.url, "https://valid.org")

    def test_health_check(self):
        res = health()
        self.assertEqual(res.get("status"), "ok")

    def test_cors_vercel_regex_match(self):
        from main import vercel_origin_regex
        import re
        self.assertTrue(bool(re.match(vercel_origin_regex, "https://scamshield-ngfa0g1xm-shouryadmc5-7692.vercel.app")))
        self.assertTrue(bool(re.match(vercel_origin_regex, "https://scamshield-ai.vercel.app")))
        self.assertFalse(bool(re.match(vercel_origin_regex, "http://malicious-vercel.app.fake.com")))


class TestNebiusFallback(unittest.TestCase):
    def test_unconfigured_nebius_uses_rule_based_response(self):
        request = AnalyzeRequest(message="URGENT: verify your password now")
        with patch("nebius_client.is_configured", return_value=False):
            result = asyncio.run(main.analyze(request))

        self.assertEqual(
            set(result),
            {"risk_score", "risk_level", "indicators", "recommendation", "analysis_method"},
        )
        self.assertIn("rule-based", result["analysis_method"].lower())
        self.assertIn("not configured", result["analysis_method"].lower())

    def test_missing_model_does_not_send_submitted_content_to_nebius(self):
        request = AnalyzeRequest(message="PRIVATE_USER_MESSAGE_CONTENT")
        with (
            patch.dict(os.environ, {"NEBIUS_API_KEY": "test-key"}),
            patch("nebius_client.call_nebius") as call_nebius,
        ):
            os.environ.pop("NEBIUS_MODEL", None)
            result = asyncio.run(main.analyze(request))

        call_nebius.assert_not_called()
        self.assertIn("not configured", result["analysis_method"].lower())

    def test_nebius_error_falls_back_to_rules(self):
        private_message = "PRIVATE_USER_MESSAGE_CONTENT"
        request = AnalyzeRequest(message=private_message)

        async def fail_request(*args):
            raise NebiusError("Nebius API returned HTTP 503.")

        with (
            patch("nebius_client.is_configured", return_value=True),
            patch("nebius_client.call_nebius", side_effect=fail_request),
            self.assertLogs(main._log, level="WARNING") as captured,
        ):
            result = asyncio.run(main.analyze(request))

        self.assertIn("rule-based", result["analysis_method"].lower())
        self.assertIn("inference failed", result["analysis_method"].lower())
        self.assertNotIn(private_message, "\n".join(captured.output))


class TestDetectorImprovements(unittest.TestCase):
    # -------------------------------------------------------------
    # Focused tests for engine improvements & edge cases
    # -------------------------------------------------------------
    def test_shortened_url_with_sensitive_path_escalates_score(self):
        result = evaluate_rules(None, "https://bit.ly/secure-account-login")
        self.assertGreaterEqual(result["risk_score"], 30)
        self.assertEqual(result["risk_level"], "Medium")
        combined_inds = " ".join(result["indicators"]).lower()
        self.assertTrue("shortener" in combined_inds)
        self.assertTrue("sensitive" in combined_inds or "authentication" in combined_inds)

    def test_benign_shortened_url_remains_low_risk(self):
        result = evaluate_rules(None, "https://bit.ly/grocery-list-sunday")
        self.assertEqual(result["risk_level"], "Low")
        self.assertLess(result["risk_score"], 30)
        self.assertFalse(any("sensitive" in ind.lower() for ind in result["indicators"]))

    def test_brand_substring_does_not_trigger_false_positive(self):
        benign_urls = [
            "https://first-bank.com",
            "https://purchase-online.com",
            "https://pineapple.com",
            "https://snapple.com",
            "https://example.com/first-post",
        ]
        for u in benign_urls:
            res = evaluate_rules(None, u)
            self.assertEqual(res["risk_level"], "Low", f"Failed for {u}")
            self.assertEqual(res["risk_score"], 0, f"Expected 0 score for {u}, got {res['risk_score']}")
            self.assertFalse(any("spoofing" in ind.lower() or "brand lure" in ind.lower() for ind in res["indicators"]))

    def test_compound_advance_fee_prize_fraud(self):
        msg = "Congratulations! You have won $10,000 in our international lottery. Wire transfer a $50 processing fee to claim your prize."
        result = evaluate_rules(msg, None)
        self.assertGreaterEqual(result["risk_score"], 60)
        self.assertEqual(result["risk_level"], "High")
        combined_inds = " ".join(result["indicators"]).lower()
        self.assertTrue("advance-fee" in combined_inds or "wire transfer" in combined_inds)

    def test_changed_bank_details_payment_request_is_flagged_without_scam_keywords(self):
        message = (
            "Please pay the outstanding invoice to our updated bank account; "
            "the previous account is closed."
        )
        result = evaluate_rules(message, None)
        self.assertGreaterEqual(result["risk_score"], 30)
        self.assertIn(result["risk_level"], ["Medium", "High"])
        self.assertTrue(any("changed or replacement bank details" in item for item in result["indicators"]))

        neutral_message = (
            "The vendor changed its bank details; update the contact sheet after finance verifies them."
        )
        neutral_result = evaluate_rules(neutral_message, None)
        self.assertEqual(neutral_result["risk_level"], "Low")
        self.assertFalse(
            any("changed or replacement bank details" in item for item in neutral_result["indicators"])
        )

    def test_fake_invoice_and_billing_fraud(self):
        msg = "Geek Squad: Invoice #9823 for $399 auto-renewal charged. Call immediately if unauthorized transaction."
        result = evaluate_rules(msg, None)
        self.assertGreaterEqual(result["risk_score"], 40)
        self.assertIn(result["risk_level"], ["Medium", "High"])
        combined_inds = " ".join(result["indicators"]).lower()
        self.assertTrue("invoice" in combined_inds or "unauthorized" in combined_inds or "billing" in combined_inds)

    def test_benign_messages_with_sensitive_words_remain_low(self):
        benign_messages = [
            "I went to the bank today to deposit money.",
            "Thanks for the payment for dinner.",
            "The high school science prize was awarded yesterday.",
            "The bank approved our mortgage application.",
            "Payment received for your electric bill. Thank you.",
        ]
        for msg in benign_messages:
            res = evaluate_rules(msg, None)
            self.assertEqual(res["risk_level"], "Low", f"Expected Low for: {msg}")
            self.assertEqual(res["risk_score"], 0, f"Expected 0 for: {msg}")
            self.assertEqual(len(res["indicators"]), 0, f"Expected 0 indicators for: {msg}")

    def test_scoring_is_strictly_deterministic(self):
        msg = "Security Alert: Verify your Chase password immediately at https://bit.ly/secure-account-login"
        url = "https://bit.ly/secure-account-login"
        runs = [evaluate_rules(msg, url) for _ in range(5)]
        first = runs[0]
        for r in runs[1:]:
            self.assertEqual(r["risk_score"], first["risk_score"])
            self.assertEqual(r["risk_level"], first["risk_level"])
            self.assertEqual(r["indicators"], first["indicators"])
            self.assertEqual(r["recommendation"], first["recommendation"])

    def test_input_bounds_validation(self):
        # Valid bounds
        req = AnalyzeRequest(message="x" * 10000, url="https://example.com")
        self.assertEqual(len(req.message), 10000)

        # Exceeding message max_length
        with self.assertRaises(ValidationError):
            AnalyzeRequest(message="x" * 10001)

        # Exceeding url max_length
        with self.assertRaises(ValidationError):
            AnalyzeRequest(url="https://example.com/" + "a" * 2048)

    def test_malformed_url_handling(self):
        # URLs with empty host or malformed format
        res = evaluate_rules(None, "http://")
        self.assertGreaterEqual(res["risk_score"], 30)
        self.assertTrue(any("malformed" in ind.lower() for ind in res["indicators"]))

    def test_api_route_integration(self):
        # Genuine in-memory ASGI dispatch test through full FastAPI/Starlette pipeline
        # (middleware, routing, Pydantic validation, serialization, and CORS headers).
        # Uses an in-memory event loop selector to prevent Windows loopback socket hangs.
        import asyncio
        import json

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

        async def _dispatch_asgi(payload: dict = None, origin: str = None):
            body = json.dumps(payload).encode("utf-8") if payload is not None else b""
            headers = [
                (b"host", b"testserver"),
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ]
            if origin:
                headers.append((b"origin", origin.encode("ascii")))

            scope = {
                "type": "http",
                "asgi": {"version": "3.0", "spec_version": "2.0"},
                "http_version": "1.1",
                "method": "POST",
                "scheme": "http",
                "path": "/api/analyze",
                "raw_path": b"/api/analyze",
                "query_string": b"",
                "headers": headers,
                "client": ("127.0.0.1", 12345),
                "server": ("testserver", 80),
            }

            sent = False
            async def receive():
                nonlocal sent
                if not sent:
                    sent = True
                    return {"type": "http.request", "body": body, "more_body": False}
                return {"type": "http.request", "body": b"", "more_body": False}

            response_status = None
            response_headers = {}
            response_chunks = []

            async def send(message):
                nonlocal response_status, response_headers
                if message["type"] == "http.response.start":
                    response_status = message["status"]
                    response_headers = {
                        k.decode("latin1").lower(): v.decode("latin1")
                        for k, v in message.get("headers", [])
                    }
                elif message["type"] == "http.response.body":
                    response_chunks.append(message.get("body", b""))

            await app(scope, receive, send)
            raw_body = b"".join(response_chunks)
            json_body = json.loads(raw_body.decode("utf-8")) if raw_body else {}
            return response_status, response_headers, json_body

        loop = _InMemorySelectorLoop()
        asyncio.set_event_loop(loop)
        try:
            # 1. Valid request through full ASGI pipeline
            status, headers, data = loop.run_until_complete(
                _dispatch_asgi(
                    {"message": "Hey Sarah, are we still meeting for lunch today?"},
                    origin="https://scamshield.vercel.app",
                )
            )
            self.assertEqual(status, 200)
            self.assertEqual(headers.get("access-control-allow-origin"), "https://scamshield.vercel.app")
            self.assertIn("risk_score", data)
            self.assertIn("risk_level", data)
            self.assertIn("indicators", data)
            self.assertIn("recommendation", data)
            self.assertIn("analysis_method", data)
            self.assertEqual(data["risk_level"], "Low")

            # 2. Both fields empty (rejected by Pydantic validation middleware -> 422 Unprocessable Entity)
            status_empty, _, data_empty = loop.run_until_complete(
                _dispatch_asgi({"message": "   ", "url": ""})
            )
            self.assertEqual(status_empty, 422)
            self.assertIn("detail", data_empty)

            # 3. Oversized payload (rejected by Pydantic max_length validator -> 422)
            status_oversized, _, data_oversized = loop.run_until_complete(
                _dispatch_asgi({"message": "a" * 10001})
            )
            self.assertEqual(status_oversized, 422)
            self.assertIn("detail", data_oversized)
        finally:
            loop.close()


class TestBenchmarkEvaluator(unittest.TestCase):
    def test_load_valid_benchmark_dataset(self):
        from evaluate import load_dataset, DEFAULT_DATASET_PATH
        items = load_dataset(DEFAULT_DATASET_PATH)
        self.assertIsInstance(items, list)
        self.assertGreater(len(items), 0)
        for it in items:
            self.assertIn("id", it)
            self.assertIn("expected_label", it)
            self.assertIn(it["expected_label"], ["benign", "scam"])
            self.assertIn("input", it)

    def test_evaluator_handles_malformed_entries(self):
        import tempfile
        from evaluate import load_dataset

        # Test missing id
        with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".json") as tf:
            tf.write('[{"expected_label": "benign", "input": {"message": "hi"}}]')
            tf_name = tf.name
        try:
            with self.assertRaises(ValueError):
                load_dataset(tf_name)
        finally:
            os.remove(tf_name)

        malformed_cases = (
            '[{"id": "same", "expected_label": "benign", "input": {"message": "one"}},'
            '{"id": "same", "expected_label": "scam", "input": {"message": "two"}}]',
            '[{"id": "non-string", "expected_label": "benign", "input": {"message": 42}}]',
        )
        for raw_data in malformed_cases:
            with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".json") as tf:
                tf.write(raw_data)
                tf_name = tf.name
            try:
                with self.assertRaises(ValueError):
                    load_dataset(tf_name)
            finally:
                os.remove(tf_name)

        # Test invalid expected_label
        with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".json") as tf:
            tf.write('[{"id": "bad-label", "expected_label": "maybe_phish", "input": {"message": "hi"}}]')
            tf_name = tf.name
        try:
            with self.assertRaises(ValueError):
                load_dataset(tf_name)
        finally:
            os.remove(tf_name)

        # Test missing input fields
        with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".json") as tf:
            tf.write('[{"id": "no-input", "expected_label": "benign", "input": {}}]')
            tf_name = tf.name
        try:
            with self.assertRaises(ValueError):
                load_dataset(tf_name)
        finally:
            os.remove(tf_name)

    def test_run_benchmark_computes_confusion_matrix_and_metrics(self):
        from evaluate import run_benchmark
        toy_dataset = [
            {"id": "t1", "category": "test", "expected_label": "benign", "input": {"message": "hello"}},
            {"id": "t2", "category": "test", "expected_label": "scam", "input": {"message": "URGENT: account suspended, verify your password now"}},
        ]
        res = run_benchmark(toy_dataset, threshold=30)
        self.assertEqual(res["total"], 2)
        cm = res["confusion_matrix"]
        self.assertEqual(cm["TP"], 1)
        self.assertEqual(cm["TN"], 1)
        self.assertEqual(cm["FP"], 0)
        self.assertEqual(cm["FN"], 0)
        self.assertEqual(res["metrics"]["accuracy"], 1.0)
        self.assertEqual(res["metrics"]["f1_score"], 1.0)
        self.assertEqual(res["label_distribution"], {"benign": 1, "scam": 1})

    def test_held_out_dataset_is_disjoint_and_loads(self):
        from difflib import SequenceMatcher
        from evaluate import (
            DEFAULT_DATASET_PATH,
            HELD_OUT_DATASET_PATH,
            load_dataset,
        )
        tuning = load_dataset(DEFAULT_DATASET_PATH)
        held_out = load_dataset(HELD_OUT_DATASET_PATH)
        self.assertEqual(len(held_out), 20)
        self.assertTrue({item["id"] for item in tuning}.isdisjoint(
            {item["id"] for item in held_out}
        ))
        tuning_inputs = {
            json.dumps(item["input"], sort_keys=True).casefold()
            for item in tuning
        }
        held_out_inputs = {
            json.dumps(item["input"], sort_keys=True).casefold()
            for item in held_out
        }
        self.assertTrue(tuning_inputs.isdisjoint(held_out_inputs))
        for tuning_item in tuning:
            for held_out_item in held_out:
                for field in ("message", "url"):
                    tuning_value = tuning_item["input"].get(field)
                    held_out_value = held_out_item["input"].get(field)
                    if tuning_value and held_out_value:
                        similarity = SequenceMatcher(
                            None,
                            " ".join(tuning_value.casefold().split()),
                            " ".join(held_out_value.casefold().split()),
                        ).ratio()
                        self.assertLess(
                            similarity,
                            0.7,
                            f"Near-duplicate {field}: {tuning_item['id']} / {held_out_item['id']}",
                        )
        self.assertEqual(
            {label: sum(item["expected_label"] == label for item in held_out)
             for label in ("benign", "scam")},
            {"benign": 10, "scam": 10},
        )

    def test_benchmark_rejects_invalid_threshold(self):
        from evaluate import run_benchmark
        with self.assertRaises(ValueError):
            run_benchmark([], threshold=101)

    def test_dataset_consistency_and_unique_ids(self):
        from evaluate import load_dataset, DEFAULT_DATASET_PATH
        items = load_dataset(DEFAULT_DATASET_PATH)
        self.assertGreaterEqual(len(items), 40, "Evaluation dataset must contain at least 40 cases")
        ids = [it["id"] for it in items]
        self.assertEqual(len(ids), len(set(ids)), "All dataset IDs must be strictly unique")
        for it in items:
            self.assertIn("category", it)
            self.assertIn("explanation", it)
            self.assertTrue(len(it["explanation"].strip()) > 5, f"Entry {it['id']} must have an informative explanation")

    def test_metrics_calculation_edge_cases(self):
        from evaluate import run_benchmark
        # All false positives test
        all_fp_dataset = [
            {"id": "e1", "category": "test", "expected_label": "benign", "input": {"message": "URGENT: verify your password now"}},
        ]
        res_fp = run_benchmark(all_fp_dataset, threshold=30)
        self.assertEqual(res_fp["confusion_matrix"]["FP"], 1)
        self.assertEqual(res_fp["metrics"]["precision"], 0.0)
        self.assertEqual(res_fp["metrics"]["recall"], 0.0)
        self.assertEqual(res_fp["metrics"]["f1_score"], 0.0)

        # Empty dataset edge case
        res_empty = run_benchmark([], threshold=30)
        self.assertEqual(res_empty["total"], 0)
        self.assertEqual(res_empty["metrics"]["accuracy"], 0.0)
        self.assertEqual(res_empty["metrics"]["f1_score"], 0.0)


if __name__ == "__main__":
    unittest.main()
