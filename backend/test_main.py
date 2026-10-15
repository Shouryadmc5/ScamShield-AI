import unittest
import sys
import os

# Add backend directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from main import evaluate_rules, safe_parse_url, app, AnalyzeRequest, health
from pydantic import ValidationError


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


if __name__ == "__main__":
    unittest.main()
