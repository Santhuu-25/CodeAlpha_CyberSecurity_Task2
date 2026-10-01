import unittest
import json
import os
from app import app, init_db

class TestPhishGuard(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True
        init_db()

    def test_01_detector_url_safe(self):
        from detector import PhishingDetector
        d = PhishingDetector()
        result = d.scan_url("https://www.google.com")
        self.assertEqual(result['risk_level'], "Low Risk")
        self.assertLess(result['risk_score'], 25)
        print("[OK] Safe URL Test Passed")

    def test_02_detector_url_suspicious(self):
        from detector import PhishingDetector
        d = PhishingDetector()
        result = d.scan_url("http://login.paypal-verification.account-update.xyz/auth?user=test@google.com")
        self.assertIn(result['risk_level'], ["High Risk", "Critical"])
        self.assertGreaterEqual(result['risk_score'], 50)
        self.assertTrue(len(result['detected_indicators']) > 0)
        print("[OK] Suspicious URL Test Passed")

    def test_03_detector_message_safe(self):
        from detector import PhishingDetector
        d = PhishingDetector()
        result = d.analyze_message("Hi John, please find the meeting notes attached for your review.")
        self.assertEqual(result['risk_level'], "Low Risk")
        print("[OK] Safe Message Test Passed")

    def test_04_detector_message_phishing(self):
        from detector import PhishingDetector
        d = PhishingDetector()
        msg = "URGENT: Your account will be suspended within 24 hours. Provide your password and 6-digit OTP code 987654 to verify your credit card."
        result = d.analyze_message(msg)
        self.assertEqual(result['risk_level'], "Critical")
        self.assertGreaterEqual(result['risk_score'], 75)
        self.assertNotIn("987654", result['input_summary'])
        self.assertIn("[REDACTED CODE]", result['input_summary'])
        print("[OK] Phishing Message Test Passed (Secret Scrubbing Verified)")

    def test_05_api_scan_url_endpoint(self):
        res = self.app.post('/api/scan-url', json={'url': 'http://192.168.1.1/login.php'})
        data = json.loads(res.data)
        self.assertTrue(data['success'])
        self.assertEqual(res.status_code, 200)
        self.assertIn('data', data)
        print("[OK] POST /api/scan-url Endpoint Passed")

    def test_06_api_analyze_message_endpoint(self):
        res = self.app.post('/api/analyze-message', json={'message': 'URGENT: Claim your $1000 prize winner gift card now!'})
        data = json.loads(res.data)
        self.assertTrue(data['success'])
        self.assertEqual(res.status_code, 200)
        print("[OK] POST /api/analyze-message Endpoint Passed")

    def test_07_api_history_and_stats(self):
        res_hist = self.app.get('/api/history')
        hist_data = json.loads(res_hist.data)
        self.assertTrue(hist_data['success'])
        self.assertGreaterEqual(hist_data['count'], 1)

        res_stats = self.app.get('/api/stats')
        stats_data = json.loads(res_stats.data)
        self.assertTrue(stats_data['success'])
        self.assertGreaterEqual(stats_data['stats']['total_scans'], 1)
        print("[OK] GET /api/history & GET /api/stats Endpoints Passed")

    def test_08_api_delete_history(self):
        res = self.app.delete('/api/history')
        data = json.loads(res.data)
        self.assertTrue(data['success'])
        
        res_hist = self.app.get('/api/history')
        hist_data = json.loads(res_hist.data)
        self.assertEqual(hist_data['count'], 0)
        print("[OK] DELETE /api/history Endpoint Passed")

if __name__ == '__main__':
    unittest.main()
