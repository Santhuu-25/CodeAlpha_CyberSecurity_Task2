import unittest
import json
from app import app, init_db

class TestRealtimeVerification(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True
        init_db()

    def test_case_1_example_com(self):
        url = "https://example.com"
        res = self.app.post('/api/scan-url', json={'url': url})
        data = json.loads(res.data)
        self.assertTrue(data['success'])
        # Verify returned JSON input matches scanned URL
        self.assertEqual(data['data']['input'], url)
        self.assertEqual(data['data']['risk_level'], 'Low Risk')
        print(f"[OK] Test Case 1 Passed: {url} -> Target in JSON matches input")

    def test_case_2_google_com(self):
        url = "https://www.google.com"
        res = self.app.post('/api/scan-url', json={'url': url})
        data = json.loads(res.data)
        self.assertTrue(data['success'])
        self.assertEqual(data['data']['input'], url)
        self.assertEqual(data['data']['risk_level'], 'Low Risk')
        print(f"[OK] Test Case 2 Passed: {url} -> Target in JSON matches input")

    def test_case_3_ip_login(self):
        url = "http://192.168.1.105/login.php"
        res = self.app.post('/api/scan-url', json={'url': url})
        data = json.loads(res.data)
        self.assertTrue(data['success'])
        self.assertEqual(data['data']['input'], url)
        self.assertIn(data['data']['risk_level'], ['High Risk', 'Critical', 'Suspicious'])
        print(f"[OK] Test Case 3 Passed: {url} -> Target in JSON matches input")

    def test_sqlite_history_integrity(self):
        res = self.app.get('/api/history')
        data = json.loads(res.data)
        self.assertTrue(data['success'])
        history_items = data['data']
        self.assertGreaterEqual(len(history_items), 3)

        # Most recent scan should match test_case_3
        latest = history_items[0]
        self.assertEqual(latest['input_summary'], "http://192.168.1.105/login.php")
        print("[OK] SQLite History Integrity Verified: Database loaded latest records accurately")

if __name__ == '__main__':
    unittest.main()
