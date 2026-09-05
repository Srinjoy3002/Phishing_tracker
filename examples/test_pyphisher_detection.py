"""
Unit test verifying detection of PyPhisher and Cloudflare Quick Tunnel signatures.
"""

import unittest
from unittest import mock
from core.lexical import analyze_lexical
from core.content_checker import analyze_content
from core.engine import scan_target


class TestPyPhisherDetection(unittest.TestCase):
    def test_lexical_trycloudflare(self):
        url = "https://occupation-exposure-piece-spam.trycloudflare.com"
        res = analyze_lexical(url)
        finding_ids = [f["id"] for f in res["findings"]]
        self.assertIn("reverse_tunnel_service", finding_ids)
        self.assertIn("tunnel_random_subdomains", finding_ids)

    def test_masked_instagram_bait(self):
        url = "https://get-unlimited-followers-for-instagram@occupation-exposure-piece-spam.trycloudflare.com"
        res = analyze_lexical(url)
        finding_ids = [f["id"] for f in res["findings"]]
        self.assertIn("reverse_tunnel_service", finding_ids)
        self.assertIn("url_redirection_trick", finding_ids)
        self.assertIn("url_masked_bait", finding_ids)

    @mock.patch("requests.get")
    def test_pyphisher_dom_signatures(self, mock_get):
        pyphisher_html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Instagram • Login</title>
            <script>
                fetch("http://ip-api.com/json").then(r => r.json()).then(data => {
                    navigator.geolocation.getCurrentPosition(pos => {});
                });
            </script>
        </head>
        <body>
            <form action="login.php" method="POST">
                <input type="text" name="username">
                <input type="password" name="password">
                <button type="submit">Log In</button>
            </form>
        </body>
        </html>
        """
        mock_resp = mock.Mock()
        mock_resp.status_code = 200
        mock_resp.text = pyphisher_html
        mock_resp.history = []
        mock_resp.headers = {}
        mock_resp.url = "https://occupation-exposure-piece-spam.trycloudflare.com"
        mock_get.return_value = mock_resp

        res = scan_target(
            "https://occupation-exposure-piece-spam.trycloudflare.com",
            fast_mode=False
        )

        finding_ids = [f["id"] for f in res["findings"]]
        self.assertIn("reverse_tunnel_service", finding_ids)
        self.assertIn("reverse_tunnel_with_login", finding_ids)
        self.assertIn("phishing_kit_endpoint", finding_ids)
        self.assertIn("victim_tracking_script", finding_ids)
        self.assertIn("geolocation_harvesting", finding_ids)
        self.assertIn("content_title_brand_mismatch", finding_ids)
        self.assertGreaterEqual(res["risk_score"], 95)
        self.assertEqual(res["classification"], "CRITICAL PHISHING")


if __name__ == "__main__":
    unittest.main()
