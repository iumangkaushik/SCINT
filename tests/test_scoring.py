"""
Tests for SCINT's risk scoring and false-positive handling.

Run from the project root:   python -m unittest -v
No network access or API keys needed - live API calls are mocked.
"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import live_intel  # noqa: E402
import scint       # noqa: E402

API_DOWN = {"ok": False, "error": "mocked: not called"}


def vt_result(malicious):
    return {"ok": True, "malicious": malicious, "suspicious": 0,
            "harmless": 60, "undetected": 10, "reputation": 0, "country": "NL"}


class PhoneScoringTests(unittest.TestCase):
    """True positives / true negatives on the bundled dummy dataset."""

    def test_known_fraud_number_scores_high(self):
        score, factors = scint.score_phone_quiet("9898329822")
        self.assertGreaterEqual(score, 75, factors)
        self.assertIn("Flagged Aadhaar", factors)

    def test_clean_number_scores_low(self):
        score, factors = scint.score_phone_quiet("9009897600")
        self.assertLess(score, 40, factors)

    def test_unknown_number_scores_zero(self):
        score, factors = scint.score_phone_quiet("9000000000")
        self.assertEqual((score, factors), (0, []))


class SharedIpFalsePositiveTests(unittest.TestCase):
    """Sharing an IP with a fraudster only means something if few people share it."""

    def _telecom(self, ip, flagged, clean):
        rows = [{"phone": f"8{i:09d}", "linked_ips": ip, "flagged": "True",
                 "calls_to_scam_numbers": "0", "voip_usage": "No"} for i in range(flagged)]
        rows += [{"phone": f"7{i:09d}", "linked_ips": ip, "flagged": "False",
                  "calls_to_scam_numbers": "0", "voip_usage": "No"} for i in range(clean)]
        return rows

    def _score_with(self, telecom_rows, phone):
        tables = {"telecom_db.csv": telecom_rows}
        with mock.patch.object(scint, "load_csv", lambda name: tables.get(name, [])):
            return scint.score_phone_quiet(phone)

    def test_small_ring_on_one_ip_is_flagged(self):
        # 2 flagged + 1 unflagged number on a VPS IP: real ring signal
        rows = self._telecom("45.133.1.98", flagged=2, clean=1)
        score, factors = self._score_with(rows, "7000000000")
        self.assertEqual(score, 10)
        self.assertIn("IP shared with 2 flagged number(s)", factors)

    def test_carrier_gateway_ip_is_not_evidence(self):
        # 1 flagged + 30 ordinary subscribers behind one mobile-carrier IP
        rows = self._telecom("49.36.12.7", flagged=1, clean=30)
        score, factors = self._score_with(rows, "7000000000")
        self.assertEqual(score, 0, "neighbours on a carrier NAT IP must not be scored")
        self.assertTrue(any("shared gateway" in f for f in factors), factors)

    def test_cgnat_range_is_never_evidence(self):
        # Even a small group is ignored inside RFC 6598 100.64.0.0/10
        rows = self._telecom("100.64.20.5", flagged=2, clean=1)
        score, _ = self._score_with(rows, "7000000000")
        self.assertEqual(score, 0)


class LiveIpScoringTests(unittest.TestCase):
    """Live IP scoring with every external API mocked out."""

    def _score(self, ip, vt):
        with mock.patch.object(live_intel, "geolocate_ip", return_value=API_DOWN), \
             mock.patch.object(live_intel, "check_abuseipdb", return_value=API_DOWN), \
             mock.patch.object(live_intel, "check_virustotal_ip", return_value=vt):
            return live_intel.live_ip_score(ip)

    def test_multi_engine_virustotal_hit_is_scored(self):
        _, score, factors = self._score("45.133.1.98", vt_result(6))
        self.assertEqual(score, 35)
        self.assertEqual(factors, ["VirusTotal: 6 engines flag malicious"])

    def test_single_engine_virustotal_hit_is_not_scored(self):
        results, score, factors = self._score("8.8.8.8", vt_result(1))
        self.assertEqual(score, 0)
        self.assertEqual(factors, [])
        self.assertIn("false positive", results["notes"][0])

    def test_private_and_cgnat_ips_never_reach_the_apis(self):
        with mock.patch.object(live_intel.requests, "get") as get:
            for ip in ("192.168.1.10", "10.0.0.5", "127.0.0.1", "100.64.3.4"):
                results, score, _ = live_intel.live_ip_score(ip)
                self.assertEqual(score, 0)
                self.assertFalse(results["geo"]["ok"])
            get.assert_not_called()

    def test_malformed_input_is_rejected_before_url_building(self):
        for bad in ("8.8.8.8/../../users/me", "999.1.1.1", "evil.com", ""):
            with self.assertRaises(ValueError):
                live_intel.validate_public_ip(bad)


if __name__ == "__main__":
    unittest.main(verbosity=2)
