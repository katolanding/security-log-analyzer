import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from analyzer import analyze


class AnalyzeTests(unittest.TestCase):
    def test_counts_and_threshold(self):
        lines = [
            "Nov 12 11:00:00 host sshd[10]: Failed password for invalid user admin from 192.0.2.10 port 444 ssh2",
            "Nov 12 11:00:01 host sshd[11]: Failed password for root from 192.0.2.10 port 445 ssh2",
            "Nov 12 11:00:02 host sshd[12]: Accepted publickey for karla from 198.51.100.20 port 555 ssh2",
        ]
        r = analyze(lines, threshold=2)
        self.assertEqual(r["total_failed"], 2)
        self.assertEqual(r["total_successful"], 1)
        self.assertEqual(r["suspicious_ips"], ["192.0.2.10"])
        self.assertEqual(r["targeted_users"]["admin"], 1)

    def test_ignore_unrelated_lines(self):
        self.assertEqual(analyze(["hello world"])["parsed_events"], 0)

    def test_reject_invalid_threshold(self):
        with self.assertRaises(ValueError):
            analyze([], threshold=0)


if __name__ == "__main__":
    unittest.main()
