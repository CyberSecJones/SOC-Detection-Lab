import csv
import tempfile
import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from detect_auth_anomalies import detect, load_events


class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.csv_path = Path(self.temp_dir.name) / "events.csv"

    def write_events(self, rows):
        with self.csv_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=["timestamp", "username", "source_ip", "event_type", "outcome", "details"],
            )
            writer.writeheader()
            writer.writerows(rows)
        return load_events(self.csv_path)

    def test_detects_repeated_failures_and_success_after_failures(self):
        rows = []
        for minute in range(5):
            rows.append({
                "timestamp": f"2026-09-12T09:{14+minute:02d}:00Z",
                "username": "analyst1",
                "source_ip": "198.51.100.7",
                "event_type": "login",
                "outcome": "failure",
                "details": "invalid password",
            })
        rows.append({
            "timestamp": "2026-09-12T09:19:00Z",
            "username": "analyst1",
            "source_ip": "198.51.100.7",
            "event_type": "login",
            "outcome": "success",
            "details": "login succeeded",
        })
        alerts = detect(self.write_events(rows))
        types = [alert["alert_type"] for alert in alerts]
        self.assertIn("repeated_failed_logins", types)
        self.assertIn("success_after_repeated_failures", types)

    def test_detects_privileged_role_change(self):
        rows = [{
            "timestamp": "2026-09-12T11:02:00Z",
            "username": "operator1",
            "source_ip": "192.0.2.5",
            "event_type": "privilege_change",
            "outcome": "success",
            "details": "assigned_admin_role",
        }]
        alerts = detect(self.write_events(rows))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["alert_type"], "privileged_role_change")

    def test_does_not_alert_on_fewer_than_five_failures(self):
        rows = [{
            "timestamp": f"2026-09-12T09:{14+i:02d}:00Z",
            "username": "analyst1",
            "source_ip": "198.51.100.7",
            "event_type": "login",
            "outcome": "failure",
            "details": "invalid password",
        } for i in range(4)]
        self.assertEqual(detect(self.write_events(rows)), [])


if __name__ == "__main__":
    unittest.main()
