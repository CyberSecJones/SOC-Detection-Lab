#!/usr/bin/env python3
"""Detect simple authentication anomalies in a synthetic CSV dataset."""

import argparse
import csv
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

FAILURE_THRESHOLD = 5
FAILURE_WINDOW = timedelta(minutes=10)
SUCCESS_LOOKBACK = timedelta(minutes=15)


def parse_timestamp(value: str) -> datetime:
    """Parse ISO-8601 timestamps and normalize them to UTC."""
    normalized = value.strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone, e.g. Z or +00:00")
    return parsed.astimezone(timezone.utc)


def load_events(input_path: Path) -> list[dict]:
    required = {"timestamp", "username", "source_ip", "event_type", "outcome", "details"}
    with input_path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
            missing = sorted(required - set(reader.fieldnames or []))
            raise ValueError(f"CSV missing required columns: {', '.join(missing)}")
        events = []
        for line_number, row in enumerate(reader, start=2):
            try:
                row["parsed_timestamp"] = parse_timestamp(row["timestamp"])
            except (ValueError, TypeError) as exc:
                raise ValueError(f"Invalid timestamp on CSV line {line_number}: {exc}") from exc
            events.append(row)
    return sorted(events, key=lambda item: item["parsed_timestamp"])


def detect(events: list[dict]) -> list[dict]:
    alerts = []
    failures_by_identity = defaultdict(list)
    emitted_brute_force = set()

    for event in events:
        ts = event["parsed_timestamp"]
        username = event["username"].strip()
        source_ip = event["source_ip"].strip()
        event_type = event["event_type"].strip().lower()
        outcome = event["outcome"].strip().lower()
        details = event["details"].strip().lower()
        identity = (username, source_ip)

        # Keep only failures inside the rolling lookback window.
        failures_by_identity[identity] = [
            prior for prior in failures_by_identity[identity]
            if ts - prior["parsed_timestamp"] <= FAILURE_WINDOW
        ]

        if event_type == "login" and outcome == "failure":
            failures_by_identity[identity].append(event)
            count = len(failures_by_identity[identity])
            if count >= FAILURE_THRESHOLD:
                # One brute-force alert per identity per window, avoiding duplicate spam.
                window_key = (identity, failures_by_identity[identity][0]["timestamp"])
                if window_key not in emitted_brute_force:
                    emitted_brute_force.add(window_key)
                    alerts.append({
                        "timestamp": event["timestamp"],
                        "severity": "medium",
                        "alert_type": "repeated_failed_logins",
                        "username": username,
                        "source_ip": source_ip,
                        "evidence": f"{count} failed logins within {int(FAILURE_WINDOW.total_seconds()/60)} minutes",
                        "recommended_action": "Review source, account context, MFA events, and nearby activity",
                    })

        elif event_type == "login" and outcome == "success":
            recent_failures = [
                prior for prior in failures_by_identity[identity]
                if ts - prior["parsed_timestamp"] <= SUCCESS_LOOKBACK
            ]
            if len(recent_failures) >= FAILURE_THRESHOLD:
                alerts.append({
                    "timestamp": event["timestamp"],
                    "severity": "high",
                    "alert_type": "success_after_repeated_failures",
                    "username": username,
                    "source_ip": source_ip,
                    "evidence": f"Successful login after {len(recent_failures)} recent failed logins for same user and IP",
                    "recommended_action": "Validate user activity, review MFA and session details, and consider containment if unauthorized",
                })

        elif event_type == "privilege_change" and outcome == "success":
            if "admin" in details or "privileged" in details or "role assignment" in details:
                alerts.append({
                    "timestamp": event["timestamp"],
                    "severity": "high",
                    "alert_type": "privileged_role_change",
                    "username": username,
                    "source_ip": source_ip,
                    "evidence": event["details"],
                    "recommended_action": "Verify approval, actor identity, target role, and change ticket",
                })

    return alerts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="Path to input authentication CSV")
    parser.add_argument("--output", type=Path, required=True, help="Path for generated alerts CSV")
    args = parser.parse_args()

    try:
        events = load_events(args.input)
        alerts = detect(events)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    columns = [
        "timestamp", "severity", "alert_type", "username",
        "source_ip", "evidence", "recommended_action",
    ]
    with args.output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(alerts)

    print(f"Loaded {len(events)} events; generated {len(alerts)} alerts.")
    print(f"Alert report: {args.output}")
    for alert in alerts:
        print(f"[{alert['severity'].upper()}] {alert['alert_type']} | "
              f"user={alert['username']} | src={alert['source_ip']} | {alert['evidence']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
