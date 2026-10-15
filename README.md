# SOC-Detection-Lab
# SOC Detection Lab: Authentication & Privilege Monitoring

## Overview

This project demonstrates foundational Security Operations Center (SOC) workflows through Python-based detection logic, synthetic authentication logs, automated alert generation, and unit testing.

The lab identifies suspicious authentication patterns and privileged role changes, then produces structured alerts with recommended investigative actions.

**Project focus:** Security monitoring, detection engineering fundamentals, alert triage, and incident investigation.

> **Data disclaimer:** This project uses synthetic lab data. The events and IP addresses are examples for educational purposes and do not represent confirmed real-world attacks.

## Objectives

- Analyze authentication events for suspicious patterns.
- Detect repeated failed login attempts.
- Identify successful logins following repeated authentication failures.
- Flag privileged role assignments for investigation.
- Generate structured alerts for analyst review.
- Test detection logic using automated unit tests.
- Practice documenting findings and recommended response actions.

## Detection Use Cases

| Detection | Logic | Severity |
|---|---|---|
| Repeated failed logins | Five or more failed login attempts for the same user and source IP within a rolling 10-minute window | Medium |
| Successful login after repeated failures | A successful login following at least five recent failed attempts for the same user and source IP within 15 minutes | High |
| Privileged role change | A privileged administrator role assignment is observed | High |

Severity is an initial triage recommendation, not a definitive determination of malicious activity. Alerts require investigation and supporting evidence.

## Tools & Technologies

- **Python:** Detection logic and automated processing
- **CSV:** Structured event input and alert output
- **Python unittest:** Automated testing
- **Git/GitHub:** Version control and project documentation

## Project Structure

```text
SOC-Detection-Lab/
├── data/
│   └── auth_events.csv
├── src/
│   └── detect_auth_anomalies.py
├── tests/
│   └── test_detection.py
├── reports/
│   └── alerts.csv
├── .gitignore
└── README.md
```

## How It Works

1. The script loads authentication and account activity events from a CSV file.
2. It evaluates events against defined detection rules.
3. Matching events generate alerts containing a timestamp, severity, alert type, username, source IP, supporting evidence, and recommended action.
4. The alerts are written to a CSV file for review.
5. Automated tests validate key detection behaviors.

## Setup & Execution

### Requirements

- Python 3 installed
- A terminal or command prompt

No third-party Python packages are required for the current version of the lab.

### Run the Detection Script

From the project root directory:

```bash
python src/detect_auth_anomalies.py --input data/auth_events.csv --output reports/alerts.csv
```

The script writes the generated alerts to:

```text
reports/alerts.csv
```

### Run Unit Tests

```bash
python -m unittest discover -s tests -v
```

Review the test results to confirm that the detection logic behaves as expected for the included test cases.

## Example Results

The current synthetic dataset generates three alerts:

| Alert | User | Source IP | Finding |
|---|---|---|---|
| Repeated failed logins | `a.lee` | `198.51.100.23` | Five failed login attempts within 10 minutes |
| Successful login after repeated failures | `a.lee` | `198.51.100.23` | Successful authentication following repeated failures |
| Privileged role change | `m.chen` | `192.0.2.50` | Administrator role assignment requiring validation |

These results demonstrate that the detection rules are functioning against the sample data. They do not establish that an account was compromised or that a role change was unauthorized.

The listed IP addresses belong to ranges reserved for documentation and examples.

## Analyst Investigation Workflow

Alerts are starting points for investigation, not proof of malicious activity.

### Authentication Anomalies

- Review the source IP, device, location, and authentication timestamps.
- Determine whether the login pattern matches the user's normal behavior.
- Examine MFA results and related authentication events.
- Check for subsequent password changes, new authentication methods, or unusual account activity.
- Escalate or contain the account according to incident response procedures when evidence supports an active compromise.

### Privileged Role Changes

- Identify the initiating account and the account receiving the role.
- Verify the requested role, approval, and associated change ticket.
- Review the permissions granted by the role.
- Examine subsequent administrative actions and access to sensitive resources.

## Testing & Validation

The project includes unit tests for core detection behaviors.

Validation should cover:

- Repeated failures inside and outside the detection window.
- Successful authentication after repeated failures.
- Events involving different users or source IPs.
- Privileged role assignments.
- Missing, malformed, or out-of-order event data.

Passing unit tests indicates that tested behaviors work as expected; it does not establish that the detections catch every attack or avoid every false positive.

## Limitations

- The current version uses synthetic CSV data rather than live security telemetry.
- Detection rules are intentionally simple and may produce false positives.
- The script does not independently verify IP reputation, user identity, MFA configuration, or change approvals.
- The current alerts require analyst review and additional context.
- Production use would require more robust timestamp handling, input validation, logging, and detection tuning.

## Planned Improvements

- Translate the detection logic into Microsoft Sentinel KQL queries.
- Add Windows authentication event examples.
- Expand test coverage for edge cases and false positives.
- Create an incident investigation report with evidence and disposition.
- Add severity scoring and alert correlation.
- Explore Azure sign-in logs, Entra ID audit logs, and cloud identity detections.

## Skills Demonstrated

- Security event analysis
- Authentication anomaly detection
- Privileged access monitoring
- Python scripting and automation
- Unit testing and validation
- Alert triage and incident investigation
- Security documentation

## Disclaimer

This project is for educational and portfolio purposes. It is not a production-ready security monitoring system and should not be used as the sole basis for security decisions.





# SOC Detection Lab: Authentication Event Triage

A beginner-friendly blue-team portfolio project using **synthetic authentication logs**.
It demonstrates log parsing, simple detection logic, repeatable tests, and incident-triage thinking.

## Project goals

- Detect repeated failed logins from the same user and source IP.
- Flag a successful login after repeated failures from the same user and source IP.
- Flag a successful privileged-role change for analyst review.
- Produce a CSV of alerts that another analyst can review.

> All records in `data/auth_events.csv` are fictional and created for this lab. This project does not connect to or modify any real system.

## Requirements

- Python 3.10 or newer
- No third-party packages required

## Run it

From this directory:

```bash
python src/detect_auth_anomalies.py --input data/auth_events.csv --output reports/alerts.csv
```

Then open `reports/alerts.csv`.

Run tests:

```bash
python -m unittest discover -s tests -v
```

## Detection logic

1. **Repeated failures:** at least 5 failed logins for the same username and source IP within a rolling 10-minute window.
2. **Success after failures:** a successful login with at least 5 prior failures for the same username and source IP in the preceding 15 minutes.
3. **Privileged role change:** a successful `privilege_change` event whose details indicate an admin or privileged role assignment.

These are triage signals, not proof of compromise. Legitimate users, shared NAT addresses, service accounts, test automation, and time-zone or log-quality issues can create false positives. An analyst should correlate with asset criticality, MFA records, known maintenance, and other telemetry before concluding an incident.

## Dataset fields

| Field | Meaning |
|---|---|
| `timestamp` | ISO-8601 timestamp in UTC |
| `username` | Synthetic account name |
| `source_ip` | Documentation/test IP address |
| `event_type` | `login` or `privilege_change` |
| `outcome` | `failure` or `success` |
| `details` | Additional event context |
