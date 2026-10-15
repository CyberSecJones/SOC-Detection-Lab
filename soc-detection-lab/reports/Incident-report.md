# Incident Report: Successful Login Following Repeated Failures

## 1. Incident Summary

**Incident ID:** SOC-001  
**Alert Type:** Successful Login After Repeated Failed Attempts  
**Initial Severity:** High — requires triage  
**Status:** Open — further investigation required  
**Data Source:** Synthetic authentication events  
**Affected User:** `a.lee`  
**Source IP:** `198.51.100.23`

### Summary

The detection script identified repeated failed authentication attempts for user `a.lee`, followed by a successful login from the same source IP address.

This pattern may indicate password guessing followed by unauthorized access. However, the available evidence does not independently confirm account compromise.

## 2. Evidence Observed

- Five failed login attempts were detected within a 10-minute window.
- A subsequent successful login matched the same username and source IP.
- The detection logic flagged the sequence for investigation.
- The events were generated from synthetic test data.

**Evidence limitation:** The current dataset does not establish whether the login was authorized, whether MFA was used, or what actions occurred after authentication.

## 3. Initial Risk Assessment

This activity warrants investigation because a successful login following repeated failures can indicate that an attacker obtained valid credentials.

Potential explanations include:

- A legitimate user repeatedly entering an incorrect password.
- An automated password-guessing attempt.
- Compromised credentials being used successfully.

The alert is a suspicious pattern, not proof of malicious activity.

## 4. Investigation Plan

### Authentication Review

- Review timestamps and the sequence of failed and successful logins.
- Examine available sign-in logs for device, location, authentication method, and MFA results.
- Compare the activity with the user's typical login behavior.
- Determine whether other accounts were targeted by the same source.

### Post-Authentication Review

- Check for password resets or changes to authentication methods.
- Review privilege changes and unusual access to sensitive resources.
- Look for suspicious downloads, account changes, or other anomalous activity.
- Correlate relevant events across available identity and endpoint logs.

## 5. Recommended Response

1. Validate the alert against the underlying authentication records.
2. Contact the account owner through an approved, trusted channel if verification is needed.
3. Escalate to the incident response team if evidence supports unauthorized access.
4. If compromise is suspected or confirmed, follow organizational procedures for session revocation, credential resets, and account containment.
5. Preserve relevant logs and document investigative actions.

Any containment action should follow incident response procedures and account for the risk of delaying action during an active compromise.

## 6. Current Disposition

**Disposition:** Suspicious activity — investigation required.

The synthetic evidence supports triggering an alert because a successful login followed repeated failures. Additional identity, device, and post-login evidence would be required to determine whether the activity was malicious.

No real account compromise has been established.

## 7. Lessons Learned

- Authentication events become more informative when analyzed as a sequence rather than individually.
- Successful authentication does not automatically mean a login is legitimate.
- Detection alerts require validation and context before a final incident determination.
- Clear documentation should distinguish observed evidence from assumptions and recommended next steps.

## 8. Lab Disclaimer

This report documents an educational exercise using synthetic data. The source IP belongs to a range reserved for documentation and examples. No real user, system, or security incident is represented.

