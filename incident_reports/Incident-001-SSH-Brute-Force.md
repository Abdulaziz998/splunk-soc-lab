# Incident 001 - SSH Brute Force Investigation

## Executive Summary

Multiple failed SSH authentication attempts were identified within the Splunk tutorial dataset. Analysis focused on identifying the attacking source IP addresses and the usernames targeted during the brute-force activity.

---

## Objective

Investigate SSH authentication failures to identify potential brute-force attacks using Splunk Enterprise and SPL.

---

## Environment

| Component | Details |
|----------|---------|
| SIEM | Splunk Enterprise |
| Dataset | Splunk Tutorial Dataset |
| Operating System | Windows 11 |
| Investigation Type | SSH Brute Force |
| Analyst | Abdulaziz Abdi |

---

## Investigation Steps

### Step 1 – Identify Attacking IP Addresses

SPL Query

```spl
index=* "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
| sort -count
```

**Evidence**

Figure 1

```
screenshots/incident-001/01-attacking-ips.png
```

**Analysis**

This query extracts IPv4 addresses from failed SSH authentication events and counts the number of attempts originating from each address.

---

### Step 2 – Identify Targeted Usernames

SPL Query

```spl
index=* "Failed password"
| rex "for (invalid user )?(?<username>\S+)"
| top username
```

**Evidence**

Figure 2

```
screenshots/incident-001/02-targeted-usernames.png
```

**Analysis**

This query extracts usernames targeted during failed SSH authentication attempts and ranks them by frequency.

---

## Indicators of Compromise (IOCs)

### Source IP Addresses

(To be completed)

### Targeted Accounts

(To be completed)

---

## MITRE ATT&CK

| Technique | ID |
|-----------|----|
| Brute Force | T1110 |

---

## Findings

(To be completed)

---

## Recommendations

- Investigate repeated failed authentication attempts.
- Monitor for successful logins following repeated failures.
- Enforce strong password policies.
- Enable Multi-Factor Authentication where applicable.
- Configure alerts for excessive authentication failures.

---

## Lessons Learned

This investigation demonstrated how Splunk SPL can rapidly identify authentication anomalies and assist SOC analysts in investigating brute-force attacks.

---

## Next Steps

Continue investigating authentication activity by correlating failed logins with successful logins, creating dashboards, and building automated detection rules.
