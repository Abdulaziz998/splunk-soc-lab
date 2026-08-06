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

The search identified **185 unique source IP addresses** responsible for failed SSH authentication attempts. The highest-volume source IP, **87.194.216.51**, generated **948 failed login attempts**, followed by **211.166.11.101** with **743 attempts**. The large number of repeated authentication failures originating from multiple external IP addresses is consistent with SSH brute-force activity.

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

| Rank | Source IP | Failed Attempts |
|------|-----------|----------------:|
| 1 | 87.194.216.51 | 948 |
| 2 | 211.166.11.101 | 743 |
| 3 | 128.241.220.82 | 622 |
| 4 | 109.169.32.135 | 515 |
| 5 | 194.215.205.19 | 514 |

### Targeted Accounts

*(To be completed after analyzing the username results.)*

---

## MITRE ATT&CK

| Technique | ID |
|-----------|----|
| Brute Force | T1110 |

---

## Findings

- 33,253 failed SSH authentication events were identified.
- 185 unique source IP addresses participated in the activity.
- The highest-volume attacker generated 948 failed login attempts.
- Multiple external IP addresses targeted the SSH service, indicating distributed brute-force behavior.

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
