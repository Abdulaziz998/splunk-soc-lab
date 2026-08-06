# Incident 001 - SSH Brute Force Investigation

## Executive Summary

An investigation into SSH authentication activity identified **33,253 failed login attempts** originating from **185 unique source IP addresses**. Analysis revealed multiple external IPs repeatedly targeting common administrative accounts such as **root**, **administrator**, and **admin**. The observed activity is consistent with an automated SSH brute-force attack and aligns with the MITRE ATT&CK technique **T1110 – Brute Force**.

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

The search identified the usernames most frequently targeted during failed SSH authentication attempts. The accounts **root (1,493 attempts)**, **administrator (1,020 attempts)**, **admin (938 attempts)**, and **operator (923 attempts)** were the primary targets. The results indicate attackers focused on common administrative and privileged accounts, which is characteristic of automated SSH brute-force attacks.

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

| Rank | Username | Failed Attempts |
|------|----------|----------------:|
| 1 | root | 1,493 |
| 2 | administrator | 1,020 |
| 3 | admin | 938 |
| 4 | operator | 923 |
| 5 | mail | 753 |

---

## MITRE ATT&CK

| Technique | ID |
|-----------|----|
| Brute Force | T1110 |

---

## Findings

- Identified **33,253 failed SSH authentication events**.
- Observed **185 unique attacking source IP addresses**.
- The most active source IP (**87.194.216.51**) generated **948 failed login attempts**.
- The most frequently targeted account was **root**, with **1,493 failed authentication attempts**.
- Additional frequently targeted accounts included **administrator**, **admin**, and **operator**.
- The attack pattern is consistent with an automated SSH brute-force campaign targeting privileged accounts.
  
---

## Recommendations

- Monitor SSH authentication logs for repeated failed login attempts.
- Configure Splunk alerts to detect excessive authentication failures from a single source IP.
- Enforce strong password policies for privileged accounts.
- Enable Multi-Factor Authentication (MFA) wherever possible.
- Restrict SSH access using firewall rules or IP allowlists.
- Regularly review authentication logs for indicators of brute-force activity.

---

## Lessons Learned

This investigation demonstrated how Splunk SPL can rapidly identify authentication anomalies and assist SOC analysts in investigating brute-force attacks.

---

## Next Steps

Continue investigating authentication activity by correlating failed logins with successful logins, creating dashboards, and building automated detection rules.
