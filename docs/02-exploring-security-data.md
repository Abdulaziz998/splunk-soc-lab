# Lab 02 - Exploring Security Data

## Objective

Explore the ingested security dataset using Splunk Processing Language (SPL) to identify available log sources, hosts, authentication events, and overall event activity.

---

## Environment

| Component | Details |
|-----------|---------|
| Operating System | Windows 11 |
| SIEM | Splunk Enterprise |
| Dataset | Splunk Tutorial Dataset |
| Browser | Microsoft Edge |
| Total Events | 109,864 |

---

## Background

Before investigating security incidents, a SOC analyst must understand what data is available. This lab focuses on exploring the dataset by identifying log sources, systems generating events, authentication activity, and overall event volume.

---

# SPL Queries

## Query 1 – Top Sourcetypes

### SPL

```spl
index=*
| top sourcetype
```

**Figure 1**

*Screenshot:* `screenshots/lab-02/01-top-sourcetypes.png`

### Analysis

The query identifies the most common log types in the environment. Understanding available sourcetypes helps analysts determine what security telemetry is available for future investigations.

---

## Query 2 – Top Hosts

### SPL

```spl
index=*
| top host
```

**Figure 2**

*Screenshot:* `screenshots/lab-02/02-top-hosts.png`

### Analysis

This query identifies which systems generated the most events. Knowing the primary event sources helps establish normal activity before beginning threat investigations.

---

## Query 3 – Failed Password Events

### SPL

```spl
index=* "Failed password"
| table _time host source _raw
```

**Figure 3**

*Screenshot:* `screenshots/lab-02/03-failed-password-events.png`

### Analysis

This search filters authentication failures from Linux SSH logs. Failed password events often represent brute-force attacks, password spraying, or unauthorized login attempts.

---

## Query 4 – Event Timeline

### SPL

```spl
index=*
| timechart count
```

**Figure 4**

*Screenshot:* `screenshots/lab-02/04-event-timeline.png`

### Analysis

The event timeline visualizes log volume over time. Analysts use this visualization to identify spikes in activity that may correspond to attacks or operational issues.

---

## Lessons Learned

- Used SPL to explore indexed security data.
- Identified available log sources and systems.
- Investigated authentication failures.
- Visualized event activity over time.
- Built a foundation for future threat hunting and incident response.

---

## Next Steps

The next lab investigates suspicious SSH authentication activity by identifying attacking IP addresses, targeted usernames, and mapping findings to the MITRE ATT&CK framework.
