# Lab 01 - Splunk Enterprise Installation & Data Ingestion

## Objective

Install Splunk Enterprise, ingest sample security logs, and verify that data is searchable using Splunk Processing Language (SPL).

---

## Environment

| Component | Details |
|----------|---------|
| Operating System | Windows 11 |
| SIEM | Splunk Enterprise 10.x |
| Dataset | Splunk Tutorial Dataset |
| Browser | Microsoft Edge |
| Data Volume | ~109,000 events |

---

## Background

A Security Information and Event Management (SIEM) platform is only valuable when it can successfully ingest, index, and search log data.

This lab establishes the foundation for every future investigation by installing Splunk Enterprise and confirming that event data is searchable.

---

## Tasks Completed

- Installed Splunk Enterprise
- Created administrator account
- Uploaded tutorial dataset
- Indexed log events
- Verified successful ingestion
- Executed first SPL searches

---

## Verification Queries

### Total Events

```spl
index=*
```

### Top Sourcetypes

```spl
index=*
| top sourcetype
```

### Top Hosts

```spl
index=*
| top host
```

---

## Results

Successful data ingestion was confirmed.

Primary sourcetypes included:

- secure-2
- access_combined_wcookie
- vendor_sales

Over 109,000 events were successfully indexed.

---

## Lessons Learned

- Installed Splunk Enterprise locally
- Learned the Search & Reporting interface
- Successfully ingested security logs
- Executed first SPL searches

---

## Next Lab

Lab 02 - SPL Search Fundamentals
