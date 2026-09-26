# Common Detection Dataset

## Purpose

This directory contains the source-of-truth telemetry used to validate both the Splunk and Microsoft Sentinel implementations.

Both SIEM implementations must be evaluated against the same underlying attack scenarios and expected outcomes.

The dataset is synthetic and contains no real credentials, secrets, or personally identifiable information.

---

# Event Model

The dataset contains two primary event types:

1. Authentication events
2. Cloud activity events

Contextual enrichment may be represented separately or incorporated into the detection logic.

---

# Authentication Event Schema

Each authentication event contains the following fields:

* `timestamp`
* `event_type`
* `user`
* `user_id`
* `source_ip`
* `source_country`
* `source_asn`
* `application`
* `authentication_method`
* `mfa_result`
* `result`
* `user_agent`
* `device_id`

Example:

```json
{
  "timestamp": "2026-09-26T09:01:14Z",
  "event_type": "authentication",
  "user": "alice",
  "user_id": "USR-001",
  "source_ip": "203.0.113.10",
  "source_country": "IE",
  "source_asn": "AS64500",
  "application": "CloudPortal",
  "authentication_method": "password",
  "mfa_result": "success",
  "result": "success",
  "user_agent": "Mozilla/5.0",
  "device_id": "DEV-001"
}
```

---

# Cloud Activity Event Schema

Each cloud activity event contains the following fields:

* `timestamp`
* `event_type`
* `user`
* `user_id`
* `source_ip`
* `cloud_service`
* `action`
* `resource`
* `resource_type`
* `result`

Example:

```json
{
  "timestamp": "2026-09-26T09:03:27Z",
  "event_type": "cloud_activity",
  "user": "alice",
  "user_id": "USR-001",
  "source_ip": "203.0.113.10",
  "cloud_service": "ObjectStorage",
  "action": "ListObjects",
  "resource": "finance-reports",
  "resource_type": "storage_container",
  "result": "success"
}
```

---

# Identity Context

The following expected-behavior information will be used for validation and enrichment:

* Known source networks
* Known countries
* Known devices
* Expected applications
* Expected cloud services
* Expected activity patterns

This context is intentionally separated from the raw attack telemetry.

The detection must not simply depend on a field explicitly labelled as malicious.

---

# Test Cases

## TC01 - Normal Authentication

A known user authenticates successfully from a known source and performs normal cloud activity.

Expected result:

`NO_ALERT`

---

## TC02 - Legitimate Unusual Authentication

A known user authenticates from an unusual location or network representing legitimate travel or remote access.

The user performs expected activity.

Expected result:

`NO_PRIMARY_ALERT`

---

## TC03 - Suspicious Authentication and Cloud Activity

A known user authenticates successfully from a suspicious or unrecognized source.

The same identity subsequently performs cloud activity from the same source.

Expected result:

`ALERT`

This is the primary positive test case.

---

## TC04 - Suspicious Authentication Without Follow-Up

A suspicious authentication occurs, but no subsequent relevant cloud activity is observed.

Expected result:

`NO_PRIMARY_ALERT`

This tests whether the detection requires the second stage of the behavior.

---

## TC05 - VPN or Proxy Activity

A user authenticates through a known corporate VPN or proxy.

The apparent source context may look unusual, but the infrastructure is known and the subsequent activity is expected.

Expected result:

`NO_ALERT`

---

## TC06 - Repeated Suspicious Activity

A user authenticates from an unrecognized source and performs multiple cloud actions within the correlation window.

Expected result:

`CORRELATED_ALERT`

The implementation should avoid treating every individual cloud action as a completely independent compromise.

---

# Detection Correlation

The primary detection should correlate events using the following signals:

* Same user identity
* Related source IP
* Successful authentication
* Subsequent cloud activity
* Defined time window

The exact correlation window will be validated experimentally.

---

# Dataset Design Principles

The dataset must NOT contain an explicit field such as:

`malicious=true`

The dataset must NOT contain an explicit field such as:

`attack_type=compromised_account`

The detection must infer suspicious behavior from telemetry and contextual information.

The dataset must contain both positive and negative examples.

Positive examples must not be trivially distinguishable by a single hard-coded value.

The same user may appear in both benign and suspicious scenarios.

The same cloud services may appear in both benign and suspicious scenarios.

The same general activity types may appear in both benign and suspicious scenarios.

This prevents the detection from simply becoming a lookup for a known malicious value.

---

# Synthetic Data Safety

All IP addresses used in the dataset should come from documentation-reserved ranges.

Recommended ranges:

* `192.0.2.0/24`
* `198.51.100.0/24`
* `203.0.113.0/24`

All identities and resources should be synthetic.

Example synthetic identities:

* `alice`
* `bob`
* `charlie`

No real credentials, access tokens, API keys, passwords, email addresses, or personal information should be included.

---

# Reproducibility

The dataset should be deterministic.

Another analyst should be able to load the data into either SIEM and reproduce the documented detection results.

All timestamps, identities, IP addresses, actions, and expected outcomes must therefore be documented.

The source-of-truth dataset should remain unchanged when creating SIEM-specific copies.

---

# SIEM Data Copies

The source-of-truth data will be used to create platform-specific copies for:

* Splunk
* Microsoft Sentinel

Any transformation required by a specific SIEM must be documented.

The underlying security scenario must remain equivalent across both platforms.

---

# Validation Principle

A detection is not considered successful simply because it returns an alert.

The detection must:

1. Detect the intended suspicious scenario.
2. Avoid triggering on the documented benign scenarios.
3. Produce useful investigation context.
4. Correlate the relevant events.
5. Have a defensible MITRE ATT&CK mapping.
6. Be reproducible by another analyst.
7. Have documented limitations and false-positive considerations.
