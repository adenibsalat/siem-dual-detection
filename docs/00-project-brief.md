# SIEM Dual-Detection Engineering Project

## 1. Project Objective

Build and compare equivalent security detections in Splunk and Microsoft Sentinel using the same synthetic cloud-activity dataset.

The project focuses on detection engineering, event correlation, query implementation, false-positive resistance, MITRE ATT&CK mapping, investigation context and reproducible testing.

## 2. Detection Engineering Question

How can a SOC identify potentially suspicious cloud activity when an identity uses successful, apparently legitimate API operations?

The detection investigates a sequence of cloud resource enumeration, identity-role enumeration and subsequent object access. No individual action is automatically treated as proof of compromise.

## 3. SIEMs Compared

* **Splunk:** SPL-based detection and investigation.
* **Microsoft Sentinel:** KQL-based detection and investigation.

The project will document differences in query logic, schema requirements, alert output and operational workflows.

## 4. Threat Scenario

A legitimate cloud identity performs a sequence of successful actions:

1. Lists objects in a cloud-storage resource.
2. Enumerates cloud identity roles.
3. Reads an object from cloud storage.

The sequence may warrant investigation because it combines resource discovery with subsequent data access. Its significance depends on the environment, permissions, user baseline and business context.

All events in the current dataset are synthetic.

## 5. Detection Hypothesis

A successful object read is more suspicious when the same user and source IP previously performed both object listing and role enumeration in the required order within the configured time windows.

The initial correlation model requires:

* Successful events.
* The same user and source IP across the sequence.
* `ListObjects` before `ListRoles`.
* `ListRoles` before `GetObject`.
* No more than 15 minutes between consecutive stages.

The 15-minute threshold is an initial test parameter, not a universally optimal production setting.

## 6. Data Sources

The repository contains synthetic authentication and cloud-activity events.

Cloud-activity fields include timestamps, user identity, source IP, service, action, resource, resource type and result.

Authentication telemetry provides additional identity and source context. The current cloud-correlation test does not yet correlate authentication events into the primary detection.

## 7. Detection Output

The intended alert context includes:

* Detection name and severity.
* User and source IP.
* Listing, role-enumeration and object-read timestamps.
* Affected resource.
* Relevant cloud service.
* Detection rationale and investigation guidance.

Severity is provisional and must be tuned against environment-specific context.

## 8. MITRE ATT&CK Mapping

The proposed mappings for the simulated operations are:

* `ListObjects`: T1619 — Cloud Storage Object Discovery.
* `ListRoles`: T1087.004 — Cloud Account.
* `GetObject`: T1530 — Data from Cloud Storage.

T1530 is the primary mapping for the positive scenario because the sequence culminates in cloud-object access. The other techniques describe the preceding discovery stages.

These mappings must be interpreted according to the simulated event semantics and verified against the official ATT&CK definitions. They provide investigative context and do not independently establish malicious intent.


## 9. Validation Strategy

The local data validator passes for the current 14 synthetic events and two expected scenarios.

The Python reference detector produces exactly one expected alert for Charlie's `ListObjects → ListRoles → GetObject` sequence. Alice's incomplete sequence does not trigger an alert.

The regression tests also pass for missing stages, incorrect order, failed object reads, mismatched users or source IPs, intervals exceeding 15 minutes, incorrect resource types, and exact 15-minute boundaries.

These checks validate the local reference detector and data integrity. They do not establish that the Splunk SPL or Microsoft Sentinel KQL executes correctly in either platform.

Further validation must cover duplicate or repeated sequences, multiple object reads, and equivalent results from both SIEM implementations.


## 10. Cross-SIEM Equivalence

Both SIEM implementations must express the same detection hypothesis and be evaluated against equivalent source events and expected outcomes.

The Sentinel query currently uses an inline synthetic `datatable` as a test harness rather than querying a live workspace table. The Splunk SPL is a draft that assumes the relevant events have been ingested under `sourcetype="cloud_activity"` with the expected field names.

Neither implementation has been confirmed through live execution. Validation must check query syntax, event ordering, time boundaries, duplicate handling, alert fields, and agreement with the expected positive and negative scenarios.

Results must be documented honestly, distinguishing local tests from genuine platform execution evidence.


## 11. False-Positive Considerations

Legitimate administrators, cloud inventory tools, backup processes and approved security tooling may perform similar operations.

Production deployment would require environment-specific baselines, appropriate exclusions, identity and network enrichment, and review of the resources accessed.

The detection identifies activity for investigation; it does not independently prove malicious intent.

## 12. Reproducibility and Safety

* All current identities, events and IP addresses are synthetic.
* Timestamps use UTC.
* The source dataset and expected outcomes are stored in the repository.
* Local validation and correlation tests are reproducible with Python.
* SIEM-specific assumptions and field mappings must be documented.
* No real credentials or production security logs are required.

## 13. Project Success Criteria

The project is complete when:

1. The dataset passes schema and integrity checks.
2. Positive and negative sequence tests pass.
3. SPL and KQL enforce equivalent ordering and time-window requirements.
4. Both queries execute successfully in their respective SIEMs.
5. Actual SIEM results match documented expected outcomes.
6. Alert context and MITRE mappings are defensible.
7. Known limitations and false-positive considerations are documented.
8. Screenshots show genuine platform execution results.
9. Another analyst can reproduce the experiment from the repository.
10. The final comparison discusses observed engineering trade-offs rather than declaring one SIEM universally superior.
