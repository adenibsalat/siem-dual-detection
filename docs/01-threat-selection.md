# Threat Selection & Detection Specification

## 1. Selected Threat

**Detection:** Cloud Resource Enumeration Followed by Object Access

The detection focuses on a sequence of successful cloud API operations that may warrant investigation.

It does not assume that resource enumeration or object access alone proves malicious activity.

## 2. Detection Hypothesis

A successful object read may be more suspicious when the same user and source IP previously performed cloud object listing and identity-role enumeration in the required order.

The initial sequence is:

1. `ListObjects`
2. `ListRoles`
3. `GetObject`

The events must be successful, share the same user and source IP, and occur within the configured time windows.

## 3. Attack Simulation

The project uses synthetic security telemetry rather than real compromised credentials or production logs.

The current dataset includes:

* Successful authentication events.
* Cloud object listing.
* Cloud identity-role enumeration.
* Cloud object reads.
* Normal and unusual source-context examples.

The dataset represents test scenarios, not a verified real-world compromise.

## 4. Relevant Telemetry

### Identity and Source

* Username
* User ID
* Source IP
* Timestamp

### Cloud Activity

* Cloud service
* API action
* Resource
* Resource type
* Operation result
* Timestamp
* User and source IP

Authentication fields such as application, MFA result, country and device identifier are available for contextual analysis, but are not currently part of the primary cloud-sequence correlation.

## 5. Correlation Model

The primary detection correlates three event types:

`ListObjects → ListRoles → GetObject`

Requirements:

* Every operation succeeds.
* All events share the same user and source IP.
* The listing precedes role enumeration.
* Role enumeration precedes the object read.
* The listing-to-role and role-to-read intervals are each no greater than 15 minutes.

The 15-minute interval is an initial hypothesis to test. It must be evaluated against legitimate operational behavior before production use.

## 6. Test Scenarios

### Scenario A — Enumeration Without Object Access

Alice lists objects and enumerates roles but does not subsequently read an object.

**Expected:** No alert from the primary three-stage correlation.

### Scenario B — Complete Correlated Sequence

Charlie lists objects, enumerates roles and then reads an object using the same user and source IP.

**Expected:** One correlated alert for the tested sequence.

### Scenario C — Missing Enumeration Stage

A user reads an object without the required preceding listing or role enumeration.

**Expected:** No alert.

### Scenario D — Incorrect Event Order

The required events occur in an order other than listing, role enumeration, then object read.

**Expected:** No alert.

### Scenario E — Failed Operation

One of the required operations fails.

**Expected:** The failed operation must not satisfy the successful-event correlation.

### Scenario F — Identity or Source Mismatch

The stages occur under different users or source IPs.

**Expected:** No correlation across those mismatched events.

### Scenario G — Outside the Time Window

One required interval exceeds 15 minutes.

**Expected:** No alert for that sequence.

These scenarios define intended behavior. They should be implemented as automated tests and verified in both SIEMs before being described as passed.

## 7. Local Validation Results

The current Python correlation test loads eight synthetic cloud-activity events and confirms that exactly one expected sequence is detected.

The detected sequence is Charlie's activity:

`14:03 ListObjects → 14:07 ListRoles → 14:12 GetObject`

The data validator confirms that the JSON datasets and expected-results CSV pass the current integrity checks.

Additional automated tests pass for missing stages, incorrect order, failed object reads, mismatched users or source IPs, intervals exceeding 15 minutes, incorrect resource types, and exact 15-minute boundaries.

These results validate the local reference detector and dataset integrity. They do not establish that the SPL or KQL executes correctly in either SIEM.


## 8. MITRE ATT&CK Mapping

The proposed mappings for the simulated operations are:

* `ListObjects`: T1619 — Cloud Storage Object Discovery.
* `ListRoles`: T1087.004 — Cloud Account.
* `GetObject`: T1530 — Data from Cloud Storage.

T1530 is the primary mapping for the positive scenario because the sequence culminates in cloud-object access. T1619 and T1087.004 describe the preceding discovery stages.

These mappings must be assessed against the official ATT&CK definitions and the precise simulated behavior. The sequence does not independently establish malicious intent, account compromise, or data exfiltration.


## 9. Splunk Implementation

File: `splunk/detections/cloud-enumeration-to-object-access.spl`

The SPL draft must:

* Parse the event timestamp consistently.
* Filter to successful cloud operations.
* Normalize action, user and source-IP values.
* Enforce the required event order.
* Apply the correlation time windows.
* Return useful investigation context.

**Validation status:** Draft only. Execute it against the source dataset in Splunk and verify positive and negative cases before claiming platform validation.

## 10. Microsoft Sentinel Implementation

File: `sentinel/detections/cloud-enumeration-to-object-access.kql`

The KQL demonstration currently uses an embedded `datatable` containing synthetic cloud events.

The query must enforce the same event order, identity and source-IP matching, success conditions and time windows as the intended detection.

**Validation status:** Demonstration query only. Validate its output in the KQL environment, then document how the logic maps to the actual Sentinel tables and fields.

## 11. Cross-SIEM Equivalence

Equivalent detections must produce equivalent outcomes from the same source events.

The comparison should cover:

* Event ordering and correlation windows.
* Schema and field mapping.
* Filtering and normalization.
* Duplicate alert behavior.
* Investigation context.
* False-positive handling.
* Query maintainability.

Syntactic similarity is not enough. Behavioral equivalence must be demonstrated with test results.

## 12. Known Limitations

* The dataset is synthetic and small.
* Unusual or correlated activity does not independently establish malicious intent.
* The current primary correlation does not incorporate authentication context.
* The 15-minute threshold is provisional.
* The local Python reference detector has passing edge-case tests, but duplicate and repeated sequences, multiple object reads, and equivalent behavior across both SIEMs require further validation.
* The SIEM query drafts have not yet been live-validated.
* Production use would require environment-specific tuning, enrichment and monitoring.

## 13. Completion Standard

The detection is ready to present as validated only when:

1. Automated tests cover positive and negative sequences.
2. Data validation and correlation tests pass.
3. SPL and KQL execute successfully in their respective platforms.
4. Both implementations produce the expected results.
5. Alert context and MITRE mappings are reviewed.
6. Limitations and assumptions are documented.
7. Genuine SIEM screenshots support the reported results.
8. Another analyst can reproduce the experiment from the repository.
