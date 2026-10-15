
# SIEM Dual Detection: Splunk vs Microsoft Sentinel

## 1. Project Overview

This project implements and compares cloud-threat detection logic for Splunk and Microsoft Sentinel using a shared synthetic security dataset and independently defined expected outcomes.

The primary detection identifies a sequence of successful cloud API operations:

1. `ListObjects` — enumerate objects in cloud storage.
2. `ListRoles` — enumerate identity roles.
3. `GetObject` — access an object in cloud storage.

The detection correlates events by username and source IP address. Events must occur in the correct chronological order, with no more than 15 minutes between consecutive stages.

The project demonstrates detection engineering, event correlation, test-driven development, MITRE ATT&CK mapping, and cross-platform SIEM query design.

**Validation status:** Local data validation and Python correlation regression tests pass. The SPL detection has been executed in Splunk Search & Reporting, including a positive detection, an identity-isolation test, and a later-listing regression test. The KQL query has been executed in Azure Data Explorer with positive and negative tests, plus a later-listing regression test. Live Microsoft Sentinel analytics-rule deployment and validation remain outstanding.

## 2. Security and Data Safety

- All identities, events, and resources are synthetic.
- The simulated source IP addresses use documentation-reserved address ranges.
- No production logs, credentials, tokens, or passwords are included.
- Timestamps use UTC.
- Expected outcomes are maintained separately in `data/expected-results.csv`.

## 3. Repository Structure

| Path | Purpose |
|---|---|
| `data/authentication-events.json` | Synthetic authentication telemetry |
| `data/cloud-activity-events.json` | Synthetic cloud API activity |
| `data/expected-results.csv` | Expected outcomes and proposed MITRE mappings |
| `scripts/validate_data.py` | Validates event structure, timestamps, scenario references, and MITRE ID formatting |
| `tests/test_cloud_correlation.py` | Tests the local reference detector and edge cases |
| `splunk/detections/cloud-enumeration-to-object-access.spl` | Splunk SPL detection query |
| `sentinel/detections/cloud-enumeration-to-object-access.kql` | Microsoft Sentinel KQL detection query |
| `docs/00-project-brief.md` | Project scope and objectives |
| `docs/01-threat-selection.md` | Threat rationale and detection hypothesis |

## 4. Detection Logic

The detection looks for:

- A successful `ListObjects` operation.
- A subsequent successful `ListRoles` operation.
- A subsequent successful `GetObject` operation against an object resource.
- The same normalized username and source IP across the sequence.
- Correct event ordering.
- A maximum interval of 15 minutes between each consecutive stage.

The sequence may warrant investigation because it combines cloud-storage discovery, identity-role enumeration, and object access within a short period. Legitimate administrative or application activity can also produce similar patterns, so an alert is not proof of compromise.

## 5. Test Scenarios

### CLOUD-NEG-001 — Incomplete Enumeration Sequence

Alice performs successful `ListObjects` and `ListRoles` operations from the same source IP, but no subsequent `GetObject` event completes the sequence.

**Expected outcome:** No alert.

### CLOUD-POS-001 — Enumeration Followed by Object Access

Charlie performs successful `ListObjects`, `ListRoles`, and `GetObject` operations from the same source IP in the expected order.

**Expected outcome:** One correlated alert.

The positive sequence is:

`14:03 UTC ListObjects → 14:07 UTC ListRoles → 14:12 UTC GetObject`

The accessed object is `finance-archive/q3-report.csv`.

## 6. Local Validation and Test Coverage

Run the data validator:

```cmd
python scripts\validate_data.py
```

Run the correlation tests:

```cmd
python tests\test_cloud_correlation.py
```

The current local checks pass for:

- Data structure, timestamps, expected-result references, and MITRE technique ID formatting.
- The expected positive sequence and incomplete negative sequence.
- Missing role enumeration or object listing.
- Incorrect event order and failed object reads.
- Mismatched users or source IP addresses.
- Listing-to-role and role-to-read intervals exceeding 15 minutes.
- Incorrect resource types.
- Exact 15-minute stage boundaries.
- Selection of the latest qualifying listing and valid role enumeration.
- Multiple qualifying object reads producing separate alerts.
- A later listing not hiding an earlier valid listing-role sequence.

The local Python reference detector produces one expected alert for Charlie's sequence.

### Splunk Validation in Search & Reporting

The SPL detection was executed in Splunk Search & Reporting against the synthetic lab dataset.

- **Positive test:** Charlie's successful `ListObjects` → `ListRoles` → `GetObject` sequence produced the expected result.
- **Identity-isolation test:** A synthetic role-enumeration event for a different user and source IP was inserted between Charlie's listing and object-access events. Charlie's detection still appeared.
- **Later-listing regression test:** An additional successful `ListObjects` event was introduced after Charlie's role enumeration but before the object read. The detection continued to return Charlie's expected object-read event, retaining the earlier qualifying listing and role timestamps.
- **Evidence:** `assets/screenshots/02-splunk-positive-detection.png`, `assets/screenshots/07-splunk-identity-isolation-test.png`, and `assets/screenshots/08-splunk-later-listing-regression-test.png`.
- **Scope limitation:** These tests cover the documented synthetic scenarios; they do not establish detection effectiveness against all production telemetry.

### KQL Execution in Azure Data Explorer

The KQL detection query was executed in Azure Data Explorer using an inline synthetic `datatable`.

- **Positive test:** The query returned the expected alert for Charlie's `ListObjects` → `ListRoles` → `GetObject` sequence.
- **Negative test:** Alice's incomplete sequence returned no alert because it did not contain a subsequent successful object read.
- **Later-listing regression test:** A temporary synthetic listing event was added after Charlie's role enumeration and before the object read. The query still returned the expected sequence with the earlier qualifying listing timestamp.
- **Evidence:** `assets/screenshots/04-kql-positive-detection.png` and `assets/screenshots/05-kql-negative-test.png`. The later-listing regression was manually verified in ADX; a separate screenshot is not currently documented.
- **Scope limitation:** This establishes execution in Azure Data Explorer using synthetic data. The query has not been deployed or tested as a live Microsoft Sentinel analytics rule.

### Validation Boundary

The local Python detector, Splunk SPL query, and KQL query have each been tested, but they have not yet been exhaustively compared across the full edge-case suite in both SIEM platforms. The ADX query uses an inline synthetic dataset rather than a live workspace table. Production readiness would require broader platform-specific testing, ingestion-field mapping, tuning, and investigation guidance.

## 7. MITRE ATT&CK Mapping

The mappings below describe behaviour represented by the synthetic cloud events. They provide investigative context and do not independently establish malicious intent, account compromise, or data exfiltration.

| Operation | ATT&CK technique | Relevant tactic | Mapping rationale |
|---|---|---|---|
| `ListObjects` | [T1619 — Cloud Storage Object Discovery](https://attack.mitre.org/techniques/T1619/) | Discovery | Represents enumeration of objects in cloud storage. |
| `ListRoles` | [T1087.004 — Cloud Account](https://attack.mitre.org/techniques/T1087/004/) | Discovery | Represents enumeration of cloud account or identity information through role-related activity. Validate against the exact API semantics of the target cloud provider. |
| `GetObject` | [T1530 — Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/) | Collection | Represents access to data stored in a cloud object. A successful read alone does not establish malicious collection or exfiltration. |

**Primary mapping:** T1530 is associated with the final object-access stage of the positive scenario. T1619 and T1087.004 describe the preceding discovery stages.

**Detection limitation:** The correlation identifies a sequence of successful operations sharing a user and source IP within the configured time windows. It does not prove that the account is compromised or that the sequence is malicious. Validate the mappings against the actual cloud-provider API semantics and legitimate operational baselines before production use.

## 8. Detection Limitations

- The dataset is synthetic and small.
- Username and source IP correlation can be insufficient when identities, sessions, NAT, proxies, or shared infrastructure complicate attribution.
- The event sequence alone does not prove that an identity or session is compromised.
- The local Python reference detector is not a substitute for testing the SIEM implementations.
- The tested Splunk query filters for `host="siem-dual-detection-lab"` and `sourcetype="_json"`. These values reflect the current lab setup; adjust the index, host, sourcetype, and field names to match your own Splunk environment.
- The Sentinel query currently uses an inline `datatable` as a synthetic test harness rather than querying a live workspace table.
- Production deployment would require ingestion-field mapping, tuning, duplicate handling, alert investigation guidance, and broader testing.

## 9. Next Steps

1. Verify the ATT&CK mappings against the official technique descriptions.
2. Expand platform-specific edge-case coverage and compare SPL and KQL results against the same expected scenarios.
3. Deploy and validate the KQL detection as a live Microsoft Sentinel analytics rule when a suitable workspace is available; the current Azure Data Explorer tests use an inline synthetic dataset.
4. Test both implementations against equivalent positive, negative, and edge-case datasets.
5. Compare actual platform results with `data/expected-results.csv`.
6. Capture reproducible test evidence and document any platform-specific differences.
7. Review false-positive risks and potential improvements before considering production use.

## 10. Project Success Criteria

- Synthetic data passes validation.
- Positive and negative scenarios have explicit expected outcomes.
- Local correlation logic passes the documented regression tests.
- Both queries execute against synthetic test data, with broader cross-platform edge-case parity still to be established.
- Results from each tested platform match the expected outcomes for the scenarios executed.
- Test evidence, limitations, and ATT&CK mappings are documented accurately.

**Current status:** Local data validation and Python correlation tests pass. The SPL has been executed in Splunk with the expected positive result. The KQL query has been executed in Azure Data Explorer with positive and negative tests. Live Microsoft Sentinel deployment and validation remain outstanding.