
# SIEM Dual Detection: Splunk vs Microsoft Sentinel

## 1. Project Overview

This project implements and compares cloud-threat detection logic for Splunk and Microsoft Sentinel using a shared synthetic security dataset and independently defined expected outcomes.

The primary detection identifies a sequence of successful cloud API operations:

1. `ListObjects` — enumerate objects in cloud storage.
2. `ListRoles` — enumerate identity roles.
3. `GetObject` — access an object in cloud storage.

The detection correlates events by username and source IP address. Events must occur in the correct chronological order, with no more than 15 minutes between consecutive stages.

The project demonstrates detection engineering, event correlation, test-driven development, MITRE ATT&CK mapping, and cross-platform SIEM query design.

**Validation status:** The local Python reference detector, data validator, and documented edge-case tests pass. The Splunk SPL and Microsoft Sentinel KQL still require execution and validation in their respective platforms.

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

- Data structure, timestamps, and expected-result references.
- The expected positive sequence and incomplete negative sequence.
- Missing role enumeration or object listing.
- Incorrect event order.
- Failed object reads.
- Mismatched users or source IPs.
- Intervals exceeding 15 minutes.
- Incorrect resource types.
- Exact 15-minute stage boundaries.

The local reference detector produces one expected alert for Charlie's sequence.

**Validation boundary:** These results establish the behaviour of the local Python reference detector and the integrity of the synthetic data. They do not establish that either SIEM query executes successfully or produces equivalent results in a live platform.

## 7. MITRE ATT&CK Mapping

The proposed mappings for the individual operations are:

| Operation | Proposed technique | Rationale |
|---|---|---|
| `ListObjects` | [T1619 — Cloud Storage Object Discovery](https://attack.mitre.org/techniques/T1619/) | Discovery of objects in cloud storage |
| `ListRoles` | [T1087.004 — Cloud Account](https://attack.mitre.org/techniques/T1087/004/) | Enumeration of cloud accounts or identity information |
| `GetObject` | [T1530 — Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/) | Access to data stored in cloud objects |

`T1530` is the primary mapping for the positive scenario because the detection culminates in cloud-object access. The other techniques describe the preceding discovery stages.

These mappings must be interpreted in the context of the simulated event semantics and verified against the official ATT&CK descriptions. A mapping is investigative context, not proof of malicious intent.

## 8. Detection Limitations

- The dataset is synthetic and small.
- Username and source IP correlation can be insufficient when identities, sessions, NAT, proxies, or shared infrastructure complicate attribution.
- The event sequence alone does not prove that an identity or session is compromised.
- The local Python reference detector is not a substitute for testing the SIEM implementations.
- The Splunk query assumes the events are available under `sourcetype="cloud_activity"` with the expected field names.
- The Sentinel query currently uses an inline `datatable` as a synthetic test harness rather than querying a live workspace table.
- Production deployment would require ingestion-field mapping, tuning, duplicate handling, alert investigation guidance, and broader testing.

## 9. Next Steps

1. Verify the ATT&CK mappings against the official technique descriptions.
2. Validate the SPL syntax, time-window behaviour, and correlation results in Splunk.
3. Execute the KQL harness in Microsoft Sentinel and verify its output.
4. Test both implementations against equivalent positive, negative, and edge-case datasets.
5. Compare actual platform results with `data/expected-results.csv`.
6. Capture reproducible test evidence and document any platform-specific differences.
7. Review false-positive risks and potential improvements before considering production use.

## 10. Project Success Criteria

- Synthetic data passes validation.
- Positive and negative scenarios have explicit expected outcomes.
- Local correlation logic passes the documented regression tests.
- Both SIEM queries execute correctly against equivalent events.
- Actual SIEM results match the expected outcomes.
- Test evidence, limitations, and ATT&CK mappings are documented accurately.

**Current status:** Local data validation and Python correlation tests pass. Live Splunk and Sentinel validation remains outstanding.