# SIEM Dual-Detection Engineering Project

## 1. Project Objective

Build and validate equivalent security detections in Splunk and Microsoft Sentinel for the same realistic cloud identity attack scenario.

The project will compare not only SPL and KQL syntax, but also the telemetry requirements, detection logic, investigation context, false-positive handling, MITRE ATT&CK mapping, and analyst workflow required to operationalize the detection.

The goal is to demonstrate practical detection-engineering skills rather than simply demonstrate knowledge of two SIEM query languages.

## 2. Detection Engineering Question

How can a SOC detect suspicious use of a legitimate cloud identity when the authentication itself may appear valid?

The detection should use multiple contextual signals rather than relying on a single indicator such as an unusual IP address or geographic location.

## 3. SIEMs Compared

### Splunk

Splunk Enterprise / Splunk-style SPL detection workflow.

### Microsoft Sentinel

Microsoft Sentinel using Kusto Query Language (KQL) and Microsoft security telemetry concepts.

## 4. Threat Scenario

An attacker obtains valid cloud credentials and uses them to authenticate to a cloud environment.

The attacker attempts to operate using the legitimate identity while performing activity that differs from the account's expected behavior.

The detection engineering challenge is to identify the suspicious identity usage while minimizing alerts caused by legitimate users travelling, using VPNs, changing networks, or accessing resources from unusual locations.

## 5. Attacker Objective

Obtain access to cloud resources using compromised legitimate credentials while avoiding detection based on the fact that the credentials themselves are valid.

## 6. Initial Access

Compromised cloud credentials.

The project will simulate the resulting identity activity rather than obtaining or using real credentials.

## 7. Attack Chain

1. Valid cloud account authentication
2. Authentication from an unusual source/context
3. Successful authentication
4. Subsequent cloud activity using the same identity
5. Detection correlation between authentication and subsequent activity
6. Analyst investigation and response

## 8. Detection Objective

Detect potentially compromised cloud accounts by identifying suspicious authentication context combined with subsequent successful activity.

The detection should provide sufficient context for an analyst to determine whether the activity represents legitimate unusual behavior or potential account compromise.

## 9. MITRE ATT&CK Techniques

Primary technique:

- T1078.004 - Valid Accounts: Cloud Accounts

Additional techniques will only be mapped where the simulated behavior and available telemetry provide sufficient evidence to justify the mapping.

The project will avoid mapping techniques solely because they appear conceptually related.

## 10. Data Sources

### Splunk

Authentication and cloud activity events containing, where available:

- Timestamp
- Username / account
- Source IP
- Destination / application
- Authentication result
- User agent
- Geographic information
- Cloud resource or service
- Action performed
- Event type
- Session or correlation identifier

### Microsoft Sentinel

Equivalent authentication and cloud activity telemetry containing the fields required to reproduce the detection logic.

The project will document any differences between the telemetry models rather than pretending that the two platforms expose identical schemas.

## 11. Detection Requirements

### Detection Logic

The detection must identify suspicious use of a legitimate cloud identity using multiple contextual signals.

A single unusual login characteristic must not automatically result in a high-confidence compromise alert.

### Required Fields

The detection should expose enough information to investigate:

- User/account
- Source IP
- Authentication timestamp
- Authentication result
- Source location where available
- Application/resource
- User agent where available
- Subsequent activity
- Detection reason
- Risk/context indicators

### Correlation Requirements

Where telemetry allows, authentication activity should be correlated with subsequent activity performed by the same identity.

### Time-Based Requirements

The detection should define an explicit correlation window rather than relying on unlimited historical searches.

## 12. Expected Detection Output

A detection should produce an analyst-readable result containing:

- Account
- Source IP
- Authentication time
- Suspicious context
- Subsequent activity
- Detection rationale
- MITRE ATT&CK technique
- Recommended investigation steps

## 13. Validation Strategy

The detection will be tested against:

1. Benign normal authentication
2. Legitimate unusual authentication
3. Suspicious authentication followed by cloud activity
4. Multiple authentication attempts
5. Authentication without subsequent suspicious activity
6. Multiple users and source IPs
7. Repeated activity from the same source

Detection results will be compared against the expected outcome for each test case.

## 14. False Positive Considerations

Potential false positives include:

- Corporate VPN usage
- Remote workers
- Legitimate travel
- Cloud-hosted corporate infrastructure
- Security testing
- Service accounts
- New devices
- Shared accounts

The project will document how detection logic can reduce unnecessary alerts without simply suppressing unusual activity.

## 15. Investigation Workflow

The investigation should allow an analyst to move from:

Authentication event
→ identity context
→ source context
→ subsequent activity
→ affected resources
→ timeline
→ determination of suspicious/legitimate activity.

## 16. Response / Containment

Potential response actions will be documented at a conceptual level, including:

- Validate the activity with the user
- Review recent authentication history
- Review subsequent cloud activity
- Revoke active sessions where appropriate
- Reset or rotate credentials where compromise is confirmed
- Review MFA configuration
- Investigate related identities and source infrastructure

## 17. Splunk vs Sentinel Comparison Criteria

The project will compare:

- Query language
- Data normalization
- Detection logic
- Correlation capabilities
- Enrichment
- Investigation workflow
- Alert context
- False-positive handling
- MITRE ATT&CK integration
- Detection maintainability
- Analyst usability

The comparison will focus on observed engineering trade-offs rather than declaring one SIEM universally superior.

## 18. Project Success Criteria

The project is successful when:

1. The same threat scenario can be represented in both SIEMs.
2. Equivalent detection objectives can be implemented in SPL and KQL.
3. Each detection is mapped to MITRE ATT&CK using defensible evidence.
4. The detections are validated against both positive and negative test cases.
5. False-positive considerations are documented.
6. Detection output contains actionable analyst context.
7. The project documents meaningful differences between the two SIEM implementations.
8. Another detection engineer can reproduce the experiment from the repository.
9. Post 2 can demonstrate the complete detection lifecycle from attack behavior to alert to investigation.