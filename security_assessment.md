 # SSH Authentication Analyzer — Student Security Assessment

## 1. Purpose

Evaluate whether a Python log analyzer identifies selected suspicious
SSH authentication patterns in synthetic logs.

This is a limited student software assessment, not a production
security assessment, full RMF implementation, or compliance certification.

## 2. System Boundary

Included:
- Local Python analyzer.
- Synthetic SSH authentication logs.
- Automated tests and evaluation script.
- Generated text and JSON reports.

Excluded:
- A deployed SSH server.
- Production accounts, networks, and authentication policies.
- Live monitoring, automated blocking, and incident response actions.

## 3. Data Flow

Synthetic log file
→ Parse authentication events
→ Validate IP addresses and timestamps
→ Apply detection rules
→ Generate text or JSON report

The analyzer runs locally and does not send logs to an external service.

## 4. Assessment Objectives

Verify that the analyzer:
- Extracts supported IPv4 and IPv6 source addresses.
- Handles missing or invalid source addresses.
- Parses supported timestamps.
- Detects repeated failures within an inclusive time window.
- Correlates successes with preceding failures for the same IP and user.
- Avoids correlation alerts for different users or source IPs.
- Produces readable text and valid JSON reports.
- Handles selected invalid command-line inputs and missing files.

## 5. Assessment Procedure

1. Run:
   python3 -m unittest -v

2. Record the test count, failures, errors, and Python version.

3. Run:
   python3 evaluate.py

4. Compare expected and actual alert types for each scenario.

5. Preserve the evaluation report and terminal output as evidence.

6. Review sample reports for clear evidence and limitations.

## 6. Recorded Results

Based on the reported local runs:
- 25 automated tests passed.
- Six of six synthetic scenarios matched expectations.
- Four expected rule detections.
- Eight correct rule non-detections.
- Zero unexpected or missed rule detections in those scenarios.

These are development results from a small synthetic dataset.
They do not demonstrate performance on independent or real-world data.

## 7. Findings and Remaining Work

### Finding 1: Limited evaluation coverage
The evaluation uses six known development scenarios.

Recommendation:
Create a separate, independently labeled dataset with more varied
normal and suspicious activity.

Status: Open.

### Finding 2: Timestamp assumptions
The supported syslog format omits the year and timezone.
The analyzer uses a supplied year and does not handle year rollover.

Recommendation:
Add explicit timezone and year-rollover handling, or support a
timestamp format that includes both.

Status: Open.

### Finding 3: Limited authentication coverage
The analyzer supports selected SSH password messages.

Recommendation:
Add and test public-key authentication and other relevant SSH events.

Status: Open.

### Finding 4: No operational security controls assessed
No live SSH configuration, account policy, log collection pipeline,
or response process was tested.

Recommendation:
Assess those components separately in an authorized isolated lab.

Status: Outside this assessment's scope.

## 8. Evidence Files

- log_analyzer.py
- test_log_analyzer.py
- evaluate.py
- sample_auth.log
- evaluation_report.txt
- incident_report.md
- Generated security reports

## 9. Assessment Conclusion

The recorded tests support the analyzer's expected behavior for the
specific cases exercised.

The project demonstrates log analysis, detection logic, software
testing, evidence documentation, and communication of limitations.

It does not establish organizational compliance or prove that an
operational system is secure.