# SSH Authentication Investigation — Synthetic Lab

## Executive Summary

A controlled scenario contained three failed SSH password logins,
followed by a successful login for the same username and source IP.

The analyzer generated two alerts:
- Repeated authentication failures within five minutes.
- Successful authentication following repeated failures.

This sequence warrants investigation but does not establish that an
account was compromised.

## Scope

- Environment: Synthetic SSH log dataset.
- Source IP: 192.0.2.10 — documentation-only address.
- Account: student — fictional lab account.
- Assumed year: 2026.
- Detection threshold: Three failures.
- Detection window: 300 seconds.
- No production systems or actual users were investigated.

## Timeline

| Time | Event |
|---|---|
| 10:00:00 | Failed password authentication |
| 10:01:00 | Failed password authentication |
| 10:02:00 | Failed password authentication |
| 10:03:00 | Successful password authentication |

## Analysis

Three failures occurred within two minutes, meeting the repeated-failure
threshold. A success followed within three minutes of the first failure,
using the same source IP and username.

Possible explanations include a legitimate user correcting a password,
automated credential guessing, or unauthorized account access.

The available authentication records cannot distinguish these
explanations without additional evidence.

## Recommended Investigation

1. Confirm whether the account owner recognizes the login.
2. Review surrounding authentication and session activity.
3. Check whether the source address is expected.
4. Review account privileges and authentication protections.
5. Escalate according to organizational procedures if evidence supports
   unauthorized access.

## Validation Results

- 25 automated tests passed, based on the recorded local test run.
- Six synthetic development scenarios matched expected alert types.
- Four correct rule detections and eight correct rule non-detections.
- Zero unexpected detections and zero missed detections in this dataset.

## Limitations

The dataset is small, synthetic, and used during development.
Results do not establish real-world detection accuracy.

The tool does not analyze session commands, verify user identity,
or prove compromise. Source IPs may be shared.

## Outcome

The analyzer identified the intended suspicious sequence.
No real incident was confirmed, and no production remediation occurred.