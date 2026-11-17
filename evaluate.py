import tempfile
from pathlib import Path

from log_analyzer import collect_results


def make_entry(time_text, outcome="Failed", username="student"):
    return (
        f"Nov 17 {time_text} lab sshd[100]: "
        f"{outcome} password for {username} "
        "from 192.0.2.10 port 50000 ssh2\n"
    )


failures = (
    make_entry("10:00:00")
    + make_entry("10:01:00")
    + make_entry("10:02:00")
)

scenarios = [
    (
        "Normal successful login",
        make_entry("10:00:00", outcome="Accepted"),
        set(),
    ),
    (
        "Two failures below threshold",
        make_entry("10:00:00") + make_entry("10:01:00"),
        set(),
    ),
    (
        "Failures spread beyond five minutes",
        make_entry("10:00:00")
        + make_entry("10:10:00")
        + make_entry("10:20:00"),
        set(),
    ),
    (
        "Three failures within five minutes",
        failures,
        {"repeated_failures"},
    ),
    (
        "Success after failures for same user",
        failures + make_entry("10:03:00", outcome="Accepted"),
        {"repeated_failures", "success_after_failures"},
    ),
    (
        "Success for a different user",
        failures
        + make_entry(
            "10:03:00",
            outcome="Accepted",
            username="other_user",
        ),
        {"repeated_failures"},
    ),
]

rule_types = {"repeated_failures", "success_after_failures"}

true_positives = 0
false_positives = 0
false_negatives = 0
true_negatives = 0
passed = 0
report = []

with tempfile.TemporaryDirectory() as folder:
    for index, (name, sample, expected) in enumerate(scenarios, start=1):
        log_path = Path(folder) / f"scenario_{index}.log"
        log_path.write_text(sample, encoding="utf-8")

        results = collect_results(
            log_path,
            threshold=3,
            window_seconds=300,
            year=2026,
        )

        actual = {alert["type"] for alert in results["alerts"]}

        true_positives += len(expected & actual)
        false_positives += len(actual - expected)
        false_negatives += len(expected - actual)
        true_negatives += len(rule_types - (expected | actual))

        matches = actual == expected
        passed += int(matches)

        report.extend([
            f"{'PASS' if matches else 'FAIL'}: {name}",
            f"  Expected: {', '.join(sorted(expected)) or 'none'}",
            f"  Actual: {', '.join(sorted(actual)) or 'none'}",
        ])


def percentage(numerator, denominator):
    if denominator == 0:
        return "N/A"

    return f"{100 * numerator / denominator:.1f}%"


report.extend([
    "",
    "EVALUATION SUMMARY",
    "==================",
    f"Scenarios matching expectations: {passed}/{len(scenarios)}",
    f"Correct rule detections (TP): {true_positives}",
    f"Unexpected rule detections (FP): {false_positives}",
    f"Missed rule detections (FN): {false_negatives}",
    f"Correct rule non-detections (TN): {true_negatives}",
    "Precision: "
    + percentage(true_positives, true_positives + false_positives),
    "Recall: "
    + percentage(true_positives, true_positives + false_negatives),
    "",
    "Scope: Six synthetic scenarios and two rule types.",
    "Each scenario/rule pair is one evaluation decision.",
    "Repeated alerts of the same type are not evaluated separately.",
    "These examples are known development cases, not an independent test set.",
    "Results do not establish real-world detection accuracy.",
])

report_text = "\n".join(report)
Path("evaluation_report.txt").write_text(
    report_text + "\n",
    encoding="utf-8",
)

print(report_text)
print("\nSaved to evaluation_report.txt")