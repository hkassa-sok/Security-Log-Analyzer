import argparse
import ipaddress
import json
import re
from datetime import datetime
from pathlib import Path


# Supported format:
# Nov 17 10:00:00 host sshd[123]: Failed password ...
SSH_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r"\s+\S+\s+sshd(?:\[\d+\])?:\s+"
    r"(?P<outcome>Failed|Accepted) password for "
    r"(?:invalid user )?(?P<username>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)\b"
)


def get_event_time(log_entry, year):
    """Read a syslog timestamp using an explicitly supplied year."""
    try:
        return datetime.strptime(
            f"{year} {log_entry[:15]}",
            "%Y %b %d %H:%M:%S",
        )
    except ValueError:
        return None


def get_source_ip(log_entry):
    """Extract and validate an IPv4 or IPv6 source address."""
    match = re.search(r"\bfrom\s+(\S+)", log_entry)

    if match is None:
        return None

    try:
        return str(ipaddress.ip_address(match.group(1)))
    except ValueError:
        return None


def has_failure_burst(failure_times, threshold, window_seconds):
    """Check for a threshold of failures within an inclusive window."""
    if threshold < 1 or window_seconds < 1:
        raise ValueError("Threshold and window must be positive.")

    times = sorted(failure_times)
    left = 0

    for right in range(len(times)):
        while (
            times[right] - times[left]
        ).total_seconds() > window_seconds:
            left += 1

        if right - left + 1 >= threshold:
            return True

    return False


def find_failure_burst(events, threshold, window_seconds):
    """Return evidence for the first qualifying burst."""
    ordered = sorted(
        events,
        key=lambda event: (event["time"], event["line"]),
    )
    left = 0

    for right in range(len(ordered)):
        while (
            ordered[right]["time"] - ordered[left]["time"]
        ).total_seconds() > window_seconds:
            left += 1

        count = right - left + 1

        if count >= threshold:
            return {
                "count": count,
                "start": ordered[left]["time"].isoformat(),
                "end": ordered[right]["time"].isoformat(),
                "lines": [
                    event["line"]
                    for event in ordered[left:right + 1]
                ],
            }

    return None


def collect_results(log_file, threshold, window_seconds, year):
    """Parse events, calculate counts, and generate alerts."""
    if threshold < 1:
        raise ValueError("Threshold must be at least 1.")

    if window_seconds < 1:
        raise ValueError("Window must be at least 1 second.")

    if not 1 <= year <= 9999:
        raise ValueError("Year must be between 1 and 9999.")

    counts = {
        "total_lines": 0,
        "failed_logins": 0,
        "successful_logins": 0,
        "unrecognized_entries": 0,
        "invalid_source_entries": 0,
        "invalid_timestamp_entries": 0,
    }

    failed_by_ip = {}
    failures_by_ip = {}
    events = []

    with Path(log_file).open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            counts["total_lines"] += 1
            match = SSH_PATTERN.search(line)

            if match is None:
                counts["unrecognized_entries"] += 1
                continue

            outcome = match.group("outcome")

            if outcome == "Failed":
                counts["failed_logins"] += 1
            else:
                counts["successful_logins"] += 1

            source_ip = get_source_ip(line)
            event_time = get_event_time(line, year)

            if source_ip is None:
                counts["invalid_source_entries"] += 1

            if event_time is None:
                counts["invalid_timestamp_entries"] += 1

            if source_ip is not None and outcome == "Failed":
                failed_by_ip[source_ip] = (
                    failed_by_ip.get(source_ip, 0) + 1
                )

            if source_ip is None or event_time is None:
                continue

            event = {
                "time": event_time,
                "ip": source_ip,
                "username": match.group("username"),
                "outcome": outcome,
                "line": line_number,
            }

            events.append(event)

            if outcome == "Failed":
                failures_by_ip.setdefault(source_ip, []).append(event)

    alerts = []

    # One burst alert per qualifying source IP.
    for source_ip, failures in sorted(failures_by_ip.items()):
        evidence = find_failure_burst(
            failures,
            threshold,
            window_seconds,
        )

        if evidence is not None:
            alerts.append({
                "type": "repeated_failures",
                "ip": source_ip,
                "message": (
                    f"{source_ip} had at least {threshold} failed "
                    f"logins within {window_seconds} seconds."
                ),
                **evidence,
            })

    # Correlate successes with earlier failures for the same IP/user.
    # Sort events so input lines do not need to be chronological.
    prior_failures = {}

    for event in sorted(
        events,
        key=lambda item: (item["time"], item["line"]),
    ):
        key = (event["ip"], event["username"])
        history = prior_failures.setdefault(key, [])

        # Keep only failures within this event's lookback window.
        history = [
            failure
            for failure in history
            if 0 <= (
                event["time"] - failure["time"]
            ).total_seconds() <= window_seconds
        ]
        prior_failures[key] = history

        if event["outcome"] == "Failed":
            history.append(event)

        elif len(history) >= threshold:
            alerts.append({
                "type": "success_after_failures",
                "ip": event["ip"],
                "username": event["username"],
                "count": len(history),
                "start": history[0]["time"].isoformat(),
                "end": event["time"].isoformat(),
                "lines": [
                    failure["line"] for failure in history
                ] + [event["line"]],
                "message": (
                    f"Successful login for {event['username']} "
                    f"from {event['ip']} followed {len(history)} "
                    f"failures within {window_seconds} seconds."
                ),
            })

    return {
        "input_file": str(log_file),
        "threshold": threshold,
        "window_seconds": window_seconds,
        "assumed_year": year,
        "counts": counts,
        "failed_by_ip": dict(sorted(failed_by_ip.items())),
        "alerts": alerts,
        "limitations": [
            "Student lab tool; alerts require investigation.",
            "Supports English syslog-style sshd password messages.",
            "Does not support public-key authentication messages.",
            "Uses a supplied year; does not handle year rollover.",
            "Timestamps have no timezone; use a consistent time source.",
            "Invalid IPs or timestamps are excluded from timed rules.",
            "A shared IP does not necessarily identify one person.",
            "Successful login after failures does not prove compromise.",
            "The first qualifying failure burst per IP is reported.",
        ],
    }


def format_report(results):
    """Convert structured results into a readable text report."""
    counts = results["counts"]

    lines = [
        "SSH AUTHENTICATION LOG REPORT",
        "=============================",
        f"Input file: {results['input_file']}",
        f"Assumed year: {results['assumed_year']}",
        f"Total lines: {counts['total_lines']}",
        f"Failed logins: {counts['failed_logins']}",
        f"Successful logins: {counts['successful_logins']}",
        f"Unrecognized entries: {counts['unrecognized_entries']}",
        "Login entries with missing/invalid IPs: "
        f"{counts['invalid_source_entries']}",
        "Login entries with invalid timestamps: "
        f"{counts['invalid_timestamp_entries']}",
        "",
        "FAILED LOGINS BY SOURCE IP",
        "-------------------------",
    ]

    sources = sorted(
        results["failed_by_ip"].items(),
        key=lambda item: (-item[1], item[0]),
    )

    for source_ip, count in sources:
        lines.append(f"{source_ip}: {count} failed attempts")

    if not sources:
        lines.append("No failed logins with valid source IPs found.")

    lines.extend([
        "",
        "ALERTS",
        "------",
        f"Threshold: {results['threshold']} failures",
        f"Window: {results['window_seconds']} seconds",
    ])

    for alert in results["alerts"]:
        lines.extend([
            f"[REVIEW] {alert['message']}",
            f"  Time range: {alert['start']} to {alert['end']}",
            "  Evidence lines: "
            + ", ".join(str(number) for number in alert["lines"]),
        ])

    if not results["alerts"]:
        lines.append("No alerts generated.")

    lines.extend([
        "",
        f"Total alerts: {len(results['alerts'])}",
        "",
        "LIMITATIONS",
        "-----------",
    ])

    lines.extend(results["limitations"])

    return "\n".join(lines)


def analyze_logs(log_file, threshold, window_seconds=None, year=2026):
    """Keep the earlier function interface for existing tests."""
    if window_seconds is not None:
        results = collect_results(
            log_file, threshold, window_seconds, year
        )
        return format_report(results)

    # Compatibility mode: whole-file counting without timestamps.
    if threshold < 1:
        raise ValueError("Threshold must be at least 1.")

    total = failed = successful = unrecognized = invalid = 0
    failures = {}

    with Path(log_file).open("r", encoding="utf-8") as file:
        for line in file:
            total += 1

            if "Failed password" in line:
                failed += 1
                source_ip = get_source_ip(line)

                if source_ip is None:
                    invalid += 1
                else:
                    failures[source_ip] = (
                        failures.get(source_ip, 0) + 1
                    )

            elif "Accepted password" in line:
                successful += 1

                if get_source_ip(line) is None:
                    invalid += 1
            else:
                unrecognized += 1

    lines = [
        "SSH AUTHENTICATION LOG REPORT",
        "=============================",
        f"Total lines: {total}",
        f"Failed logins: {failed}",
        f"Successful logins: {successful}",
        f"Unrecognized entries: {unrecognized}",
        f"Login entries with missing/invalid IPs: {invalid}",
        "",
        "Whole-file counting mode; timestamps are not considered.",
    ]

    alert_count = 0

    for source_ip, count in sorted(failures.items()):
        lines.append(f"{source_ip}: {count} failed attempts")

        if count >= threshold:
            alert_count += 1
            lines.append(
                f"[REVIEW] {source_ip} had {count} failed logins."
            )

    lines.append(f"Sources reaching threshold: {alert_count}")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Analyze SSH authentication logs."
    )

    parser.add_argument("log_file", type=Path)
    parser.add_argument("--threshold", type=int, default=3)
    parser.add_argument("--window-seconds", type=int, default=300)
    parser.add_argument("--year", type=int, default=2026)
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
    )
    parser.add_argument("--output", type=Path, default=None)

    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("--threshold must be at least 1.")

    if args.window_seconds < 1:
        parser.error("--window-seconds must be at least 1.")

    if not 1 <= args.year <= 9999:
        parser.error("--year must be between 1 and 9999.")

    output_file = args.output or Path(
        "security_report.json"
        if args.format == "json"
        else "security_report.txt"
    )

    if args.log_file.resolve() == output_file.resolve():
        parser.error("Input and output must be different files.")

    # Also detect existing hard links to the same file.
    try:
        if output_file.exists() and args.log_file.samefile(output_file):
            parser.error("Input and output refer to the same file.")
    except OSError as error:
        parser.exit(1, f"Could not check file paths: {error}\n")

    try:
        results = collect_results(
            args.log_file,
            args.threshold,
            args.window_seconds,
            args.year,
        )

        if args.format == "json":
            report = json.dumps(results, indent=2)
        else:
            report = format_report(results)

        output_file.write_text(report + "\n", encoding="utf-8")

    except (OSError, UnicodeError, ValueError) as error:
        parser.exit(1, f"Analysis failed: {error}\n")

    print(report)
    print(f"\nReport saved to: {output_file}")


if __name__ == "__main__":
    main()