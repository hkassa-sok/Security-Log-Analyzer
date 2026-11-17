import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from log_analyzer import (
    analyze_logs,
    collect_results,
    get_event_time,
    get_source_ip,
    has_failure_burst,
)


ANALYZER_PATH = Path(__file__).resolve().with_name("log_analyzer.py")


def make_entry(
    time_text,
    outcome="Failed",
    username="student",
    source_ip="192.0.2.10",
):
    """Build one synthetic SSH log entry."""
    return (
        f"Nov 17 {time_text} lab sshd[100]: "
        f"{outcome} password for {username} "
        f"from {source_ip} port 50000 ssh2\n"
    )


def evaluate_sample(sample):
    """Analyze a sample using an isolated temporary file."""
    with tempfile.TemporaryDirectory() as folder:
        log_path = Path(folder) / "sample.log"
        log_path.write_text(sample, encoding="utf-8")

        return collect_results(
            log_path,
            threshold=3,
            window_seconds=300,
            year=2026,
        )


def correlation_alerts(results):
    """Select only success-after-failures alerts."""
    return [
        alert
        for alert in results["alerts"]
        if alert["type"] == "success_after_failures"
    ]


class TestSourceIP(unittest.TestCase):
    def test_ipv4(self):
        entry = make_entry("10:00:00")
        self.assertEqual(get_source_ip(entry), "192.0.2.10")

    def test_ipv6(self):
        entry = make_entry("10:00:00", source_ip="2001:db8::10")
        self.assertEqual(get_source_ip(entry), "2001:db8::10")

    def test_invalid_ip(self):
        entry = make_entry("10:00:00", source_ip="invalid-ip")
        self.assertIsNone(get_source_ip(entry))

    def test_missing_source(self):
        self.assertIsNone(get_source_ip("Connection closed"))


class TestAnalysis(unittest.TestCase):
    def test_counts_and_threshold(self):
        sample = (
            make_entry("10:00:00")
            + make_entry("10:01:00")
            + make_entry(
                "10:02:00",
                outcome="Accepted",
                source_ip="192.0.2.20",
            )
            + "Connection closed\n"
        )

        with tempfile.TemporaryDirectory() as folder:
            log_path = Path(folder) / "sample.log"
            log_path.write_text(sample, encoding="utf-8")

            report = analyze_logs(log_path, threshold=2)

        self.assertIn("Total lines: 4", report)
        self.assertIn("Failed logins: 2", report)
        self.assertIn("Successful logins: 1", report)
        self.assertIn("Unrecognized entries: 1", report)
        self.assertIn(
            "[REVIEW] 192.0.2.10 had 2 failed logins.",
            report,
        )
        self.assertIn("Sources reaching threshold: 1", report)

    def test_below_threshold(self):
        with tempfile.TemporaryDirectory() as folder:
            log_path = Path(folder) / "sample.log"
            log_path.write_text(
                make_entry("10:00:00"),
                encoding="utf-8",
            )

            report = analyze_logs(log_path, threshold=2)

        self.assertIn("Sources reaching threshold: 0", report)
        self.assertNotIn("[REVIEW]", report)

    def test_empty_file(self):
        with tempfile.TemporaryDirectory() as folder:
            log_path = Path(folder) / "empty.log"
            log_path.write_text("", encoding="utf-8")

            report = analyze_logs(log_path, threshold=3)

        self.assertIn("Total lines: 0", report)
        self.assertIn("Failed logins: 0", report)
        self.assertIn("Successful logins: 0", report)
        self.assertIn("Sources reaching threshold: 0", report)
        self.assertNotIn("[REVIEW]", report)


class TestEventTime(unittest.TestCase):
    def test_valid_timestamp(self):
        result = get_event_time(
            make_entry("10:02:00"),
            year=2026,
        )

        self.assertEqual(
            result,
            datetime(2026, 11, 17, 10, 2, 0),
        )

    def test_invalid_timestamp(self):
        result = get_event_time(
            "Not a valid timestamp",
            year=2026,
        )

        self.assertIsNone(result)


class TestFailureBurst(unittest.TestCase):
    def test_failures_inside_window(self):
        times = [
            datetime(2026, 11, 17, 10, 0),
            datetime(2026, 11, 17, 10, 2),
            datetime(2026, 11, 17, 10, 4),
        ]

        self.assertTrue(has_failure_burst(times, 3, 300))

    def test_failures_spread_apart(self):
        times = [
            datetime(2026, 11, 17, 10, 0),
            datetime(2026, 11, 17, 10, 10),
            datetime(2026, 11, 17, 10, 20),
        ]

        self.assertFalse(has_failure_burst(times, 3, 300))

    def test_exact_window_boundary(self):
        times = [
            datetime(2026, 11, 17, 10, 0),
            datetime(2026, 11, 17, 10, 2),
            datetime(2026, 11, 17, 10, 5),
        ]

        self.assertTrue(has_failure_burst(times, 3, 300))

    # New test 1
    def test_empty_failure_list(self):
        self.assertFalse(has_failure_burst([], 3, 300))

    # New test 2: exercise the full parsing/detection pipeline.
    def test_unordered_events(self):
        sample = (
            make_entry("10:04:00")
            + make_entry("10:00:00")
            + make_entry("10:02:00")
        )

        results = evaluate_sample(sample)
        bursts = [
            alert
            for alert in results["alerts"]
            if alert["type"] == "repeated_failures"
        ]

        self.assertEqual(len(bursts), 1)
        self.assertEqual(
            bursts[0]["start"],
            "2026-11-17T10:00:00",
        )
        self.assertEqual(
            bursts[0]["end"],
            "2026-11-17T10:04:00",
        )

    # New test 3
    def test_just_outside_window(self):
        sample = (
            make_entry("10:00:00")
            + make_entry("10:02:00")
            + make_entry("10:05:01")
        )

        results = evaluate_sample(sample)

        self.assertEqual(results["alerts"], [])

    # New test 4
    def test_later_burst(self):
        sample = (
            make_entry("08:00:00")
            + make_entry("10:00:00")
            + make_entry("10:01:00")
            + make_entry("10:02:00")
        )

        results = evaluate_sample(sample)
        bursts = [
            alert
            for alert in results["alerts"]
            if alert["type"] == "repeated_failures"
        ]

        self.assertEqual(len(bursts), 1)
        self.assertEqual(bursts[0]["lines"], [2, 3, 4])


class TestSuccessAfterFailures(unittest.TestCase):
    def run_scenario(
        self,
        success_user="student",
        success_time="10:03:00",
        success_ip="192.0.2.10",
    ):
        sample = (
            make_entry("10:00:00")
            + make_entry("10:01:00")
            + make_entry("10:02:00")
            + make_entry(
                success_time,
                outcome="Accepted",
                username=success_user,
                source_ip=success_ip,
            )
        )

        return evaluate_sample(sample)

    def test_success_after_failures(self):
        results = self.run_scenario()
        alerts = correlation_alerts(results)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["username"], "student")
        self.assertEqual(alerts[0]["count"], 3)
        self.assertEqual(alerts[0]["lines"], [1, 2, 3, 4])

    def test_different_user_does_not_trigger(self):
        results = self.run_scenario(success_user="other_user")

        self.assertEqual(correlation_alerts(results), [])

    def test_late_success_does_not_trigger(self):
        results = self.run_scenario(success_time="10:10:00")

        self.assertEqual(correlation_alerts(results), [])

    # New test 5
    def test_different_ip_does_not_trigger(self):
        results = self.run_scenario(success_ip="192.0.2.99")

        self.assertEqual(correlation_alerts(results), [])

    # New test 6
    def test_success_before_failures_does_not_trigger(self):
        results = self.run_scenario(success_time="09:59:00")

        self.assertEqual(correlation_alerts(results), [])

    # New test 7
    def test_success_at_window_boundary(self):
        results = self.run_scenario(success_time="10:05:00")
        alerts = correlation_alerts(results)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["count"], 3)


class TestCommandLine(unittest.TestCase):
    # New test 8: multiple invalid inputs within one test method.
    def test_invalid_arguments(self):
        cases = [
            ["--threshold", "0"],
            ["--window-seconds", "0"],
            ["--year", "0"],
        ]

        with tempfile.TemporaryDirectory() as folder:
            log_path = Path(folder) / "sample.log"
            log_path.write_text("", encoding="utf-8")

            for arguments in cases:
                with self.subTest(arguments=arguments):
                    result = subprocess.run(
                        [
                            sys.executable,
                            str(ANALYZER_PATH),
                            str(log_path),
                            *arguments,
                        ],
                        cwd=folder,
                        capture_output=True,
                        text=True,
                    )

                    self.assertEqual(result.returncode, 2)
                    self.assertIn("error:", result.stderr)
                    self.assertFalse(
                        (Path(folder) / "security_report.txt").exists()
                    )

    # New test 9
    def test_missing_input_file(self):
        with tempfile.TemporaryDirectory() as folder:
            missing_path = Path(folder) / "missing.log"

            result = subprocess.run(
                [
                    sys.executable,
                    str(ANALYZER_PATH),
                    str(missing_path),
                ],
                cwd=folder,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 1)
            self.assertIn("Analysis failed:", result.stderr)
            self.assertFalse(
                (Path(folder) / "security_report.txt").exists()
            )

    # New test 10
    def test_json_output(self):
        sample = (
            make_entry("10:00:00")
            + make_entry("10:01:00")
            + make_entry("10:02:00")
            + make_entry("10:03:00", outcome="Accepted")
        )

        with tempfile.TemporaryDirectory() as folder:
            log_path = Path(folder) / "sample.log"
            output_path = Path(folder) / "report.json"
            log_path.write_text(sample, encoding="utf-8")

            result = subprocess.run(
                [
                    sys.executable,
                    str(ANALYZER_PATH),
                    str(log_path),
                    "--threshold", "3",
                    "--window-seconds", "300",
                    "--year", "2026",
                    "--format", "json",
                    "--output", str(output_path),
                ],
                cwd=folder,
                capture_output=True,
                text=True,
            )

            self.assertEqual(
                result.returncode,
                0,
                msg=result.stderr,
            )

            # Parse the saved report, not the terminal status message.
            report = json.loads(
                output_path.read_text(encoding="utf-8")
            )

            self.assertEqual(report["counts"]["total_lines"], 4)
            self.assertEqual(report["counts"]["failed_logins"], 3)
            self.assertEqual(report["counts"]["successful_logins"], 1)
            self.assertEqual(report["threshold"], 3)
            self.assertEqual(report["window_seconds"], 300)

            self.assertCountEqual(
                [alert["type"] for alert in report["alerts"]],
                ["repeated_failures", "success_after_failures"],
            )


if __name__ == "__main__":
    unittest.main()