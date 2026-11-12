"""Analyze SSH authentication logs. Standard library only."""
from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

FAILED = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port \d+", re.I)
ACCEPTED = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port \d+", re.I)


def analyze(lines: list[str], threshold: int = 5) -> dict:
    """Return aggregate counts; never transmit input data."""
    if threshold < 1:
        raise ValueError("threshold must be >= 1")
    failures: Counter[str] = Counter()
    successes: Counter[str] = Counter()
    users: Counter[str] = Counter()
    events = 0
    for line in lines:
        failed = FAILED.search(line)
        if failed:
            failures[failed.group("ip")] += 1
            users[failed.group("user")] += 1
            events += 1
            continue
        accepted = ACCEPTED.search(line)
        if accepted:
            successes[accepted.group("ip")] += 1
            events += 1
    return {
        "parsed_events": events,
        "total_failed": sum(failures.values()),
        "total_successful": sum(successes.values()),
        "failed_by_ip": dict(sorted(failures.items())),
        "successful_by_ip": dict(sorted(successes.items())),
        "targeted_users": dict(sorted(users.items())),
        "suspicious_ips": sorted(ip for ip, count in failures.items() if count >= threshold),
        "threshold": threshold,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze SSH auth logs locally")
    parser.add_argument("logfile", type=Path, help="SSH auth log file (UTF-8)")
    parser.add_argument("--threshold", type=int, default=5, help="Failures per IP to flag (default: 5)")
    parser.add_argument("--json", type=Path, dest="json_out", help="Write JSON report")
    args = parser.parse_args()
    try:
        lines = args.logfile.read_text(encoding="utf-8").splitlines()
        result = analyze(lines, args.threshold)
    except (OSError, UnicodeError, ValueError) as exc:
        parser.error(str(exc))
    print(f"Events: {result['parsed_events']} | Failed: {result['total_failed']} | Successful: {result['total_successful']}")
    print(f"Suspicious IPs (>= {args.threshold} failures):")
    for ip in result["suspicious_ips"]:
        print(f"  {ip}: {result['failed_by_ip'][ip]} failures")
    if args.json_out:
        args.json_out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"Report: {args.json_out}")


if __name__ == "__main__":
    main()
