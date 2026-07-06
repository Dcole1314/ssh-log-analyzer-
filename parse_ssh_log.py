#!/usr/bin/env python3
"""Parse an SSH auth log, flag IPs with bursts of failed logins, and build a
per-flagged-IP timeline of everything that source did."""

import argparse
import csv
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta

PREFIX = (
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+sshd\[(?P<pid>\d+)\]:\s+"
)
IP = r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})"

# Each entry: (kind, label, compiled regex). Order doesn't matter since prefixes
# after the common PREFIX are mutually exclusive. Lines that match none are ignored.
# rsyslog collapses runs of identical lines into a "message repeated N times" entry;
# that count is expanded when tallying attempts, but kept as one raw line in the timeline.
EVENT_PATTERNS = [
    ("failed", "FAILED LOGIN", re.compile(
        PREFIX + r"Failed password for (?:invalid user )?(?P<user>\S+) from " + IP + r" port \d+ ssh2")),
    ("repeated_failed", "FAILED LOGIN (repeated)", re.compile(
        PREFIX + r"message repeated (?P<count>\d+) times: \[ Failed password for "
        r"(?:invalid user )?(?P<user>\S+) from " + IP + r" port \d+ ssh2\]")),
    ("accepted", "LOGIN SUCCESS", re.compile(
        PREFIX + r"Accepted (?P<method>password|publickey) for (?P<user>\S+) from " + IP + r" port \d+ ssh2")),
    ("conn_closed", "CONNECTION CLOSED", re.compile(
        PREFIX + r"Connection closed by (?:authenticating user \S+ |invalid user \S+ )?" + IP + r" port \d+ \[preauth\]")),
    ("received_disconnect", "DISCONNECT", re.compile(
        PREFIX + r"Received disconnect from " + IP + r" port \d+:\d+: .*\[preauth\]")),
    ("disconnected_invalid", "DISCONNECT", re.compile(
        PREFIX + r"Disconnected from invalid user (?P<user>\S+) " + IP + r" port \d+ \[preauth\]")),
    ("session_opened", "SESSION OPENED", re.compile(
        PREFIX + r"pam_unix\(sshd:session\): session opened for user (?P<user>\S+)\(uid=\d+\) by \(uid=\d+\)")),
    ("session_closed", "SESSION CLOSED", re.compile(
        PREFIX + r"pam_unix\(sshd:session\): session closed for user (?P<user>\S+)")),
]


def parse_timestamp(month, day, time_str, year):
    """Combine a syslog month/day/time (no year field) with an explicit year into a datetime."""
    return datetime.strptime(f"{month} {day} {year} {time_str}", "%b %d %Y %H:%M:%S")


def parse_log(path, year):
    """Return (attempts, all_events).

    attempts: ip -> list of (timestamp, username) for failed logins, used for
    the burst/window report.
    all_events: chronological list of every recognized event, with ip resolved
    via the sshd PID even for lines (like session open/close) that don't carry
    an IP themselves, used for per-IP timelines.
    """
    attempts = defaultdict(list)
    all_events = []
    pid_to_ip = {}

    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            for kind, label, pattern in EVENT_PATTERNS:
                match = pattern.match(line)
                if not match:
                    continue
                fields = match.groupdict()
                ts = parse_timestamp(fields["month"], fields["day"], fields["time"], year)
                pid = fields["pid"]
                ip = fields.get("ip") or pid_to_ip.get(pid)
                if fields.get("ip"):
                    pid_to_ip[pid] = fields["ip"]

                user = fields.get("user")
                if kind == "repeated_failed":
                    count = int(fields["count"])
                    attempts[ip].extend([(ts, user)] * count)
                elif kind == "failed":
                    attempts[ip].append((ts, user))

                all_events.append({
                    "timestamp": ts,
                    "kind": kind,
                    "label": label,
                    "ip": ip,
                    "pid": pid,
                    "user": user,
                    "raw": line.strip(),
                })
                break
    return attempts, all_events


def max_attempts_in_window(timestamps, window_minutes):
    """Slide a window_minutes window over sorted timestamps; return (max_count, window_start, window_end)."""
    window = timedelta(minutes=window_minutes)
    best_count, best_start, best_end = 0, None, None
    left = 0
    for right in range(len(timestamps)):
        while timestamps[right] - timestamps[left] > window:
            left += 1
        count = right - left + 1
        if count > best_count:
            best_count, best_start, best_end = count, timestamps[left], timestamps[right]
    return best_count, best_start, best_end


def build_report(attempts, window_minutes, threshold):
    """Turn per-IP failed-login attempts into summary rows, sorted flagged-first
    then by burst size, ready to write out as the CSV report."""
    rows = []
    for ip, ip_attempts in attempts.items():
        timestamps = sorted(ts for ts, _ in ip_attempts)
        usernames = sorted({user for _, user in ip_attempts})
        best_count, window_start, window_end = max_attempts_in_window(timestamps, window_minutes)
        rows.append({
            "ip": ip,
            "total_failed_attempts": len(ip_attempts),
            "max_attempts_in_window": best_count,
            "window_start": window_start.isoformat(sep=" ") if window_start else "",
            "window_end": window_end.isoformat(sep=" ") if window_end else "",
            "first_seen": timestamps[0].isoformat(sep=" "),
            "last_seen": timestamps[-1].isoformat(sep=" "),
            "distinct_usernames": len(usernames),
            "usernames_tried": ",".join(usernames),
            "flagged": best_count >= threshold,
        })
    rows.sort(key=lambda r: (r["flagged"], r["max_attempts_in_window"]), reverse=True)
    return rows


def write_report(rows, output_path):
    """Write the summary rows from build_report() out as a CSV file."""
    fieldnames = [
        "ip", "flagged", "max_attempts_in_window", "total_failed_attempts",
        "window_start", "window_end", "first_seen", "last_seen",
        "distinct_usernames", "usernames_tried",
    ]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_timelines(rows, all_events, output_path):
    """Write a case-file style timeline for each flagged IP: every event that
    source triggered, in order, including sessions opened/closed under it."""
    flagged_rows = {r["ip"]: r for r in rows if r["flagged"]}
    if not flagged_rows:
        return

    events_by_ip = defaultdict(list)
    for event in all_events:
        if event["ip"] in flagged_rows:
            events_by_ip[event["ip"]].append(event)

    with open(output_path, "w", encoding="utf-8") as f:
        for ip, row in sorted(flagged_rows.items(), key=lambda kv: kv[1]["max_attempts_in_window"], reverse=True):
            ip_events = sorted(events_by_ip[ip], key=lambda e: e["timestamp"])
            f.write("=" * 80 + "\n")
            f.write(f"CASE FILE: {ip}\n")
            f.write(f"Flagged: {row['max_attempts_in_window']} failed attempts within window "
                    f"({row['window_start']} to {row['window_end']})\n")
            f.write(f"Usernames tried: {row['usernames_tried']}\n")
            f.write(f"Total events recorded for this source: {len(ip_events)}\n")
            f.write("=" * 80 + "\n")
            for event in ip_events:
                ts = event["timestamp"].isoformat(sep=" ")
                user = f"user={event['user']}" if event["user"] else ""
                f.write(f"{ts}  {event['label']:<24} {user:<16} {event['raw']}\n")
            f.write("\n")


def main():
    """CLI entry point: parse the log, write the summary CSV, and write case-file
    timelines for any IP that got flagged."""
    parser = argparse.ArgumentParser(description="Flag IPs with bursts of failed SSH login attempts.")
    parser.add_argument("logfile", help="Path to the SSH auth log file to parse")
    parser.add_argument("-o", "--output", default="security_report.csv",
                         help="Path to write the CSV summary report (default: security_report.csv)")
    parser.add_argument("--timeline-output", default="ip_timelines.txt",
                         help="Path to write per-flagged-IP case-file timelines (default: ip_timelines.txt)")
    parser.add_argument("--window", type=int, default=5,
                         help="Sliding window size in minutes (default: 5)")
    parser.add_argument("--threshold", type=int, default=5,
                         help="Minimum failed attempts within the window to flag an IP (default: 5)")
    parser.add_argument("--year", type=int, default=datetime.now().year,
                         help="Year to assume for log timestamps, since syslog lines omit one (default: current year)")
    args = parser.parse_args()

    attempts, all_events = parse_log(args.logfile, args.year)
    if not attempts:
        print(f"No failed login attempts found in {args.logfile}", file=sys.stderr)

    rows = build_report(attempts, args.window, args.threshold)
    write_report(rows, args.output)

    flagged = [r for r in rows if r["flagged"]]
    print(f"Parsed {sum(r['total_failed_attempts'] for r in rows)} failed attempts from {len(rows)} IP(s).")
    print(f"Flagged {len(flagged)} IP(s) with {args.threshold}+ failed attempts within {args.window} minutes:")
    for r in flagged:
        print(f"  {r['ip']}: {r['max_attempts_in_window']} attempts in window "
              f"({r['window_start']} to {r['window_end']})")
    print(f"Report written to {args.output}")

    if flagged:
        write_timelines(rows, all_events, args.timeline_output)
        print(f"Timelines for flagged IPs written to {args.timeline_output}")


if __name__ == "__main__":
    main()
