# SSH Auth Log Parser

Parses an SSH/syslog auth log, flags source IPs with bursts of failed login
attempts, and writes both a CSV summary report and a per-flagged-IP "case
file" timeline of everything that source did.

## What it does

1. Reads the log line by line and recognizes these `sshd` event types:
   - `Failed password` (including rsyslog's collapsed `message repeated N
     times:` form)
   - `Accepted password` / `Accepted publickey`
   - `Connection closed by ... [preauth]`
   - `Received disconnect from ...`
   - `Disconnected from invalid user ...`
   - `pam_unix(sshd:session): session opened/closed`
2. For each source IP, slides a configurable time window over its failed
   attempts and finds the busiest window. If that count meets the threshold,
   the IP is **flagged**.
3. Writes a CSV summary (one row per IP) and, for every flagged IP, a
   chronological timeline of *all* its events — including login successes and
   session open/close lines, which are correlated back to the IP via the
   shared `sshd[PID]` even though those lines don't carry an IP themselves.

## Requirements

Python 3.7+, standard library only (no dependencies to install).

## Usage

```
python parse_ssh_log.py <logfile> [options]
```

### Options

| Flag                 | Default              | Description                                              |
|----------------------|----------------------|------------------------------------------------------------|
| `logfile`            | *(required)*         | Path to the SSH auth log to parse                        |
| `-o`, `--output`     | `security_report.csv`| Path to write the CSV summary report                      |
| `--timeline-output`  | `ip_timelines.txt`   | Path to write per-flagged-IP case-file timelines           |
| `--window`           | `5`                  | Sliding window size, in minutes                            |
| `--threshold`        | `5`                  | Minimum failed attempts within the window to flag an IP    |
| `--year`             | current year         | Year to assume for timestamps (syslog lines omit the year) |

### Example

```
python parse_ssh_log.py ssh_auth.log --year 2026 -o security_report.csv --timeline-output ip_timelines.txt
```

Console output:

```
Parsed 37 failed attempts from 4 IP(s).
Flagged 3 IP(s) with 5+ failed attempts within 5 minutes:
  185.220.101.7: 14 attempts in window (2026-07-05 14:20:11 to 2026-07-05 14:21:55)
  45.142.120.15: 13 attempts in window (2026-07-04 03:12:01 to 2026-07-04 03:13:30)
  103.45.67.201: 6 attempts in window (2026-07-06 09:05:02 to 2026-07-06 09:05:47)
Report written to security_report.csv
Timelines for flagged IPs written to ip_timelines.txt
```

## Output files

**`security_report.csv`** — one row per IP that had at least one failed
login, with columns: `ip`, `flagged`, `max_attempts_in_window`,
`total_failed_attempts`, `window_start`, `window_end`, `first_seen`,
`last_seen`, `distinct_usernames`, `usernames_tried`. Sorted flagged-first,
then by burst size.

**`ip_timelines.txt`** — only generated if at least one IP was flagged. One
"CASE FILE" block per flagged IP: why it was flagged, the usernames it
tried, and every recognized event for that source in chronological order
(failed attempts, eventual success, session open/close), pulled straight
from the raw log lines.

## Notes on log format

The parser expects standard OpenSSH-via-syslog lines, e.g.:

```
Jul  6 09:05:56 prod-web01 sshd[16313]: Accepted password for backup from 103.45.67.201 port 47735 ssh2
```

Lines it doesn't recognize (e.g. `sudo` entries, kernel messages) are
skipped rather than causing an error.
