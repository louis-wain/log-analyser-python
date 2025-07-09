import time
import os
import re
from datetime import datetime, timedelta
from collections import defaultdict
import csv
from pathlib import Path

LOG_FILE = "sample_logs/auth.log"
ALERT_THRESHOLD = 5
TIME_WINDOW = timedelta(seconds=60)

log_pattern = re.compile(
    r'^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*Failed password.*from (?P<ip>\d+\.\d+\.\d+\.\d+)'
)

def load_blacklist(filepath="blacklist.txt"):
    """Loads the blacklist from filepath
    
    Keyword arguments:
    filepath -- string containing filepath of blacklist
    """
    try:
        with open(filepath, "r") as f:
            return set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        print("[!] blacklist.txt not found - continuing without blacklist.")
    return set()

def follow_log(filepath):
    """Parses a logfile

    Keyword arguments:
    filepath -- string containing filepath of auth.log
    """
    with open(filepath, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            yield line.strip()

def parse_line(line):
    """Parses each line entering the auth.log file for IP and datetime

    Keyword arguments:
    line -- string of a line from auth.log
    """
    match = log_pattern.search(line)
    if match:
        month = match.group('month')
        day = match.group('day')
        time_str = match.group('time')
        ip = match.group('ip')
        timestamp_str = f"{month} {day} {time_str} {datetime.now().year}"
        timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S %Y")
        return timestamp, ip
    return None, None

def log_alert(timestamp, ip, alert_type, details):
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)
    output_file = output_dir / "flagged_ips.csv"

    is_new = not output_file.exists()

    with open(output_file, "a", newline="") as csvfile:
        writer = csv.writer(csvfile)
        if is_new:
            writer.writerow(["timestamp", "ip", "alert_type", "details"])
        writer.writerow([timestamp.isoformat(), ip, alert_type, details])

if __name__ == "__main__":
    failed_attempts = defaultdict(list)
    blacklist = load_blacklist()
    print(f"[+] Loaded {len(blacklist)} blacklisted IPs.")
    print(f"[+] Monitoring {LOG_FILE} for failed SSH logins...\n")

    for line in follow_log(LOG_FILE):
        timestamp, ip = parse_line(line)
        if not ip:
            continue

        if ip in blacklist:
            print(f"[BLACKLISTED] Connection attempt from blacklisted IP: {ip}")
            log_alert(timestamp, ip, "blacklist", "Matched in blacklist")
            continue

        attempts = failed_attempts[ip]
        attempts.append(timestamp)

        now = timestamp
        failed_attempts[ip] = [t for t in attempts if now - t <= TIME_WINDOW]

        if len(failed_attempts[ip]) > ALERT_THRESHOLD:
            print(f"[ALERT] Possible brute-force from {ip} ({len(failed_attempts[ip])} failures in 60s)")
            log_alert(timestamp, ip, "bruteforce", f"{len(failed_attempts[ip])} failures in 60s")