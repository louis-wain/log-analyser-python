# SSH Brute Force & Blacklist Log Analyser
Simple python script that monitors SSH authentication logs in real time, detects possible brute force attacks and blacklisted IPs.
Logs alerts for later analysis.

## Requirements
- Python 3.6+
- `auth.log` file, I've included one containing synthetic data

## Setup
1. Clone or download repo
2. Create and activate virtual environment
3. Add your own `sample_logs/auth.log` and `blacklist.txt` files, or use the ones provided
4. Run the log analyser script: `python monitor.py`

## Triggering Alerts
Open a second terminal and add synthetic failed login entries. You can change the IP here to match blacklisted ones.
`echo "Jul  9 12:00:01 localhost sshd[12345]: Failed password for invalid user root from 192.168.1.10 port 22 ssh2" >> sample_logs/auth.log`