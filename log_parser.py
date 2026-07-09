"""
Jun 20 02:05:56 localhost sshd-session[2715]: Failed password for invalid user wrongpassword from ::1 port 42068 ssh2
Jun 20 02:06:25 localhost sshd-session[2733]: Accepted password for abhishek from ::1 port 48998 ssh2
Jun 20 02:06:54 localhost sudo[2772]: abhishek : TTY=pts/1 ; PWD=/home/abhishek ; USER=root ; COMMAND=/bin/tail -f /var/log/secure
Jun 20 02:06:54 localhost sudo[2772]: pam_unix(sudo:session): session opened for user root(uid=0) by abhishek(uid=1000)

"""
import re
from datetime import datetime
from collections import defaultdict
import db

#scan log file
def scan_logs(filepath):
    try:
        events = []
        last_position = db.get_scanner_state(filepath)
        with open(filepath,"r") as logs:
            if last_position is None:
                logs.seek(0,2)
                new_position = logs.tell()
            else:
                logs.seek(last_position)
                for log_line in logs:
                    event = extract_data(log_line)
                    if event:
                        events.append(event)
                new_position = logs.tell()
            db.save_scanner_state(filepath,new_position)
        return events
        
    except FileNotFoundError:
        print(f"Log File not Found: {filepath}")
    except PermissionError:
        print("Permission denied,use sudo before command")


#extract data from a single log_line
def extract_data(log_line):
    event = {
        "Event_type" : None,
        "IP" : None,
        "Username" : None,
        "Service" : None,
        "Time_stamp" : None,
        "Command" : None
    }
    
    current_year = datetime.now().year

    time_stamp = None
    time_match = re.search(r"\w+\s+\d+\s+\d{2}:\d{2}:\d{2}",log_line)
    if time_match:
        timestamp_str = f"{current_year} " + time_match.group(0)
        time_stamp = datetime.strptime(timestamp_str, "%Y %b %d %H:%M:%S")

    if "Failed password" in log_line:
        ip_match = re.search(r"from (\S+) port",log_line)
        username_match = re.search(r"for (?:invalid user )?(\S+) from",log_line)
        service_match = re.search(r"([\w-]+)\[\d+\]",log_line) 
        
        event["Event_type"] = "Authentication Failure"
        event["IP"] = ip_match.group(1) if ip_match else None
        event["Username"] = username_match.group(1) if username_match else None
        event["Service"] = service_match.group(1) if service_match else None
        event["Time_stamp"] = time_stamp
    
    elif "Accepted password" in log_line:
        ip_match = re.search(r"from (\S+) port",log_line)
        username_match = re.search(r"for (.*?) from",log_line)
        service_match = re.search(r"([\w-]+)\[\d+\]",log_line)
        
        event["Event_type"] = "Authentication Success"
        event["IP"] = ip_match.group(1) if ip_match else None
        event["Username"] = username_match.group(1) if username_match else None
        event["Service"] = service_match.group(1) if service_match else None
        event["Time_stamp"] = time_stamp

    elif "COMMAND=" in log_line:
        username_match = re.search(r"sudo\[\d+\]: (\w+) : TTY",log_line)
        command_match = re.search(r"COMMAND=(.*)",log_line)
        
        event["Event_type"] = "Sudo Command"
        event["Username"] = username_match.group(1) if username_match else None
        event["Service"] = "sudo"
        event["Time_stamp"] = time_stamp
        event["Command"] = command_match.group(1) if command_match else None

    elif "session opened for user root" in log_line:
        username_match = re.search(r"by (\w+)\(uid=",log_line)

        event["Event_type"] = "Root Session"
        event["Username"] = username_match.group(1) if username_match else None
        event["Time_stamp"] = time_stamp
    else: 
        return None

    return event

#create incident and save to db
def create_incident(source, incident_type, severity, description, time_stamp, username, ip, command, artifact, event_action):
    try:
        db.save_incident(source, incident_type, severity, description, time_stamp, username, ip, command, artifact, event_action)
    except Exception as e:
        print(f"Database unreachable: {e}")

#detection parameters:
#detects login in between 10 pm and 5am
def detect_after_hour_login(events):
    for event in events:
        ts = event["Time_stamp"]
        if ts and (ts.hour >= 22 or ts.hour < 5):
            if event["Event_type"] == "Authentication Success":
                create_incident("auth_log", "Suspicious Login", 60, "Suspicious After Hour Login", event["Time_stamp"], event["Username"], event["IP"], event["Command"], None, None)

            elif event["Event_type"] == "Authentication Failure":
                create_incident("auth_log", "Suspicious Login Attempt", 50, "Suspicious Failed After Hour Login", event["Time_stamp"], event["Username"], event["IP"], event["Command"], None, None)

#brute force condition --> 10 or more than attempts under 2 minutes from the same ip
def detect_brute_force(events):
    failed_by_ip = defaultdict(list)
    for event in events:
        if event["Event_type"] == "Authentication Failure":
            ip = event["IP"]
            failed_by_ip[ip].append(event)

            if len(failed_by_ip[ip]) >= 10:
                first_ts = failed_by_ip[ip][0]["Time_stamp"]
                last_ts = failed_by_ip[ip][-1]["Time_stamp"]
                difference = last_ts - first_ts

                if difference.total_seconds() < 120:
                    create_incident("auth_log", "Brute Force Attempt", 80, "Possible brute force attempt, many login attempts under 2 minutes", first_ts, failed_by_ip[ip][0]["Username"], failed_by_ip[ip][0]["IP"], failed_by_ip[ip][0]["Command"], None, None)

                failed_by_ip[ip] = []

#sensitive commands are flagged
def detect_sensitive_commands(events):
    sensitive_commands = {
    "useradd": ("Account Modification", 80),
    "adduser": ("Account Modification", 80),
    "usermod": ("Account Modification", 80),
    "userdel": ("Account Modification", 80),

    "passwd": ("Credential Modification", 90),

    "visudo": ("Privilege Escalation", 90),

    "rm": ("Log Tampering", 100),
    "truncate": ("Log Tampering", 100),

    "systemctl stop": ("Security Service Disabled", 100),

    "iptables": ("Firewall Modification", 90),
    "firewall-cmd": ("Firewall Modification", 90),

    "wget": ("Remote Download", 60),
    "curl": ("Remote Download", 60),
    "chmod": ("Permission Modification", 80),
    "chown": ("Ownership Modification", 80),

    "ssh-keygen": ("SSH Key Modification", 85),
    "ssh-copy-id": ("SSH Key Modification", 85),

    "crontab": ("Scheduled Task Modification", 75),

    "dnf remove": ("Software Removal", 70),
    "yum remove": ("Software Removal", 70),
    "rpm -e": ("Software Removal", 70)
}
    for event in events:
        if event["Event_type"] == "Sudo Command":
            for cmd, (label, score) in sensitive_commands.items():
                command = event["Command"]
                if cmd and cmd in command:
                    create_incident("auth_log", label, score, f'Sensitive command detected:{event["Command"]}', event["Time_stamp"], event["Username"], event["IP"], event["Command"], None, None)


def main():
    events = scan_logs("/var/log/secure")

    if not events:
        print("No new events found")
        return 
    detect_after_hour_login(events)
    detect_brute_force(events)
    detect_sensitive_commands(events)

    print(f"Processed {len(events)} events")


if __name__ == "__main__":
    main()