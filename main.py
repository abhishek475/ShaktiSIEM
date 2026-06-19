"""
Jun 10 23:29:34 localhost sshd[1970]: Failed password for abhishek from ::1 port 52800 ssh2
Jun 10 23:30:12 localhost sshd[1985]: Accepted password for abhishek from ::1 port 40180 ssh2
Jun 10 23:31:20 localhost sudo[1961]: abhishek : TTY=pts/0 ; PWD=/home/abhishek ; USER=root ; COMMAND=/bin/tail -f /var/log/secure
Jun 10 23:31:20 localhost pam_unix(sudo:session): session opened for user root by abhishek(uid=1000)
"""
import re
from datetime import datetime
from collections import defaultdict

events = []

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
        username_match = re.search(r"for (\w+) from",log_line)
        service_match = re.search(r"localhost (\w+)\[\d+\]",log_line) 
        
        event["Event_type"] = "Authentication Failure"
        event["IP"] = ip_match.group(1) if ip_match else None
        event["Username"] = username_match.group(1) if username_match else None
        event["Service"] = service_match.group(1) if service_match else None
        event["Time_stamp"] = time_stamp
    
    elif "Accepted password" in log_line:
        ip_match = re.search(r"from (\S+) port",log_line)
        username_match = re.search(r"for (\w+) from",log_line)
        service_match = re.search(r"localhost (\w+)\[\d+\]",log_line)
        
        event["Event_type"] = "Authentication Success"
        event["IP"] = ip_match.group(1) if ip_match else None
        event["Username"] = username_match.group(1) if username_match else None
        event["Service"] = service_match.group(1) if service_match else None
        event["Time_stamp"] = time_stamp

    elif "COMMAND=" in log_line:
        username_match = re.search(r"sudo\[\d+\]: (\w+) : TTY",log_line)
        command_match = re.search(r"COMMAND=(.*)",log_line)
        
        event["Event_type"] = "Sudo Session"
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


with open("/home/abhishek/Documents/test_file.txt") as log:
    for log_line in log:
        event = extract_data(log_line)

        if event:
            events.append(event)


print(events)







