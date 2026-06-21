"""
Jun 20 02:05:56 localhost sshd-session[2715]: Failed password for invalid user wrongpassword from ::1 port 42068 ssh2
Jun 20 02:06:25 localhost sshd-session[2733]: Accepted password for abhishek from ::1 port 48998 ssh2
Jun 20 02:06:54 localhost sudo[2772]: abhishek : TTY=pts/1 ; PWD=/home/abhishek ; USER=root ; COMMAND=/bin/tail -f /var/log/secure
Jun 20 02:06:54 localhost sudo[2772]: pam_unix(sudo:session): session opened for user root(uid=0) by abhishek(uid=1000)
"""
import re
from datetime import datetime
from collections import defaultdict

events = []
incidents = []

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

def create_incident(incident_type,severity,username,ip,time_stamp,command,description):
    incident = {
        "Incident_type" : incident_type,
        "Severity" : severity,
        "Username" : username,
        "IP" : ip,
        "Time_stamp" : time_stamp,
        "Command" : command,
        "Description" : description
    }
    incidents.append(incident)

def detect_after_hour_login(events):
    for event in events:
        ts = event["Time_stamp"]
        if ts and (ts.hour >= 22 or ts.hour < 5):
            if event["Event_type"] == "Authentication Success":
                create_incident("Suspicious Login",60,event["Username"],event["IP"],event["Time_stamp"],event["Command"],"Suspicious After Hour Login")

            elif event["Event_type"] == "Authentication Failure":
                create_incident("Suspicious Login Attempt",50,event["Username"],event["IP"],event["Time_stamp"],event["Command"],"Suspicious Failed After Hour Login")

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
                    create_incident("Brute Force Attempt",80,failed_by_ip[ip][0]["Username"],failed_by_ip[ip][0]["IP"],first_ts,failed_by_ip[ip][0]["Command"],"Possible brute force attempt, many login attempts under 2 minutes")

                failed_by_ip[ip]= []

    
  
   

                

           

    

    




        

