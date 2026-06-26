from inotify_simple import INotify,flags
import os
from datetime import datetime
from db import save_incident,db_ping

#flags
file_flags = (
        flags.MODIFY|
        flags.DELETE_SELF|
        flags.MOVE_SELF|
        flags.ATTRIB
    )
dir_flags = (
        flags.CREATE|
        flags.DELETE|
        flags.MOVED_TO|
        flags.MOVED_FROM|
        flags.ATTRIB
    )


#adding watcher to files or dir
def create_watch_map(watch_list,inotify,flag,watch_map):
    for (path,description,severity) in watch_list:
        if os.path.exists(path):
            watch_map[inotify.add_watch(path,flag)] = (path,description,severity)
        else:
            print("Path not Found")

file_watch_list = [
    ("/etc/passwd",               "File Tampering",          100),
    ("/etc/shadow",               "File Tampering",          100),
    ("/etc/sudoers",              "Privilege Escalation",    100),
    ("/etc/ssh/sshd_config",      "SSH Config Modification", 90),
    ("/etc/crontab",              "Persistence Attempt",     85),
    ("/etc/hosts",                "Host File Tampering",     75),
    ("/bin/bash",                 "Binary Tampering",        100),
    ]

dir_watch_list = [
    ("/root/.ssh",     "SSH Key Modification", 100),
    ("/tmp",           "Suspicious File Drop", 60),
    ]
watch_map = {}
inotify = INotify()

create_watch_map(file_watch_list,inotify,file_flags,watch_map)
create_watch_map(dir_watch_list,inotify,dir_flags,watch_map)

local_buffer = []
while True:
    events = inotify.read()
    for event in events:
        wd = event.wd
        if wd == -1:
            print("inotify queue overflow,some events maybe missed")
            continue
        time_stamp = datetime.now()
        (path,description,severity) = watch_map[wd]
        event_action =  ", ".join(f.name for f in flags.from_mask(event.mask))
        artifact = os.path.join(path,event.name) if event.name else path
        
        if db_ping():
            if local_buffer:
                for buffer in local_buffer:
                    save_incident(
                        buffer["source"],
                        buffer["incident_type"],
                        buffer["severity"],
                        buffer["description"],
                        buffer["username"],
                        buffer["ip"],
                        buffer["command"],
                        buffer["time_stamp"],
                        buffer["artifact"],
                        buffer["event_action"]
                    )
                local_buffer = []

            save_incident(
                    "inotify",
                    description,
                    severity,
                    f"{description} on {artifact}",
                    None,
                    None,
                    None,
                    time_stamp,
                    artifact,
                    event_action
                    )
        else:
            if len(local_buffer) > 10:
                print("Local buffer full,incident dropped")
            else:
                local_buffer.append({
                    "source" : "inotify",
                    "incident_type" : description,
                    "severity" : severity,
                    "description" : f"{description} on {artifact}",
                    "username" : None,
                    "ip" : None,
                    "command" : None,
                    "time_stamp" : time_stamp,
                    "artifact" : artifact,
                    "event_action" : event_action
            }   )

            






