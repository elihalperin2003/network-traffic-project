from config import EXTERNAL_IP, SENSITIVE_PORT, LARGE_PACKET, NIGHT_ACTIVITY
from datetime import datetime


def check_ip_external_addresses(line):
    if not any(line[1].startswith(_) for _ in EXTERNAL_IP):
        return True
    return False


def check_port_sensitive(line):
    if line[3] in SENSITIVE_PORT:
        return True
    return False


def check_large_packet(line):
    if int(line[5]) > LARGE_PACKET:
        return True
    return False


def check_night_activity(line):
    def sum_minute(time):
        return (time.hour * 60) + time.minute

    hour_line = datetime.strptime(line[0], "%Y-%m-%d %H:%M:%S")
    start = datetime.strptime(NIGHT_ACTIVITY["start"], "%H:%M")
    end = datetime.strptime(NIGHT_ACTIVITY["end"], "%H:%M")
    if sum_minute(start) < sum_minute(hour_line) < sum_minute(end):
        return True
    return False


def check_hour(line):
    hour_line = datetime.strptime(line[0], "%Y-%m-%d %H:%M:%S")
    return hour_line.hour


def check_suspicious_detection(line):
    suspicion_checks = {"EXTERNAL_IP": lambda line: check_ip_external_addresses(line),
                        "SENSITIVE_PORT": lambda line: check_port_sensitive(line),
                        "LARGE_PACKET": lambda line: check_large_packet(line),
                        "NIGHT_ACTIVITY": lambda line: check_night_activity(line)}
    return list(filter(lambda key: suspicion_checks[key](line), suspicion_checks))

# c = ["2024-01-15 04:01:00","192.168.1.100","10.0.0.5","443","HTTPS","10204"]
# print(check_suspicious_detection(c))
#כינגזירגי