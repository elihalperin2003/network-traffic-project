from checks import check_ip_external_addresses, check_port_sensitive, check_large_packet, check_night_activity, \
    check_hour
from collections import defaultdict


def analyze_ip_external_addresses(file):
    return [line[1] for line in file if check_ip_external_addresses(line)]


def analyze_port_sensitive(file):
    return [line for line in file if check_port_sensitive(line)]


def analyze_large_packet(file):
    return [line for line in file if check_large_packet(line)]


def analyze_night_activity(file):
    return [line for line in file if check_night_activity(line)]


def labeling_size_packet(file):
    return [line.append("LARGE") if check_large_packet(line) else line.append("NORMAL") for line in file]


def len_ip_addresses(file):
    ip_addresses = [line[1] for line in file]
    return {ip: ip_addresses.count(ip) for ip in set(ip_addresses)}


def port_to_protocol_mapping(file):
    return {line[3]: line[4] for line in file}


def suspicious_detection_for_ips(file):
    checks = [["EXTERNAL_IP", check_ip_external_addresses], ["SENSITIVE_PORT", check_port_sensitive],
              ["LARGE_PACKET", check_large_packet], ["NIGHT_ACTIVITY", check_night_activity]]
    suspicion_report = defaultdict(set)
    for line in file:
        for suspicion_name, check_func in checks:
            if check_func(line):
                suspicion_report[line[1]].add(suspicion_name)
    return {ip: list(suspicions) for ip, suspicions in suspicion_report.items() if suspicions}


def filtering_2_suspicions(file):
    return {ip: suspicions for ip, suspicions in suspicious_detection_for_ips(file).items() if len(suspicions) >= 2}


def finding_hour(file):
    return list(map(lambda line: check_hour(line), file))


def package_size_conversion(bytes_line):
    return list(map(lambda bites: round(bites / 1024, 1), bytes_line))


def analyze_port_sensitive_lambda(file):
    return list(filter(lambda line: check_port_sensitive(line), file))


def analyze_night_activity_lambda(file):
    return list(filter(lambda line: check_night_activity(line), file))

# d = [["2024-01-15 08:00:29", "10.1.0.8", "10.0.0.7", "54", "HTTP", "762"],
#      ["2024-01-15 03:00:29", "10.1.0.8", "10.0.0.7", "80", "HTTP", "762"],
#      ["2024-01-15 03:00:29", "10.2.0.8", "10.0.0.7", "80", "HTTP", "50000"],
#      ["2024-01-15 03:00:29", "10.1.0.8", "10.0.0.7", "80", "HTTP", "762"],
#      ["2024-01-15 03:00:29", "10.4.0.8", "10.0.0.7", "80", "HTTP", "10000"]
#      ]
#
# dd = [["2024-01-15 09:00:29", "10.1.0.8", "10.0.0.7", "23", "HTTP", "762"],
#       ["2024-01-15 08:02:29", "10.2.0.8", "10.0.0.7", "338", "HTTP", "76200"]]
# print(analyze_night_activity_lambda(dd))
