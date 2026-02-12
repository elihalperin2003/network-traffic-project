from checks import check_ip_external_addresses, check_port_sensitive, check_large_packet, check_night_activity


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

# d = [["2024-01-15 00:00:29", "10.0.0.8", "10.0.0.7", "80", "HTTP", "762"],
#      ["2024-01-15 00:00:29", "10.0.0.8", "10.0.0.7", "443", "HTTPS", "762"],
#      ["2024-01-15 00:00:29", "18.0.0.8", "10.0.0.7", "443", "HTTPS", "762"],
#      ["2024-01-15 00:00:29", "18.0.0.8", "10.0.0.7", "80", "HTTP", "762"],
#      ["2024-01-15 00:00:29", "10.0.0.8", "10.0.0.7", "80", "HTTP", "762"],
#      ["2024-01-15 00:00:29", "10.0.0.8", "10.0.0.7", "22", "SSH", "762"],
#      ["2024-01-15 00:00:29", "10.5.0.8", "10.0.0.7", "22", "SSH", "762"],
#      ["2024-01-15 00:00:29", "20.0.0.8", "10.0.0.7", "80", "HTTP", "762"],
#
#      ]
# print(port_to_protocol_mapping(d))
