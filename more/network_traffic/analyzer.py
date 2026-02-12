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