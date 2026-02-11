from checks import check_ip_external_addresses, check_port_sensitive


def analyze_ip_external_addresses(file):
    return [line[1] for line in file if check_ip_external_addresses(line)]


def analyze_port_sensitive(file):
    return [line[3] for line in file if check_port_sensitive(line)]
