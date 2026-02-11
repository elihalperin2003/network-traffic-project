from checks import check_ip_external_addresses

def analyze_ip_external_addresses(file):
    return [line[1] for line in file if check_ip_external_addresses(line)]
