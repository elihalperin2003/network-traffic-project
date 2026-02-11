from config import EXTERNAL_IP, SENSITIVE_PORT, LARGE_PACKET

def check_ip_external_addresses(line):
    if not any(line[1].startswith(_) for _ in EXTERNAL_IP):
        return True
    return False

def check_port_sensitive(line):
    if line[3] in SENSITIVE_PORT:
        return True
    return False

def check_large_packet(line):
    if line[5] > LARGE_PACKET:
        return True
    return False