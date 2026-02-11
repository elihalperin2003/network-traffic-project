from config import EXTERNAL_IP

def check_ip_external_addresses(line):
    if not any(line[1].startswith(_) for _ in EXTERNAL_IP):
        return True
    return False
