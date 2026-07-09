from datetime import datetime
import bisect

first_day = {
    "NTP": ("2018-01-12 10:35", "2018-01-12 10:45"),
    "DNS": ("2018-01-12 10:52", "2018-01-12 11:05"),
    "LDAP": ("2018-01-12 11:22", "2018-01-12 11:32"),
    "MSSQL": ("2018-01-12 11:36", "2018-01-12 11:45"),
    "NetBIOS": ("2018-01-12 11:50", "2018-01-12 12:00"),
    "SNMP": ("2018-01-12 12:12", "2018-01-12 12:23"),
    "SSDP": ("2018-01-12 12:27", "2018-01-12 12:37"),
    "UDP": ("2018-01-12 12:45", "2018-01-12 13:09"),
    "UDP-Lag": ("2018-01-12 13:11", "2018-01-12 13:15"),
    "WebDDoS": ("2018-01-12 13:18", "2018-01-12 13:29"),
    "SYN": ("2018-01-12 13:29", "2018-01-12 13:34"),
    "TFTP": ("2018-01-12 13:35", "2018-01-12 17:15"),
}

second_day = {
    "PortMap": ("2018-03-11 09:43", "2018-03-11 09:51"),
    "NetBIOS": ("2018-03-11 10:00", "2018-03-11 10:09"),
    "LDAP": ("2018-03-11 10:21", "2018-03-11 10:30"),
    "MSSQL": ("2018-03-11 10:33", "2018-03-11 10:42"),
    "UDP": ("2018-03-11 10:53", "2018-03-11 11:03"),
    "UDP-Lag": ("2018-03-11 11:14", "2018-03-11 11:24"),
    "SYN": ("2018-03-11 11:28", "2018-03-11 17:35"),
}

victim_ips = {
    "192.168.50.1",
    "192.168.50.4",
    "205.174.165.81",
    "192.168.50.8",
    "192.168.50.5",
    "192.168.50.6",
    "192.168.50.7",
    "192.168.50.9"
}

def convert_to_float(day_dict):
    converted = {}
    for attack, time_range in day_dict.items():
        start_dt = datetime.strptime(time_range[0], "%Y-%m-%d %H:%M")
        end_dt = datetime.strptime(time_range[1], "%Y-%m-%d %H:%M")
        converted[attack] = (start_dt.timestamp(), end_dt.timestamp())
    return converted

def create_sorted_attack_list(day_dict_float):
    """Create a sorted list of (start_time, end_time, attack_name)"""
    attacks = []
    for attack, (start, end) in day_dict_float.items():
        attacks.append((start, end, attack))
    attacks.sort(key=lambda x: x[0])
    return attacks

# Pre-convert and pre-sort both days for efficiency
first_day_float = convert_to_float(first_day)
second_day_float = convert_to_float(second_day)
first_day_attacks = create_sorted_attack_list(first_day_float)
second_day_attacks = create_sorted_attack_list(second_day_float)

def get_attack(timestamp,src_ip):

    if src_ip in victim_ips:
        return "Benign"

    dt = datetime.fromtimestamp(timestamp)
    date_str = dt.strftime("%Y-%m-%d")
    
    # Choose which day's attacks to search
    if date_str == "2018-01-12":
        attacks = first_day_attacks
    elif date_str == "2018-03-11":
        attacks = second_day_attacks
    else:
        return "Benign" 
    
    start_times = [attack[0] for attack in attacks]
    idx = bisect.bisect_right(start_times, timestamp) - 1
    
    if idx >= 0:
        start_time, end_time, attack_name = attacks[idx]
        if start_time <= timestamp <= end_time:
            
            return attack_name 
    
    return "Benign"  