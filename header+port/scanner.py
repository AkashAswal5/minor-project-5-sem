import socket
from threading import Thread, Lock

print_lock = Lock()

# Function to resolve hostname to IP address
def resolve_target(target):
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        return None

# Function to scan a single port
def scan_port(target_ip, port, result):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    connect_result = s.connect_ex((target_ip, port))
    with print_lock:
        if connect_result == 0:
            result.append(f"Port {port} is open on {target_ip}")
    s.close()

# Function to run port scan using multithreading
def port_scanner(target_ip, start_port, end_port, result):
    threads = []
    for port in range(start_port, end_port + 1):
        t = Thread(target=scan_port, args=(target_ip, port, result))
        threads.append(t)
        t.start()
    
    for thread in threads:
        thread.join()
