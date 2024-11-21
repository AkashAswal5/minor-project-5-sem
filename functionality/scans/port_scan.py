import socket

def perform_open_port_scan(ip):
    open_ports = []
    for port in range(20, 1025):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
    result = f"Target IP: {ip}\nOpen Ports: {', '.join(map(str, open_ports))}\n"
    return result
