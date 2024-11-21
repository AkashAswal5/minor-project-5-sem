import socket
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import concurrent.futures
import subprocess
import json

def scan_with_nmap(target_ip):
    """
    Use Nmap to perform a port scan on the target IP.
    """
    try:
        # Run Nmap scan with options to detect open ports
        nmap_command = ["nmap", "-p", "1-65535", "--open", "-oX", "-", target_ip]
        result = subprocess.run(nmap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        nmap_output = result.stdout.decode("utf-8")

        # Parse XML output (can use xml.etree.ElementTree for parsing)
        return {"scan_results": nmap_output}

    except Exception as e:
        return {"error": str(e)}

app = Flask(__name__)
CORS(app)

# List of common ports to scan
common_ports = [21, 22, 23, 25, 53, 80, 443, 8080, 3306, 5432]

@app.route('/')
def index():
    return render_template('index.html')  # Assuming a basic HTML interface

def scan_port(target_ip, port):
    """
    Scans a single port on the target IP address to check if it's open.
    """
    try:
        # Create a socket object
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # 1 second timeout
        result = sock.connect_ex((target_ip, port))  # Returns 0 if port is open
        sock.close()
        
        if result == 0:
            return {"port": port, "status": "open"}
        else:
            return {"port": port, "status": "closed"}
    
    except socket.error as e:
        return {"port": port, "status": "error", "message": str(e)}

@app.route('/scan_ports', methods=['POST'])
def scan_ports():
    """
    Endpoint to scan for open ports on a given target IP.
    """
    data = request.get_json()
    target_ip = data.get('ip')  # IP to scan (can be passed in the request body)

    if not target_ip:
        return jsonify({"error": "IP address is required."}), 400

    results = []
    
    # Perform the scan in parallel using ThreadPoolExecutor
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_port = {executor.submit(scan_port, target_ip, port): port for port in common_ports}
        for future in concurrent.futures.as_completed(future_to_port):
            result = future.result()
            results.append(result)

    return jsonify({"target_ip": target_ip, "scan_results": results})

if __name__ == '__main__':
    app.run(debug=True, port=5001)
