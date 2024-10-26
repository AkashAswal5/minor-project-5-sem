from flask import Flask, render_template, request, jsonify
import requests
from bs4 import BeautifulSoup
import socket
from threading import Thread, Lock

app = Flask(__name__)

# SQL injection payloads to test
sql_payloads = [
    "' OR 1=1 --",
    "' OR 'a'='a",
    "' OR ''='",
    "' OR 1=1 LIMIT 1 --",
    "' OR SLEEP(5) --",
    "' UNION SELECT NULL, NULL --"
]

def find_input_fields(html):
    """
    Find all input fields from the HTML and their corresponding forms.
    """
    soup = BeautifulSoup(html, 'html.parser')
    forms = soup.find_all('form')
    fields = []

    for form in forms:
        action = form.get('action')
        method = form.get('method', 'get').lower()
        inputs = form.find_all('input')
        for input_field in inputs:
            name = input_field.get('name')
            if name:
                fields.append({'name': name, 'action': action, 'method': method})
    
    return fields

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan/sql', methods=['POST'])
def scan_sql_injection():
    data = request.get_json()
    target_url = data.get('url')

    try:
        # Send initial GET request to get the form and input fields
        response = requests.get(target_url)
        input_fields = find_input_fields(response.text)

        vulnerabilities = []
        for input_field in input_fields:
            action = input_field['action']
            method = input_field['method']
            name = input_field['name']

            # Test SQL injection for each payload
            for payload in sql_payloads:
                if method == 'get':
                    params = {name: payload}
                    test_url = f"{target_url.rstrip('/')}/{action.lstrip('/')}"
                    response = requests.get(test_url, params=params)
                else:  # POST request
                    data = {name: payload}
                    test_url = f"{target_url.rstrip('/')}/{action.lstrip('/')}"
                    response = requests.post(test_url, data=data)

                # Simple logic to detect SQL vulnerability (based on errors in the response)
                if "error" in response.text.lower() or "syntax" in response.text.lower():
                    vulnerabilities.append(f"Potential vulnerability in field '{name}' with payload '{payload}'.")

        if vulnerabilities:
            return jsonify({"vulnerable": True, "vulnerabilities": vulnerabilities})
        else:
            return jsonify({"vulnerable": False, "vulnerabilities": []})

    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/scan/xss', methods=['POST'])
def scan_xss():
    url = request.json.get('url')
    # Here you would integrate your XSS scanning logic
    result = f"XSS scan results for {url}: Vulnerability found!"
    return jsonify({'result': result})

@app.route('/scan/command', methods=['POST'])
def scan_command_injection():
    url = request.json.get('url')
    # Here you would integrate your command injection scanning logic
    result = f"Command Injection scan results for {url}: No vulnerabilities found."
    return jsonify({'result': result})

@app.route('/scan/port', methods=['POST'])
def scan_ports():
    data = request.get_json()
    target = data.get('url')
    start_port = 1
    end_port = 65535

    # Lock for thread-safe printing
    print_lock = Lock()
    open_ports = []

    # Function to scan a single port
    def scan_port(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)  # Timeout for each connection attempt
        result = s.connect_ex((target, port))  # Returns 0 if port is open
        with print_lock:
            if result == 0:
                open_ports.append(port)
        
        s.close()

    # Function to run port scan using multithreading
    def port_scanner(start_port, end_port):
        threads = []
        for port in range(start_port, end_port + 1):
            t = Thread(target=scan_port, args=(port,))
            threads.append(t)
            t.start()
        
        # Wait for all threads to finish
        for thread in threads:
            thread.join()

    try:
        port_scanner(start_port, end_port)
        return jsonify({'result': f'Port scan results for {target}: Open ports: {open_ports}'})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/scan/security-headers', methods=['POST'])
def scan_security_headers():
    url = request.json.get('url')
    # Here you would integrate your security header scanning logic
    result = f"Security headers for {url}: X-Content-Type-Options: nosniff; Content-Security-Policy: default-src 'self';"
    return jsonify({'result': result})

if __name__ == '__main__':
    app.run(debug=True)
from flask import Flask, render_template, request, jsonify
import requests
from bs4 import BeautifulSoup
import socket
from threading import Thread, Lock

app = Flask(__name__)

# SQL injection payloads to test
sql_payloads = [
    "' OR 1=1 --",
    "' OR 'a'='a",
    "' OR ''='",
    "' OR 1=1 LIMIT 1 --",
    "' OR SLEEP(5) --",
    "' UNION SELECT NULL, NULL --"
]

# XSS payloads to test
xss_payloads = [
    "<script>alert('XSS');</script>",
    "<img src=x onerror=alert('XSS')>",
    "';!--\"<XSS>=&{()}"
]

# Command injection payloads to test
command_payloads = [
    "; ls",
    "| ls",
    "&& ls",
    "; whoami",
    "&& whoami"
]

def find_input_fields(html):
    """Find all input fields from the HTML and their corresponding forms."""
    soup = BeautifulSoup(html, 'html.parser')
    forms = soup.find_all('form')
    fields = []

    for form in forms:
        action = form.get('action')
        method = form.get('method', 'get').lower()
        inputs = form.find_all('input')
        for input_field in inputs:
            name = input_field.get('name')
            if name:
                fields.append({'name': name, 'action': action, 'method': method})
    
    return fields

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan/sql', methods=['POST'])
def scan_sql_injection():
    data = request.get_json()
    target_url = data.get('url')

    try:
        # Send initial GET request to get the form and input fields
        response = requests.get(target_url)
        input_fields = find_input_fields(response.text)

        vulnerabilities = []
        for input_field in input_fields:
            action = input_field['action']
            method = input_field['method']
            name = input_field['name']

            # Test SQL injection for each payload
            for payload in sql_payloads:
                if method == 'get':
                    params = {name: payload}
                    test_url = f"{target_url.rstrip('/')}/{action.lstrip('/')}"
                    response = requests.get(test_url, params=params)
                else:  # POST request
                    data = {name: payload}
                    test_url = f"{target_url.rstrip('/')}/{action.lstrip('/')}"
                    response = requests.post(test_url, data=data)

                # Detect SQL vulnerability (based on errors in the response)
                if "error" in response.text.lower() or "syntax" in response.text.lower():
                    vulnerabilities.append(f"Potential vulnerability in field '{name}' with payload '{payload}'.")

        if vulnerabilities:
            return jsonify({"vulnerable": True, "vulnerabilities": vulnerabilities})
        else:
            return jsonify({"vulnerable": False, "vulnerabilities": []})

    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/scan/xss', methods=['POST'])
def scan_xss():
    data = request.get_json()
    target_url = data.get('url')

    try:
        # Send initial GET request to get the form and input fields
        response = requests.get(target_url)
        input_fields = find_input_fields(response.text)

        vulnerabilities = []
        for input_field in input_fields:
            action = input_field['action']
            method = input_field['method']
            name = input_field['name']

            for payload in xss_payloads:
                if method == 'get':
                    params = {name: payload}
                    test_url = f"{target_url.rstrip('/')}/{action.lstrip('/')}"
                    response = requests.get(test_url, params=params)
                else:  # POST request
                    data = {name: payload}
                    test_url = f"{target_url.rstrip('/')}/{action.lstrip('/')}"
                    response = requests.post(test_url, data=data)

                # Check if payload is reflected in the response
                if payload in response.text:
                    vulnerabilities.append(f"Potential XSS vulnerability in field '{name}' with payload '{payload}'.")

        if vulnerabilities:
            return jsonify({"vulnerable": True, "vulnerabilities": vulnerabilities})
        else:
            return jsonify({"vulnerable": False, "vulnerabilities": []})

    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/scan/command', methods=['POST'])
def scan_command_injection():
    data = request.get_json()
    target_url = data.get('url')

    try:
        # Send initial GET request to get the form and input fields
        response = requests.get(target_url)
        input_fields = find_input_fields(response.text)

        vulnerabilities = []
        for input_field in input_fields:
            action = input_field['action']
            method = input_field['method']
            name = input_field['name']

            for payload in command_payloads:
                if method == 'get':
                    params = {name: payload}
                    test_url = f"{target_url.rstrip('/')}/{action.lstrip('/')}"
                    response = requests.get(test_url, params=params)
                else:  # POST request
                    data = {name: payload}
                    test_url = f"{target_url.rstrip('/')}/{action.lstrip('/')}"
                    response = requests.post(test_url, data=data)

                # Check if the response contains indications of command execution (adjust as necessary)
                if "root" in response.text or "bin" in response.text:  # Customize this check based on your context
                    vulnerabilities.append(f"Potential command injection vulnerability in field '{name}' with payload '{payload}'.")

        if vulnerabilities:
            return jsonify({"vulnerable": True, "vulnerabilities": vulnerabilities})
        else:
            return jsonify({"vulnerable": False, "vulnerabilities": []})

    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/scan/port', methods=['POST'])
def scan_ports():
    data = request.get_json()
    target = data.get('url')
    start_port = 1
    end_port = 65535

    # Lock for thread-safe printing
    print_lock = Lock()
    open_ports = []

    # Function to scan a single port
    def scan_port(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)  # Timeout for each connection attempt
        result = s.connect_ex((target, port))  # Returns 0 if port is open
        with print_lock:
            if result == 0:
                open_ports.append(port)
        
        s.close()

    # Function to run port scan using multithreading
    def port_scanner(start_port, end_port):
        threads = []
        for port in range(start_port, end_port + 1):
            t = Thread(target=scan_port, args=(port,))
            threads.append(t)
            t.start()
        
        # Wait for all threads to finish
        for thread in threads:
            thread.join()

    try:
        port_scanner(start_port, end_port)
        return jsonify({'result': f'Port scan results for {target}: Open ports: {open_ports}'})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/scan/security-headers', methods=['POST'])
def scan_security_headers():
    url = request.json.get('url')
    try:
        response = requests.get(url)
        security_headers = {
            "X-Content-Type-Options": response.headers.get("X-Content-Type-Options"),
            "X-XSS-Protection": response.headers.get("X-XSS-Protection"),
            "Content-Security-Policy": response.headers.get("Content-Security-Policy"),
            "Strict-Transport-Security": response.headers.get("Strict-Transport-Security"),
            "X-Frame-Options": response.headers.get("X-Frame-Options"),
        }
        return jsonify({'security_headers': security_headers})
    except Exception as e:
        return jsonify({"error": str(e)})

if __name__ == '__main__':
    app.run(debug=True)
