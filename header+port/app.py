from flask import Flask, render_template, request, jsonify
from scanner import port_scanner, resolve_target
from security import scan_security_headers
import threading

app = Flask(__name__)

# Route for homepage
@app.route('/')
def index():
    return render_template('index.html')



# Route for port scanner
@app.route('/port_scan', methods=['POST'])
def port_scan():
    target = request.form['target']
    start_port = int(request.form['start_port'])
    end_port = int(request.form['end_port'])
    
    
    # Resolve target IP
    target_ip = resolve_target(target)
    if not target_ip:
        return jsonify({"error": f"Unable to resolve {target}"}), 400

    # Running port scanner in a separate thread (non-blocking)
    result = []
    thread = threading.Thread(target=lambda: port_scanner(target_ip, start_port, end_port, result))
    thread.start()
    thread.join()

    return jsonify(result)

# Route for scanning security headers
@app.route('/scan', methods=['POST'])
def scan():
    url = request.form['url']
    header_results = scan_security_headers(url)
    return jsonify(header_results)

if __name__ == "__main__":
    app.run(port=5001, debug=True)
