from flask import Flask, render_template, request, jsonify
import requests
from datetime import datetime
from urllib.parse import urlparse

app = Flask(__name__)

security_headers = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Permissions-Policy",
    "X-XSS-Protection",
    "Referrer-Policy",
]

upcoming_headers = [
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
]

def scan_security_headers(url):
    try:
        # Get current date and time
        report_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        # Send request and fetch headers
        response = requests.get(url)
        headers = response.headers

        # Gather basic info
        site_info = {
            "site": url,
            "ip_address": requests.get(f"https://api.ipify.org?domain={urlparse(url).hostname}").text,
            "report_time": report_time,
        }

        # Check for missing headers
        missing_headers = []
        for header in security_headers:
            if header not in headers:
                missing_headers.append(header)

        # Prepare detailed report
        detailed_report = {
            "site_info": site_info,
            "headers_found": {header: headers.get(header, "N/A") for header in security_headers},
            "missing_headers": missing_headers,
            "warnings": [],
            "raw_headers": dict(headers),
            "upcoming_headers": upcoming_headers,
            "additional_info": {
                "server": headers.get("Server", "N/A"),
                "access_control_allow_origin": headers.get("Access-Control-Allow-Origin", "N/A"),
                "cookies": headers.get("Set-Cookie", "N/A"),
            },
        }

        # Check for header-specific warnings or recommendations
        if headers.get("Referrer-Policy") and headers.get("Referrer-Policy") != "no-referrer":
            detailed_report["warnings"].append("The 'origin-when-cross-origin' value is not recommended for Referrer-Policy.")

        return detailed_report

    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

# Route for homepage
@app.route('/')
def index():
    return render_template('index.html')

# Route for scanning headers
@app.route('/scan', methods=['POST'])
def scan():
    url = request.form['url']
    header_results = scan_security_headers(url)
    return jsonify(header_results)

if __name__ == "__main__":
    app.run(debug=True , port=5003)
