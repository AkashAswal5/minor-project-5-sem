import requests
from datetime import datetime
from urllib.parse import urlparse

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
        report_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        response = requests.get(url)
        headers = response.headers

        site_info = {
            "site": url,
            "ip_address": requests.get(f"https://api.ipify.org?domain={urlparse(url).hostname}").text,
            "report_time": report_time,
        }

        missing_headers = [header for header in security_headers if header not in headers]

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

        if headers.get("Referrer-Policy") and headers.get("Referrer-Policy") != "no-referrer":
            detailed_report["warnings"].append(
                "The 'origin-when-cross-origin' value is not recommended for Referrer-Policy."
            )

        return detailed_report

    except requests.exceptions.RequestException as e:
        return {"error": str(e)}
