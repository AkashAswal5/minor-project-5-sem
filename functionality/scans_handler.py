from scans.sql_scan import perform_sql_injection_scan
from scans.xss_scan import perform_xss_scan
from scans.malware_scan import perform_malware_scan
from scans.port_scan import perform_open_port_scan

def perform_scan(url, scan_type):
    scan_results = ""

    if scan_type == 'sql':
        scan_results = perform_sql_injection_scan(url)
    elif scan_type == 'xss':
        scan_results = perform_xss_scan(url)
    elif scan_type == 'malware':
        scan_results = perform_malware_scan(url)
    elif scan_type == 'port':
        scan_results = perform_open_port_scan(url)

    return scan_results
