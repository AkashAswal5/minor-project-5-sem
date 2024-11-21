from scans.sql_scan import perform_sql_injection_scan
from scans.xss_scan import perform_xss_scan
from scans.port_scan import perform_open_port_scan

def perform_scan(url, scan_type):
    if scan_type == 'sql':
        return perform_sql_injection_scan(url)
    elif scan_type == 'xss':
        return perform_xss_scan(url)
    elif scan_type == 'port':
        return perform_open_port_scan(url)
    else:
        return "Invalid scan type selected."
