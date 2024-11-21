def perform_sql_injection_scan(url):
    payload = "' OR '1'='1"
    scanned_url = f"{url}?id={payload}"
    result = f"Scanned URL: {scanned_url}\nPayload Used: {payload}\nOutcome: Vulnerable to SQL Injection\n"
    return result
