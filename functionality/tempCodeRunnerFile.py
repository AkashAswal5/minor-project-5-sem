from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import subprocess
import os

app = Flask(__name__)
app.secret_key = "PqrSt@Qw#@7&"

# Configure SQLAlchemy with SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    ip_address = db.Column(db.String(100), nullable=True)
    last_access_time = db.Column(db.DateTime, nullable=True)
    searches = db.relationship('Search', backref='user', lazy=True)

# Search model
class Search(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    search_term = db.Column(db.String(300), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Initialize the database
with app.app_context():
    db.create_all()

# Home page
@app.route("/")
def index():
    return render_template("index.html")

# User registration
@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]
    existing_user = User.query.filter_by(username=username).first()

    if existing_user:
        flash("Username already exists!")
        return redirect(url_for("index"))

    hashed_password = generate_password_hash(password)
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    flash("Registration successful! Please log in.")
    return redirect(url_for("index"))

# User login
@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]

    user = User.query.filter_by(username=username).first()

    if user and check_password_hash(user.password, password):
        user.ip_address = request.remote_addr
        user.last_access_time = datetime.utcnow()
        db.session.commit()

        session["user_id"] = user.id
        session["username"] = user.username
        flash("Login successful!")
        return redirect(url_for("dashboard"))
    else:
        flash("Invalid credentials!")
        return redirect(url_for("index"))

# User logout
@app.route("/logout")
def logout():
    session.pop("user_id", None)
    session.pop("username", None)
    flash("Logged out successfully!")
    return redirect(url_for("index"))

# Dashboard
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("index"))

    user_id = session["user_id"]
    user = User.query.get(user_id)
    searches = Search.query.filter_by(user_id=user_id).all()
    return render_template("dashboard.html", user=user, searches=searches)

# SQL Injection Scan
@app.route('/sql_injection', methods=['GET', 'POST'])
def sql_injection():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    scan_results = None
    if request.method == 'POST':
        target_url = request.form.get('target_url')
        command = ['sqlmap', '-u', target_url, '--batch']

        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=600)
            scan_results = result.stdout
        except Exception as e:
            scan_results = f"Error running SQLmap: {str(e)}"

    return render_template('sql_injection.html', scan_results=scan_results)

# XSS Scan
@app.route('/xss_scan', methods=['POST', 'GET'])
def xss_scan():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    scan_results = None
    if request.method == 'POST':
        target_url = request.form.get('target_url')
        payload = "<script>alert('XSS')</script>"
        scanned_url = f"{target_url}?q={payload}"

        try:
            scan_results = f"Scanned URL: {scanned_url}\nPayload: {payload}\nOutcome: Simulation complete."
        except Exception as e:
            scan_results = f"Error during XSS simulation: {str(e)}"

    return render_template('xss_scan.html', scan_results=scan_results)

# Open Port Scan
@app.route('/port_scan', methods=['GET', 'POST'])
def port_scan():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    scan_results = None

    if request.method == 'POST':
        target_ip = request.form.get('target_ip')

        # Command to run Nmap for basic port scanning
        try:
            command = ['nmap', '-sT', '-F', target_ip]  # '-sT' for TCP connect scan, '-F' for faster scanning
            result = subprocess.run(command, capture_output=True, text=True, timeout=600)
            scan_results = result.stdout
        except Exception as e:
            scan_results = f"Error scanning ports: {str(e)}"

    return render_template('port_scan.html', scan_results=scan_results)

# Security Header Scan Route
@app.route('/header_scan', methods=['POST'])
def security_headers_scan():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    url = request.form.get('url')
    if not url:
        flash("URL is required!")
        return redirect(url_for('dashboard'))

    # Scan security headers using the imported function
    header_results = security_header(url)
    return render_template('securit_headers_report.html', header_results=header_results)

# Learning dashboard routes
@app.route("/learning_dashboard")
def learning_dashboard():
    return render_template("learning_dashboard.html")

@app.route("/learning_box/youtube_links")
def youtube_links():
    return render_template("learning_box/youtube_links.html")

@app.route("/learning_box/important_links")
def important_links():
    return render_template("learning_box/important_links.html")

@app.route("/learning_box/notes")
def notes():
    return render_template("learning_box/notes.html")

@app.route("/learning_box/tryhackme")
def tryhackme():
    return render_template("learning_box/tryhackme.html")

@app.route('/perform_scan', methods=['POST'])
def perform_scan_route():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Get form data
    url = request.form.get('url')
    scan_type = request.form.get('scan_type')
    user_id = session['user_id']

    # Check if required data is present
    if not url or not scan_type:
        flash("URL and scan type are required.")
        return redirect(url_for('dashboard'))

    try:
        # Perform the scan
        scan_results = perform_scan(url, scan_type)

        # Save the search to the database
        new_search = Search(search_term=f"{url} ({scan_type})", user_id=user_id)
        db.session.add(new_search)
        db.session.commit()

        flash(f"{scan_type.capitalize()} scan completed.")
    except Exception as e:
        flash(f"Error during scan: {str(e)}")
        scan_results = None

    # Render the dashboard with scan results
    user = User.query.get(user_id)
    searches = Search.query.filter_by(user_id=user_id).all()
    return render_template('dashboard.html', user=user, searches=searches, scan_results=scan_results)



if __name__ == "__main__":
    app.run(debug=True)

