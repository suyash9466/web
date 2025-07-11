import os
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from flask import Flask, request, render_template, jsonify, session
import datetime

app = Flask(__name__, template_folder="templates")

# Set a secret key for session management
app.secret_key = os.environ.get('SECRET_KEY', 'default-secret-key')

class AdvancedVulnerabilityScanner:
    def __init__(self, target_url):
        # Validate URL format
        parsed = urlparse(target_url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("Invalid URL format")
        
        self.target_url = target_url if target_url.endswith('/') else target_url + '/'
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "Mozilla/5.0"
        self.vulnerabilities = []

    def load_wordlist(self, path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[!] Wordlist not found: {path}")
            return []
        except Exception as e:
            print(f"[!] Error loading wordlist: {e}")
            return []

    def get_all_forms(self, url):
        try:
            res = self.session.get(url, timeout=10)
            soup = BeautifulSoup(res.content, "html.parser")
            return soup.find_all("form")
        except Exception as e:
            print(f"[!] Error getting forms: {e}")
            return []

    def submit_form(self, form, payload, url):
        try:
            action = form.attrs.get("action", "").lower()
            method = form.attrs.get("method", "get").lower()
            inputs = form.find_all("input")
            form_data = {}
            for input in inputs:
                name = input.attrs.get("name")
                input_type = input.attrs.get("type", "text")
                value = input.attrs.get("value", "")
                if input_type in ["text", "search", "password", "email"]:
                    value = payload
                if name:
                    form_data[name] = value
            target = urljoin(url, action)
            if method == "post":
                return self.session.post(target, data=form_data, timeout=10)
            return self.session.get(target, params=form_data, timeout=10)
        except Exception as e:
            print(f"[!] Error submitting form: {e}")
            return None

    def check_xss(self):
        payloads = self.load_wordlist("wordlists/xss.txt")
        if not payloads: return
        
        for payload in payloads:
            forms = self.get_all_forms(self.target_url)
            for form in forms:
                res = self.submit_form(form, payload, self.target_url)
                if res and payload in res.text:
                    self.vulnerabilities.append({"type": "XSS", "payload": payload})

    def check_sql_injection(self):
        payloads = self.load_wordlist("wordlists/sqli.txt")
        if not payloads: return
        
        errors = ["sql syntax", "mysql_fetch", "ORA-", "unclosed quotation", "syntax error"]
        for payload in payloads:
            forms = self.get_all_forms(self.target_url)
            for form in forms:
                res = self.submit_form(form, payload, self.target_url)
                if res and any(err in res.text.lower() for err in errors):
                    self.vulnerabilities.append({"type": "SQL Injection", "payload": payload})

    def check_csrf(self):
        forms = self.get_all_forms(self.target_url)
        for form in forms:
            inputs = form.find_all("input")
            if not any("csrf" in (i.attrs.get("name") or "").lower() for i in inputs):
                self.vulnerabilities.append({"type": "CSRF", "detail": "No CSRF token found."})

    def check_command_injection(self):
        payloads = self.load_wordlist("wordlists/command_injection.txt")
        if not payloads: return
        
        indicators = ["uid=", "gid=", "root", "user", "windows", "linux", "darwin"]
        for payload in payloads:
            forms = self.get_all_forms(self.target_url)
            for form in forms:
                res = self.submit_form(form, payload, self.target_url)
                if res and any(ind in res.text.lower() for ind in indicators):
                    self.vulnerabilities.append({"type": "Command Injection", "payload": payload})

    def check_directory_traversal(self):
        payloads = self.load_wordlist("wordlists/directory_traversal.txt")
        if not payloads: return
        
        for payload in payloads:
            try:
                res = self.session.get(self.target_url + payload, timeout=10)
                if "root:x" in res.text or "[extensions]" in res.text:
                    self.vulnerabilities.append({"type": "Directory Traversal", "payload": payload})
            except:
                continue

    def check_open_redirect(self):
        payloads = self.load_wordlist("wordlists/open_redirect.txt")
        if not payloads: return
        
        for payload in payloads:
            try:
                redirect_url = f"{self.target_url}?next={payload}"
                res = self.session.get(redirect_url, allow_redirects=False, timeout=10)
                if res.status_code in [301, 302] and payload.replace("//", "") in res.headers.get("Location", ""):
                    self.vulnerabilities.append({"type": "Open Redirect", "payload": payload})
            except:
                continue

    def check_auth_bypass(self):
        paths = self.load_wordlist("wordlists/auth_bypass.txt")
        if not paths: return
        
        for path in paths:
            try:
                res = self.session.get(urljoin(self.target_url, path), timeout=10)
                if res.status_code == 200 and ("Welcome" in res.text or "admin" in res.text):
                    self.vulnerabilities.append({"type": "Auth Bypass", "url": path})
            except:
                continue

    def check_clickjacking(self):
        try:
            res = self.session.get(self.target_url, timeout=10)
            if "x-frame-options" not in res.headers:
                self.vulnerabilities.append({"type": "Clickjacking", "detail": "Missing X-Frame-Options header."})
        except:
            return

    def check_security_headers(self):
        try:
            res = self.session.get(self.target_url, timeout=10)
            headers = ["X-Frame-Options", "Content-Security-Policy", "X-XSS-Protection", "Strict-Transport-Security"]
            for h in headers:
                if h not in res.headers:
                    self.vulnerabilities.append({"type": "Missing Security Header", "header": h})
        except:
            return

    def check_info_disclosure(self):
        paths = self.load_wordlist("wordlists/info_disclosure_paths.txt")
        if not paths: return
        
        for path in paths:
            try:
                res = self.session.get(urljoin(self.target_url, path), timeout=10)
                if res.status_code == 200 and any(ext in path for ext in [".git", ".svn", ".bak", ".zip", ".env"]):
                    self.vulnerabilities.append({"type": "Info Disclosure", "url": path})
            except:
                continue

    def check_crlf_injection(self):
        payloads = self.load_wordlist("wordlists/crlf.txt")
        if not payloads: return
        
        for payload in payloads:
            try:
                res = self.session.get(self.target_url + payload, timeout=10)
                if "injected" in res.headers.get("Set-Cookie", ""):
                    self.vulnerabilities.append({"type": "CRLF Injection", "payload": payload})
            except:
                continue

    def scan(self):
        # Run all checks with try-except to prevent single failure from stopping entire scan
        checks = [
            self.check_xss,
            self.check_sql_injection,
            self.check_csrf,
            self.check_command_injection,
            self.check_directory_traversal,
            self.check_crlf_injection,
            self.check_open_redirect,
            self.check_auth_bypass,
            self.check_clickjacking,
            self.check_info_disclosure,
            self.check_security_headers
        ]
        
        for check in checks:
            try:
                check()
            except Exception as e:
                print(f"[!] Check failed: {e}")
                continue

        return self.vulnerabilities

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/scan', methods=['POST'])
def scan_api():
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({"error": "URL missing"}), 400
            
        scanner = AdvancedVulnerabilityScanner(data['url'])
        vulnerabilities = scanner.scan()
        
        # Store results in session
        session['vulnerabilities'] = vulnerabilities
        session['scan_url'] = data['url']
        session['scan_time'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        return jsonify({
            "redirect": "/results"
        })
        
    except Exception as e:
        return jsonify({
            "error": "Scan failed",
            "details": str(e)
        }), 500

@app.route('/results')
def results():
    return render_template(
        "results.html",
        vulnerabilities=session.get('vulnerabilities', []),
        scan_url=session.get('scan_url', 'Unknown URL'),
        scan_time=session.get('scan_time', 'Unknown time')
    )

if __name__ == '__main__':
    # Use environment variable for debug mode
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=debug_mode, host='0.0.0.0', port=port)
