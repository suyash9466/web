import os
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from flask import Flask, request, render_template, jsonify

app = Flask(__name__, template_folder="templates")

class AdvancedVulnerabilityScanner:
    def __init__(self, target_url):
        # Validate and format URL
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

    def get_all_forms(self, url):
        try:
            res = self.session.get(url)
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
                return self.session.post(target, data=form_data)
            return self.session.get(target, params=form_data)
        except Exception as e:
            print(f"[!] Error submitting form: {e}")
            return None

    def check_xss(self):
        payloads = self.load_wordlist("wordlists/xss.txt")
        for payload in payloads:
            forms = self.get_all_forms(self.target_url)
            for form in forms:
                res = self.submit_form(form, payload, self.target_url)
                if res and payload in res.text:
                    self.vulnerabilities.append({"type": "XSS", "payload": payload})

    def check_sql_injection(self):
        payloads = self.load_wordlist("wordlists/sqli.txt")
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
        indicators = ["uid=", "gid=", "root", "user", "windows", "linux", "darwin"]
        for payload in payloads:
            forms = self.get_all_forms(self.target_url)
            for form in forms:
                res = self.submit_form(form, payload, self.target_url)
                if res and any(ind in res.text.lower() for ind in indicators):
                    self.vulnerabilities.append({"type": "Command Injection", "payload": payload})

    def check_directory_traversal(self):
        payloads = self.load_wordlist("wordlists/directory_traversal.txt")
        for payload in payloads:
            try:
                res = self.session.get(self.target_url + payload)
                if "root:x" in res.text or "[extensions]" in res.text:
                    self.vulnerabilities.append({"type": "Directory Traversal", "payload": payload})
            except:
                continue

    def check_open_redirect(self):
        payloads = self.load_wordlist("wordlists/open_redirect.txt")
        for payload in payloads:
            try:
                redirect_url = f"{self.target_url}?next={payload}"
                res = self.session.get(redirect_url, allow_redirects=False)
                if res.status_code in [301, 302] and payload.replace("//", "") in res.headers.get("Location", ""):
                    self.vulnerabilities.append({"type": "Open Redirect", "payload": payload})
            except:
                continue

    def check_auth_bypass(self):
        paths = self.load_wordlist("wordlists/auth_bypass.txt")
        for path in paths:
            try:
                res = self.session.get(urljoin(self.target_url, path))
                if res.status_code == 200 and ("Welcome" in res.text or "admin" in res.text):
                    self.vulnerabilities.append({"type": "Auth Bypass", "url": path})
            except:
                continue

    def check_clickjacking(self):
        try:
            res = self.session.get(self.target_url)
            if "x-frame-options" not in res.headers:
                self.vulnerabilities.append({"type": "Clickjacking", "detail": "Missing X-Frame-Options header."})
        except:
            return

    def check_security_headers(self):
        try:
            res = self.session.get(self.target_url)
            headers = ["X-Frame-Options", "Content-Security-Policy", "X-XSS-Protection", "Strict-Transport-Security"]
            for h in headers:
                if h not in res.headers:
                    self.vulnerabilities.append({"type": "Missing Security Header", "header": h})
        except:
            return

    def check_info_disclosure(self):
        paths = self.load_wordlist("wordlists/info_disclosure_paths.txt")
        for path in paths:
            try:
                res = self.session.get(urljoin(self.target_url, path))
                if res.status_code == 200 and any(ext in path for ext in [".git", ".svn", ".bak", ".zip", ".env"]):
                    self.vulnerabilities.append({"type": "Info Disclosure", "url": path})
            except:
                continue

    def check_crlf_injection(self):
        payloads = self.load_wordlist("wordlists/crlf.txt")
        for payload in payloads:
            try:
                res = self.session.get(self.target_url + payload)
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

        if not self.vulnerabilities:
            return "[+] No vulnerabilities found."
        result = "[+] Vulnerabilities Found:\n"
        for v in self.vulnerabilities:
            result += f" - {v['type']} => {v.get('payload') or v.get('url') or v.get('header') or v.get('detail', '')}\n"
        return result

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
        result = scanner.scan()
        return jsonify({"output": result})
        
    except Exception as e:
        return jsonify({
            "error": "Scan failed",
            "details": str(e)
        }), 500

if __name__ == '__main__':
    # Use environment variable for debug mode
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug_mode, host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))
