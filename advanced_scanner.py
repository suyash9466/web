# advanced_scanner.py

import os
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from flask import Flask, request, render_template, jsonify

app = Flask(__name__, template_folder="templates")

class AdvancedVulnerabilityScanner:
    def __init__(self, target_url):
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
        except:
            return []

    def submit_form(self, form, payload, url):
        action = form.attrs.get("action", "").lower()
        method = form.attrs.get("method", "get").lower()
        inputs = form.find_all("input")
        form_data = {}
        for input in inputs:
            name = input.attrs.get("name")
            input_type = input.attrs.get("type", "text")
            value = input.attrs.get("value", "")
            if input_type in ["text", "search"]:
                value = payload
            if name:
                form_data[name] = value
        target = urljoin(url, action)
        if method == "post":
            return self.session.post(target, data=form_data)
        return self.session.get(target, params=form_data)

    def check_xss(self):
        payloads = self.load_wordlist("wordlists/xss.txt")
        for payload in payloads:
            forms = self.get_all_forms(self.target_url)
            for form in forms:
                res = self.submit_form(form, payload, self.target_url)
                if payload in res.text:
                    self.vulnerabilities.append({"type": "XSS", "payload": payload})

    def check_sql_injection(self):
        payloads = self.load_wordlist("wordlists/sqli.txt")
        errors = ["sql syntax", "mysql_fetch", "ORA-", "unclosed quotation"]
        for payload in payloads:
            forms = self.get_all_forms(self.target_url)
            for form in forms:
                res = self.submit_form(form, payload, self.target_url)
                if any(err in res.text.lower() for err in errors):
                    self.vulnerabilities.append({"type": "SQL Injection", "payload": payload})

    def check_csrf(self):
        forms = self.get_all_forms(self.target_url)
        for form in forms:
            inputs = form.find_all("input")
            if not any("csrf" in (i.attrs.get("name") or "").lower() for i in inputs):
                self.vulnerabilities.append({"type": "CSRF", "detail": "No CSRF token found."})

    def check_command_injection(self):
        payloads = self.load_wordlist("wordlists/command_injection.txt")
        indicators = ["uid=", "gid=", "root", "user", "windows"]
        for payload in payloads:
            forms = self.get_all_forms(self.target_url)
            for form in forms:
                res = self.submit_form(form, payload, self.target_url)
                if any(ind in res.text.lower() for ind in indicators):
                    self.vulnerabilities.append({"type": "Command Injection", "payload": payload})

    def check_directory_traversal(self):
        payloads = self.load_wordlist("wordlists/directory_traversal.txt")
        for payload in payloads:
            res = self.session.get(self.target_url + payload)
            if "root:x" in res.text or "[extensions]" in res.text:
                self.vulnerabilities.append({"type": "Directory Traversal", "payload": payload})

    def check_open_redirect(self):
        payloads = self.load_wordlist("wordlists/open_redirect.txt")
        for payload in payloads:
            redirect_url = f"{self.target_url}?next={payload}"
            res = self.session.get(redirect_url, allow_redirects=False)
            if res.status_code in [301, 302] and payload.replace("//", "") in res.headers.get("Location", ""):
                self.vulnerabilities.append({"type": "Open Redirect", "payload": payload})

    def check_auth_bypass(self):
        paths = self.load_wordlist("wordlists/auth_bypass.txt")
        for path in paths:
            res = self.session.get(urljoin(self.target_url, path))
            if "Welcome" in res.text or "admin" in res.text:
                self.vulnerabilities.append({"type": "Auth Bypass", "url": path})

    def check_host_header_injection(self):
        headers = {"Host": "evil.com"}
        res = self.session.get(self.target_url, headers=headers)
        if "evil.com" in res.text:
            self.vulnerabilities.append({"type": "Host Header Injection"})

    def check_clickjacking(self):
        res = self.session.get(self.target_url)
        if "x-frame-options" not in res.headers:
            self.vulnerabilities.append({"type": "Clickjacking", "detail": "Missing X-Frame-Options header."})

    def check_security_headers(self):
        res = self.session.get(self.target_url)
        headers = ["X-Frame-Options", "Content-Security-Policy", "X-XSS-Protection", "Strict-Transport-Security"]
        for h in headers:
            if h not in res.headers:
                self.vulnerabilities.append({"type": "Missing Security Header", "header": h})

    def check_info_disclosure(self):
        paths = self.load_wordlist("wordlists/info_disclosure_paths.txt")
        for path in paths:
            res = self.session.get(urljoin(self.target_url, path))
            if res.status_code == 200 and any(ext in path for ext in [".git", ".svn", ".bak", ".zip"]):
                self.vulnerabilities.append({"type": "Info Disclosure", "url": path})

    def check_lfi(self):
        payloads = self.load_wordlist("wordlists/lfi.txt")
        for payload in payloads:
            res = self.session.get(urljoin(self.target_url, payload))
            if "root:x" in res.text or "/bin/bash" in res.text:
                self.vulnerabilities.append({"type": "LFI", "payload": payload})

    def check_rfi(self):
        payloads = self.load_wordlist("wordlists/rfi.txt")
        for payload in payloads:
            res = self.session.get(urljoin(self.target_url, payload))
            if "http" in payload and ("include" in res.text or "fopen" in res.text):
                self.vulnerabilities.append({"type": "RFI", "payload": payload})

    def check_crlf_injection(self):
        payloads = self.load_wordlist("wordlists/crlf.txt")
        for payload in payloads:
            res = self.session.get(self.target_url + payload)
            if "injected" in res.headers.get("Set-Cookie", ""):
                self.vulnerabilities.append({"type": "CRLF Injection", "payload": payload})

    def scan(self):
        self.check_xss()
        self.check_sql_injection()
        self.check_csrf()
        self.check_command_injection()
        self.check_directory_traversal()
        self.check_lfi()
        self.check_rfi()
        self.check_crlf_injection()
        self.check_open_redirect()
        self.check_auth_bypass()
        self.check_host_header_injection()
        self.check_clickjacking()
        self.check_info_disclosure()
        self.check_security_headers()

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
    data = request.get_json()
    url = data.get("url")
    if not url:
        return jsonify({"error": "URL missing"}), 400
    scanner = AdvancedVulnerabilityScanner(url)
    result = scanner.scan()
    return jsonify({"output": result})

if __name__ == '__main__':
    app.run(debug=True)
