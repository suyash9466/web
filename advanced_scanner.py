import os
import requests
import time
import random
import logging
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from flask import Flask, request, render_template, jsonify, session
import datetime

app = Flask(__name__, template_folder="templates")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Set a secret key for session management
app.secret_key = os.environ.get('SECRET_KEY', 'default-secret-key')

class AdvancedVulnerabilityScanner:
    def __init__(self, target_url):
        # Validate URL format
        parsed = urlparse(target_url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("Invalid URL format")
        
        self.target_url = target_url if target_url.endswith('/') else target_url + '/'
        
        # Configure session with browser-like headers
        self.session = requests.Session()
        self.session.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "max-age=0",
            "DNT": "1"
        }
        
        # Bypass SSL verification for problematic sites
        self.session.verify = False
        requests.packages.urllib3.disable_warnings()
        
        # Timeout and retry configuration
        self.timeout = 30
        self.retries = 2
        self.delay = random.uniform(0.5, 2.0)  # Random delay between requests
        
        self.vulnerabilities = []
        logger.info(f"Scanner initialized for: {self.target_url}")

    def load_wordlist(self, path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            logger.error(f"Wordlist not found: {path}")
            return []
        except Exception as e:
            logger.error(f"Error loading wordlist: {e}")
            return []

    def safe_request(self, method, url, **kwargs):
        """Robust request handling with retries and delays"""
        for attempt in range(self.retries + 1):
            try:
                # Random delay to mimic human behavior
                time.sleep(self.delay)
                
                # Set default timeout
                if 'timeout' not in kwargs:
                    kwargs['timeout'] = self.timeout
                    
                response = self.session.request(method, url, **kwargs)
                response.raise_for_status()
                return response
            except requests.exceptions.RequestException as e:
                logger.warning(f"Request failed (attempt {attempt+1}/{self.retries+1}): {str(e)}")
                if attempt < self.retries:
                    wait_time = 2 ** attempt  # Exponential backoff
                    logger.info(f"Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                else:
                    logger.error(f"Request failed for {url}: {str(e)}")
                    return None
            except Exception as e:
                logger.error(f"Unexpected error: {str(e)}")
                return None

    def get_all_forms(self, url):
        try:
            logger.info(f"Fetching forms from: {url}")
            res = self.safe_request('GET', url)
            if res is None:
                return []
                
            soup = BeautifulSoup(res.content, "html.parser")
            forms = soup.find_all("form")
            logger.info(f"Found {len(forms)} forms")
            return forms
        except Exception as e:
            logger.error(f"Error getting forms: {e}")
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
                if input_type in ["text", "search", "password", "email", "number"]:
                    value = payload
                if name:
                    form_data[name] = value
            
            target = urljoin(url, action)
            logger.info(f"Submitting form to: {target} with method: {method}")
            
            if method == "post":
                return self.safe_request('POST', target, data=form_data)
            return self.safe_request('GET', target, params=form_data)
        except Exception as e:
            logger.error(f"Error submitting form: {e}")
            return None

    # Vulnerability checks with comprehensive error handling
    def check_xss(self):
        try:
            logger.info("Starting XSS check")
            payloads = self.load_wordlist("wordlists/xss.txt") or []
            forms = self.get_all_forms(self.target_url)
            
            for payload in payloads:  # Test ALL payloads
                for form in forms:
                    res = self.submit_form(form, payload, self.target_url)
                    if res and payload in res.text:
                        self.vulnerabilities.append({"type": "XSS", "payload": payload})
        except Exception as e:
            logger.error(f"XSS check failed: {e}")
        finally:
            logger.info("Completed XSS check")

    def check_sql_injection(self):
        try:
            logger.info("Starting SQL Injection check")
            payloads = self.load_wordlist("wordlists/sqli.txt") or []
            errors = ["sql syntax", "mysql_fetch", "ORA-", "unclosed quotation", "syntax error"]
            forms = self.get_all_forms(self.target_url)
            
            for payload in payloads:  # Test ALL payloads
                for form in forms:
                    res = self.submit_form(form, payload, self.target_url)
                    if res and any(err in res.text.lower() for err in errors):
                        self.vulnerabilities.append({"type": "SQL Injection", "payload": payload})
        except Exception as e:
            logger.error(f"SQL Injection check failed: {e}")
        finally:
            logger.info("Completed SQL Injection check")

    def check_csrf(self):
        try:
            logger.info("Starting CSRF check")
            forms = self.get_all_forms(self.target_url)
            for form in forms:
                inputs = form.find_all("input")
                if not any("csrf" in (i.attrs.get("name") or "").lower() for i in inputs):
                    self.vulnerabilities.append({"type": "CSRF", "detail": "No CSRF token found."})
        except Exception as e:
            logger.error(f"CSRF check failed: {e}")
        finally:
            logger.info("Completed CSRF check")

    def check_command_injection(self):
        try:
            logger.info("Starting Command Injection check")
            payloads = self.load_wordlist("wordlists/command_injection.txt") or []
            indicators = ["uid=", "gid=", "root", "user"]
            forms = self.get_all_forms(self.target_url)
            
            for payload in payloads:  # Test ALL payloads
                for form in forms:
                    res = self.submit_form(form, payload, self.target_url)
                    if res and any(ind in res.text.lower() for ind in indicators):
                        self.vulnerabilities.append({"type": "Command Injection", "payload": payload})
        except Exception as e:
            logger.error(f"Command Injection check failed: {e}")
        finally:
            logger.info("Completed Command Injection check")

    def check_directory_traversal(self):
        try:
            logger.info("Starting Directory Traversal check")
            payloads = self.load_wordlist("wordlists/directory_traversal.txt") or []
            
            for payload in payloads:  # Test ALL payloads
                res = self.safe_request('GET', self.target_url + payload)
                if res and ("root:x" in res.text or "[extensions]" in res.text):
                    self.vulnerabilities.append({"type": "Directory Traversal", "payload": payload})
        except Exception as e:
            logger.error(f"Directory Traversal check failed: {e}")
        finally:
            logger.info("Completed Directory Traversal check")

    def check_open_redirect(self):
        try:
            logger.info("Starting Open Redirect check")
            payloads = self.load_wordlist("wordlists/open_redirect.txt") or []
            
            for payload in payloads:  # Test ALL payloads
                redirect_url = f"{self.target_url}?next={payload}"
                res = self.safe_request('GET', redirect_url, allow_redirects=False)
                if res and res.status_code in [301, 302] and payload.replace("//", "") in res.headers.get("Location", ""):
                    self.vulnerabilities.append({"type": "Open Redirect", "payload": payload})
        except Exception as e:
            logger.error(f"Open Redirect check failed: {e}")
        finally:
            logger.info("Completed Open Redirect check")

    def check_auth_bypass(self):
        try:
            logger.info("Starting Auth Bypass check")
            paths = self.load_wordlist("wordlists/auth_bypass.txt") or []
            
            for path in paths:  # Test ALL paths
                url = urljoin(self.target_url, path)
                res = self.safe_request('GET', url)
                if res and res.status_code == 200 and ("Welcome" in res.text or "admin" in res.text):
                    self.vulnerabilities.append({"type": "Auth Bypass", "url": path})
        except Exception as e:
            logger.error(f"Auth Bypass check failed: {e}")
        finally:
            logger.info("Completed Auth Bypass check")

    def check_clickjacking(self):
        try:
            logger.info("Starting Clickjacking check")
            res = self.safe_request('GET', self.target_url)
            if res and "x-frame-options" not in res.headers:
                self.vulnerabilities.append({"type": "Clickjacking", "detail": "Missing X-Frame-Options header."})
        except Exception as e:
            logger.error(f"Clickjacking check failed: {e}")
        finally:
            logger.info("Completed Clickjacking check")

    def check_security_headers(self):
        try:
            logger.info("Starting Security Headers check")
            res = self.safe_request('GET', self.target_url)
            if res:
                headers = ["X-Frame-Options", "Content-Security-Policy", "X-XSS-Protection", "Strict-Transport-Security"]
                for h in headers:
                    if h not in res.headers:
                        self.vulnerabilities.append({"type": "Missing Security Header", "header": h})
        except Exception as e:
            logger.error(f"Security Headers check failed: {e}")
        finally:
            logger.info("Completed Security Headers check")

    def check_info_disclosure(self):
        try:
            logger.info("Starting Info Disclosure check")
            paths = self.load_wordlist("wordlists/info_disclosure_paths.txt") or []
            
            for path in paths:  # Test ALL paths
                url = urljoin(self.target_url, path)
                res = self.safe_request('GET', url)
                if res and res.status_code == 200 and any(ext in path for ext in [".git", ".svn", ".bak", ".zip"]):
                    self.vulnerabilities.append({"type": "Info Disclosure", "url": path})
        except Exception as e:
            logger.error(f"Info Disclosure check failed: {e}")
        finally:
            logger.info("Completed Info Disclosure check")

    def check_crlf_injection(self):
        try:
            logger.info("Starting CRLF Injection check")
            payloads = self.load_wordlist("wordlists/crlf.txt") or []
            
            for payload in payloads:  # Test ALL payloads
                res = self.safe_request('GET', self.target_url + payload)
                if res and ("injected" in res.headers.get("Set-Cookie", "") or "injected" in res.headers.get("Location", "")):
                    self.vulnerabilities.append({"type": "CRLF Injection", "payload": payload})
        except Exception as e:
            logger.error(f"CRLF Injection check failed: {e}")
        finally:
            logger.info("Completed CRLF Injection check")

    def scan(self):
        logger.info(f"Starting scan of: {self.target_url}")
        start_time = time.time()
        
        # Run all checks
        checks = [
            self.check_security_headers,
            self.check_clickjacking,
            self.check_open_redirect,
            self.check_info_disclosure,
            self.check_csrf,
            self.check_xss,
            self.check_sql_injection,
            self.check_command_injection,
            self.check_directory_traversal,
            self.check_crlf_injection,
            self.check_auth_bypass
        ]
        
        for check in checks:
            try:
                check()
            except Exception as e:
                logger.error(f"Check failed: {e}")
                continue

        scan_duration = time.time() - start_time
        logger.info(f"Scan completed in {scan_duration:.2f} seconds. Found {len(self.vulnerabilities)} vulnerabilities")
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
            
        logger.info(f"Starting scan for: {data['url']}")
        scanner = AdvancedVulnerabilityScanner(data['url'])
        vulnerabilities = scanner.scan()
        
        # Store results in session
        session['vulnerabilities'] = vulnerabilities
        session['scan_url'] = data['url']
        session['scan_time'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        logger.info(f"Scan completed. Found {len(vulnerabilities)} vulnerabilities")
        return jsonify({
            "redirect": "/results"
        })
        
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}", exc_info=True)
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
    
    # Configure logging level
    if debug_mode:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)
    
    app.run(debug=debug_mode, host='0.0.0.0', port=port)
