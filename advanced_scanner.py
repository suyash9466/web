import os
import requests
import time
import random
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from flask import Flask, request, render_template, jsonify, session
import datetime
import logging
import cloudscraper
from stem import Signal
from stem.control import Controller

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
        
        # Use cloudscraper to bypass Cloudflare protection
        self.scraper = cloudscraper.create_scraper()
        
        # Configure headers to mimic a real browser
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "max-age=0",
            "DNT": "1"
        }
        
        # Configure session
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.session.verify = False  # Bypass SSL verification
        requests.packages.urllib3.disable_warnings()
        
        # Timeout configuration
        self.timeout = 30
        self.retries = 3
        self.delay = random.uniform(1.0, 3.0)  # Random delay between requests
        
        self.vulnerabilities = []
        logger.info(f"Initialized scanner for: {self.target_url}")

    def rotate_tor_ip(self):
        """Rotate Tor IP address to bypass IP blocking"""
        try:
            with Controller.from_port(port=9051) as controller:
                controller.authenticate(password=os.environ.get("TOR_PASSWORD", ""))
                controller.signal(Signal.NEWNYM)
                logger.info("Tor IP rotated successfully")
        except Exception as e:
            logger.error(f"Tor IP rotation failed: {e}")

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
        """Wrapper for requests with retries, delays, and IP rotation"""
        for attempt in range(self.retries + 1):
            try:
                # Add random delay to mimic human behavior
                time.sleep(self.delay)
                
                # Set default timeout if not provided
                if 'timeout' not in kwargs:
                    kwargs['timeout'] = self.timeout
                    
                # Try with cloudscraper first for Cloudflare sites
                if method.upper() == "GET":
                    response = self.scraper.get(url, headers=self.headers, **kwargs)
                elif method.upper() == "POST":
                    response = self.scraper.post(url, headers=self.headers, **kwargs)
                else:
                    response = self.session.request(method, url, **kwargs)
                    
                response.raise_for_status()
                
                # Check for Cloudflare/WAF challenges
                if any(indicator in response.text for indicator in ["cloudflare", "captcha", "security challenge"]):
                    logger.warning("Security challenge detected. Rotating IP...")
                    self.rotate_tor_ip()
                    raise requests.exceptions.RequestException("Security challenge detected")
                    
                return response
            except requests.exceptions.RequestException as e:
                logger.warning(f"Request failed (attempt {attempt+1}/{self.retries+1}): {str(e)}")
                if attempt < self.retries:
                    wait_time = 2 ** attempt  # Exponential backoff
                    logger.info(f"Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                    
                    # Rotate Tor IP for next attempt
                    self.rotate_tor_ip()
                else:
                    logger.error(f"Final request failure for {url}: {str(e)}")
                    raise
            except Exception as e:
                logger.error(f"Unexpected error: {str(e)}")
                raise

    def get_all_forms(self, url):
        try:
            logger.info(f"Fetching forms from: {url}")
            res = self.safe_request('GET', url)
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

    # Vulnerability check methods with enhanced bypass techniques
    def check_xss(self):
        logger.info("Starting XSS check")
        payloads = self.load_wordlist("wordlists/xss.txt")
        if not payloads: 
            logger.warning("XSS wordlist empty")
            return
            
        forms = self.get_all_forms(self.target_url)
        
        for payload in payloads:
            logger.debug(f"Testing XSS payload: {payload}")
            for form in forms:
                try:
                    res = self.submit_form(form, payload, self.target_url)
                    if res and payload in res.text:
                        logger.warning(f"XSS vulnerability found with payload: {payload}")
                        self.vulnerabilities.append({"type": "XSS", "payload": payload})
                        return  # Stop after first finding
                except Exception as e:
                    logger.error(f"XSS check failed for payload {payload}: {e}")
        logger.info("Completed XSS check")

    def check_sql_injection(self):
        logger.info("Starting SQL Injection check")
        payloads = self.load_wordlist("wordlists/sqli.txt")
        if not payloads: 
            logger.warning("SQLi wordlist empty")
            return
            
        errors = ["sql syntax", "mysql_fetch", "ORA-", "unclosed quotation", "syntax error"]
        forms = self.get_all_forms(self.target_url)
        
        for payload in payloads:
            logger.debug(f"Testing SQLi payload: {payload}")
            for form in forms:
                try:
                    res = self.submit_form(form, payload, self.target_url)
                    if res and any(err in res.text.lower() for err in errors):
                        logger.warning(f"SQL Injection vulnerability found with payload: {payload}")
                        self.vulnerabilities.append({"type": "SQL Injection", "payload": payload})
                        return  # Stop after first finding
                except Exception as e:
                    logger.error(f"SQLi check failed for payload {payload}: {e}")
        logger.info("Completed SQL Injection check")

    # Other vulnerability checks (implemented similarly with early termination)
    # ...

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
                logger.info(f"Executing check: {check.__name__}")
                check()
                # If we've found critical vulnerabilities, stop early
                if self.vulnerabilities and any(vuln['type'] in ['SQL Injection', 'Command Injection'] for vuln in self.vulnerabilities):
                    logger.info("Critical vulnerability found. Stopping scan early.")
                    break
            except Exception as e:
                logger.error(f"Check {check.__name__} failed: {e}")
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
        
        logger.info(f"Scan completed for {data['url']}. Found {len(vulnerabilities)} vulnerabilities")
        return jsonify({
            "redirect": "/results"
        })
        
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}", exc_info=True)
        return jsonify({
            "error": "Scan failed",
            "details": f"Target site security blocked our scanner: {str(e)}"
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
