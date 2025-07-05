# LFIMap - Advanced Local File Inclusion Exploitation Framework

![LFIMap Logo](https://drive.usercontent.google.com/download?id=1whpYzqNjkc6MVPuybUgEKeP5yvg3onDh&export=download)
Advanced Local File Inclusion Exploitation Framework

[![Python Version](https://img.shields.io/badge/python-3.6+-blue.svg)](https://python.org)
[![PyPI version](https://badge.fury.io/py/lfimap-ng.svg)](https://pypi.org/project/lfimap-ng/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macos-lightgrey.svg)](https://gitlab.com/relunsec/lfimap)
[![GitLab](https://img.shields.io/badge/GitLab-RelunSec-orange.svg)](https://gitlab.com/relunsec/lfimap)

**The most comprehensive Local File Inclusion exploitation framework with 18+ attack techniques, 30+ bypass plugins, and advanced post-exploitation capabilities.**

[Features](#-features) • [Installation](#-installation) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [Contributing](#-contributing)

---

## 🚀 Features

### 🎯 18+ Exploitation Techniques
- **Basic LFI** - Directory traversal and file enumeration
- **PHP Filter** - Source code disclosure via `php://filter` with multiple encodings
- **Log Poisoning** - Code injection through web server logs
- **Session Poisoning** - PHP session file manipulation with ID bruteforcing
- **Proc/Self/Environ** - Unix environment variable exploitation
- **Data URI** - Code execution via `data://` scheme
- **Timing-Based Blind LFI** - Statistical analysis for blind vulnerabilities
- **Advanced Wrappers** - `expect://`, `file://`, `phar://`, `zip://`, `glob://`, `ftp://`, `gopher://`
- **Race Condition LFI** - Temporary file exploitation
- **Proc Symlink** - `/proc/self/fd/X` and `cwd` symlink attacks
- **Remote File Inclusion** - External file inclusion capabilities
- **PHP Input Wrapper** - POST data inclusion attacks

### 🛡️ 30+ Bypass Plugins

#### 🔓 WAF & Filter Evasion
- `403` - 12+ HTTP 403 bypass techniques
- `waf-detection` - Identifies Cloudflare, Sucuri, ModSecurity, etc.
- `unicodetrick` - Overlong UTF-8 encoding bypasses
- `multi-encoding` - Double/triple URL encoding
- `path-normalization` - Directory traversal variations
- `case-variation` - Case-sensitive filter bypass
- `xforwardedfor` - X-Forwarded-For header spoofing
- `spoofhost-header` - Host header manipulation

#### 🎭 Advanced Obfuscation
- `questionmark` - Query parameter injection
- `extra-dot` - Dot notation bypasses
- `semicolon-injection` - Semicolon-based evasion
- `doubleslash2slash` - Path normalization tricks
- `tab-trick` - Tab character injection
- `comment-trick` - Comment-based bypasses
- `dotdot-trick` - Enhanced directory traversal
- `fat-dot` - Unicode dot variations
- `utf7-bypass` - UTF-7 encoding evasion
- `base64-in-path` - Base64 path encoding
- `iis-double-slash` - IIS-specific bypasses
- `clrf-injection` - CRLF injection techniques

#### 🔍 Detection & Exploitation
- `lfi-error-fingerprint` - Error message analysis
- `mimetype-check` - MIME type validation bypass
- `wrapper-data` - Data wrapper exploitation
- `session-id-bruteforce` - Automated session enumeration
- `exfil-data` - Data exfiltration assistance
- `race-condition-lfi` - Race condition exploitation
- `rate-limit-adapter` - Rate limiting evasion

### 🎛️ Advanced Capabilities
- **Interactive Wizard** - Beginner-friendly guided setup
- **Parameter Fuzzing** - Automatic vulnerable parameter discovery
- **Multi-Target Support** - Batch scanning from file input
- **Post-Exploitation Shell** - Interactive command execution
- **Professional Output** - Rich console with structured logging
- **Enterprise Authentication** - Basic, NTLM with domain support
- **Proxy Integration** - Burp Suite, OWASP ZAP compatibility

---

## ⚡ Installation

### 🔧 Quick Install
```bash
git clone https://gitlab.com/relunsec/lfimap.git
cd lfimap
pip install -r requirements.txt
cd lfimap
```
Using Github:
```bash
git clone https://github.com/relunsec/LFIMap/
cd LFIMap
pip install -r requirements.txt
cd lfimap
```

Manual install (if needed):

```bash
pip install requests rich requests-ntlm
```

Dependency check:

```bash
cd lfimap
python3 cli.py --check-depends
python  cli.py --list-depends
```
Precompiled Bin (Linux only):
```bash
git clone https://gitlab.com/relunsec/lfimap.git
cd lfimap
cd dist
chmod +x lfimap
sudo make install
```
Docs (Linux only):
```bash
cd docs
sudo make make-docs
```
Using PIP:
```bash
pip install lfimap-ng
```

---

## 🔧 Usage Examples

```bash
# Basic LFI Scan
python lfimap.py -u "http://example.com/vuln.php?file=FUZZ" --method basic

# PHP filter to read config.php
python lfimap.py -u "http://example.com/?file=FUZZ" --method php-filter --php-filter-file config.php

# Poison access log & get shell
python lfimap.py -u "http://example.com/?page=FUZZ" --method log-poisoning \
  --injection-string "<?php system($_GET['cmd']); ?>" --cmd-param cmd

# Parameter fuzzing with plugins
python lfimap.py -u "http://example.com/index.php" --fuzz-param --plugin 403,unicodetrick

# All methods minus blind/time-based
python lfimap.py -u "http://target.com/index.php?f=FUZZ" --method all -eT timing-based
```

---

## 🪜 Contributing

Your contributions are welcome!

- New plugins, methods, bypasses
- Bug fixes or improvements
- Submit pull requests and open issues

---

## ⚠️ Legal & Ethical Disclaimer

This tool is intended for authorized security testing and educational purposes **only**. Do **NOT** use it on systems you do not own or have explicit permission to test.

The developers take no responsibility for misuse or damage caused.

---

Created with ❤️ by RelunSec.
