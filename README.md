# 🛡️ oSMS – Open Security Misconfiguration Scanner

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/github/license/TheOSuite/oSMS)
![Build](https://img.shields.io/badge/Build-Passing-brightgreen)

> **Beginner-friendly Python GUI tool to detect Security Misconfiguration issues in web applications.**

---

##  Overview

`oSMS` is a lightweight vulnerability scanner that helps you detect **security misconfigurations** in web applications. Built for ease of use, it features a fully graphical interface and a suite of common web checks. Ideal for **bug bounty beginners**, **CTF learners**, or **pentesters** who want a quick recon tool.

---

##  What It Scans For

|  Test                       |  Description                                                              |
|------------------------------|-----------------------------------------------------------------------------|
| **HTTP Headers**             | Checks for missing security headers (`CSP`, `HSTS`, etc.)                  |
| **Directory Listing**        | Detects exposed directory indices                                          |
| **Error Messages**           | Looks for verbose backend error messages                                   |
| **Tech Stack Exposure**      | Reveals frameworks/languages from headers or HTML                          |
| **Default Credentials**      | Brute-force basic login pages with known creds                             |
| **XXE Injection**            | Attempts to exploit XML External Entity issues                             |
| **Open Ports**               | Scans common TCP ports via raw sockets                                     |
| **S3 Bucket Misconfigs**     | Checks for public S3 buckets                                               |
| **WAF/CDN Detection**        | Identifies Cloudflare, Akamai, etc.                                        |
| **CORS Misconfig**           | Flags wildcard or insecure `Access-Control-Allow-Origin` headers           |
| **Insecure Cookies**         | Finds cookies missing `Secure` or `HttpOnly` flags                         |
| **Outdated Server Software** | Flags versions of Apache/nginx/IIS that are likely vulnerable              |
| **HTTP Methods**             | Detects unsafe HTTP methods like `TRACE`                                   |

---

## 🖥️ GUI Features

-  **Tkinter GUI** – no terminal required
-  **Progress Bar** – visual scan feedback
-  **Color-coded log viewer**
-  **Stop scan button**
-  **Custom test selection**
-  **Export results as `.html`, `.pdf`, or `.txt`**
-  **Configurable ports, creds, timeouts, and rate limits**

---

##  Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/TheOSuite/oSMS.git
cd oSMS
````

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

> ✅ Python 3.8 or later is required.

### 3. Run the Tool

```bash
python oSMS.py
```

---

## Configuration

Accessible via the **"Config"** button in the GUI.

* Custom scan **ports**: `21,22,80,443,...`
* Custom **credentials**: `admin:admin,user:password,...`
* **Rate limit**: seconds between requests
* **Timeout**: request timeout in seconds

Saves to `osms_config.json`.

---

## Output

* `scan_log_YYYYMMDD_HHMMSS.txt`: detailed log of scan
* `report.html`: color-coded, browser-viewable report
* `report.pdf`: printable version of scan results

---

## 🛑 Legal Disclaimer

This tool is for **authorized testing and educational purposes only**.
**Do not scan websites you don’t own or have explicit permission to test.**

> ⚠️ Unauthorized scanning is illegal. The developer assumes no liability for misuse.

---

## Credits

Created by **The O Suite** https://www.TheOSuite.com
Contributions, forks, and stars are always welcome 

---
