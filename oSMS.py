import sys
import asyncio
if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import tkinter as tk
from tkinter import messagebox, filedialog, scrolledtext, ttk
import aiohttp
import asyncio
import requests  # Fallback for sync tasks
from urllib.parse import urljoin, urlparse
import socket
import threading
import time
import datetime
import re
import json
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

stop_scan_flag = False
log_lines = []
common_ports = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 8080, 8443, 3306, 5432, 6379, 27017]
default_creds = [("admin", "admin"), ("admin", "password"), ("user", "user"), ("root", "root"), ("guest", "guest")]
config_file = "osms_config.json"

# Utils
def load_config():
    try:
        with open(config_file, "r") as f:
            return json.load(f)
    except:
        return {"ports": common_ports, "creds": default_creds, "rate_limit": 1, "timeout": 10}  # Default with timeout

def save_config(config):
    with open(config_file, "w") as f:
        json.dump(config, f)

config = load_config()

# Logging
def log_output(text, color="black", severity="INFO"):
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    full_text = f"[{timestamp}] [{severity}] {text}"
    output_box.tag_config(color, foreground=color)
    output_box.insert(tk.END, full_text + "\n", color)
    output_box.see(tk.END)
    log_lines.append(full_text)

# Vulnerability Tests (Async where possible)
async def fetch_url(session, url, method="GET", data=None, headers=None, read_text=False):
    timeout_val = config.get("timeout", 10)
    try:
        async with session.request(method, url, data=data, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout_val)) as res:
            text = await res.text() if read_text else None
            return res, text
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        log_output(f"Fetch error for {url}: {str(e)}", "orange", "WARNING")
        return None, None

async def check_http_headers(session, url, cached_res):
    missing = [h for h in [
        'Content-Security-Policy', 'Strict-Transport-Security',
        'X-Content-Type-Options', 'X-Frame-Options', 'X-XSS-Protection'
    ] if h not in cached_res.headers]
    if missing:
        return ("Missing Security Headers: " + ", ".join(missing), "red", "High")
    return ("All recommended headers present.", "green", "Low")

async def check_directory_listing(session, url):
    res, text = await fetch_url(session, urljoin(url, "/"), read_text=True)
    if res and text and "Index of /" in text:
        return ("Directory Listing Enabled.", "red", "High")
    return ("No directory listing." if res else "Fetch failed.", "green" if res else "orange", "Low")

async def check_error_messages(session, url):
    res, text = await fetch_url(session, urljoin(url, "/nonexistent"), read_text=True)
    if res and res.status in [404, 500] and text and re.search(r"(exception|traceback|stack|debug)", text, re.I):
        return ("Verbose error messages exposed.", "red", "Medium")
    return ("Error messages generic." if res else "Fetch failed.", "green" if res else "orange", "Low")

async def check_tech_exposure(session, url, cached_res, cached_text):
    if cached_text is None:
        return ("Error reading response.", "orange", "Low")
    exposed = []
    if "x-powered-by" in cached_res.headers:
        exposed.append(cached_res.headers['x-powered-by'])
    if "server" in cached_res.headers and not re.match(r"^(nginx|apache)$", cached_res.headers['server'], re.I):
        exposed.append(cached_res.headers['server'])
    tech_patterns = ["wordpress", "drupal", "joomla", "phpmyadmin", "laravel"]
    if any(p in cached_text.lower() for p in tech_patterns):
        exposed.append("HTML hints at tech stack.")
    if exposed:
        return ("Tech Exposure: " + ", ".join(exposed), "red", "Medium")
    return ("No tech exposure.", "green", "Low")

async def check_default_credentials(session, url):
    # Detect login form
    login_res, login_text = await fetch_url(session, urljoin(url, "/login"), read_text=True)
    if not login_res:
        login_res, login_text = await fetch_url(session, urljoin(url, "/admin"), read_text=True)
    if not login_res:
        return ("No login endpoint found.", "orange", "Low")
    if login_text is None:
        return ("Error reading login page.", "orange", "Low")
    form_match = re.search(r'<form.*?(username|user|login).*?(password|pass)', login_text, re.I)
    if not form_match:
        return ("No detectable login form.", "orange", "Low")
    results = []
    for user, pwd in config["creds"]:
        data = {"username": user, "password": pwd}  # Assume common fields
        post_res, post_text = await fetch_url(session, str(login_res.url), "POST", data=data, read_text=True)
        if post_res and post_text and post_res.status in [200, 302] and "logout" in post_text.lower():
            results.append(f"Default creds: {user}/{pwd}")
    if results:
        return ("\n".join(results), "red", "High")
    return ("No default creds work.", "green", "Low")

async def check_xxe(session, url):
    endpoints = [url, urljoin(url, "/api"), urljoin(url, "/xml")]
    payload = """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>"""
    headers = {'Content-Type': 'application/xml'}
    for ep in endpoints:
        res, text = await fetch_url(session, ep, "POST", data=payload, headers=headers, read_text=True)
        if res and text and "root:" in text:
            return ("XXE vulnerability!", "red", "High")
    return ("No XXE detected.", "green", "Low")

def check_open_ports(url):  # Sync for socket
    results = []
    try:
        ip = socket.gethostbyname(urlparse(url).hostname)
        for port in config["ports"]:
            if stop_scan_flag: break
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            if s.connect_ex((ip, port)) == 0:
                service = {80: "HTTP", 443: "HTTPS", 22: "SSH"}.get(port, "Unknown")
                results.append(f"Open Port {port} ({service})")
            s.close()
        if results:
            return ("\n".join(results), "red", "Medium")
        return ("No open ports.", "green", "Low")
    except Exception as e:
        return (f"Port Scan Error: {e}", "orange", "Low")

async def check_s3_buckets(session, url):
    domain = urlparse(url).hostname.replace("www.", "")
    buckets = [f"http://{domain}.s3.amazonaws.com", f"http://s3.amazonaws.com/{domain}"]
    for bucket in buckets:
        res, text = await fetch_url(session, bucket, read_text=True)
        if res and text and "<ListBucketResult" in text:
            return (f"Open S3: {bucket}", "red", "High")
    return ("No open S3.", "green", "Low")

async def detect_waf(session, url, cached_res):
    headers = cached_res.headers
    waf_indicators = ["cloudflare", "akamai", "sucuri", "incapsula"]
    detected = [v for k, v in headers.items() if any(w in v.lower() for w in waf_indicators)]
    if detected:
        return ("WAF Detected: " + ", ".join(detected), "orange", "Low")
    return ("No WAF detected.", "green", "Low")

async def check_cors(session, url):
    res, _ = await fetch_url(session, url, headers={"Origin": "http://evil.com"})
    if res and "Access-Control-Allow-Origin" in res.headers and res.headers["Access-Control-Allow-Origin"] == "*":
        return ("CORS Misconfig: Wildcard Origin.", "red", "Medium")
    return ("CORS secure" if res else "Fetch failed.", "green" if res else "orange", "Low")

async def check_cookie_flags(session, url, cached_res):
    cookies = cached_res.cookies
    insecure = [name for name, morsel in cookies.items() if 'secure' not in morsel or 'httponly' not in morsel]
    if insecure:
        return ("Insecure Cookies: " + ", ".join(insecure), "red", "Medium")
    return ("Cookies have secure flags.", "green", "Low")

async def check_outdated_software(session, url, cached_res):
    server = cached_res.headers.get("Server", "")
    if re.search(r"apache/2\.[0-3]|nginx/1\.[0-9]|iis/[1-7]", server, re.I):
        return ("Outdated Server Software Detected.", "red", "High")
    return ("Software appears up-to-date.", "green", "Low")

async def check_http_methods(session, url):
    res, text = await fetch_url(session, url, "OPTIONS", read_text=True)
    if res and text and "TRACE" in text.upper():
        return ("Unsafe HTTP Methods Enabled (e.g., TRACE).", "red", "Medium")
    return ("HTTP methods secure." if res else "Fetch failed.", "green" if res else "orange", "Low")

# Scanner Execution
async def perform_async_tests(session, url, selected_tests, progress_step, cached_res, cached_text):
    results = {"High": 0, "Medium": 0, "Low": 0}
    test_map = {
        "HTTP Headers": lambda: check_http_headers(session, url, cached_res),
        "Directory Listing": lambda: check_directory_listing(session, url),
        "Error Messages": lambda: check_error_messages(session, url),
        "Tech Exposure": lambda: check_tech_exposure(session, url, cached_res, cached_text),
        "Default Credentials": lambda: check_default_credentials(session, url),
        "XXE Injection": lambda: check_xxe(session, url),
        "S3 Buckets": lambda: check_s3_buckets(session, url),
        "WAF Detection": lambda: detect_waf(session, url, cached_res),
        "CORS": lambda: check_cors(session, url),
        "Cookie Flags": lambda: check_cookie_flags(session, url, cached_res),
        "Outdated Software": lambda: check_outdated_software(session, url, cached_res),
        "HTTP Methods": lambda: check_http_methods(session, url),
    }
    coros = [test_map[test]() for test in selected_tests if test in test_map]
    for coro in asyncio.as_completed(coros):
        if stop_scan_flag: break
        result, color, severity = await coro
        log_output(result, color, severity)
        results[severity] += 1
        progress_bar["value"] += progress_step
        await asyncio.sleep(config["rate_limit"])  # Rate limit
    return results

def perform_sync_tests(url, selected_tests, progress_step, results):
    if "Open Ports" in selected_tests:
        log_output("Open Ports", "blue", "INFO")
        result, color, severity = check_open_ports(url)
        log_output(result, color, severity)
        results[severity] += 1
        progress_bar["value"] += progress_step

async def run_scan(url, selected_tests):
    progress_bar["value"] = 0
    num_tests = len(selected_tests)
    progress_step = 100 / num_tests if num_tests else 0
    results = {"High": 0, "Medium": 0, "Low": 0}
    async with aiohttp.ClientSession() as session:
        cached_res, cached_text = await fetch_url(session, url, read_text=True)
        if cached_res is None:
            log_output("Failed to fetch base URL.", "red", "ERROR")
            return results
        async_results = await perform_async_tests(session, url, selected_tests, progress_step, cached_res, cached_text)
        results.update({k: results.get(k, 0) + v for k, v in async_results.items()})
    perform_sync_tests(url, selected_tests, progress_step, results)  # Sync after async
    if not stop_scan_flag:
        summary = f"Summary: High: {results['High']}, Medium: {results['Medium']}, Low: {results['Low']}\nRecommendations: Prioritize High issues."
        log_output(summary, "blue", "INFO")
        progress_bar["value"] = 100

def threaded_scan():
    global stop_scan_flag
    stop_scan_flag = False
    urls = [u.strip() for u in url_entry.get().split(",") if u.strip()]
    if not urls or not all(re.match(r"https?://", u) for u in urls):
        messagebox.showerror("Invalid Input", "Enter valid URLs (comma-separated, starting with http/https).")
        return
    selected_tests = [test for test, var in test_vars.items() if var.get()]
    if not selected_tests:
        messagebox.showerror("No Tests", "Select at least one test.")
        return
    if not messagebox.askyesno("Confirm", "Scan may send requests to targets. Proceed?"):
        return
    output_box.delete(1.0, tk.END)
    log_lines.clear()
    scan_button["state"] = "disabled"
    stop_button["state"] = "normal"
    for url in urls:
        if stop_scan_flag: break
        log_output(f"Scanning {url}...", "blue", "INFO")
        asyncio.run(run_scan(url, selected_tests))
    scan_button["state"] = "normal"
    stop_button["state"] = "disabled"
    save_log_file()

def stop_scan():
    global stop_scan_flag
    stop_scan_flag = True

def save_as_html():
    html = "<html><head><style>body{font-family:Arial;} .red{color:red;} .green{color:green;} .orange{color:orange;} .blue{color:blue;}</style></head><body>"
    html += f"<h2>oSMS Report - {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</h2><pre>"
    for line in log_lines:
        color = "black"
        if "[High]" in line or "[ERROR]" in line: color = "red"
        elif "[Medium]" in line or "[WARNING]" in line: color = "orange"
        elif "[Low]" in line: color = "green"
        elif "[INFO]" in line: color = "blue"
        html += f"<span style='color:{color}'>{line}</span><br>"
    html += "</pre></body></html>"
    path = filedialog.asksaveasfilename(defaultextension=".html")
    if path:
        with open(path, "w") as f:
            f.write(html)

def save_as_pdf():
    path = filedialog.asksaveasfilename(defaultextension=".pdf")
    if path:
        c = canvas.Canvas(path, pagesize=letter)
        y = 750
        c.drawString(100, y, f"oSMS Report - {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        y -= 20
        for line in log_lines:
            color = (0,0,0)  # Black default
            if "red" in line: color = (1,0,0)
            elif "green" in line: color = (0,1,0)
            elif "orange" in line: color = (1,0.5,0)
            elif "blue" in line: color = (0,0,1)
            c.setFillColorRGB(*color)
            c.drawString(100, y, line)
            y -= 15
            if y < 50:
                c.showPage()
                y = 750
        c.save()

def save_log_file():
    filename = f"scan_log_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(filename, "w") as f:
        f.write("\n".join(log_lines))

# Config Dialog
def open_config():
    config_win = tk.Toplevel(root)
    config_win.title("Configure oSMS")

    tk.Label(config_win, text="Custom Ports (comma-separated):").pack()
    ports_entry = tk.Entry(config_win, width=50)
    ports_entry.insert(0, ",".join(map(str, config["ports"])))
    ports_entry.pack()

    tk.Label(config_win, text="Custom Creds (user:pass, comma-separated):").pack()
    creds_entry = tk.Entry(config_win, width=50)
    creds_entry.insert(0, ",".join(f"{u}:{p}" for u, p in config["creds"]))
    creds_entry.pack()

    tk.Label(config_win, text="Rate Limit (seconds per request):").pack()
    rate_entry = tk.Entry(config_win, width=10)
    rate_entry.insert(0, str(config["rate_limit"]))
    rate_entry.pack()

    tk.Label(config_win, text="Timeout (seconds):").pack()
    timeout_entry = tk.Entry(config_win, width=10)
    timeout_entry.insert(0, str(config.get("timeout", 10)))
    timeout_entry.pack()

    def save():
        config["ports"] = [int(p) for p in ports_entry.get().split(",") if p.strip().isdigit()]
        config["creds"] = [tuple(c.split(":")) for c in creds_entry.get().split(",") if ":" in c]
        config["rate_limit"] = float(rate_entry.get() or 1)
        config["timeout"] = int(timeout_entry.get() or 10)
        save_config(config)
        config_win.destroy()

    tk.Button(config_win, text="Save", command=save).pack()

# GUI Setup
root = tk.Tk()
root.title("oSMS - By The O Suite")

ttk.Label(root, text="Target URL(s) (comma-separated):").pack(pady=5)
url_entry = ttk.Entry(root, width=60)
url_entry.pack(pady=5)

# Test Selection
test_frame = ttk.LabelFrame(root, text="Select Tests")
test_frame.pack(pady=5, fill="x")
test_vars = {}
tests = ["HTTP Headers", "Directory Listing", "Error Messages", "Tech Exposure", "Default Credentials",
         "XXE Injection", "Open Ports", "S3 Buckets", "WAF Detection", "CORS", "Cookie Flags",
         "Outdated Software", "HTTP Methods"]
for test in tests:
    var = tk.BooleanVar(value=True)
    test_vars[test] = var
    ttk.Checkbutton(test_frame, text=test, variable=var).pack(anchor="w")

button_frame = ttk.Frame(root)
button_frame.pack(pady=5)
scan_button = ttk.Button(button_frame, text="Start Scan", command=lambda: threading.Thread(target=threaded_scan).start())
scan_button.pack(side="left", padx=5)
stop_button = ttk.Button(button_frame, text="Stop Scan", command=stop_scan, state="disabled")
stop_button.pack(side="left", padx=5)
config_button = ttk.Button(button_frame, text="Config", command=open_config)
config_button.pack(side="left", padx=5)
export_html = ttk.Button(button_frame, text="Export HTML", command=save_as_html)
export_html.pack(side="left", padx=5)
export_pdf = ttk.Button(button_frame, text="Export PDF", command=save_as_pdf)
export_pdf.pack(side="left", padx=5)

progress_bar = ttk.Progressbar(root, orient="horizontal", mode="determinate", length=500)
progress_bar.pack(pady=5)

output_box = scrolledtext.ScrolledText(root, width=100, height=30)
output_box.pack(padx=10, pady=10)

root.mainloop()
