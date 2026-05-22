from mitmproxy import http
from datetime import datetime
import csv
import os
import math
import time
import json
import attacks

# Load firewall config
def load_firewall_config():
    if os.path.exists('firewall_config.json'):
        with open('firewall_config.json', 'r') as f:
            return json.load(f)
    return {
        'firewall_enabled': True,
        'blocked_ports': [22, 23, 3389, 445],
        'allowed_ports': [80, 443, 8080, 3000, 5000]
    }

CSVFILE = "traffic_events.csv"

def load_html():
    file_path = "WAF_blocked.html"
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Blocked by InteliWFA</h1><p>Security Threat Detected.</p>"

HTML_RESPONSE = load_html()

# DDOS / RATE LIMIT CONFIG
MAX_REQUESTS = 50
TIME_WINDOW = 60
BLOCK_TIME = 120

request_log = {}
blocked_ips = {}

# BRUTE-FORCE LIMIT CONFIG
BRUTE_MAX_ATTEMPTS = 5
BRUTE_TIME_WINDOW = 300
BRUTE_BLOCK_TIME = 120

brute_log = {}
brute_blocked_ips = {}

def init_csv():
    if not os.path.exists(CSVFILE):
        with open(CSVFILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp", "client_ip", "method", "url", "path",
                "attack_type", "body_len", "body_entropy"
            ])

def shannon_entropy(s):
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    probs = [v / len(s) for v in freq.values()]
    return -sum(p * math.log2(p) for p in probs if p > 0)

def check_ddos(client_ip):
    now = time.time()
    
    if client_ip in blocked_ips:
        if now < blocked_ips[client_ip]:
            return True
        else:
            del blocked_ips[client_ip]
    
    if client_ip not in request_log:
        request_log[client_ip] = []
    
    request_log[client_ip] = [t for t in request_log[client_ip] if now - t <= TIME_WINDOW]
    request_log[client_ip].append(now)
    
    if len(request_log[client_ip]) > MAX_REQUESTS:
        blocked_ips[client_ip] = now + BLOCK_TIME
        del request_log[client_ip]
        return True
    return False

def check_bruteforce(client_ip, path):
    now = time.time()
    
    if client_ip in brute_blocked_ips:
        if now < brute_blocked_ips[client_ip]:
            return True
        else:
            del brute_blocked_ips[client_ip]
    
    key = (client_ip, path)
    if key not in brute_log:
        brute_log[key] = []
    
    brute_log[key] = [t for t in brute_log[key] if now - t <= BRUTE_TIME_WINDOW]
    brute_log[key].append(now)
    
    if len(brute_log[key]) >= BRUTE_MAX_ATTEMPTS:
        brute_blocked_ips[client_ip] = now + BRUTE_BLOCK_TIME
        del brute_log[key]
        return True
    return False

def check_port_access(dst_port):
    """Check if port is allowed by firewall rules"""
    config = load_firewall_config()
    
    if not config.get('firewall_enabled', True):
        return True  # Firewall OFF - allow all
    
    # Check if port is explicitly blocked
    if dst_port in config.get('blocked_ports', []):
        return False
    
    # Check if port is explicitly allowed
    if dst_port in config.get('allowed_ports', []):
        return True
    
    # Default: block if not in allowed list
    return False

def request(flow: http.HTTPFlow):

    if "WAF_blocked.html" in flow.request.path:
        return
    
    # Load firewall config
    config = load_firewall_config()
    
    # If firewall is OFF, allow everything (no blocking at all)
    if not config.get('firewall_enabled', True):
        # Still log to CSV but don't block anything
        init_csv()
        req = flow.request
        
        # Get client IP
        client_ip = "(unknown)"
        try:
            addr = flow.client_conn.address
            if addr:
                client_ip = f"{addr[0]}:{addr[1]}"
        except:
            pass
        
        # Log without blocking
        try:
            body = req.get_text(strict=False) or ""
        except:
            body = ""
        
        body_len = len(body)
        entropy = round(shannon_entropy(body), 3)
        
        with open(CSVFILE, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                datetime.utcnow().isoformat() + "Z", client_ip,
                req.method, req.pretty_url, req.path,
                "FIREWALL_OFF", body_len, entropy
            ])
        
        return  # ⭐ RETURN HERE - NO BLOCKING AT ALL
    
    if "WAF_blocked.html" in flow.request.path:
        return
    
    init_csv()
    req = flow.request
    
    # Get destination port
    dst_port = flow.server_conn.address[1] if flow.server_conn.address else 80
    
    # Check port access FIRST
    if not check_port_access(dst_port):
        blocked_page = HTML_RESPONSE.replace("{{ATTACK_TYPE}}", f"PORT_BLOCKED_{dst_port}")
        flow.response = http.Response.make(
            403,
            blocked_page.encode("utf-8"),
            {"Content-Type": "text/html"}
        )
        return
    
    # Get client IP
    client_ip = "(unknown)"
    try:
        addr = flow.client_conn.address
        if addr:
            client_ip = f"{addr[0]}:{addr[1]}"
    except:
        pass
    
    # DDOS CHECK
    if check_ddos(client_ip):
        with open(CSVFILE, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                datetime.utcnow().isoformat() + "Z", client_ip,
                req.method, req.pretty_url, req.path,
                "DDOS", 0, 0.0
            ])
        
        blocked_page = HTML_RESPONSE.replace("{{ATTACK_TYPE}}", 'DDOS')
        flow.response = http.Response.make(403, blocked_page.encode("utf-8"), {"Content-Type": "text/html"})
        return
    
    # BRUTE FORCE CHECK
    login_paths = ["/login", "/signin", "/auth", "/admin"]
    if any(p in req.path.lower() for p in login_paths):
        if check_bruteforce(client_ip, req.path):
            with open(CSVFILE, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    datetime.utcnow().isoformat() + "Z", client_ip,
                    req.method, req.pretty_url, req.path,
                    "BRUTE_FORCE", 0, 0.0
                ])
            
            blocked_page = HTML_RESPONSE.replace("{{ATTACK_TYPE}}", 'BRUTE_FORCE')
            flow.response = http.Response.make(403, blocked_page.encode("utf-8"), {"Content-Type": "text/html"})
            return
    
    # BODY ANALYSIS
    try:
        body = req.get_text(strict=False) or ""
    except:
        body = ""
    
    body_len = len(body)
    entropy = round(shannon_entropy(body), 3)
    
    # ATTACK DETECTION
    file_result = attacks.check_file_upload(req)
    
    if file_result == "FILE_UPLOAD_ABUSE":
        attack_type = "FILE_UPLOAD_ABUSE"
    elif file_result == "NORMAL":
        attack_type = "NORMAL"
    else:
        found = attacks.check_other_attacks(req)
        attack_type = "|".join(found) if found else "NORMAL"
    
    # WRITE CSV
    with open(CSVFILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.utcnow().isoformat() + "Z", client_ip,
            req.method, req.pretty_url, req.path,
            attack_type, body_len, entropy
        ])
    
    # BLOCK IF ATTACK
    if attack_type != "NORMAL":
        blocked_page = HTML_RESPONSE.replace("{{ATTACK_TYPE}}", attack_type)
        flow.response = http.Response.make(403, blocked_page.encode("utf-8"), {"Content-Type": "text/html"})