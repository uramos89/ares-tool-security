#!/usr/bin/env python3
"""
Ares VulnDB — Embedded Vulnerability Knowledge Base
Maps OS + Server + Version + Port → known CVEs and test procedures.
Auto-updatable via JSON import.
"""
import re

# ═══════════════════════════════════════════════════════════
# OS Fingerprinting
# ═══════════════════════════════════════════════════════════

OS_SIGNATURES = [
    # Linux signatures
    ("linux", [
        "linux", "ubuntu", "debian", "centos", "red hat", "fedora",
        "suse", "opensuse", "alpine", "arch", "manjaro",
    ]),
    # Windows signatures
    ("windows", [
        "windows", "win32", "win64", "microsoft-iis", "iis",
    ]),
    # Unix signatures
    ("unix", [
        "freebsd", "openbsd", "netbsd", "solaris", "aix", "hp-ux",
    ]),
    # macOS
    ("macos", [
        "mac os", "darwin", "apple",
    ]),
]

# ═══════════════════════════════════════════════════════════
# Server-to-OS mapping (common combos)
# ═══════════════════════════════════════════════════════════

SERVER_OS_MAP = {
    "apache": "linux",
    "nginx": "linux",
    "iis": "windows",
    "tomcat": "linux",
    "glassfish": "linux",
    "jetty": "linux",
    "jboss": "linux",
    "weblogic": "linux",
    "websphere": "linux",
    "caddy": "linux",
    "lighttpd": "linux",
    "node.js": "linux",
}

# ═══════════════════════════════════════════════════════════
# CVE Knowledge Base
# Key: (os, server_lower, major_version, port)
# Value: list of (cve_id, title, description, severity, test_fn, fix)
# ═══════════════════════════════════════════════════════════

# CVEs organized by technology stack
CVE_DB = {
    
    # ─── Apache HTTPD ───
    "apache": {
        "2.4": {
            "general": [
                ("CVE-2023-25690", "Apache HTTP Server 2.4.0-2.4.55", "HTTP request splitting via mod_rewrite and mod_proxy", "high",
                 "Check if mod_rewrite + mod_proxy are enabled by testing rewrite rules",
                 "Update Apache to 2.4.56+"),
                ("CVE-2023-27522", "Apache HTTP Server 2.4.0-2.4.55", "HTTP Response Smuggling via mod_proxy", "high",
                 "Test proxy configuration for smuggling vectors",
                 "Update Apache to 2.4.56+"),
                ("CVE-2022-31813", "Apache HTTP Server 2.4.0-2.4.53", "Mod_proxy XSS via crafted request URL", "medium",
                 "Test proxy endpoints with XSS payloads",
                 "Update Apache to 2.4.54+"),
            ],
            22: [
                ("CVE-2024-6387", "OpenSSH regreSSHion (Apache on Linux)", "Remote code execution in SSH on glibc-based Linux", "critical",
                 "Check if target OS uses glibc (most Linux distros). Port 22 open = vulnerable if unpatched",
                 "Update OpenSSH to 9.8p1+"),
            ],
        },
        "2.2": {
            "general": [
                ("CVE-2017-9798", "Apache 2.2.x - OPTIONS memory leak", "Memory leak on OPTIONS request", "medium",
                 "Send OPTIONS * HTTP/1.0 request and measure response size",
                 "Upgrade to Apache 2.4+"),
                ("CVE-2012-0883", "Apache 2.2.x - HTTPOnly cookie disclosure", "envvars disclosure in mod_cgi/mod_fastcgi", "high",
                 "Test CGI scripts for environment variable leakage",
                 "Upgrade to Apache 2.4+"),
            ],
        },
    },
    
    # ─── IIS (Windows) ───
    "iis": {
        "10.0": {
            "general": [
                ("CVE-2022-22039", "IIS 10.0 - Windows Server 2022", "Remote code execution via Windows Network File System", "critical",
                 "Check if NFS role is installed on server",
                 "Install security update KB5015808"),
            ],
            21: [
                ("CVE-2022-22029", "IIS FTP on Windows Server", "FTP anonymous access vulnerability", "high",
                 "Test FTP anonymous login and directory listing",
                 "Disable anonymous FTP access"),
            ],
        },
        "8.5": {
            "general": [
                ("CVE-2021-31166", "IIS 8.5 - HTTP Protocol Stack RCE", "Remote code execution in http.sys", "critical",
                 "Check Windows version (2012 R2). Send crafted HTTP request",
                 "Install KB5003197"),
            ],
        },
        "7.5": {
            "general": [
                ("CVE-2010-3972", "IIS 7.5 - FTP Stack Overflow", "FTP service buffer overflow", "critical",
                 "Check FTP service version. Long NLST command test",
                 "Install KB2524375"),
            ],
        },
    },
    
    # ─── Nginx ───
    "nginx": {
        "1.2": {
            "general": [
                ("CVE-2023-44487", "Nginx 1.2x - HTTP/2 Rapid Reset", "HTTP/2 rapid reset DDoS vulnerability", "high",
                 "Check if HTTP/2 is enabled. Test rapid GOAWAY frames",
                 "Update Nginx to 1.25.3+"),
            ],
        },
        "1.0": {
            "general": [
                ("CVE-2021-23017", "Nginx 1.0 - DNS resolver vulnerability", "Memory corruption in DNS resolver", "high",
                 "Check if resolver directive is configured",
                 "Update Nginx to 1.21.5+"),
            ],
        },
    },
    
    # ─── GlassFish ───
    "glassfish": {
        "4.1": {
            "general": [
                ("CVE-2023-34852", "GlassFish 4.1.1 - Unrestricted file upload", "PUT method allows file upload without restriction", "critical",
                 "Test PUT method on / path. If 200/201, upload PoC file",
                 "Disable PUT method. Update to GlassFish 5+"),
                ("CVE-2017-17495", "GlassFish 4.1 - Admin console default creds", "Default admin:admin credentials on admin console", "critical",
                 "Test /admin and /common with admin:admin login",
                 "Change default admin password"),
                ("CVE-2021-40866", "GlassFish 4.1.1 - Path traversal", "Path traversal via ..;/ sequences in URL", "high",
                 "Inject ..;/ into URL paths",
                 "Update to GlassFish 5.0+"),
            ],
            4848: [
                ("CVE-2023-34852", "GlassFish Admin Console (4848)", "Admin console exposed on port 4848 with default creds", "critical",
                 "Check if port 4848 is open. Test admin:admin",
                 "Close admin port in production"),
            ],
        },
    },
    
    # ─── Tomcat ───
    "tomcat": {
        "9.0": {
            "general": [
                ("CVE-2025-24813", "Tomcat 9.0 - Path Equivalence RCE", "Race condition in path validation allows RCE", "critical",
                 "Test PUT jsp file via path equivalence",
                 "Update Tomcat to 9.0.100+"),
                ("CVE-2023-42795", "Tomcat 9.0 - Request smuggling", "HTTP request smuggling via Transfer-Encoding", "medium",
                 "Send chunked request with malformed TE header",
                 "Update to Tomcat 9.0.81+"),
            ],
        },
        "8.5": {
            "general": [
                ("CVE-2025-24813", "Tomcat 8.5 - Path Equivalence RCE", "Race condition in path validation", "critical",
                 "Same as CVE-2025-24813 for Tomcat 8.5.x",
                 "Update Tomcat to 8.5.100+"),
            ],
        },
        "7.0": {
            "general": [
                ("CVE-2020-1938", "Tomcat 7.0 - Ghostcat (AJP RCE)", "AJP connector file read/exec via Ghostcat protocol", "critical",
                 "Check if AJP connector (port 8009) is exposed",
                 "Disable AJP connector or use firewall"),
                ("CVE-2017-12617", "Tomcat 7.0 - PUT method JSP upload", "PUT method allows JSP file upload leading to RCE", "critical",
                 "Test PUT method upload of .jsp file",
                 "Update to 7.0.82+ or disable PUT"),
            ],
        },
    },
    
    # ─── OpenSSH ───
    "openssh": {
        "9.2": {
            "general": [
                ("CVE-2024-6387", "OpenSSH 9.2p1 - regreSSHion", "Signal handler race condition in sshd", "critical",
                 "Check glibc version. Port 22 open",
                 "Patch OpenSSH to 9.8p1"),
            ],
        },
        "7.9": {
            "general": [
                ("CVE-2018-15473", "OpenSSH 7.9 - User enumeration", "Username enumeration via timing attack", "medium",
                 "Test SSH user enumeration with known/common users",
                 "Update OpenSSH to 8.0+"),
            ],
        },
        "7.2": {
            "general": [
                ("CVE-2016-6210", "OpenSSH 7.2 - User enumeration", "Timing-based username enumeration", "medium",
                 "Send invalid password for root vs non-existent user, compare timing",
                 "Update OpenSSH to 7.3+"),
            ],
        },
    },
    
    # ─── WordPress ───
    "wordpress": {
        "6.0": {
            "general": [
                ("CVE-2022-21661", "WordPress 6.0 - SQL injection via WP_Query", "Privilege escalation via SQL injection in WP_Query", "high",
                 "Check WordPress version in /readme.html",
                 "Update WordPress to 6.0.3+"),
            ],
        },
        "5.0": {
            "general": [
                ("CVE-2019-8942", "WordPress 5.0 - RCE via crop-image", "Remote code execution via image cropping", "critical",
                 "Check if POST /wp-admin/admin-ajax.php?action=crop_image is accessible",
                 "Update WordPress to 5.0.1+"),
            ],
        },
    },
    
    # ─── SMTP / Mail ───
    "smtp": {
        "25": {
            "general": [
                ("CVE-2022-39196", "Postfix SMTP - Mail command injection", "SMTP verb injection via crafted email addresses", "high",
                 "Test RCPT TO with special characters",
                 "Update Postfix to 3.7.3+"),
                ("CVE-2023-51764", "Postfix SMTP - STARTTLS plaintext injection", "STLS injection via plaintext command in STARTTLS", "high",
                 "Test STARTTLS negotiation",
                 "Update Postfix to 3.8.5+"),
            ],
        },
    },
    
    # ─── RDP (Windows) ───
    "rdp": {
        "3389": {
            "general": [
                ("CVE-2019-0708", "RDP - BlueKeep (Windows 7/2008)", "Remote code execution in RDP service", "critical",
                 "Check OS version via RDP banner. Windows 7/2008R2 are vulnerable",
                 "Install KB4499175"),
                ("CVE-2020-0610", "RDP - Windows 10 1903/1909", "RDP denial of service", "medium",
                 "Check Windows 10 version via banner",
                 "Install KB4532695"),
            ],
        },
    },
}

# ═══════════════════════════════════════════════════════════
# Port-to-technology hints
# ═══════════════════════════════════════════════════════════

PORT_TECH_MAP = {
    22: "openssh",
    25: "smtp",
    80: "apache,nginx,iis",
    3306: "mysql",
    5432: "postgresql",
    6379: "redis",
    27017: "mongodb",
    8080: "tomcat,apache,glassfish",
    8443: "tomcat,glassfish",
    4848: "glassfish",
    8009: "tomcat-ajp",
    3389: "rdp",
}


# ═══════════════════════════════════════════════════════════
# Lookup functions
# ═══════════════════════════════════════════════════════════

def detect_os(server_banner, body=""):
    """Detect OS from server banner and response body."""
    combined = (server_banner + " " + body).lower()
    
    for os_name, signatures in OS_SIGNATURES:
        for sig in signatures:
            if sig in combined:
                return os_name
    
    # Fallback by server type
    for srv, os_name in SERVER_OS_MAP.items():
        if srv in server_banner.lower():
            return os_name
    
    return "unknown"


def extract_server_version(server_banner):
    """Extract server type and version from banner."""
    # Apache/2.4.6 (CentOS)
    # nginx/1.18.0
    # Microsoft-IIS/10.0
    # GlassFish Server Open Source Edition  4.1.1
    
    # Apache
    m = re.match(r'apache[/\s]*([\d.]+)', server_banner.lower())
    if m:
        return ("apache", m.group(1))
    
    # Nginx
    m = re.match(r'nginx[/\s]*([\d.]+)', server_banner.lower())
    if m:
        return ("nginx", m.group(1))
    
    # IIS
    m = re.match(r'microsoft-iis[/\s]*([\d.]+)', server_banner.lower())
    if m:
        return ("iis", m.group(1))
    
    # GlassFish
    m = re.search(r'glassfish[^\d]*([\d.]+)', server_banner.lower())
    if m:
        return ("glassfish", m.group(1))
    
    # Tomcat
    m = re.search(r'tomcat[^\d]*([\d.]+)', server_banner.lower())
    if m:
        return ("tomcat", m.group(1))
    
    # OpenSSH
    m = re.search(r'openssh[_\s]*([\d.]+)', server_banner.lower())
    if m:
        return ("openssh", m.group(1))
    
    # Generic: return server name
    srv_name = server_banner.split("/")[0].lower() if "/" in server_banner else server_banner.lower()
    return (srv_name, "")


def lookup_cves(server_type, version, os_name, open_ports):
    """
    Lookup CVEs for a specific server + version + OS + open ports.
    Returns list of (cve_id, title, description, severity, test_hint, fix)
    """
    results = []
    
    if not server_type or server_type not in CVE_DB:
        return results
    
    # Get all version entries
    server_cves = CVE_DB[server_type]
    
    # Find matching version (major.x)
    major_ver = version.split(".")[0] + "." + version.split(".")[1] if len(version.split(".")) >= 2 else version
    best_match = None
    
    # Try exact match first, then partial
    for ver_key in sorted(server_cves.keys(), reverse=True):
        if version.startswith(ver_key) or major_ver == ver_key or ver_key.startswith(major_ver):
            best_match = ver_key
            break
    
    if best_match:
        version_cves = server_cves[best_match]
        
        # Add general CVEs
        if "general" in version_cves:
            for cve in version_cves["general"]:
                results.append(cve)
        
        # Add port-specific CVEs
        for port in open_ports:
            port_key = str(port)
            if port_key in version_cves:
                for cve in version_cves[port_key]:
                    results.append(cve)
    
    return results


def get_cve_reference(cve_id):
    """Generate CVE reference links."""
    return {
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "mitre": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}",
    }
