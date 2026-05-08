#!/usr/bin/env python3
"""
Ares Tool Security — Full Scan (Cross-Platform)
Runs all 4 audit modules against a single target.
Generates 4 separate .md reports in reports/

Usage:
    python3 scripts/full-scan.py https://example.com
"""
import sys, os, subprocess, platform

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 scripts/full-scan.py <target-url>")
        sys.exit(1)

    target = sys.argv[1]
    script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    modules_dir = os.path.join(script_dir, "modules")

    modules = [
        ("web-audit",    "🌐 Web Audit"),
        ("brute-force",  "🔨 Brute Force"),
        ("ddos-audit",   "🛡️  DDoS Audit"),
        ("vuln-scan",    "🎯 Vuln Scan"),
    ]

    os_name = platform.system()
    python_cmd = "python" if os_name == "Windows" else "python3"

    print("")
    print("  ╔══════════════════════════════════════════╗")
    print(f"  ║    Ares Tool Security — Full Scan       ║")
    print(f"  ║    Target: {target}")
    print(f"  ║    OS: {os_name}")
    print(f"  ╚══════════════════════════════════════════╝")
    print("")

    for module_name, module_label in modules:
        module_path = os.path.join(modules_dir, f"{module_name}.py")
        if not os.path.exists(module_path):
            print(f"  ⚠️  Module not found: {module_name}.py — skipping")
            continue

        print(f"  ── {module_label} ──")
        sys.stdout.flush()

        result = subprocess.run(
            [python_cmd, module_path, target],
            capture_output=False,
            cwd=script_dir
        )

        print(f"  ── Done: {module_name} ──")
        print("")

    print("  ╔══════════════════════════════════════════╗")
    print("  ║    Full scan complete                    ║")
    print(f"  ║    Reports in: {os.path.join(script_dir, 'reports')}")
    print("  ╚══════════════════════════════════════════╝")
    print("")

if __name__ == "__main__":
    main()
