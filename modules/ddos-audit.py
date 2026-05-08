#!/usr/bin/env python3
"""Module: DDoS Resilience Test — Load handling, CDN/WAF detection, connection limits."""
import sys, os, time, threading
from urllib.request import Request, urlopen
from urllib.error import URLError
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from lib.reporter import AuditReport

class DDoSAudit:
    def __init__(self, target: str):
        self.target = target.rstrip("/")
        self.report = AuditReport(target, "ddos-audit")
        self._homepage_body = None

    def _fetch(self, path="/"):
        try:
            req = Request(f"{self.target}{path}")
            with urlopen(req, timeout=10) as r:
                body = r.read().decode("utf-8", errors="ignore")
                return r.status, dict(r.headers), body
        except Exception as e:
            return None, {}, str(e)

    def _get_homepage(self) -> str:
        if self._homepage_body is None:
            _, _, body = self._fetch("/")
            self._homepage_body = body or ""
        return self._homepage_body

    def _is_catch_all(self, body: str) -> bool:
        homepage = self._get_homepage()
        if not homepage or not body:
            return False
        if len(body) == len(homepage) and len(body) > 0:
            return True
        if len(body) > 200 and len(homepage) > 200:
            return body[:200] == homepage[:200]
        return False

    def run(self) -> str:
        print(f"\n  🛡️  DDoS Resilience Audit — {self.target}")
        print(f"  {'─' * 50}")
        self._check_waf_cdn()
        self._check_rate_limiting_headers()
        self._concurrent_load_test()
        self._check_timeout_config()
        return self.report.generate()

    def _check_waf_cdn(self):
        print(f"\n  🔍 1/4 — WAF / CDN Detection")
        status, headers, _ = self._fetch()
        if not status:
            return

        waf_signs = {
            "Cloudflare": ["cf-ray", "cf-cache-status", "cf-request-id"],
            "CloudFront": ["x-amz-cf-id", "x-amz-cf-pop"],
            "CloudFront WAF": ["x-amzn-waf-action"],
            "Akamai": ["x-akamai-", "x-akamai-transformed"],
            "Fastly": ["x-served-by", "x-cache", "x-timer"],
            "StackPath": ["x-ss-request-id"],
            "Incapsula": ["x-iinfo"],
            "Sucuri": ["x-sucuri-id", "x-sucuri-cache"],
            "AWS WAF": ["x-amzn-requestid", "x-amzn-trace-id"],
            "Azure WAF": ["x-azure-ref"],
            "F5 BIG-IP": ["x-application-context"],
            "Imperva": ["x-cdn", "x-request-id"],
        }

        detected = []
        for waf_name, sigs in waf_signs.items():
            for sig in sigs:
                if any(sig.lower() in h.lower() for h in headers):
                    detected.append(waf_name)
                    break

        # Also check server header
        server = headers.get("Server", "")
        owasp_headers = {
            "X-Content-Type-Options": "Missing",
            "X-Frame-Options": "Missing",
            "X-XSS-Protection": "Missing",
        }

        if detected:
            for waf in set(detected):
                print(f"    {'🛡️':<4} WAF/CDN detected: {waf}")
                self.report.add_finding("ok", f"WAF/CDN detected: {waf}")
        else:
            print(f"    {'❌':<4} No WAF/CDN detected — server potentially exposed")
            print(f"    {'':<4} Server: {server}")
            self.report.add_finding("high", "No WAF or CDN detected",
                detail=f"Server: {server}. Direct origin without mitigation layer.",
                fix="Consider Cloudflare, AWS WAF, or CloudFront as reverse proxy")

    def _check_rate_limiting_headers(self):
        print(f"\n  🔍 2/4 — Rate Limiting Headers")
        status, headers, _ = self._fetch()
        if not status:
            return

        rl_headers_found = []
        for h in headers:
            hl = h.lower()
            if any(x in hl for x in ["ratelimit", "rate-limit", "retry-after", "x-ratelimit"]):
                rl_headers_found.append(f"{h}: {headers[h]}")

        if rl_headers_found:
            for h in rl_headers_found:
                print(f"    {'✅':<4} Rate limit header: {h}")
            self.report.add_finding("ok", "Rate limiting headers present", 
                detail="; ".join(rl_headers_found))
        else:
            print(f"    {'❌':<4} No rate limiting headers in response")
            self.report.add_finding("medium", "No rate limiting headers",
                detail="Headers like RateLimit-Limit, Retry-After are absent",
                fix="Implement rate limiting and add RateLimit-* headers")

    def _concurrent_load_test(self):
        print(f"\n  🔍 3/4 — Concurrent Load Test (10 parallel requests)")
        results = []
        lock = threading.Lock()
        
        def make_request(idx):
            try:
                req = Request(f"{self.target}/")
                start = time.time()
                with urlopen(req, timeout=15) as r:
                    elapsed = time.time() - start
                    with lock:
                        results.append({"idx": idx, "status": r.status, "time": round(elapsed, 3), "size": len(r.read())})
            except Exception as e:
                with lock:
                    results.append({"idx": idx, "status": "ERR", "time": 0, "error": str(e)[:60]})

        threads = []
        for i in range(10):
            t = threading.Thread(target=make_request, args=(i,))
            threads.append(t)
            t.start()
            time.sleep(0.05)  # Stagger starts

        for t in threads:
            t.join()

        completed = [r for r in results if r["status"] != "ERR"]
        failed = [r for r in results if r["status"] == "ERR"]
        statuses = [r["status"] for r in completed]
        times = [r["time"] for r in completed]
        unique_statuses = set(statuses)

        print(f"    {'📊':<4} Results: {len(completed)} OK / {len(failed)} ERR")
        print(f"    {'':<4} Status codes: {unique_statuses}")
        if times:
            print(f"    {'':<4} Avg response: {sum(times)/len(times):.3f}s | Min: {min(times):.3f}s | Max: {max(times):.3f}s")
            if all(t < 2 for t in times):
                print(f"    {'✅':<4} All responses under 2s — good")
                self.report.add_finding("ok", "Concurrent load OK", 
                    detail=f"10 parallel requests. Avg: {sum(times)/len(times):.3f}s, 0 errors")
            else:
                slow = [t for t in times if t >= 2]
                print(f"    {'⚠️':<4} {len(slow)}/{len(times)} requests took >2s under load")
                self.report.add_finding("medium", "Slow under concurrent load",
                    detail=f"{len(slow)}/{len(times)} requests >2s. Avg: {sum(times)/len(times):.3f}s",
                    fix="Review server resources, add caching, consider CDN")
        if failed:
            self.report.add_finding("high", "Connection failures under load",
                detail=f"{len(failed)}/10 requests failed during concurrent test",
                fix="Check server connection limits and timeout settings")

    def _check_timeout_config(self):
        print(f"\n  🔍 4/4 — Timeout & Connection Test")
        status, headers, _ = self._fetch()
        if not status:
            return

        keep_alive = headers.get("Connection", "")
        timeout_hint = headers.get("Keep-Alive", headers.get("Keep-Alive", ""))

        if "keep-alive" in keep_alive.lower():
            print(f"    {'✅':<4} Keep-Alive: active ({timeout_hint or 'default'})")
            self.report.add_finding("ok", "Keep-Alive enabled",
                detail=f"Connection: keep-alive ({timeout_hint})")
        else:
            print(f"    {'ℹ️':<4} Connection: {keep_alive or 'not specified'}")
            self.report.add_finding("low", "Connection header analysis", 
                detail=f"Connection: {keep_alive}")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else input("Target URL/IP: ")
    audit = DDoSAudit(target)
    report_path = audit.run()
    print(f"\n  {'📝':<4} Report: {report_path}")
