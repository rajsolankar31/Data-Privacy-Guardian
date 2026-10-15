import re
import urllib.parse
from typing import Dict, Any, List
import requests
from bs4 import BeautifulSoup
from .document_scanner import mask_evidence

# Known third-party tracking networks, analytics, fingerprinting & advertising domains
KNOWN_TRACKERS = {
    "Google Analytics / Tag Manager": re.compile(r"(?i)(?:google-analytics\.com|googletagmanager\.com|analytics\.js|gtag\/js)"),
    "Facebook / Meta Pixel": re.compile(r"(?i)(?:connect\.facebook\.net|fbevents\.js|facebook\.com\/tr)"),
    "TikTok Pixel": re.compile(r"(?i)(?:analytics\.tiktok\.com|ttq\.load)"),
    "Criteo Ad Tracker": re.compile(r"(?i)(?:criteo\.com|criteo\.net)"),
    "Hotjar Session Recording": re.compile(r"(?i)(?:static\.hotjar\.com|hotjar\.js)"),
    "FullStory Session Replay": re.compile(r"(?i)(?:fullstory\.com\/s\/fs\.js)"),
    "CrazyEgg Heatmap Tracker": re.compile(r"(?i)(?:script\.crazyegg\.com)"),
    "Yandex Metrica": re.compile(r"(?i)(?:mc\.yandex\.ru\/metrika)"),
    "Outbrain / Taboola Ad Networks": re.compile(r"(?i)(?:outbrain\.com|taboola\.com)"),
    "FingerprintJS Browser Fingerprinting": re.compile(r"(?i)(?:fingerprint\.com|fpjs|getHighEntropyValues)"),
}

# Suspicious / Malicious attack scripts & privacy vectors
SUSPICIOUS_SCRIPT_PATTERNS = {
    "Keylogger / Keystroke Interceptor": re.compile(r"(?i)(?:addEventListener\s*\(\s*['\"](?:keyup|keydown|keypress)['\"]|\.onkeypress\s*=)"),
    "Hidden Form Password Harvesting": re.compile(r"(?i)(?:input\[type=['\"]password['\"]\]|document\.forms.*\.password)"),
    "Clipboard Access / Hijacking": re.compile(r"(?i)(?:navigator\.clipboard\.readText|document\.execCommand\s*\(\s*['\"]copy['\"]\)|\.clipboardData)"),
    "Cryptominer WebAssembly Worker": re.compile(r"(?i)(?:coinhive|cryptonight|webminer|Wasm\.instantiate.*(?:miner|crypto))"),
    "Obfuscated Payload Execution": re.compile(r"(?i)(?:eval\s*\(|unescape\s*\(|String\.fromCharCode\s*\(|window\[['\"]eval['\"]\])"),
    "Browser Fingerprinting Canvas Probe": re.compile(r"(?i)(?:toDataURL\s*\(\s*['\"]image\/png['\"]\)|\.getImageData\s*\(.*canvas)"),
    "AudioContext Fingerprinting": re.compile(r"(?i)(?:OfflineAudioContext|createOscillator|createDynamicsCompressor)"),
}

# Dangerous / Invasive Tracking Query Parameters in URLs
TRACKING_QUERY_PARAMS = {
    "fbclid": "Meta / Facebook Click Identifier (Cross-site user tracking)",
    "gclid": "Google Ads Click Identifier (Ad attribution tracking)",
    "msclkid": "Microsoft Bing Click Identifier",
    "mc_eid": "Mailchimp Individual Subscriber Email ID",
    "utm_source": "Campaign Traffic Source Tag",
    "utm_medium": "Campaign Medium Tag",
    "utm_campaign": "Campaign Name Tag",
    "utm_term": "Paid Search Keyword Tracking",
    "utm_content": "Ad Variant Attribution Tracking",
    "_hsenc": "HubSpot Encrypted Contact Identifier",
    "_hsmi": "HubSpot Marketing Message ID",
}


def analyze_url_parameters(url: str) -> List[Dict[str, Any]]:
    """Inspects query parameters in a URL for user tracking and cross-site identifiers."""
    findings = []
    try:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        for param_key, values in params.items():
            lower_k = param_key.lower()
            if lower_k in TRACKING_QUERY_PARAMS:
                findings.append({
                    "Parameter": param_key,
                    "Values": ", ".join([mask_evidence(v, keep_chars=3) for v in values]),
                    "Category": "URL Tracking Parameter",
                    "Description": TRACKING_QUERY_PARAMS[lower_k],
                    "Privacy Impact": "Links this link visit to your specific user profile/click ID across the web."
                })
    except Exception:
        pass
    return findings


def scan_live_web_link(url: str, timeout_seconds: int = 8) -> Dict[str, Any]:
    """
    Performs a deep privacy, security, and tracker inspection of a target link:
    1. Analyzes URL parameters for tracking tokens (gclid, fbclid, utm tags).
    2. Inspects destination HTTP headers for privacy & security policies (HSTS, CSP, Referrer-Policy).
    3. Parses HTML DOM scripts for known tracking networks (Google, Meta, TikTok, Hotjar, Criteo).
    4. Audits inline JavaScript for attack scripts (Keyloggers, Clipboard hijacking, Browser fingerprinting, Crypto-miners).
    5. Computes a Unified Privacy & Link Threat Risk Score (0 - 100).
    """
    results = {
        "url": url,
        "is_accessible": False,
        "status_code": None,
        "final_url": url,
        "url_trackers": [],
        "third_party_trackers": [],
        "suspicious_scripts": [],
        "security_headers": {},
        "missing_privacy_headers": [],
        "risk_score": 0.0,
        "risk_level": "Low",
        "threat_summary": []
    }

    # 1. URL parameter scan
    url_trackers = analyze_url_parameters(url)
    results["url_trackers"] = url_trackers

    # Fetch webpage safely with custom User-Agent and timeout
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) DataPrivacyGuardian/2.0 PrivacyAuditor"
    }

    try:
        resp = requests.get(url, headers=headers, timeout=timeout_seconds, allow_redirects=True)
        results["is_accessible"] = True
        results["status_code"] = resp.status_code
        results["final_url"] = resp.url

        # Check for redirects to different domains
        orig_netloc = urllib.parse.urlparse(url).netloc
        final_netloc = urllib.parse.urlparse(resp.url).netloc
        if orig_netloc and final_netloc and orig_netloc != final_netloc:
            results["threat_summary"].append(f"Domain redirected: {orig_netloc} -> {final_netloc}")

        # 2. Inspect Security & Privacy Headers
        resp_headers = {k.lower(): v for k, v in resp.headers.items()}
        results["security_headers"] = {
            "strict-transport-security": resp_headers.get("strict-transport-security", "Missing"),
            "content-security-policy": "Present" if "content-security-policy" in resp_headers else "Missing",
            "referrer-policy": resp_headers.get("referrer-policy", "Missing (Default reveals referer)"),
            "permissions-policy": "Present" if "permissions-policy" in resp_headers else "Missing",
        }

        if "content-security-policy" not in resp_headers:
            results["missing_privacy_headers"].append("Content-Security-Policy (Permits injection of external scripts)")
        if "strict-transport-security" not in resp_headers:
            results["missing_privacy_headers"].append("HSTS (Permits insecure downgraded HTTP connections)")
        if "referrer-policy" not in resp_headers:
            results["missing_privacy_headers"].append("Referrer-Policy (Browser leaks visiting URL to destination)")

        # 3. Parse HTML DOM
        soup = BeautifulSoup(resp.text, "html.parser")
        scripts = soup.find_all("script")
        script_sources = [s.get("src", "") for s in scripts if s.get("src")]
        inline_scripts = [s.string for s in scripts if s.string]

        # Scan for known 3rd-party trackers
        for tracker_name, rx in KNOWN_TRACKERS.items():
            matched_sources = [src for src in script_sources if rx.search(src)]
            inline_matches = [s for s in inline_scripts if rx.search(s)]
            if matched_sources or inline_matches:
                evidence = matched_sources[0] if matched_sources else inline_matches[0][:80]
                results["third_party_trackers"].append({
                    "Tracker Name": tracker_name,
                    "Type": "Third-Party Telemetry & Profiling",
                    "Evidence": evidence[:90],
                    "Impact": "Builds behavioral cross-site tracking profiles of visitors."
                })

        # Scan for suspicious / attack scripts
        all_js_code = "\n".join(inline_scripts)
        for attack_type, rx in SUSPICIOUS_SCRIPT_PATTERNS.items():
            matches = list(rx.finditer(all_js_code))
            if matches:
                sample_snippet = matches[0].group(0)
                results["suspicious_scripts"].append({
                    "Threat Type": attack_type,
                    "Severity": "High",
                    "Detected Code Pattern": mask_evidence(sample_snippet, keep_chars=4),
                    "Security Danger": (
                        "Monitors user keystrokes" if "Keylogger" in attack_type else
                        "Reads user clipboard contents" if "Clipboard" in attack_type else
                        "Generates unique hardware fingerprint" if "Fingerprint" in attack_type else
                        "Executes dynamic uninspected payloads" if "Obfuscated" in attack_type else
                        "Exfiltrates credentials or consumes CPU resources"
                    )
                })

    except requests.exceptions.RequestException as e:
        results["is_accessible"] = False
        results["threat_summary"].append(f"Connection failed / timeout: {str(e)}")

    # 4. Calibrated Threat & Privacy Risk Score (0 to 100)
    score = 0.0

    # URL Tracking tokens: 5 pts each (up to 20)
    score += min(len(results["url_trackers"]) * 8, 20)

    # Third-party advertising / telemetry trackers: 10 pts each (up to 40)
    score += min(len(results["third_party_trackers"]) * 10, 40)

    # Suspicious / attack scripts: 25 pts each (up to 40)
    score += min(len(results["suspicious_scripts"]) * 25, 40)

    # Missing critical security headers
    score += min(len(results["missing_privacy_headers"]) * 5, 15)

    results["risk_score"] = min(100.0, round(score, 1))

    if results["risk_score"] >= 65:
        results["risk_level"] = "Critical"
    elif results["risk_score"] >= 35:
        results["risk_level"] = "Medium-High"
    else:
        results["risk_level"] = "Low"

    return results
