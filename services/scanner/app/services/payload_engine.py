PAYLOADS: dict[str, dict[str, list[str]]] = {
    "sqli": {
        "quick": ["'"],
        "standard": ["'", '"', "' OR '1'='1", "' AND '1'='2"],
        "deep": [
            "'",
            '"',
            "' OR '1'='1",
            "' AND '1'='2",
            "') OR ('1'='1",
            "') AND ('1'='2",
        ],
        "aggressive": [
            "'",
            '"',
            "' OR '1'='1",
            "' AND '1'='2",
            "') OR ('1'='1",
            "') AND ('1'='2",
            "' OR SLEEP(3)-- ",
            "' OR pg_sleep(3)-- ",
            "'; WAITFOR DELAY '0:0:3'--",
        ],
    },
    "xss": {
        "quick": ["SCANNER_XSS_MARKER"],
        "standard": ["SCANNER_XSS_MARKER", "<b>SCANNER_XSS_MARKER</b>"],
        "deep": [
            "SCANNER_XSS_MARKER",
            "<b>SCANNER_XSS_MARKER</b>",
            '"><SCANNER_XSS_MARKER',
            "';SCANNER_XSS_MARKER;//",
        ],
        "aggressive": [
            "SCANNER_XSS_MARKER",
            "<b>SCANNER_XSS_MARKER</b>",
            '"><SCANNER_XSS_MARKER',
            "';SCANNER_XSS_MARKER;//",
            "<svg data-marker=SCANNER_XSS_MARKER>",
            "<img alt=SCANNER_XSS_MARKER>",
        ],
    },
    "ssrf": {
        "quick": ["https://example.com/"],
        "standard": ["https://example.com/", "http://127.0.0.1/"],
        "deep": [
            "https://example.com/",
            "http://127.0.0.1/",
            "http://localhost/",
            "http://169.254.169.254/",
        ],
        "aggressive": [
            "https://example.com/",
            "http://127.0.0.1/",
            "http://localhost/",
            "http://169.254.169.254/",
            "http://[::1]/",
            "file:///etc/hosts",
        ],
    },
    "rce": {
        "quick": ["SCANNER_RCE_MARKER"],
        "standard": ["SCANNER_RCE_MARKER", "{{7*7}}"],
        "deep": ["SCANNER_RCE_MARKER", "{{7*7}}", "${7*7}", "<%= 7*7 %>"],
        "aggressive": [
            "SCANNER_RCE_MARKER",
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
            "#{7*7}",
            "*{7*7}",
        ],
    },
}

PROFILE_ORDER = ("quick", "standard", "deep", "aggressive")


def get_payloads(vulnerability_type: str, scan_profile: str = "standard") -> list[str]:
    vuln_key = (vulnerability_type or "").strip().lower()
    profile_key = (scan_profile or "standard").strip().lower()

    if vuln_key not in PAYLOADS:
        return []
    if profile_key not in PROFILE_ORDER:
        profile_key = "standard"

    return list(PAYLOADS[vuln_key][profile_key])
