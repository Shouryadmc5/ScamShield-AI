import os
import ipaddress
import re
from typing import List, Optional, Set, Tuple
from urllib.parse import urlparse, unquote
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, model_validator
import uvicorn

app = FastAPI(
    title="ScamShield AI Backend",
    description="Deterministic rule-based scam message and phishing URL detection API",
    version="0.1.0",
)

# Configure CORS: In production, specify FRONTEND_URL or ALLOWED_ORIGINS
# Defaults to localhost dev origins if not configured.
default_dev_origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5174",
]
env_origins = os.getenv("ALLOWED_ORIGINS", os.getenv("FRONTEND_URL", "")).strip()
if env_origins:
    allowed_origins = [o.strip().rstrip("/") for o in env_origins.split(",") if o.strip()]
else:
    allowed_origins = default_dev_origins

# Always allow Vercel production and preview deployments (*.vercel.app) securely via regex
vercel_origin_regex = r"^https:\/\/.*\.vercel\.app$"

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=vercel_origin_regex,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "cutt.ly", "rb.gy", "shorturl.at"
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "loan", "click", "country", "link",
    "gq", "cf", "tk", "ml", "ga", "buzz", "rest", "fit", "surf",
    "win", "date", "racing", "vip", "icu", "party", "gdn"
}

# Recognized legitimate primary domain sets for major targeted brands
LEGITIMATE_BRAND_DOMAINS = {
    "paypal": {"paypal.com", "paypal.me"},
    "apple": {"apple.com", "icloud.com"},
    "google": {"google.com", "gmail.com", "youtube.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.de", "amazon.in", "aws.amazon.com"},
    "netflix": {"netflix.com"},
    "chase": {"chase.com"},
    "bankofamerica": {"bankofamerica.com", "bofa.com"},
    "wellsfargo": {"wellsfargo.com"},
    "usps": {"usps.com", "usps.gov"},
    "fedex": {"fedex.com"},
    "dhl": {"dhl.com"},
    "irs": {"irs.gov"},
    "binance": {"binance.com"},
    "coinbase": {"coinbase.com"},
    "whatsapp": {"whatsapp.com"},
    "telegram": {"telegram.org", "t.me"},
}

URGENCY_PATTERNS = [
    (r"\bimmediat(e|ely)\b", "Demands immediate action"),
    (r"\burgent(ly)?\b", "Uses urgent language"),
    (r"\bact now\b", "High-pressure call to action ('act now')"),
    (r"\bwithin (24|48|12) hours?\b", "Imposes tight artificial deadline"),
    (r"\blimited time\b", "Uses limited time pressure"),
    (r"\baccount (suspended|locked|terminated|disabled|restricted|frozen)\b", "Threatens account suspension or lockout"),
    (r"\bfinal notice\b", "Threatens final notice action"),
    (r"\baction required\b", "Insists action is required"),
]

CREDENTIAL_PATTERNS = [
    (r"\bverify your (account|identity|password|pin|credentials)\b", "Solicits account or password verification"),
    (r"\bconfirm your (password|pin|security code|identity)\b", "Requests sensitive confirmation of password/PIN"),
    (r"\benter your (ssn|social security|credentials|password)\b", "Requests personal SSN or login credentials"),
    (r"\bupdate your (login|billing|credentials|information)\b", "Requests credential or billing update"),
    (r"\b(one-time passcode|one-time password|otp)\b", "Requests one-time verification passcode (OTP)"),
    (r"\bsecurity code\b", "Mentions security code or PIN submission"),
    (r"\blogin credentials\b", "Explicitly asks for login credentials"),
]

FINANCIAL_PATTERNS = [
    (r"\bwire transfer\b", "Requests payment via wire transfer"),
    (r"\bgift card(s)?\b", "Requests non-traceable gift card payment"),
    (r"\b(crypto|cryptocurrency|bitcoin|ethereum|usdt)\b", "References cryptocurrency transfer"),
    (r"\bclaim your (prize|reward|refund|lottery)\b", "Lures with prizes, rewards, or lottery claims"),
    (r"\byou('ve| have) won\b", "Claims recipient has won money or a sweepstakes"),
    (r"\brefund of \$?\d+\b", "Promises unsolicited refunds"),
    (r"\bunclaimed (funds|money|reward)\b", "Claims unclaimed funds are awaiting collection"),
    (r"\bfee to release\b", "Demands advance fee before releasing funds"),
    (r"\bpayment (overdue|declined|pending)\b", "Claims urgent overdue or pending payment issue"),
]

SUSPICIOUS_SCHEMES = {"data", "javascript", "file", "vbscript", "blob"}


class AnalyzeRequest(BaseModel):
    message: Optional[str] = None
    url: Optional[str] = None

    @model_validator(mode="after")
    def check_non_empty(self):
        msg = (self.message or "").strip()
        u = (self.url or "").strip()
        if not msg and not u:
            raise ValueError("At least one non-empty field ('message' or 'url') must be provided.")
        return self


class AnalyzeResponse(BaseModel):
    risk_score: int
    risk_level: str
    indicators: List[str]
    recommendation: str
    analysis_method: str


def safe_parse_url(raw_url: str):
    """
    Safely normalizes and parses a URL without executing network calls.
    Returns (scheme, host, path, has_at, is_malformed, is_ip, original_raw)
    """
    cleaned = raw_url.strip()
    # Unquote escaped URL characters defensively
    try:
        unquoted = unquote(cleaned)
    except Exception:
        unquoted = cleaned

    has_at_symbol = "@" in unquoted

    # Handle schemes that don't necessarily use :// (e.g. javascript:, data:, file:, mailto:)
    scheme_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+\-.]*):", unquoted)
    explicit_scheme = scheme_match.group(1).lower() if scheme_match else None

    if explicit_scheme in SUSPICIOUS_SCHEMES:
        return {
            "scheme": explicit_scheme,
            "host": "",
            "path": unquoted[len(explicit_scheme) + 1:],
            "has_at": False,
            "is_ip": False,
            "is_malformed": False,
            "raw": cleaned
        }

    # Ensure standard hierarchical urlparse has a scheme to accurately split host and path
    url_to_parse = unquoted
    if "://" not in url_to_parse:
        url_to_parse = f"http://{url_to_parse}"

    try:
        parsed = urlparse(url_to_parse)
        scheme = (parsed.scheme or "").lower()
        netloc = parsed.netloc or ""
        path = parsed.path or ""

        # Extract host: strip user-info and port
        if "@" in netloc:
            # netloc is user:pass@host:port
            host_part = netloc.split("@")[-1]
        else:
            host_part = netloc

        host = host_part.split(":")[0].strip().lower()

        # Check if host is IPv4 or IPv6
        is_ip = False
        if host:
            try:
                ipaddress.ip_address(host)
                is_ip = True
            except ValueError:
                is_ip = False

        return {
            "scheme": scheme,
            "host": host,
            "path": path.lower(),
            "has_at": has_at_symbol,
            "is_ip": is_ip,
            "is_malformed": False,
            "raw": cleaned
        }
    except Exception:
        return {
            "scheme": "unknown",
            "host": "",
            "path": "",
            "has_at": "@" in cleaned,
            "is_ip": False,
            "is_malformed": True,
            "raw": cleaned
        }


def extract_base_domain(host: str) -> str:
    """Extracts effective second-level base domain (e.g., sub.example.com -> example.com)"""
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def evaluate_rules(message: Optional[str], url: Optional[str]):
    """
    Deterministic rule-based heuristics evaluating suspicious lures and URL properties.
    Bounded strictly between 0 and 100.
    """
    score = 0
    indicator_set: Set[str] = set()

    text = (message or "").strip()
    target_url = (url or "").strip()

    # Extract any URLs embedded inside message text
    embedded_urls = re.findall(r"https?://[^\s]+", text)
    candidate_urls = []
    if target_url:
        candidate_urls.append(target_url)
    for u in embedded_urls:
        if u not in candidate_urls:
            candidate_urls.append(u)

    # -------------------------------------------------------------
    # 1. MESSAGE TEXT ANALYSIS
    # -------------------------------------------------------------
    has_urgency = False
    has_credential = False
    has_financial = False

    if text:
        text_lower = text.lower()

        # Check Urgency
        for pattern, desc in URGENCY_PATTERNS:
            if re.search(pattern, text_lower):
                has_urgency = True
                indicator_set.add("Creates artificial urgency or threatens account closure")
                break

        # Check Credentials Harvesting
        for pattern, desc in CREDENTIAL_PATTERNS:
            if re.search(pattern, text_lower):
                has_credential = True
                indicator_set.add("Solicits confidential verification codes, passwords, or credentials")
                break

        # Check Financial lures
        for pattern, desc in FINANCIAL_PATTERNS:
            if re.search(pattern, text_lower):
                has_financial = True
                indicator_set.add("References prizes, unusual refunds, wire transfers, or cryptocurrency payments")
                break

        # Excessive uppercase characters (High pressure)
        words = text.split()
        if len(words) >= 4:
            caps_count = sum(1 for w in words if w.isupper() and len(w) > 1)
            if caps_count / len(words) >= 0.4:
                score += 10
                indicator_set.add("Contains aggressive capitalization commonly used in high-pressure lures")

        # Context-aware scoring: Credential request + Urgency = High probability phishing
        if has_credential and has_urgency:
            score += 65
        elif has_credential:
            score += 40
        elif has_urgency:
            # Urgency alone on ordinary messages is only a mild indicator (e.g., "Urgent: we need to leave now")
            score += 15

        if has_financial:
            score += 30

    # -------------------------------------------------------------
    # 2. URL INSPECTION (Deterministic & Passive)
    # -------------------------------------------------------------
    seen_hosts: Set[str] = set()

    for raw_u in candidate_urls:
        parsed_info = safe_parse_url(raw_u)

        if parsed_info["is_malformed"]:
            score += 30
            indicator_set.add("Malformed or unparseable URL structure")
            continue

        scheme = parsed_info["scheme"]
        host = parsed_info["host"]
        path = parsed_info["path"]
        is_ip = parsed_info["is_ip"]
        has_at = parsed_info["has_at"]

        # Prevent duplicate penalty application for the exact same host across multiple URLs
        host_already_scored = host in seen_hosts if host else False
        if host:
            seen_hosts.add(host)

        # Dangerous Schemes
        if scheme in SUSPICIOUS_SCHEMES:
            score += 45
            indicator_set.add(f"Contains dangerous executable URL scheme ('{scheme}:')")
        elif scheme == "http":
            score += 10
            indicator_set.add("Uses unencrypted HTTP connection instead of secure HTTPS")

        # User-info (@ symbol in authority)
        if has_at:
            score += 30
            indicator_set.add("URL contains '@' user-info notation commonly used to disguise true host")

        # Punycode / Internationalized Domain Name (IDN homograph risk)
        if host.startswith("xn--") or ".xn--" in host:
            score += 25
            indicator_set.add(f"Domain uses Punycode ('{host}') which may conceal homograph impersonation")

        # Raw IP address as host
        if is_ip:
            score += 35
            indicator_set.add(f"URL uses raw IP address ('{host}') instead of a recognized domain")

        if host and not host_already_scored:
            # Link shorteners
            if host in KNOWN_SHORTENERS:
                score += 20
                indicator_set.add(f"Uses link shortener ({host}) concealing true destination")

            # High-abuse TLDs
            tld = host.split(".")[-1] if "." in host else ""
            if tld in SUSPICIOUS_TLDS:
                score += 20
                indicator_set.add(f"Domain uses a top-level domain frequently associated with spam or phishing (.{tld})")

            # Deep subdomain nesting
            subdomain_parts = host.split(".")
            if len(subdomain_parts) > 4:
                score += 15
                indicator_set.add("Unusually deep subdomain hierarchy often used to camouflage domain names")

            # Brand Impersonation Checks
            base_domain = extract_base_domain(host)
            for brand, legit_domains in LEGITIMATE_BRAND_DOMAINS.items():
                # Check if host is a legitimate domain for this brand
                is_legit = any(host == ld or host.endswith(f".{ld}") for ld in legit_domains)
                if is_legit:
                    continue

                # Brand in domain stem or subdomains on non-legitimate domain
                brand_in_host = brand in host
                brand_in_path = brand in path

                if brand_in_host:
                    score += 35
                    indicator_set.add(f"Potential brand spoofing: brand '{brand}' referenced in unverified domain '{host}'")
                    break
                elif brand_in_path:
                    score += 15
                    indicator_set.add(f"Potential brand lure: URL path mentions '{brand}' while hosted on '{host}'")
                    break

    # -------------------------------------------------------------
    # 3. SCORE BOUNDING & RISK CATEGORIZATION
    # -------------------------------------------------------------
    risk_score = min(max(score, 0), 100)

    # Risk level thresholding:
    # 0-29: Low (benign or single weak signal)
    # 30-59: Medium (suspicious indicators warranting caution)
    # 60-100: High (strong indicators / confirmed phishing patterns)
    if risk_score >= 60:
        risk_level = "High"
    elif risk_score >= 30:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    # Actionable and consistent recommendations
    if risk_level == "High":
        recommendation = "Do not click links, provide passwords, or send funds. Report and block the sender immediately."
    elif risk_level == "Medium":
        recommendation = "Exercise caution. Verify the communication through an official verified channel before taking action."
    else:
        if not indicator_set:
            recommendation = "No prominent scam patterns detected. Always verify unexpected requests through trusted channels."
        else:
            recommendation = "Low risk indicators detected. Review sender details before taking any sensitive action."

    indicators = sorted(list(indicator_set))

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "indicators": indicators,
        "recommendation": recommendation,
        "analysis_method": "Deterministic rule-based heuristics (message lures and URL structural inspection)",
    }


@app.get("/health")
def health():
    return {"status": "ok", "service": "ScamShield AI Backend"}


@app.post("/api/analyze", response_model=AnalyzeResponse)
def analyze(payload: AnalyzeRequest):
    result = evaluate_rules(payload.message, payload.url)
    return result


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)
