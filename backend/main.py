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
    "citibank": {"citi.com", "citibank.com"},
    "venmo": {"venmo.com"},
    "zelle": {"zellepay.com"},
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
    (r"\bverify your (account|identity|password|pin|credentials|banking|card|profile)\b", "Solicits account or password verification"),
    (r"\bconfirm your (password|pin|security code|identity|account details|card details)\b", "Requests sensitive confirmation of password/PIN"),
    (r"\benter your (ssn|social security|credentials|password|pin)\b", "Requests personal SSN or login credentials"),
    (r"\bupdate your (login|billing|credentials|information|address|security)\b", "Requests credential, billing, or address update"),
    (r"\b(one-time passcode|one-time password|otp)\b", "Requests one-time verification passcode (OTP)"),
    (r"\bsecurity code\b", "Mentions security code or PIN submission"),
    (r"\blogin credentials\b", "Explicitly asks for login credentials"),
    (r"\b(unlock|reactivate|restore) (your )?(account|access)\b", "Urges action to unlock or restore access"),
]

PRIZE_PATTERNS = [
    (r"\bclaim (your )?(prize|reward|refund|lottery|payout|winnings)\b", "Lures with prizes, rewards, or lottery claims"),
    (r"\byou('ve| have| are) (won|selected as (a |the )?winner)\b", "Claims recipient has won money or a sweepstakes"),
    (r"\b(winner notification|selected winner|sweepstakes winner|lottery winner)\b", "Claims recipient is a sweepstakes/lottery winner"),
    (r"\bunclaimed (funds|money|reward|prize)\b", "Claims unclaimed funds or rewards are awaiting collection"),
    (r"\brefund of \$?\d+\b", "Promises unsolicited refunds"),
]

SUSPICIOUS_PAYMENT_PATTERNS = [
    (r"\bwire transfer\b", "Requests payment via wire transfer"),
    (r"\bgift card(s)?\b", "Requests non-traceable gift card payment"),
    (r"\b(crypto|cryptocurrency|bitcoin|ethereum|usdt)\b", "References cryptocurrency transfer"),
    (r"\b(processing |advance |release |clearance )?fee to (release|claim|collect)\b", "Demands advance fee before releasing funds"),
    (r"\b(processing|release|clearance) fee\b", "Demands processing or release fee"),
    (r"\b(send|pay|transfer) (via |through )?(zelle|venmo|cash ?app)\b", "Directs payment through peer-to-peer payment apps"),
]

BILLING_PATTERNS = [
    (r"\bpayment (overdue|declined|pending|failed)\b", "Claims urgent overdue or pending payment issue"),
    (r"\b(unauthorized|fraudulent) (transaction|charge|payment|activity)\b", "Claims unauthorized charge or transaction alert"),
    (r"\b(invoice|subscription|renewal) (overdue|renewed|auto-renewal|charged)\b", "References unexpected invoice or subscription charge"),
]

INSTITUTION_PATTERNS = [
    (r"\b(chase|bank of america|wells fargo|citibank|citi bank|paypal|venmo|zelle)\b", "financial institution or payment service"),
    (r"\b(irs|internal revenue service)\b", "tax authority"),
    (r"\b(usps|fedex|dhl|ups)\b", "delivery service"),
    (r"\b(netflix|amazon|apple|microsoft|geek squad)\b", "major service provider"),
]

FINANCIAL_PATTERNS = PRIZE_PATTERNS + SUSPICIOUS_PAYMENT_PATTERNS + BILLING_PATTERNS

SENSITIVE_PATH_KEYWORDS = {
    "login", "signin", "verify", "verification", "security", "secure",
    "account", "password", "credential", "credentials", "banking",
    "wallet", "auth", "confirm", "update-account", "update-billing"
}

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


def is_brand_in_host(host: str, brand: str) -> bool:
    """Checks whether brand is referenced as a domain label or concatenated with action words."""
    action_suffixes = "login|signin|verify|security|alert|update|support|service|account|online|billing|auth|refund"
    if re.search(r"(?:^|[.\-_])" + re.escape(brand) + r"(?:[.\-_]|$)", host):
        return True
    if re.search(r"(?:^|[.\-_])" + re.escape(brand) + r"(?:" + action_suffixes + r")", host):
        return True
    return False


def is_brand_in_path(path: str, brand: str) -> bool:
    """Checks whether brand is referenced in URL path as a distinct segment or token."""
    action_suffixes = "login|signin|verify|security|alert|update|support|service|account|online|billing|auth|refund"
    if re.search(r"(?:^|[/.\-_])" + re.escape(brand) + r"(?:[/.\-_]|$)", path):
        return True
    if re.search(r"(?:^|[/.\-_])" + re.escape(brand) + r"(?:" + action_suffixes + r")(?:[/.\-_]|$)", path):
        return True
    return False


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
    has_account_threat = False
    has_credential = False
    has_prize = False
    has_payment_demand = False
    has_billing_alert = False
    has_institution_lure = False

    if text:
        text_lower = text.lower()

        # Check Urgency & Account threats
        for pattern, desc in URGENCY_PATTERNS:
            if re.search(pattern, text_lower):
                has_urgency = True
                if re.search(r"\baccount (suspended|locked|terminated|disabled|restricted|frozen)\b|\bfinal notice\b", pattern):
                    has_account_threat = True
                    indicator_set.add("Threatens account closure, suspension, or final action")
                else:
                    indicator_set.add("Uses artificial urgency or tight deadlines")
                break

        # Check Credentials Harvesting
        for pattern, desc in CREDENTIAL_PATTERNS:
            if re.search(pattern, text_lower):
                has_credential = True
                indicator_set.add("Solicits confidential verification codes, passwords, or credentials")
                break

        # Check Prize lures
        for pattern, desc in PRIZE_PATTERNS:
            if re.search(pattern, text_lower):
                has_prize = True
                indicator_set.add("References prizes, lottery winnings, or unsolicited reward claims")
                break

        # Check Suspicious Payment Demands
        for pattern, desc in SUSPICIOUS_PAYMENT_PATTERNS:
            if re.search(pattern, text_lower):
                has_payment_demand = True
                indicator_set.add("Demands payment via wire transfer, gift card, cryptocurrency, or advance fee")
                break

        # Check Billing / Fake Invoice Alerts
        for pattern, desc in BILLING_PATTERNS:
            if re.search(pattern, text_lower):
                has_billing_alert = True
                indicator_set.add("References overdue billing, unauthorized transactions, or fake invoice charges")
                break

        # Check Institution Impersonation in text
        for pattern, brand_type in INSTITUTION_PATTERNS:
            m = re.search(pattern, text_lower)
            if m:
                if has_credential or has_urgency or has_account_threat or has_billing_alert or has_payment_demand:
                    has_institution_lure = True
                    matched_brand = m.group(1).title()
                    indicator_set.add(f"Impersonates {brand_type} ('{matched_brand}') in lure or billing context")
                    break

        # Excessive uppercase characters (High pressure)
        words = text.split()
        if len(words) >= 4:
            caps_count = sum(1 for w in words if w.isupper() and len(w) > 1)
            if caps_count / len(words) >= 0.4:
                score += 10
                indicator_set.add("Contains aggressive capitalization commonly used in high-pressure lures")

        # Context-aware scoring: Credential request + Urgency = High probability phishing
        if has_credential and (has_urgency or has_account_threat):
            score += 65
        elif has_credential:
            score += 40
        elif has_account_threat:
            score += 35
        elif has_urgency:
            score += 15

        # Compound financial & prize scam scoring
        if has_prize and has_payment_demand:
            score += 60
            indicator_set.add("Advance-fee fraud pattern: combines prize claim with upfront payment demand")
        elif has_prize:
            score += 30
        elif has_payment_demand:
            score += 35

        # Billing alerts / invoice fraud
        if has_billing_alert:
            if has_urgency or has_account_threat or has_payment_demand:
                score += 40
            else:
                score += 25

        # Institution lure compounding
        if has_institution_lure:
            score += 15

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
            is_shortener = host in KNOWN_SHORTENERS
            # Link shorteners
            if is_shortener:
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

            # Check if URL path targets sensitive authentication/account actions
            path_tokens = set(re.split(r"[/.\-_?=&%]+", path.lower()))
            has_sensitive_path = bool(path_tokens.intersection(SENSITIVE_PATH_KEYWORDS)) or bool(
                re.search(
                    r"(?:^|[/.\-_])(secure-account|account-login|account-verify|update-account|update-billing|verify-identity|claim-prize|prize-reward)(?:[/.\-_]|$)",
                    path.lower(),
                )
            )

            # If a link shortener conceals a destination while its path points to sensitive targets
            if is_shortener and has_sensitive_path:
                score += 20
                clean_path = path.strip("/")
                indicator_set.add(f"Shortened URL conceals sensitive authentication or account path ('{clean_path}')")

            # Brand Impersonation Checks
            base_domain = extract_base_domain(host)
            for brand, legit_domains in sorted(LEGITIMATE_BRAND_DOMAINS.items()):
                # Check if host is a legitimate domain for this brand
                is_legit = any(host == ld or host.endswith(f".{ld}") for ld in legit_domains)
                if is_legit:
                    continue

                # Brand in domain stem or subdomains on non-legitimate domain
                brand_in_host = is_brand_in_host(host, brand)
                brand_in_path = is_brand_in_path(path, brand)

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
