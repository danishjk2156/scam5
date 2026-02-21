# -*- coding: utf-8 -*-
"""
NLP Module for Scam Detection
Analyzes entire conversation history, not just single messages
"""

import re
from typing import List, Dict


def _get_msg_text(msg: Dict) -> str:
    """Helper: read message text regardless of field name (text or message)"""
    return msg.get("text") or msg.get("message") or ""


def detect_scam_intent(text: str, conversation_history: List[Dict] = None) -> bool:
    """Detect scam intent from message and conversation history"""
    keywords = [
        "urgent", "immediately", "blocked", "suspended",
        "verify", "upi", "account", "otp", "kyc", "today",
        "send", "pay", "transfer", "money", "rupee", "rs",
        "pin", "password", "cvv", "aadhaar", "pan",
        "warning", "last chance", "expire", "limited time",
        "cashback", "refund", "won", "prize", "lottery",
        "customs", "parcel", "courier", "insurance", "loan"
    ]

    text_lower = text.lower()
    score = sum(1 for k in keywords if k in text_lower)

    if conversation_history:
        for msg in conversation_history:
            if msg.get("sender", "").lower() == "scammer":
                msg_text = _get_msg_text(msg).lower()
                score += sum(0.5 for k in keywords if k in msg_text)

    return score >= 1.5


def detect_scam_type(text: str, conversation_history: List[Dict] = None) -> str:
    """Detect type of scam from message and conversation history"""
    all_text = text.lower()

    if conversation_history:
        for msg in conversation_history:
            if msg.get("sender", "").lower() == "scammer":
                all_text += " " + _get_msg_text(msg).lower()

    # ── Most specific / least ambiguous checks first ──────────────────────────
    if "kyc" in all_text:
        return "KYC Scam"
    if "income tax" in all_text or "it department" in all_text or "tax refund" in all_text:
        return "Tax Scam"
    if "courier" in all_text or "parcel" in all_text or "customs" in all_text:
        return "Courier Scam"
    if "won" in all_text or "prize" in all_text or "lottery" in all_text or "congratulations" in all_text:
        return "Lottery Scam"
    if "tech support" in all_text or "virus" in all_text or "microsoft" in all_text:
        return "Tech Support Scam"
    if "crypto" in all_text or "bitcoin" in all_text or "investment" in all_text:
        return "Investment Scam"
    if "insurance" in all_text or "policy" in all_text:
        return "Insurance Scam"
    if "job offer" in all_text or "work from home" in all_text or "part time job" in all_text or "salary" in all_text:
        return "Job Scam"
    if "electricity" in all_text or "disconnection" in all_text:
        return "Utility Scam"
    if "refund" in all_text:
        return "Refund Scam"
    if "loan" in all_text or "credit" in all_text:
        return "Loan Scam"

    # ── Bank impersonation before generic credential theft ────────────────────
    # OTP/PIN requests are symptoms of bank impersonation when bank context exists
    if "bank" in all_text or "sbi" in all_text or "hdfc" in all_text or "icici" in all_text or "account" in all_text:
        return "Bank Impersonation"
    if "otp" in all_text or "pin" in all_text or "password" in all_text or "cvv" in all_text:
        return "Credential Theft"

    # ── Broader checks last ───────────────────────────────────────────────────
    if "upi" in all_text or "@ybl" in all_text or "@paytm" in all_text or "cashback" in all_text:
        return "UPI Fraud"
    if "phish" in all_text or ("click" in all_text and "http" in all_text):
        return "Phishing"

    urgency_words = ["urgent", "immediately", "hurry", "quick", "now", "today"]
    payment_words = ["send", "pay", "transfer", "deposit", "rupee"]
    if any(w in all_text for w in urgency_words) and any(w in all_text for w in payment_words):
        return "Payment Scam"

    return "Unknown"


def extract_intelligence(text: str, conversation_history: List[Dict] = None) -> dict:
    """Extract all intelligence from message and conversation history"""

    all_text = text
    if conversation_history:
        for msg in conversation_history:
            if msg.get("sender", "").lower() == "scammer":
                all_text += " " + _get_msg_text(msg)

    # ── UPI IDs ──────────────────────────────────────────────────────────────
    #
    # KEY RULES:
    #   1. Known UPI handles (@paytm, @ybl, etc.) → always UPI
    #   2. Addresses in "email" context  → always EMAIL (even dotless domains)
    #   3. Addresses in payment context (send/transfer/pay/UPI ID) with dotless
    #      domain → UPI; with dotted domain → email
    #
    # ROOT-CAUSE FIX (v2):
    #   "email us at scammer.fraud@fakebank" was wrongly classified as UPI
    #   because the domain "fakebank" has no dot.  The word "email" provides
    #   clear context that this is an email address, not a UPI ID.
    #   Fix: email-context patterns are matched FIRST and their captures are
    #   routed directly to a separate email_context_addresses set, which is
    #   excluded from UPI and merged into emailAddresses later.

    # Step 1: Capture addresses that appear in explicit EMAIL context.
    #         These are ALWAYS treated as emails regardless of domain structure.
    email_context_patterns = [
        r'(?:email|e-mail|mail)\s+(?:us\s+)?(?:at\s+)?([a-zA-Z0-9\._-]+@[a-zA-Z0-9\._-]+)',
        r'(?:email|e-mail|mail)\s+(?:to\s+)?([a-zA-Z0-9\._-]+@[a-zA-Z0-9\._-]+)',
        r'(?:email|e-mail)\s+(?:id|address)[:\s]+([a-zA-Z0-9\._-]+@[a-zA-Z0-9\._-]+)',
    ]
    email_context_addresses = set()
    for pattern in email_context_patterns:
        for match in re.findall(pattern, all_text, re.IGNORECASE):
            val = match[0] if isinstance(match, tuple) else match
            val = val.strip().lower()
            if '@' in val:
                email_context_addresses.add(val)

    # Step 2: Capture UPI IDs — exclude anything already captured as email-context
    upi_patterns = [
        # Pattern 1: known UPI provider handles — always UPI (full match, no group)
        r'\b[\w\.\-]+@(?:okicici|oksbi|okhdfc|okaxis|okbob|okciti|okkotak|paytm|okhdfcbank|phonepe|gpay|googlepay|ybl|axl|icici|ibl|sbi|hdfc|fakebank|fakeupi|upi)\b',

        # Patterns 2-4: payment context — NOT email context
        r'(?:send)\s+(?:the\s+)?(?:otp\s+)?(?:to\s+)?([a-zA-Z0-9\._-]+@[a-zA-Z0-9\._-]+)',
        r'transfer\s+(?:to\s+)?([a-zA-Z0-9\._-]+@[a-zA-Z0-9\._-]+)',
        r'UPI\s*ID[:\s]+([a-zA-Z0-9\._-]+@[a-zA-Z0-9\._-]+)',
        r'pay\s+(?:to\s+)?([a-zA-Z0-9\._-]+@[a-zA-Z0-9\._-]+)',
    ]

    upi_ids = set()
    for pattern in upi_patterns:
        for match in re.findall(pattern, all_text, re.IGNORECASE):
            val = match[0] if isinstance(match, tuple) else match
            val = val.strip().lower()
            if '@' not in val:
                continue
            # Skip if already identified as email via email-context
            if val in email_context_addresses:
                continue
            domain = val.split('@', 1)[1]
            # UPI domains have NO dot; anything with a dot in the domain is an email
            if '.' not in domain:
                upi_ids.add(val)

    # ── Phone Numbers ─────────────────────────────────────────────────────────
    phone_patterns = [
        r'\+91[-\s]?\d{10}',
        r'\b91\d{10}\b',
        r'\b[6-9]\d{9}\b',
        r'(?:call|contact|phone|mobile|number|reach)[:\s]+(\+?91[-\s]?\d{10}|\d{10})',
    ]
    phone_numbers = set()
    for pattern in phone_patterns:
        for match in re.findall(pattern, all_text, re.IGNORECASE):
            val = match[0] if isinstance(match, tuple) else match
            clean = re.sub(r'[^\d]', '', str(val))
            if len(clean) == 10 and clean[0] in '6789':
                phone_numbers.add(f"+91{clean}")
            elif len(clean) == 12 and clean.startswith('91') and clean[2] in '6789':
                phone_numbers.add(f"+{clean}")

    # ── Phishing Links ────────────────────────────────────────────────────────
    link_patterns = [
        r'https?://[^\s<>"\']+',
        r'www\.[^\s<>"\']+',
    ]
    phishing_links = set()
    legit_domains = [
        'google', 'facebook', 'twitter', 'linkedin', 'youtube', 'wikipedia',
        'sbi.co.in', 'hdfcbank.com', 'icicibank.com', 'axisbank.com',
        'rbi.org.in', 'incometax.gov.in', 'uidai.gov.in', 'npci.org.in'
    ]
    for pattern in link_patterns:
        for match in re.findall(pattern, all_text, re.IGNORECASE):
            match = match.rstrip('.,)')
            if not any(d in match.lower() for d in legit_domains):
                phishing_links.add(match)

    # ── Bank Accounts ─────────────────────────────────────────────────────────
    bank_patterns = [
        r'account\s*(?:number|no\.?|#)?\s*(?:is|:)?\s*(\d{9,18})',
        r'a/?c\s*(?:number|no\.?|#)?\s*(?:is|:)?\s*(\d{9,18})',
        r'(?:bank|savings|current|ifsc)\s*(?:account|a/?c)\s*(?:is|:)?\s*(\d{9,18})',
    ]
    bank_accounts = set()
    phone_digits = set()
    for p in phone_numbers:
        d = re.sub(r'\D', '', p)
        phone_digits.add(d)
        if len(d) >= 10:
            phone_digits.add(d[-10:])
    for pattern in bank_patterns:
        for match in re.findall(pattern, all_text, re.IGNORECASE):
            clean = re.sub(r'\D', '', str(match))
            if 9 <= len(clean) <= 18:
                if clean not in phone_digits and clean[-10:] not in phone_digits:
                    bank_accounts.add(clean)

    # ── Email Addresses ───────────────────────────────────────────────────────
    # Require a dot in the domain (real emails) and exclude anything already
    # captured as a UPI ID.  Also merge in email-context addresses (which may
    # have dotless domains like scammer.fraud@fakebank).
    email_pattern = r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
    raw_emails = set(re.findall(email_pattern, all_text, re.IGNORECASE))
    email_addresses = {
        e for e in raw_emails
        if '.' in e.split('@', 1)[1] and e.lower() not in upi_ids
    }
    # Add email-context captures (even dotless domains like user@fakebank)
    email_addresses |= {e for e in email_context_addresses if e not in upi_ids}

    # ── Case / Reference IDs ──────────────────────────────────────────────────
    case_id_patterns = [
        r'(?:case|ticket|ref(?:erence)?|complaint|order|policy|SR|CR)\s*(?:id|number|no\.?|#)?[:\s]+([A-Z0-9][A-Z0-9\-]{3,19})',
        r'(?:case|ticket|ref(?:erence)?|complaint|order|policy)\s*(?:id|number|no\.?|#)\s*(?:is|:)\s*([A-Z0-9][A-Z0-9\-]{3,19})',
        r'(?:staff|employee|badge)\s*(?:id|number|no\.?|#)?[:\s]+([A-Z0-9][A-Z0-9\-]{2,19})',
    ]
    case_ids = set()
    for pattern in case_id_patterns:
        for match in re.findall(pattern, all_text, re.IGNORECASE):
            stripped = match.strip()
            if re.search(r'\d', stripped):
                case_ids.add(stripped)

    # ── Suspicious Keywords ───────────────────────────────────────────────────
    keyword_list = [
        "urgent", "immediately", "verify", "blocked", "suspended",
        "otp", "pin", "password", "kyc", "aadhaar", "expire",
        "limited time", "last chance", "warning", "send money",
        "transfer", "pay now", "cashback", "refund", "lottery", "prize"
    ]
    text_lower = all_text.lower()
    suspicious_keywords = [k for k in keyword_list if k in text_lower]

    return {
        "upiIds": list(upi_ids),
        "phoneNumbers": list(phone_numbers),
        "phishingLinks": list(phishing_links),
        "bankAccounts": list(bank_accounts),
        "emailAddresses": list(email_addresses),
        "caseIds": list(case_ids),
        "suspiciousKeywords": suspicious_keywords
    }


def analyze_conversation_for_scam(conversation_history: List[Dict]) -> Dict:
    """Analyze entire conversation to detect scam patterns"""
    empty = {
        "scamDetected": False, "scamType": "Unknown", "confidence": 0.0,
        "intelligence": {
            "upiIds": [], "phoneNumbers": [], "phishingLinks": [],
            "bankAccounts": [], "emailAddresses": [], "suspiciousKeywords": []
        }
    }

    if not conversation_history:
        return empty

    scammer_messages = [
        _get_msg_text(msg)
        for msg in conversation_history
        if msg.get("sender", "").lower() == "scammer"
    ]

    if not scammer_messages:
        return empty

    all_scammer_text = " ".join(scammer_messages)
    scam_detected = detect_scam_intent(all_scammer_text)
    scam_type = detect_scam_type(all_scammer_text)
    intelligence = extract_intelligence(all_scammer_text)

    confidence = 0.0
    if intelligence["upiIds"]:         confidence += 0.35
    if intelligence["phoneNumbers"]:   confidence += 0.25
    if intelligence["phishingLinks"]:  confidence += 0.20
    if intelligence["bankAccounts"]:   confidence += 0.15
    if intelligence["emailAddresses"]: confidence += 0.10
    if len(intelligence["suspiciousKeywords"]) >= 3: confidence += 0.20
    confidence = min(confidence, 1.0)

    return {
        "scamDetected": scam_detected or confidence > 0.3,
        "scamType": scam_type,
        "confidence": confidence,
        "intelligence": intelligence
    }