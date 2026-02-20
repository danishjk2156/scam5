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

    # Check conversation history
    if conversation_history:
        for msg in conversation_history:
            if msg.get("sender", "").lower() == "scammer":
                msg_text = _get_msg_text(msg).lower()   # FIXED: checks both "text" and "message"
                score += sum(0.5 for k in keywords if k in msg_text)

    return score >= 1.5


def detect_scam_type(text: str, conversation_history: List[Dict] = None) -> str:
    """Detect type of scam from message and conversation history"""
    all_text = text.lower()

    if conversation_history:
        for msg in conversation_history:
            if msg.get("sender", "").lower() == "scammer":
                all_text += " " + _get_msg_text(msg).lower()   # FIXED

    if "upi" in all_text or "@ok" in all_text or "@ybl" in all_text or "@paytm" in all_text or "cashback" in all_text:
        return "UPI Fraud"
    if "phish" in all_text or "click" in all_text or "http" in all_text or "link" in all_text:
        return "Phishing"
    if "bank" in all_text or "account" in all_text or "sbi" in all_text or "hdfc" in all_text:
        return "Bank Impersonation"
    if "won" in all_text or "prize" in all_text or "lottery" in all_text or "congratulations" in all_text:
        return "Lottery Scam"
    if "kyc" in all_text or "update" in all_text:
        return "KYC Scam"
    if "otp" in all_text or "pin" in all_text or "password" in all_text:
        return "Credential Theft"
    if "refund" in all_text:
        return "Refund Scam"
    if "courier" in all_text or "parcel" in all_text or "delivery" in all_text or "customs" in all_text:
        return "Courier Scam"
    if "loan" in all_text or "credit" in all_text:
        return "Loan Scam"
    if "insurance" in all_text or "policy" in all_text:
        return "Insurance Scam"
    if "job" in all_text or "work from home" in all_text or "salary" in all_text:
        return "Job Scam"
    if "income tax" in all_text or "it department" in all_text or "tax refund" in all_text:
        return "Tax Scam"
    if "electricity" in all_text or "bill" in all_text or "disconnection" in all_text:
        return "Utility Scam"
    if "crypto" in all_text or "bitcoin" in all_text or "investment" in all_text:
        return "Investment Scam"
    if "tech support" in all_text or "virus" in all_text or "microsoft" in all_text:
        return "Tech Support Scam"

    urgency_words = ["urgent", "immediately", "hurry", "quick", "now", "today"]
    payment_words = ["send", "pay", "transfer", "deposit", "rupee"]
    if any(w in all_text for w in urgency_words) and any(w in all_text for w in payment_words):
        return "Payment Scam"

    return "Unknown"


def extract_intelligence(text: str, conversation_history: List[Dict] = None) -> dict:
    """Extract all intelligence from message and conversation history"""

    # Combine all scammer messages
    all_text = text
    if conversation_history:
        for msg in conversation_history:
            if msg.get("sender", "").lower() == "scammer":
                all_text += " " + _get_msg_text(msg)   # FIXED

    # ── UPI IDs ──────────────────────────────────────────────────────────────
    # KEY RULE: UPI domains have NO dot (e.g. @fakebank, @paytm)
    #           Emails have dots in domain (e.g. @fake-amazon.com)
    upi_patterns = [
        # Known UPI handles — always UPI
        r'\b[\w\.\-]+@(?:okicici|oksbi|okhdfc|okaxis|okbob|okciti|okkotak|paytm|okhdfcbank|phonepe|gpay|googlepay|ybl|axl|icici|ibl|sbi|hdfc|fakebank|fakeupi|upi)\b',
        # Contextual patterns — "send to X@Y", "pay to X@Y", "UPI ID: X@Y"
        r'send\s+(?:to\s+)?([a-zA-Z0-9\._-]+@[a-zA-Z0-9]+)',
        r'transfer\s+(?:to\s+)?([a-zA-Z0-9\._-]+@[a-zA-Z0-9]+)',
        r'UPI\s*ID[:\s]+([a-zA-Z0-9\._-]+@[a-zA-Z0-9]+)',
        r'pay\s+(?:to\s+)?([a-zA-Z0-9\._-]+@[a-zA-Z0-9]+)',
    ]
    upi_ids = set()
    for pattern in upi_patterns:
        for match in re.findall(pattern, all_text, re.IGNORECASE):
            val = match[0] if isinstance(match, tuple) else match
            val = val.strip().lower()
            domain = val.split('@')[1] if '@' in val else ''
            # UPI domains have NO dot — if domain has a dot it's an email, not UPI
            if '@' in val and '.' not in domain:
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
            if len(clean) == 10:
                phone_numbers.add(f"+91{clean}")
            elif len(clean) == 12 and clean.startswith('91'):
                phone_numbers.add(f"+{clean}")

    # ── Phishing Links ────────────────────────────────────────────────────────
    link_patterns = [
        r'https?://[^\s<>"\']+',
        r'www\.[^\s<>"\']+',
    ]
    phishing_links = set()
    legit_domains = ['google', 'facebook', 'twitter', 'linkedin', 'youtube', 'wikipedia']
    for pattern in link_patterns:
        for match in re.findall(pattern, all_text, re.IGNORECASE):
            match = match.rstrip('.,)')
            if not any(d in match.lower() for d in legit_domains):
                phishing_links.add(match)

    # ── Bank Accounts ─────────────────────────────────────────────────────────
    bank_patterns = [
        r'account\s*(?:number|no\.?|#)[:\s]+(\d{9,18})',
        r'a/?c\s*(?:number|no\.?|#)?[:\s]+(\d{9,18})',
        r'\b(\d{9,18})\b',
    ]
    bank_accounts = set()
    for pattern in bank_patterns:
        for match in re.findall(pattern, all_text, re.IGNORECASE):
            clean = re.sub(r'\D', '', str(match))
            # Must be 9-18 digits and NOT a phone number
            if 9 <= len(clean) <= 18 and not any(clean == re.sub(r'\D','',p) for p in phone_numbers):
                bank_accounts.add(clean)

    # ── Email Addresses ───────────────────────────────────────────────────────
    email_pattern = r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
    raw_emails = set(re.findall(email_pattern, all_text, re.IGNORECASE))
    # Keep only real emails (domain has a dot) and exclude UPI IDs already captured
    email_addresses = {
        e for e in raw_emails
        if '.' in e.split('@')[1] and e.lower() not in upi_ids
    }

    # ── Case / Reference IDs ──────────────────────────────────────────────────
    case_id_patterns = [
        r'(?:case|ticket|ref(?:erence)?|complaint|order|policy|SR|CR)\s*(?:id|no\.?|#)?[:\s]+([A-Z0-9\-]{4,20})',
    ]
    case_ids = set()
    for pattern in case_id_patterns:
        for match in re.findall(pattern, all_text, re.IGNORECASE):
            case_ids.add(match.strip())

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
        _get_msg_text(msg)                    # FIXED
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
