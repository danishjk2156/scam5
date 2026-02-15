# -*- coding: utf-8 -*-
"""
Improved NLP Module for Scam Detection
Analyzes entire conversation history, not just single messages
FULLY FIXED VERSION - Standardized field names
"""

import re
from typing import List, Dict

def detect_scam_intent(text: str, conversation_history: List[Dict] = None) -> bool:
    """
    Detect scam intent from message and conversation history
    
    Args:
        text: Current message text
        conversation_history: List of previous messages (optional)
    
    Returns:
        True if scam detected, False otherwise
    """
    keywords = [
        "urgent", "immediately", "blocked", "suspended",
        "verify", "upi", "account", "otp", "kyc", "today",
        "send", "pay", "transfer", "money", "rupee", "rs",
        "pin", "password", "cvv", "aadhaar", "pan",
        "warning", "last chance", "expire", "limited time"
    ]
    
    # Check current message
    text_lower = text.lower()
    score = sum(1 for k in keywords if k in text_lower)
    
    # Also check conversation history if provided
    if conversation_history:
        for msg in conversation_history:
            # FIXED: Standardized to check "sender" field
            if msg.get("sender") == "scammer":
                msg_text = msg.get("message", "").lower()
                score += sum(0.5 for k in keywords if k in msg_text)  # Half weight for history
    
    # FIXED: Lower threshold for better detection
    return score >= 1.5


def detect_scam_type(text: str, conversation_history: List[Dict] = None) -> str:
    """
    Detect type of scam from message and conversation history
    
    Args:
        text: Current message text
        conversation_history: List of previous messages (optional)
    
    Returns:
        Scam type string
    """
    # Combine all text for analysis
    all_text = text.lower()
    
    if conversation_history:
        for msg in conversation_history:
            # FIXED: Standardized to check "sender" field
            if msg.get("sender") == "scammer":
                msg_text = msg.get("message", "")
                all_text += " " + msg_text.lower()
    
    # Check for different scam types
    if "upi" in all_text or "@ok" in all_text or "@ybl" in all_text or "@paytm" in all_text:
        return "UPI Fraud"
    
    if "bank" in all_text or "account" in all_text:
        return "Bank Impersonation"
    
    if "won" in all_text or "prize" in all_text or "lottery" in all_text:
        return "Lottery Scam"
    
    if "kyc" in all_text or "verify" in all_text or "update" in all_text:
        return "KYC Scam"
    
    if "otp" in all_text or "pin" in all_text or "password" in all_text:
        return "Credential Theft"
    
    if "refund" in all_text or "cashback" in all_text:
        return "Refund Scam"
    
    if "courier" in all_text or "parcel" in all_text or "delivery" in all_text:
        return "Courier Scam"
    
    if "loan" in all_text or "credit" in all_text:
        return "Loan Scam"
    
    # If urgency + payment request detected, it's likely a scam
    urgency_words = ["urgent", "immediately", "hurry", "quick", "now", "today"]
    payment_words = ["send", "pay", "transfer", "deposit", "₹", "rupee"]
    
    has_urgency = any(word in all_text for word in urgency_words)
    has_payment = any(word in all_text for word in payment_words)
    
    if has_urgency and has_payment:
        return "Payment Scam"
    
    return "Unknown"


def extract_intelligence(text: str, conversation_history: List[Dict] = None) -> dict:
    """
    Extract intelligence from message and conversation history
    
    Args:
        text: Current message text
        conversation_history: List of previous messages (optional)
    
    Returns:
        Dictionary with extracted intelligence
    """
    # Combine all scammer messages for analysis
    all_text = text
    
    if conversation_history:
        for msg in conversation_history:
            # FIXED: Standardized to check "sender" field
            if msg.get("sender") == "scammer":
                msg_text = msg.get("message", "")
                all_text += " " + msg_text
    
    # Extract UPI IDs - improved patterns
    upi_patterns = [
        r'\b[\w\.-]+@(?:okicici|oksbi|okhdfc|okaxis|paytm|phonepe|ybl|axl)\b',  # Common UPI handles
        r'\b[\w\.-]+@[a-zA-Z]{2,}\b',  # Generic UPI pattern
        r'send (?:to |money to |₹\d+ to )?([a-zA-Z0-9.\-_]+@[a-zA-Z]+)',  # Extract from instructions
    ]
    
    upi_ids = set()
    for pattern in upi_patterns:
        matches = re.findall(pattern, all_text, re.IGNORECASE)
        for match in matches:
            if isinstance(match, tuple):
                match = match[0] if match else ""
            # Filter out email-like patterns that aren't UPI
            if match and '@' in match and not any(domain in match.lower() for domain in ['gmail', 'yahoo', 'hotmail', 'outlook']):
                upi_ids.add(match.lower())
    
    # Extract phone numbers - multiple formats
    phone_patterns = [
        r'\+91[-\s]?\d{10}',  # +91 format
        r'\b91\d{10}\b',  # 91 format
        r'\b[6-9]\d{9}\b',  # Indian mobile number
        r'call\s+(?:on\s+)?(\d{10})',  # "call 1234567890"
        r'contact\s+(?:on\s+)?(\d{10})',  # "contact 1234567890"
    ]
    
    phone_numbers = set()
    for pattern in phone_patterns:
        matches = re.findall(pattern, all_text, re.IGNORECASE)
        for match in matches:
            # Clean and normalize
            if isinstance(match, tuple):
                match = match[0] if match else ""
            clean_number = re.sub(r'[^\d]', '', str(match))
            if len(clean_number) >= 10:
                # Add +91 prefix if not present
                if len(clean_number) == 10:
                    phone_numbers.add(f"+91{clean_number}")
                elif len(clean_number) == 12 and clean_number.startswith('91'):
                    phone_numbers.add(f"+{clean_number}")
                else:
                    phone_numbers.add(f"+{clean_number}")
    
    # Extract phishing links - improved pattern
    link_patterns = [
        r'https?://[^\s]+',  # Standard http/https links
        r'www\.[^\s]+',  # www. links
        r'\b[a-z0-9-]+\.[a-z]{2,}(?:/[^\s]*)?\b',  # domain.com/path
    ]
    
    phishing_links = set()
    for pattern in link_patterns:
        matches = re.findall(pattern, all_text, re.IGNORECASE)
        for match in matches:
            # Filter out legitimate domains
            if not any(legit in match.lower() for legit in ['google', 'facebook', 'twitter', 'linkedin']):
                phishing_links.add(match)
    
    # Extract suspicious keywords
    suspicious_keywords = []
    keyword_list = [
        "urgent", "immediately", "verify", "blocked", "suspended",
        "account", "otp", "pin", "password", "kyc", "aadhaar",
        "expire", "limited time", "last chance", "warning",
        "send money", "transfer", "pay now"
    ]
    
    text_lower = all_text.lower()
    for keyword in keyword_list:
        if keyword in text_lower and keyword not in suspicious_keywords:
            suspicious_keywords.append(keyword)
    
    return {
        "upiIds": list(upi_ids),
        "phoneNumbers": list(phone_numbers),
        "phishingLinks": list(phishing_links),
        "suspiciousKeywords": suspicious_keywords
    }


def analyze_conversation_for_scam(conversation_history: List[Dict]) -> Dict:
    """
    Analyze entire conversation to detect scam patterns
    
    Args:
        conversation_history: List of all messages in conversation
    
    Returns:
        Dictionary with analysis results
    """
    if not conversation_history:
        return {
            "scamDetected": False,
            "scamType": "Unknown",
            "confidence": 0.0,
            "intelligence": {
                "upiIds": [],
                "phoneNumbers": [],
                "phishingLinks": [],
                "suspiciousKeywords": []
            }
        }
    
    # Get all scammer messages
    scammer_messages = []
    for msg in conversation_history:
        # FIXED: Standardized to check "sender" field
        if msg.get("sender") == "scammer":
            scammer_messages.append(msg.get("message", ""))
    
    if not scammer_messages:
        return {
            "scamDetected": False,
            "scamType": "Unknown",
            "confidence": 0.0,
            "intelligence": {
                "upiIds": [],
                "phoneNumbers": [],
                "phishingLinks": [],
                "suspiciousKeywords": []
            }
        }
    
    # Analyze all messages together
    all_scammer_text = " ".join(scammer_messages)
    
    scam_detected = detect_scam_intent(all_scammer_text)
    scam_type = detect_scam_type(all_scammer_text)
    intelligence = extract_intelligence(all_scammer_text)
    
    # Calculate confidence based on intelligence extracted
    confidence = 0.0
    if intelligence["upiIds"]:
        confidence += 0.4
    if intelligence["phoneNumbers"]:
        confidence += 0.3
    if intelligence["phishingLinks"]:
        confidence += 0.2
    if len(intelligence["suspiciousKeywords"]) >= 3:
        confidence += 0.3
    
    confidence = min(confidence, 1.0)
    
    return {
        "scamDetected": scam_detected or confidence > 0.3,
        "scamType": scam_type,
        "confidence": confidence,
        "intelligence": intelligence
    }