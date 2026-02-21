"""
Agentic Honeypot — v4.0

Key improvements over v3:
  - Scam-type-aware investigative questions (not just generic)
  - Richer red-flag identification surfaced in responses
  - Better Gemini prompts that reference specific red flags
  - Improved information elicitation strategies per scam type
  - Policy/order number extraction
  - More diverse dynamic question templates
"""

import json
import random
import re
import requests
import time
from typing import Dict, List, Any, Optional
from datetime import datetime
from enum import Enum


class ScamType(Enum):
    UPI_FRAUD = "UPI Fraud"
    PHISHING = "Phishing"
    LOAN_SCAM = "Loan Scam"
    TECH_SUPPORT = "Tech Support Scam"
    GIFT_CARD = "Gift Card Scam"
    GOVT_IMPERSONATION = "Government Impersonation"
    LOTTERY = "Lottery Scam"
    CREDIT_CARD = "Credit Card Fraud"
    SIM_CARD = "SIM Card Scam"
    COURIER = "Courier Scam"
    BANK_IMPERSONATION = "Bank Impersonation"
    KYC_SCAM = "KYC Scam"
    INSURANCE_SCAM = "Insurance Scam"
    TAX_SCAM = "Tax Scam"
    JOB_SCAM = "Job Scam"
    UNKNOWN = "Unknown"


class ConversationStage(Enum):
    INITIAL = "initial"
    BUILDING_TRUST = "building_trust"
    EXTRACTING = "extracting"
    DEEP_EXTRACTION = "deep_extraction"
    EXIT_PREPARATION = "exit_preparation"
    ENDED = "ended"


# ═══════════════════════════════════════════════════════════════════════════════
# SCAM-TYPE-AWARE INVESTIGATIVE QUESTIONS
# ═══════════════════════════════════════════════════════════════════════════════

# Generic investigative questions (work for any scam type)
GENERIC_QUESTIONS = [
    # Target: phone numbers
    "Can you give me your direct phone number so I can call back and confirm?",
    "What is the helpline number I should call to verify this?",
    "Can you share a callback number with your country code?",
    "Is there a toll-free number I can reach your department on?",
    "Can you give me the landline number of your office to verify?",
    # Target: UPI IDs
    "If I need to make any payment, what UPI ID should I use?",
    "Can you share the official UPI ID so I can verify it in my payment app?",
    "What is the exact UPI handle I should send the payment to?",
    # Target: links/URLs
    "Is there a website or link where I can check my case status?",
    "Can you send me the official portal link to verify this?",
    "Do you have any online form or link where I can submit my details securely?",
    "Can you share the URL of your bank's customer support page?",
    # Target: email
    "Can you give me your official company email so I can verify before doing anything?",
    "Can you email me the details so I have it in writing?",
    "What email address should I write to if I want to file a complaint?",
    "Can you send a confirmation email to my registered email ID?",
    # Target: bank account
    "If I need to transfer, what bank account number and IFSC should I use?",
    "Can you tell me the exact account number and branch name for the transfer?",
    # Target: identity/org info
    "What is your full name and staff ID badge number please?",
    "Is there a senior manager or supervisor I can speak to right now?",
    "What is the exact branch address I should visit to confirm this in person?",
    "What is the name of your branch and the state it is in?",
    "Can you tell me your employee ID so I can verify with the head office?",
    "Which department exactly are you calling from?",
    "What is your designation in the organization?",
    # Target: verification/red flags (these surface red flags while asking)
    "Can you tell me which RBI regulation requires me to share my OTP with you?",
    "Can you give me a case number I can verify on the official website?",
    "Why can I not visit the branch directly instead of sharing details over chat?",
    "Can you confirm the last 4 digits of my registered mobile number first?",
    "How do I know this is not a fraudulent call? Can you prove your identity?",
    "Can you send me an official SMS from the registered number first?",
    "My family member works in a bank, can I check with them first before proceeding?",
    "I want to verify this with the bank's customer care, can you give me the number?",
    "Can you tell me my account balance to prove you have access to my account?",
    "Why is the bank contacting me on chat instead of through the official app?",
    "I am not comfortable sharing OTP, is there any other way to verify?",
    "Can you give me some time? I want to check with my family before proceeding.",
    "What happens if I do not share the OTP right now? Will my account really be blocked?",
    "I have heard about scams like this, can you give me something official to verify?",
    "Can you share a reference letter or official document to prove this is real?",
]

# Scam-type-specific questions for richer probing
SCAM_TYPE_QUESTIONS = {
    "Bank Impersonation": [
        "Which branch are you calling from? I want to visit in person to verify.",
        "Can you tell me the exact IFSC code of your branch?",
        "What is the registered complaint number for this issue?",
        "I will call the bank's official number to verify — what should I tell them?",
        "Can you tell me when the unauthorized transaction happened exactly?",
        "What amount was the unauthorized transaction for?",
        "Which RBI circular number mandates sharing OTP over phone?",
        "Can you give me the reference number of the flagged transaction?",
    ],
    "UPI Fraud": [
        "What is the exact UPI ID I should verify in my app?",
        "Which payment app is this UPI ID registered with?",
        "How much cashback amount am I supposed to receive?",
        "Can you send the payment request from your end so I can verify the name?",
        "Why does the UPI ID not show a verified business name?",
        "Can you share the transaction reference number of the original payment?",
        "Is there a customer care number for this UPI service?",
    ],
    "Credential Theft": [
        "Why does the bank need my OTP — isn't the OTP for my own transactions?",
        "Can you verify my identity first before I share anything?",
        "My bank told me to never share OTP — can you confirm this is different?",
        "Can you give me a case reference so I can call the bank to verify?",
        "What is the transaction ID that triggered this security alert?",
    ],
    "Phishing": [
        "This link looks unfamiliar — can you share the official website URL instead?",
        "Is this link on the bank's registered domain?",
        "Can you give me the customer support email to verify this link?",
        "Why does this URL not match the bank's official website?",
        "Can you send this offer to my registered email from the official ID?",
    ],
    "KYC Scam": [
        "Which KYC regulation requires updating through chat?",
        "Can you give me the official KYC update portal link?",
        "What is the deadline for completing this KYC update?",
        "I updated my KYC at the branch last month — why is it needed again?",
        "Can you share the RBI circular number about mandatory KYC update?",
        "What is your employee ID in the KYC department?",
    ],
    "Courier Scam": [
        "What is the exact tracking number of this parcel?",
        "Which courier company is handling this delivery?",
        "Can you give me the sender's name and address on the parcel?",
        "What customs office is the parcel currently at?",
        "Can you share the customs duty order reference number?",
        "What is the declared value and contents of the parcel?",
    ],
    "Lottery Scam": [
        "What is the name of the lottery organization?",
        "Can you give me the official registration number of this lottery?",
        "When was the draw held and what was the winning ticket number?",
        "Can you share the official website where I can verify my prize?",
        "Why do I need to pay tax upfront instead of it being deducted from the prize?",
        "Can you email me the winning notification from an official email address?",
    ],
    "Insurance Scam": [
        "What is my policy number that you are referring to?",
        "Can you tell me the policy start date and maturity date?",
        "Which insurance company issued this policy?",
        "Can you share the IRDA registration number of your company?",
        "What is the sum assured under this policy?",
        "Can you give me the branch office address to verify?",
    ],
    "Tax Scam": [
        "What is my PAN number on file if you are from the IT department?",
        "Can you share the assessment order number?",
        "Which assessment year is this tax notice for?",
        "Can you give me the official e-filing portal link to check?",
        "What is the demand notice reference number?",
    ],
    "Loan Scam": [
        "What is the RBI registration number of your NBFC?",
        "Can you share the loan application reference number?",
        "What is the official interest rate and processing fee?",
        "Why is there a processing fee before loan approval?",
        "Can you share the registered office address of your company?",
    ],
    "Tech Support Scam": [
        "What is the error code or virus name detected on my computer?",
        "Can you give me your Microsoft employee ID to verify?",
        "What is the official support ticket number for my case?",
        "Why are you calling me instead of showing an alert in the software?",
        "Can you share the remote session ID you want me to enter?",
    ],
    "Job Scam": [
        "What is the company name and its registration number?",
        "Can you share the official job posting link on a verified job portal?",
        "What is the HR department's official email address?",
        "Why is there a registration or training fee for a job?",
        "What is the CIN number of this company?",
    ],
    "Refund Scam": [
        "What is the original order/transaction reference number?",
        "Can you share the refund approval reference number?",
        "Why do I need to share my bank details for a refund — don't you already have them?",
        "Can you tell me the exact refund amount and the original purchase date?",
    ],
}

# Red-flag-aware responses — these explicitly call out suspicious behavior
RED_FLAG_RESPONSES = [
    "Sir, I notice you are asking me to hurry — my bank always says to never rush. Can you explain why this is so urgent?",
    "I am concerned because real banks never ask for OTP over phone. Can you tell me which RBI regulation requires this?",
    "You are threatening that my account will be blocked — but the official app shows no issues. Why is there a mismatch?",
    "I find it suspicious that you are asking for payment to a personal UPI ID instead of an official account. Can you explain?",
    "My bank representative never contacts on WhatsApp or SMS — they use the bank app. Why are you contacting me this way?",
    "I have been told that processing fees are deducted from the amount, not collected separately. Why are you asking me to pay?",
    "This link does not look like the bank's official website — can you share the registered domain instead?",
    "You are asking for my Aadhaar number — but UIDAI says Aadhaar should not be shared over phone. Can you explain?",
    "I noticed you became more aggressive when I asked for verification. A real officer would not do that. Can you explain?",
    "Real refunds go back to the original payment method — why do you need my account details again?",
]


class AgenticHoneypot:
    def __init__(self, gemini_api_key: str):
        self.gemini_api_key = gemini_api_key
        self.base_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
        self.sessions: Dict[str, Any] = {}
        self.min_messages_before_end = 8
        self.max_messages_per_session = 20

        # Rate limiter
        self._api_call_times: List[float] = []
        self._rpm_limit = 5

        if not gemini_api_key or gemini_api_key == "your_gemini_key":
            print("⚠️  WARNING: Gemini API key missing! All responses will use fallback.")
        else:
            masked = gemini_api_key[:8] + "..." + gemini_api_key[-4:] if len(gemini_api_key) > 12 else "***"
            print(f"✅ Gemini API key loaded: {masked}")
            print(f"📊 Rate limit: {self._rpm_limit} RPM")

    def _check_rate_limit(self) -> bool:
        now = time.time()
        self._api_call_times = [t for t in self._api_call_times if now - t < 60]
        if len(self._api_call_times) >= self._rpm_limit:
            print(f"⚠️ Rate limit hit ({len(self._api_call_times)}/{self._rpm_limit} RPM). Using fallback.")
            return False
        self._api_call_times.append(now)
        return True

    def _call_gemini(self, prompt: str, temperature: float = 0.7,
                     max_tokens: int = 500, response_json: bool = False) -> Optional[str]:
        if not self._check_rate_limit():
            return None

        gen_config = {
            "temperature": temperature,
            "top_p": 0.95,
            "maxOutputTokens": max_tokens,
        }
        if response_json:
            gen_config["response_mime_type"] = "application/json"

        try:
            response = requests.post(
                f"{self.base_url}?key={self.gemini_api_key}",
                headers={"Content-Type": "application/json"},
                json={
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": gen_config,
                },
                timeout=12,
            )

            if response.status_code == 200:
                result = response.json()
                if result.get("candidates"):
                    candidate = result["candidates"][0]
                    finish_reason = candidate.get("finishReason", "STOP")
                    if finish_reason not in ("STOP", "stop"):
                        print(f"⚠️ Gemini cut off: {finish_reason}")
                        return None
                    return candidate["content"]["parts"][0]["text"].strip()
                else:
                    block_reason = result.get("promptFeedback", {}).get("blockReason", "unknown")
                    print(f"⚠️ Gemini no candidates. Block: {block_reason}")
                    return None
            elif response.status_code == 429:
                print("⚠️ Gemini 429 rate limited. Using fallback.")
                return None
            else:
                error_msg = ""
                try:
                    error_msg = response.json().get("error", {}).get("message", "")
                except Exception:
                    error_msg = response.text[:200]
                print(f"⚠️ Gemini {response.status_code}: {error_msg}")
                return None

        except requests.exceptions.Timeout:
            print("❌ Gemini timeout (12s)")
        except requests.exceptions.ConnectionError as e:
            print(f"❌ Gemini connection error: {e}")
        except Exception as e:
            print(f"❌ Gemini error: {e}")
        return None

    # ─── Helpers ──────────────────────────────────────────────────────────────

    def _get_msg_text(self, msg: Dict) -> str:
        return msg.get("text") or msg.get("message") or ""

    def _get_conversation_context(self, session: Dict) -> str:
        context = []
        for msg in session.get("conversation_history", [])[-12:]:
            role = "Scammer" if msg.get("sender") == "scammer" else "You"
            context.append(f"{role}: {self._get_msg_text(msg)}")
        return "\n".join(context)

    def _get_recent_agent_replies(self, session: Dict, n: int = 5) -> List[str]:
        replies = []
        for msg in reversed(session.get("conversation_history", [])):
            if msg.get("sender") in ("agent", "user"):
                replies.append(self._get_msg_text(msg).strip().lower())
                if len(replies) >= n:
                    break
        return replies

    def _is_repeat(self, text: str, session: Dict) -> bool:
        text_lower = text.strip().lower()
        recent = self._get_recent_agent_replies(session, n=6)
        for r in recent:
            if text_lower == r:
                return True
            if len(text_lower) > 20 and len(r) > 20 and text_lower[:40] == r[:40]:
                return True
        return False

    def _get_detected_scam_type(self, session: Dict) -> str:
        """Get the best-known scam type for this session."""
        return session.get("scam_type", "Unknown")

    def _get_non_repeating_question(self, session: Dict) -> str:
        """Pick a question that hasn't been used recently.
        Prioritizes: (1) scam-type-specific questions, (2) missing-intel questions,
        (3) red-flag-aware responses, (4) generic questions."""
        recent = self._get_recent_agent_replies(session, n=10)
        used_prefixes = set()
        for r in recent:
            used_prefixes.add(r[:40])

        def is_unused(q: str) -> bool:
            return q.lower()[:40] not in used_prefixes

        artifacts = session.get("extracted_intelligence", {}).get("artifacts", {})
        scam_type = self._get_detected_scam_type(session)

        # Pool 1: Scam-type-specific questions
        type_qs = SCAM_TYPE_QUESTIONS.get(scam_type, [])
        available_type = [q for q in type_qs if is_unused(q)]
        if available_type:
            return random.choice(available_type)

        # Pool 2: Red-flag-aware responses (surface red flags explicitly)
        red_flag_count = len(session.get("detected_red_flags", []))
        if red_flag_count >= 1:
            available_rf = [q for q in RED_FLAG_RESPONSES if is_unused(q)]
            if available_rf and random.random() < 0.4:  # 40% chance
                return random.choice(available_rf)

        # Pool 3: Missing-intelligence-targeted generic questions
        available_generic = [q for q in GENERIC_QUESTIONS if is_unused(q)]
        if available_generic:
            priority = []
            if not artifacts.get("phone_numbers"):
                priority.extend([q for q in available_generic if any(w in q.lower() for w in ["phone", "number", "call", "helpline", "toll"])])
            if not artifacts.get("upi_ids"):
                priority.extend([q for q in available_generic if any(w in q.lower() for w in ["upi", "payment"])])
            if not artifacts.get("urls"):
                priority.extend([q for q in available_generic if any(w in q.lower() for w in ["website", "link", "portal", "url"])])
            if not artifacts.get("emails"):
                priority.extend([q for q in available_generic if any(w in q.lower() for w in ["email", "mail"])])
            if not artifacts.get("bank_accounts"):
                priority.extend([q for q in available_generic if any(w in q.lower() for w in ["bank account", "ifsc", "transfer"])])
            if not artifacts.get("case_ids"):
                priority.extend([q for q in available_generic if any(w in q.lower() for w in ["case", "reference", "ticket", "employee id"])])
            if priority:
                return random.choice(list(set(priority)))
            return random.choice(available_generic)

        # Pool 4: Dynamic generated question
        return self._generate_dynamic_question(session)

    def _generate_dynamic_question(self, session: Dict) -> str:
        """Generate a contextual question when all pools are exhausted."""
        artifacts = session.get("extracted_intelligence", {}).get("artifacts", {})
        gaps = []
        if not artifacts.get("phone_numbers"):
            gaps.append("phone number")
        if not artifacts.get("upi_ids"):
            gaps.append("UPI ID")
        if not artifacts.get("urls"):
            gaps.append("website link")
        if not artifacts.get("bank_accounts"):
            gaps.append("bank account details")
        if not artifacts.get("emails"):
            gaps.append("email address")
        if not artifacts.get("case_ids"):
            gaps.append("case reference number")

        dynamic_templates = [
            "Sir, I am very worried about my account. Can you please give me your {gap} so I can verify everything?",
            "Before I do anything, I need your {gap} for my records. My family is asking me to be careful.",
            "OK sir, I will cooperate but first please share your {gap} so I can confirm with my bank branch.",
            "My son is telling me to be careful. Can you share your {gap} so he can also verify?",
            "I want to help but I am scared. Please give me your {gap} so I feel safe about this.",
            "One more thing sir, can you also provide your {gap}? I want to keep a record of everything.",
            "I am noting down everything. What is your {gap}? I need it for my personal records.",
            "My neighbor who works in bank said I should ask for your {gap} before sharing anything.",
            "Sir, without your {gap} I cannot proceed. My wife is insisting I verify everything first.",
            "I want to believe you but I need your {gap} — even my bank branch asks for this during verification.",
        ]

        if gaps:
            gap = random.choice(gaps)
            template = random.choice(dynamic_templates)
            return template.format(gap=gap)

        stalling = [
            "Sir, please give me 5 minutes, I am getting another call from the bank.",
            "My internet is very slow, can you please wait while I try to check?",
            "I am at the ATM right now, can you tell me what to do step by step?",
            "Sir, my phone is about to die. Can you message me all the details quickly?",
            "Hold on sir, my daughter is calling me. I will get back to you in 2 minutes.",
            "I am confused about the process. Can you explain from the beginning once more?",
            "Sir, I tried but the OTP is not coming. What should I do now?",
            "The app is showing error. Can you give me another way to do the verification?",
        ]
        return random.choice(stalling)

    def _should_end_conversation(self, session: Dict) -> bool:
        """Only end after 8+ scammer messages to maximise turn count score"""
        history = session.get("conversation_history", [])
        scammer_messages = [m for m in history if m.get("sender") == "scammer"]

        if len(scammer_messages) < self.min_messages_before_end:
            return False

        if len(history) >= self.max_messages_per_session:
            return True

        recent = [self._get_msg_text(m).lower() for m in scammer_messages[-3:]]
        sensitive = ["pin", "password", "otp", "aadhaar", "pan", "cvv"]
        if sum(1 for m in recent if any(k in m for k in sensitive)) >= 3:
            if len(scammer_messages) >= 10:
                return True

        extraction_score = self._calculate_extraction_score(session)
        if extraction_score > 0.7 and len(scammer_messages) >= 10:
            return True

        return False

    # ─── Detect Red Flags (session-level) ─────────────────────────────────────

    def _detect_red_flags_from_message(self, message: str, session: Dict) -> List[str]:
        """Detect red flags from the current message for scoring purposes."""
        msg_lower = message.lower()
        flags = []

        if any(w in msg_lower for w in ["urgent", "immediately", "hurry", "quick", "right now", "act fast"]):
            flags.append("urgency pressure tactics")
        if any(w in msg_lower for w in ["otp", "pin", "password", "cvv", "mpin"]):
            flags.append("requesting sensitive credentials")
        if any(w in msg_lower for w in ["blocked", "suspended", "frozen", "deactivated", "compromised"]):
            flags.append("threatening account suspension")
        if any(w in msg_lower for w in ["send", "pay", "transfer", "deposit", "processing fee"]):
            flags.append("unsolicited payment demand")
        if any(w in msg_lower for w in ["legal action", "police", "arrest", "court", "warrant", "fir"]):
            flags.append("legal intimidation tactics")
        if any(w in msg_lower for w in ["bank manager", "rbi", "fraud department", "customs", "income tax", "government"]):
            flags.append("impersonating authority figure")
        if any(w in msg_lower for w in ["won", "prize", "lottery", "cashback", "bonus", "reward"]):
            flags.append("unrealistic offer or prize claim")
        if any(w in msg_lower for w in ["click", "download", "install"]) and any(w in msg_lower for w in ["http", "link", "www"]):
            flags.append("directing to suspicious link")
        if any(w in msg_lower for w in ["aadhaar", "pan card", "voter id", "passport"]):
            flags.append("requesting government identity documents")
        if any(w in msg_lower for w in ["share your", "provide your", "tell me your", "give me your"]):
            flags.append("systematically harvesting personal data")

        if not flags:
            flags = ["unverified caller", "unsolicited contact"]

        return flags

    # ─── Analysis (rule-based to save API calls) ─────────────────────────────

    def _analyze_message_with_gemini(self, message: str, session: Dict) -> Dict:
        """Analyze scammer message — always rule-based to save RPM for responses."""
        return self._fallback_analysis(message, session)

    def _fallback_analysis(self, message: str, session: Dict) -> Dict:
        msg_lower = message.lower()
        scammer_count = len([m for m in session.get("conversation_history", []) if m.get("sender") == "scammer"])
        artifacts = session.get("extracted_intelligence", {}).get("artifacts", {})

        question = self._get_non_repeating_question(session)

        if scammer_count <= 1:
            stage = "initial"
        elif scammer_count <= 3:
            stage = "building_trust"
        elif scammer_count <= 6:
            stage = "extracting"
        else:
            stage = "deep_extraction"

        gaps = []
        if not artifacts.get("upi_ids"):       gaps.append("UPI ID needed")
        if not artifacts.get("phone_numbers"):  gaps.append("Phone number needed")
        if not artifacts.get("urls"):           gaps.append("Website URL needed")
        if not artifacts.get("bank_accounts"):  gaps.append("Bank account number needed")
        if not artifacts.get("case_ids"):       gaps.append("Case/reference ID needed")
        if not artifacts.get("emails"):         gaps.append("Email address needed")

        red_flags = self._detect_red_flags_from_message(message, session)

        # Update session-level red flags
        if "detected_red_flags" not in session:
            session["detected_red_flags"] = []
        for flag in red_flags:
            if flag not in session["detected_red_flags"]:
                session["detected_red_flags"].append(flag)

        scam_type = "Unknown"
        if "kyc" in msg_lower:                                              scam_type = "KYC Scam"
        elif "upi" in msg_lower or "fakebank" in msg_lower:                 scam_type = "UPI Fraud"
        elif "otp" in msg_lower or "pin" in msg_lower:                      scam_type = "Credential Theft"
        elif "sbi" in msg_lower or "hdfc" in msg_lower or "bank" in msg_lower: scam_type = "Bank Impersonation"
        elif "lottery" in msg_lower or "prize" in msg_lower:                scam_type = "Lottery Scam"
        elif "courier" in msg_lower or "parcel" in msg_lower:               scam_type = "Courier Scam"
        elif "insurance" in msg_lower or "policy" in msg_lower:             scam_type = "Insurance Scam"
        elif "income tax" in msg_lower or "tax" in msg_lower:               scam_type = "Tax Scam"
        elif "job" in msg_lower or "work from home" in msg_lower:           scam_type = "Job Scam"
        elif "refund" in msg_lower:                                         scam_type = "Refund Scam"
        elif "loan" in msg_lower:                                           scam_type = "Loan Scam"
        elif "tech support" in msg_lower or "virus" in msg_lower:           scam_type = "Tech Support Scam"

        return {
            "stage": stage,
            "scam_type": scam_type,
            "urgency_level": "high" if any(w in msg_lower for w in ["urgent", "immediately"]) else "medium",
            "scammer_tactic": "urgency with credential/payment request",
            "red_flags": red_flags,
            "key_elements": {
                "has_upi_id": bool(re.search(r'@[a-zA-Z0-9]+', message)),
                "has_urgency": any(w in msg_lower for w in ["urgent", "immediately", "hurry"]),
                "requests_sensitive_info": any(w in msg_lower for w in ["otp", "pin", "password"]),
                "requests_payment": any(w in msg_lower for w in ["send", "pay", "transfer"]),
                "has_contact_info": bool(re.search(r'\d{10}', message)),
            },
            "victim_response_strategy": "Ask investigative questions to extract contact details and reference red flags",
            "specific_question_to_ask": question,
            "intelligence_gaps": gaps,
            "confidence_score": 0.7,
        }

    # ─── Gemini: Generate Response ────────────────────────────────────────────

    def _generate_contextual_response(self, message: str, session: Dict,
                                       analysis: Dict, ending_conversation: bool = False) -> str:
        context = self._get_conversation_context(session)
        stage = session.get("current_stage", ConversationStage.INITIAL)
        artifacts = session.get("extracted_intelligence", {}).get("artifacts", {})
        recent_replies = self._get_recent_agent_replies(session, n=5)
        all_red_flags = session.get("detected_red_flags", [])

        if ending_conversation:
            prompt = f"""You are a victim in a scam conversation who needs to end the chat naturally.

CONVERSATION:
{context}

SCAMMER'S LATEST MESSAGE: "{message}"

Write a short natural excuse to leave. Must be a COMPLETE sentence, 10-15 words, casual Indian English.
Examples: "Phone battery dying, will message you later", "My boss just called, speak later", "Network is very bad here, talk later"

Your response (complete sentence only):"""

        else:
            strategy = analysis.get("victim_response_strategy", "Ask for more details")
            suggested_question = analysis.get("specific_question_to_ask", "")
            gaps = analysis.get("intelligence_gaps", [])
            red_flags = analysis.get("red_flags", [])

            if self._is_repeat(suggested_question, session):
                suggested_question = self._get_non_repeating_question(session)

            prompt = f"""You are playing the role of a confused, worried victim in a scam conversation. Your goal is to keep the scammer talking AND extract as much information as possible.

FULL CONVERSATION SO FAR:
{context}

SCAMMER'S LATEST MESSAGE: "{message}"

YOUR STAGE: {stage.value}
SCAMMER TACTIC: {analysis.get("scammer_tactic", "unknown")}
URGENCY LEVEL: {analysis.get("urgency_level", "medium")}

INTELLIGENCE ALREADY EXTRACTED:
- UPI IDs: {artifacts.get("upi_ids", [])}
- Phones: {artifacts.get("phone_numbers", [])}
- URLs: {artifacts.get("urls", [])}
- Bank Accounts: {artifacts.get("bank_accounts", [])}
- Case/Ref IDs: {artifacts.get("case_ids", [])}
- Emails: {artifacts.get("emails", [])}

STILL NEED: {", ".join(gaps) if gaps else "probe for more details"}

RED FLAGS DETECTED SO FAR: {", ".join(all_red_flags[:5]) if all_red_flags else "suspicious contact"}
NEW RED FLAGS IN THIS MESSAGE: {", ".join(red_flags[:3]) if red_flags else "none new"}

YOUR STRATEGY: {strategy}
ASK THIS QUESTION (incorporate naturally): {suggested_question}

YOUR LAST REPLIES — DO NOT REPEAT ANY OF THESE:
{chr(10).join(f"- {r}" for r in recent_replies)}

CRITICAL RULES:
1. Your response MUST be completely different from all recent replies above
2. Never say "scam", "fraud", "suspicious", "fake" — stay in character as a worried victim
3. Sound like a real Indian person — casual, simple English, slight anxiety
4. Incorporate the suggested question naturally
5. Your response MUST be a COMPLETE sentence, 20-40 words maximum
6. Do NOT start a sentence you cannot finish
7. IMPORTANT: Reference at least one red flag indirectly (e.g., "you are asking me to hurry but..." or "why do you need my OTP when bank says...")
8. If UPI mentioned — ask for EXACT UPI ID and confirm the handle
9. If phone mentioned — ask for EXACT number with employee ID
10. If website mentioned — ask for EXACT URL to verify

Your response (complete, different from recent replies, 20-40 words):"""

        raw = self._call_gemini(prompt, temperature=0.9, max_tokens=200)
        if raw:
            text = raw.replace('"', '').replace("'", "").strip()
            text = re.sub(r'^\*+|\*+$', '', text).strip()
            text = re.sub(r'^\(.*?\)\s*', '', text).strip()

            if len(text) >= 10 and not self._is_repeat(text, session):
                print(f"🤖 Response: {text}")
                return text
            else:
                print("⚠️ Gemini reply rejected (short/repeat), using pool question")

        return self._get_non_repeating_question(session)

    # ─── Intelligence Extraction ──────────────────────────────────────────────

    def _extract_intel_from_text(self, artifacts: Dict, text: str):
        """Extract intelligence from a single text string into artifacts dict."""

        # Step 1: Capture addresses in email context → always EMAIL
        email_context_patterns = [
            r'(?:email|e-mail|mail)\s+(?:us\s+)?(?:at\s+)?([a-zA-Z0-9\._-]+@[a-zA-Z0-9\._-]+)',
            r'(?:email|e-mail|mail)\s+(?:to\s+)?([a-zA-Z0-9\._-]+@[a-zA-Z0-9\._-]+)',
            r'(?:email|e-mail)\s+(?:id|address)[:\s]+([a-zA-Z0-9\._-]+@[a-zA-Z0-9\._-]+)',
        ]
        email_context_addresses = set()
        for pattern in email_context_patterns:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                val = match.group(1).strip().lower()
                if '@' in val:
                    email_context_addresses.add(val)

        # Step 2: UPI IDs — skip anything in email-context
        upi_patterns = [
            r'\b[\w\.\-]+@(?:okicici|oksbi|okhdfc|okaxis|okbob|paytm|phonepe|gpay|ybl|axl|fakebank|fakeupi|upi)\b(?!\.)',
            r'(?:send)\s+(?:the\s+)?(?:otp\s+)?(?:to\s+)?([a-zA-Z0-9\._-]+@[a-zA-Z0-9\._-]+)',
            r'transfer\s+(?:to\s+)?([a-zA-Z0-9\._-]+@[a-zA-Z0-9\._-]+)',
            r'UPI\s*ID[:\s]+([a-zA-Z0-9\._-]+@[a-zA-Z0-9\._-]+)',
            r'pay\s+(?:to\s+)?([a-zA-Z0-9\._-]+@[a-zA-Z0-9\._-]+)',
        ]
        if "upi_ids" not in artifacts:
            artifacts["upi_ids"] = []
        for pattern in upi_patterns:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                upi = match.group(1) if match.lastindex else match.group(0)
                upi = upi.strip().lower()
                domain = upi.split('@')[1] if '@' in upi else ''
                if upi in email_context_addresses:
                    continue
                if '@' in upi and '.' not in domain:
                    if upi not in artifacts["upi_ids"]:
                        artifacts["upi_ids"].append(upi)
                        print(f"🎯 UPI: {upi}")

        # URLs
        url_pattern = r'https?://[^\s<>"\']+|(?:www\.)[^\s<>"\']+'
        legit_domains = [
            'google', 'facebook', 'twitter', 'linkedin', 'youtube', 'wikipedia',
            'sbi.co.in', 'hdfcbank.com', 'icicibank.com', 'axisbank.com',
            'rbi.org.in', 'incometax.gov.in', 'uidai.gov.in', 'npci.org.in'
        ]
        if "urls" not in artifacts:
            artifacts["urls"] = []
        for url in re.findall(url_pattern, text, re.IGNORECASE):
            url = url.rstrip('.,)')
            if not any(d in url.lower() for d in legit_domains) and url not in artifacts["urls"]:
                artifacts["urls"].append(url)
                print(f"🎯 URL: {url}")

        # Phone numbers
        phone_patterns = [
            r'\+91[-\s]?\d{10}',
            r'(?<!\d)91(\d{10})(?!\d)',
            r'(?<!\d)([6-9]\d{9})(?!\d)',
            r'(?:call|contact|phone|mobile|number|reach|helpline|toll)[:\s]+(\+?91[-\s]?\d{10}|\d{10})',
        ]
        if "phone_numbers" not in artifacts:
            artifacts["phone_numbers"] = []
        for pattern in phone_patterns:
            for match in re.findall(pattern, text, re.IGNORECASE):
                val = match[0] if isinstance(match, tuple) else match
                clean = re.sub(r'[^\d]', '', str(val))
                formatted = None
                if len(clean) == 10 and clean[0] in '6789':
                    formatted = f"+91{clean}"
                elif len(clean) == 12 and clean.startswith('91') and clean[2] in '6789':
                    formatted = f"+{clean}"
                if formatted and formatted not in artifacts["phone_numbers"]:
                    artifacts["phone_numbers"].append(formatted)
                    print(f"🎯 Phone: {formatted}")

        # Bank accounts
        bank_patterns = [
            r'account\s*(?:number|no\.?|#)?\s*(?:is|:)?\s*(\d{9,18})',
            r'a/?c\s*(?:number|no\.?|#)?\s*(?:is|:)?\s*(\d{9,18})',
            r'(?:bank|savings|current|ifsc)\s*(?:account|a/?c)\s*(?:is|:)?\s*(\d{9,18})',
        ]
        if "bank_accounts" not in artifacts:
            artifacts["bank_accounts"] = []
        phone_digits = set()
        for p in artifacts.get("phone_numbers", []):
            d = re.sub(r'\D', '', p)
            phone_digits.add(d)
            if len(d) >= 10:
                phone_digits.add(d[-10:])
        for pattern in bank_patterns:
            for match in re.findall(pattern, text, re.IGNORECASE):
                clean = re.sub(r'\D', '', str(match))
                if 9 <= len(clean) <= 18 and clean not in artifacts["bank_accounts"]:
                    if clean not in phone_digits and clean[-10:] not in phone_digits:
                        artifacts["bank_accounts"].append(clean)
                        print(f"🎯 Bank Account: {clean}")

        # Emails
        email_pattern = r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
        if "emails" not in artifacts:
            artifacts["emails"] = []
        for email in re.findall(email_pattern, text, re.IGNORECASE):
            email = email.lower()
            if '.' in email.split('@')[1] and email not in artifacts["emails"] and email not in artifacts.get("upi_ids", []):
                artifacts["emails"].append(email)
                print(f"🎯 Email: {email}")
        for email in email_context_addresses:
            if email not in artifacts["emails"] and email not in artifacts.get("upi_ids", []):
                artifacts["emails"].append(email)
                print(f"🎯 Email (context): {email}")

        # Case / Reference / Staff / Policy / Order IDs
        case_patterns = [
            r'(?:case|ticket|ref(?:erence)?|complaint|order|policy)\s*(?:id|number|no\.?|#)?[:\s]+([A-Z0-9][A-Z0-9\-]{3,19})',
            r'(?:case|ticket|ref(?:erence)?|complaint|order|policy)\s*(?:id|number|no\.?|#)\s*(?:is|:)\s*([A-Z0-9][A-Z0-9\-]{3,19})',
            r'(?:staff|employee|badge|agent)\s*(?:id|number|no\.?|#)?[:\s]+([A-Z0-9][A-Z0-9\-]{2,19})',
            # Policy numbers
            r'(?:policy)\s*(?:number|no\.?|#)?[:\s]+([A-Z]{2,5}[-/]?\d{3,12})',
            # Order numbers
            r'(?:order)\s*(?:number|no\.?|#)?[:\s]+([A-Z]{2,6}[-/]?\d{3,12})',
        ]
        if "case_ids" not in artifacts:
            artifacts["case_ids"] = []
        bank_acct_set = set(artifacts.get("bank_accounts", []))
        phone_digit_set = set(re.sub(r'\D', '', p) for p in artifacts.get("phone_numbers", []))
        for pattern in case_patterns:
            for match in re.findall(pattern, text, re.IGNORECASE):
                stripped = match.strip()
                digits_only = re.sub(r'\D', '', stripped)
                if stripped.isdigit():
                    continue
                if digits_only in bank_acct_set or digits_only in phone_digit_set:
                    continue
                has_letter = bool(re.search(r'[A-Za-z]', stripped))
                has_dash = '-' in stripped
                if not has_letter and not has_dash:
                    continue
                if re.search(r'\d', stripped) and stripped not in artifacts["case_ids"]:
                    artifacts["case_ids"].append(stripped)
                    print(f"🎯 Case/Ref ID: {stripped}")

        # Amounts
        amount_patterns = [r'₹\s*(\d[\d,]*)', r'rs\.?\s*(\d[\d,]*)', r'(\d[\d,]*)\s*rupees?']
        if "amounts" not in artifacts:
            artifacts["amounts"] = []
        for pattern in amount_patterns:
            for match in re.findall(pattern, text, re.IGNORECASE):
                clean = int(re.sub(r'[^\d]', '', str(match)))
                if clean > 0 and clean not in artifacts["amounts"]:
                    artifacts["amounts"].append(clean)

    def _update_extracted_intelligence(self, session: Dict, message: str):
        if "extracted_intelligence" not in session:
            session["extracted_intelligence"] = {"artifacts": {}}
        artifacts = session["extracted_intelligence"]["artifacts"]
        self._extract_intel_from_text(artifacts, message)
        for msg in session.get("conversation_history", []):
            if msg.get("sender") == "scammer":
                self._extract_intel_from_text(artifacts, self._get_msg_text(msg))

    def _calculate_extraction_score(self, session: Dict) -> float:
        score = 0.0
        artifacts = session.get("extracted_intelligence", {}).get("artifacts", {})
        if artifacts.get("upi_ids"):        score += 0.25
        if artifacts.get("urls"):           score += 0.20
        if artifacts.get("phone_numbers"):  score += 0.20
        if artifacts.get("bank_accounts"):  score += 0.15
        if artifacts.get("emails"):         score += 0.10
        if artifacts.get("case_ids"):       score += 0.10
        if artifacts.get("amounts"):        score += 0.05
        return min(score, 1.0)

    # ─── Stage Management ─────────────────────────────────────────────────────

    def _determine_next_stage(self, session: Dict, analysis: Dict) -> ConversationStage:
        if session.get("ended"):
            return ConversationStage.ENDED

        stage_map = {
            "initial":          ConversationStage.INITIAL,
            "building_trust":   ConversationStage.BUILDING_TRUST,
            "extracting":       ConversationStage.EXTRACTING,
            "deep_extraction":  ConversationStage.DEEP_EXTRACTION,
            "exit_preparation": ConversationStage.EXIT_PREPARATION,
            "ended":            ConversationStage.ENDED,
        }
        return stage_map.get(analysis.get("stage", "building_trust"), ConversationStage.BUILDING_TRUST)

    # ─── Main Entry Point ─────────────────────────────────────────────────────

    def process_message(self, input_data: Dict) -> Dict:
        try:
            session_id = input_data["session_id"]
            message = input_data["message"]

            if session_id not in self.sessions:
                self.sessions[session_id] = {
                    "session_id": session_id,
                    "start_time": datetime.now().isoformat(),
                    "conversation_history": [],
                    "current_stage": ConversationStage.INITIAL,
                    "extracted_intelligence": {"artifacts": {}},
                    "ended": False,
                    "scam_analysis": [],
                    "detected_red_flags": [],
                }
                print(f"\n{'='*60}\n🆕 NEW SESSION: {session_id}\n{'='*60}")

            session = self.sessions[session_id]

            print(f"\n📱 SCAMMER [{session_id[:8]}]: {message}")

            # Extract intelligence from message + full history
            self._update_extracted_intelligence(session, message)

            # Analyse
            analysis = self._analyze_message_with_gemini(message, session)
            session["scam_analysis"].append({
                "timestamp": datetime.now().isoformat(),
                "analysis": analysis,
            })

            # Stage
            next_stage = self._determine_next_stage(session, analysis)
            session["current_stage"] = next_stage

            # End check
            should_end = self._should_end_conversation(session)

            # Generate response
            agent_response = self._generate_contextual_response(message, session, analysis, should_end)

            # Append agent response to session history
            session["conversation_history"].append({
                "timestamp": datetime.now().isoformat(),
                "sender": "agent",
                "message": agent_response,
            })

            # End if needed
            if should_end:
                session["ended"] = True
                session["end_time"] = datetime.now().isoformat()
                session["current_stage"] = ConversationStage.ENDED
                next_stage = ConversationStage.ENDED
                print("✅ Conversation ended")

            print(f"📊 Stage: {next_stage.value} | Extraction: {self._calculate_extraction_score(session):.2f} | RedFlags: {len(session.get('detected_red_flags', []))} | Msgs: {len(session['conversation_history'])}")

            return {
                "success": True,
                "data": {
                    "reply": agent_response,
                    "session_id": session_id,
                    "message_number": len([m for m in session["conversation_history"] if m.get("sender") == "scammer"]),
                    "conversation_stage": next_stage.value,
                    "extraction_progress": self._calculate_extraction_score(session),
                    "conversation_active": not session["ended"],
                    "should_get_report": session["ended"],
                    "analysis": {
                        "scam_type": analysis.get("scam_type", "Unknown"),
                        "urgency": analysis.get("urgency_level", "medium"),
                        "tactic": analysis.get("scammer_tactic", "unknown"),
                        "confidence": analysis.get("confidence_score", 0.5),
                        "red_flags": analysis.get("red_flags", []),
                        "intelligence_gaps": analysis.get("intelligence_gaps", []),
                    },
                },
            }

        except Exception as e:
            import traceback
            print(f"❌ ERROR: {e}")
            traceback.print_exc()
            return {"success": False, "error": str(e), "data": None}

    # ─── Report ───────────────────────────────────────────────────────────────

    def get_intelligence_report(self, session_id: str) -> Dict:
        if session_id not in self.sessions:
            return {"success": False, "error": "Session not found"}

        session = self.sessions[session_id]
        if not session.get("ended"):
            return {
                "success": False,
                "error": "Conversation still active",
                "data": {
                    "conversation_active": True,
                    "message_count": len([m for m in session["conversation_history"] if m.get("sender") == "scammer"]),
                    "extraction_progress": self._calculate_extraction_score(session),
                },
            }

        artifacts = session.get("extracted_intelligence", {}).get("artifacts", {})
        scammer_msgs = [self._get_msg_text(m) for m in session["conversation_history"] if m.get("sender") == "scammer"]

        return {
            "success": True,
            "data": {
                "session_id": session_id,
                "total_messages": len(session["conversation_history"]),
                "extraction_score": self._calculate_extraction_score(session),
                "extracted_intelligence": {
                    "upi_ids": artifacts.get("upi_ids", []),
                    "phone_numbers": artifacts.get("phone_numbers", []),
                    "urls": artifacts.get("urls", []),
                    "bank_accounts": artifacts.get("bank_accounts", []),
                    "emails": artifacts.get("emails", []),
                    "case_ids": artifacts.get("case_ids", []),
                    "amounts": artifacts.get("amounts", []),
                },
                "red_flags_detected": session.get("detected_red_flags", []),
                "scam_type": session["scam_analysis"][-1]["analysis"].get("scam_type", "Unknown") if session["scam_analysis"] else "Unknown",
                "first_message": scammer_msgs[0] if scammer_msgs else "",
                "last_message": scammer_msgs[-1] if scammer_msgs else "",
            },
        }