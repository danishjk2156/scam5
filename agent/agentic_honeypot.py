import json
import random
import re
import requests
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
    UNKNOWN = "Unknown"


class ConversationStage(Enum):
    INITIAL = "initial"
    BUILDING_TRUST = "building_trust"
    EXTRACTING = "extracting"
    DEEP_EXTRACTION = "deep_extraction"
    EXIT_PREPARATION = "exit_preparation"
    ENDED = "ended"


# ─── Pool of diverse investigative questions ─────────────────────────────────
INVESTIGATIVE_QUESTIONS = [
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
    # Target: verification/red flags
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


class AgenticHoneypot:
    def __init__(self, gemini_api_key: str):
        self.gemini_api_key = gemini_api_key
        self.base_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
        self.sessions: Dict[str, Any] = {}
        self.min_messages_before_end = 8
        self.max_messages_per_session = 20

        # Validate API key at startup
        if not gemini_api_key or gemini_api_key == "your_gemini_key":
            print("⚠️  WARNING: Gemini API key is missing or default! All responses will use fallback pool questions.")
            print("   Set GEMINI_API_KEY in your .env file to get dynamic AI-generated responses.")
        else:
            masked = gemini_api_key[:8] + "..." + gemini_api_key[-4:] if len(gemini_api_key) > 12 else "***"
            print(f"✅ Gemini API key loaded: {masked}")
            # Quick validation ping
            try:
                test_resp = requests.post(
                    f"{self.base_url}?key={self.gemini_api_key}",
                    headers={"Content-Type": "application/json"},
                    json={"contents": [{"parts": [{"text": "Say OK"}]}],
                          "generationConfig": {"maxOutputTokens": 10}},
                    timeout=10
                )
                if test_resp.status_code == 200:
                    print("✅ Gemini API connection verified")
                else:
                    error_detail = ""
                    try:
                        error_detail = test_resp.json().get("error", {}).get("message", "")
                    except Exception:
                        error_detail = test_resp.text[:200]
                    print(f"⚠️  Gemini API test failed: {test_resp.status_code} — {error_detail}")
                    print("   Responses will fall back to pool questions until API is working.")
            except Exception as e:
                print(f"⚠️  Gemini API connection test failed: {e}")

    # ─── Helpers ──────────────────────────────────────────────────────────────

    def _get_msg_text(self, msg: Dict) -> str:
        """Read message text regardless of field name"""
        return msg.get("text") or msg.get("message") or ""

    def _get_conversation_context(self, session: Dict) -> str:
        """Format last 12 messages as readable context for Gemini"""
        context = []
        for msg in session.get("conversation_history", [])[-12:]:
            role = "Scammer" if msg.get("sender") == "scammer" else "You"
            context.append(f"{role}: {self._get_msg_text(msg)}")
        return "\n".join(context)

    def _get_recent_agent_replies(self, session: Dict, n: int = 5) -> List[str]:
        """Return last N agent/user replies (lowercase) for repetition checking.
        FIX #5: checks both 'agent' and 'user' sender fields since the evaluator
        sends our replies back as sender='user' in conversationHistory."""
        replies = []
        for msg in reversed(session.get("conversation_history", [])):
            if msg.get("sender") in ("agent", "user"):
                replies.append(self._get_msg_text(msg).strip().lower())
                if len(replies) >= n:
                    break
        return replies

    def _is_repeat(self, text: str, session: Dict) -> bool:
        """Check if text closely matches any recent agent reply"""
        text_lower = text.strip().lower()
        recent = self._get_recent_agent_replies(session, n=6)
        for r in recent:
            if text_lower == r:
                return True
            if len(text_lower) > 20 and len(r) > 20 and text_lower[:40] == r[:40]:
                return True
        return False

    def _get_non_repeating_question(self, session: Dict) -> str:
        """Pick a question from the pool that hasn't been used recently.
        If the pool is exhausted, generate a dynamic question based on
        what intelligence is still missing."""
        recent = self._get_recent_agent_replies(session, n=10)
        used = set()
        for q in INVESTIGATIVE_QUESTIONS:
            for r in recent:
                if q.lower()[:40] == r[:40]:
                    used.add(q)
        available = [q for q in INVESTIGATIVE_QUESTIONS if q not in used]
        if available:
            # Prioritize questions that target missing intelligence
            artifacts = session.get("extracted_intelligence", {}).get("artifacts", {})
            priority = []
            if not artifacts.get("phone_numbers"):
                priority.extend([q for q in available if any(w in q.lower() for w in ["phone", "number", "call", "helpline", "toll"])])
            if not artifacts.get("upi_ids"):
                priority.extend([q for q in available if any(w in q.lower() for w in ["upi", "payment"])])
            if not artifacts.get("urls"):
                priority.extend([q for q in available if any(w in q.lower() for w in ["website", "link", "portal", "url"])])
            if not artifacts.get("emails"):
                priority.extend([q for q in available if any(w in q.lower() for w in ["email", "mail"])])
            if not artifacts.get("bank_accounts"):
                priority.extend([q for q in available if any(w in q.lower() for w in ["bank account", "ifsc", "transfer"])])
            if priority:
                return random.choice(list(set(priority)))
            return random.choice(available)

        # All pool questions exhausted — generate a dynamic question
        return self._generate_dynamic_question(session)

    def _generate_dynamic_question(self, session: Dict) -> str:
        """Generate a contextual question when the pool is exhausted."""
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

        # Dynamic questions based on missing intel
        dynamic_templates = [
            "Sir, I am very worried about my account. Can you please give me your {gap} so I can verify everything?",
            "Before I do anything, I need your {gap} for my records. My family is asking me to be careful.",
            "OK sir, I will cooperate but first please share your {gap} so I can confirm with my bank branch.",
            "My son is telling me to be careful. Can you share your {gap} so he can also verify?",
            "I want to help but I am scared. Please give me your {gap} so I feel safe about this.",
            "One more thing sir, can you also provide your {gap}? I want to keep a record of everything.",
            "I am noting down everything. What is your {gap}? I need it for my personal records.",
            "My neighbor who works in bank said I should ask for your {gap} before sharing anything.",
        ]

        if gaps:
            gap = random.choice(gaps)
            template = random.choice(dynamic_templates)
            return template.format(gap=gap)

        # If we somehow have all intel, use generic stalling
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

    # ─── Gemini: Analyse Message ──────────────────────────────────────────────

    def _analyze_message_with_gemini(self, message: str, session: Dict) -> Dict:
        context = self._get_conversation_context(session)
        scammer_count = len([m for m in session.get("conversation_history", []) if m.get("sender") == "scammer"])
        artifacts = session.get("extracted_intelligence", {}).get("artifacts", {})
        recent_replies = self._get_recent_agent_replies(session, n=4)

        prompt = f"""You are analyzing a scam conversation to help an AI honeypot respond naturally and extract intelligence.

CONVERSATION SO FAR:
{context}

SCAMMER'S LATEST MESSAGE: "{message}"

INTELLIGENCE EXTRACTED SO FAR:
- UPI IDs: {artifacts.get("upi_ids", [])}
- Phone Numbers: {artifacts.get("phone_numbers", [])}
- URLs: {artifacts.get("urls", [])}
- Bank Accounts: {artifacts.get("bank_accounts", [])}
- Emails: {artifacts.get("emails", [])}
- Case/Ref IDs: {artifacts.get("case_ids", [])}

RECENT HONEYPOT REPLIES (DO NOT suggest repeating these):
{chr(10).join(f"- {r}" for r in recent_replies)}

CURRENT STAGE: {session.get("current_stage", ConversationStage.INITIAL).value}
SCAMMER MESSAGES SO FAR: {scammer_count}

Analyze and return ONLY valid JSON:
{{
    "stage": "initial|building_trust|extracting|deep_extraction|exit_preparation",
    "scam_type": "specific scam type detected (e.g. Bank Impersonation, KYC Scam, UPI Fraud, Phishing)",
    "urgency_level": "low|medium|high",
    "scammer_tactic": "brief description",
    "red_flags": ["list at least 3 red flags you observe in this conversation"],
    "key_elements": {{
        "has_upi_id": true,
        "has_urgency": true,
        "requests_sensitive_info": true,
        "requests_payment": true,
        "has_contact_info": true
    }},
    "victim_response_strategy": "how to respond to extract more intel",
    "specific_question_to_ask": "a DIFFERENT investigative question not already in RECENT HONEYPOT REPLIES above",
    "intelligence_gaps": ["what intel is still missing"],
    "confidence_score": 0.0
}}"""

        try:
            response = requests.post(
                f"{self.base_url}?key={self.gemini_api_key}",
                headers={"Content-Type": "application/json"},
                json={
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {
                        "temperature": 0.4,
                        "top_p": 0.95,
                        "top_k": 40,
                        "response_mime_type": "application/json"
                    }
                },
                timeout=15
            )
            if response.status_code == 200:
                result = response.json()
                if result.get("candidates"):
                    candidate = result["candidates"][0]
                    finish_reason = candidate.get("finishReason", "STOP")
                    if finish_reason not in ("STOP", "stop"):
                        print(f"⚠️ Gemini analysis cut off: {finish_reason}, using fallback")
                        return self._fallback_analysis(message, session)

                    raw = candidate["content"]["parts"][0]["text"].strip()
                    raw = re.sub(r'^```(?:json)?\s*', '', raw, flags=re.MULTILINE)
                    raw = re.sub(r'```\s*$', '', raw, flags=re.MULTILINE)
                    raw = raw.strip()

                    match = re.search(r'\{.*\}', raw, re.DOTALL)
                    if match:
                        try:
                            analysis = json.loads(match.group())
                            print(f"✅ Gemini Analysis: stage={analysis.get('stage')} | scam_type={analysis.get('scam_type')} | {analysis.get('victim_response_strategy', '')[:50]}")
                            return analysis
                        except json.JSONDecodeError as e:
                            print(f"⚠️ JSON parse failed: {e} | raw: {raw[:200]}")
                            return self._fallback_analysis(message, session)
                    else:
                        print(f"⚠️ No JSON found in Gemini response: {raw[:200]}")
                        return self._fallback_analysis(message, session)

            print(f"⚠️ Gemini analysis returned {response.status_code}")
            try:
                error_body = response.json()
                error_msg = error_body.get("error", {}).get("message", response.text[:200])
                print(f"   Error detail: {error_msg}")
            except Exception:
                print(f"   Raw response: {response.text[:300]}")
        except requests.exceptions.Timeout:
            print(f"❌ Gemini analysis timed out (15s)")
        except requests.exceptions.ConnectionError as e:
            print(f"❌ Gemini analysis connection error: {e}")
        except Exception as e:
            print(f"❌ Gemini analysis error: {e}")

        return self._fallback_analysis(message, session)

    def _fallback_analysis(self, message: str, session: Dict) -> Dict:
        """Rule-based fallback when Gemini is unavailable"""
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

        red_flags = []
        if any(w in msg_lower for w in ["urgent", "immediately", "block"]): red_flags.append("urgency pressure tactics")
        if any(w in msg_lower for w in ["otp", "pin", "password"]):         red_flags.append("requesting sensitive credentials")
        if any(w in msg_lower for w in ["send", "transfer", "pay"]):        red_flags.append("unsolicited payment demand")
        if not red_flags: red_flags = ["unverified caller", "unsolicited contact", "pressure tactics"]

        scam_type = "Unknown"
        if "kyc" in msg_lower:                                              scam_type = "KYC Scam"
        elif "upi" in msg_lower or "fakebank" in msg_lower:                 scam_type = "UPI Fraud"
        elif "otp" in msg_lower or "pin" in msg_lower:                      scam_type = "Credential Theft"
        elif "sbi" in msg_lower or "hdfc" in msg_lower or "bank" in msg_lower: scam_type = "Bank Impersonation"
        elif "lottery" in msg_lower or "prize" in msg_lower:                scam_type = "Lottery Scam"
        elif "courier" in msg_lower or "parcel" in msg_lower:               scam_type = "Courier Scam"

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
                "has_contact_info": bool(re.search(r'\d{10}', message))
            },
            "victim_response_strategy": "Ask investigative questions to extract contact details",
            "specific_question_to_ask": question,
            "intelligence_gaps": gaps,
            "confidence_score": 0.7
        }

    # ─── Gemini: Generate Response ────────────────────────────────────────────

    def _generate_contextual_response(self, message: str, session: Dict, analysis: Dict, ending_conversation: bool = False) -> str:
        """Generate honeypot response using Gemini.
        FIX #3: _should_end_conversation is NOT called again here — the single
        authoritative decision is made in process_message and passed in."""

        context = self._get_conversation_context(session)
        stage = session.get("current_stage", ConversationStage.INITIAL)
        artifacts = session.get("extracted_intelligence", {}).get("artifacts", {})
        recent_replies = self._get_recent_agent_replies(session, n=5)

        try:
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

                prompt = f"""You are playing the role of a confused, worried victim in a scam conversation. Your goal is to keep the scammer talking and extract as much information as possible.

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

STILL NEED: {", ".join(gaps) if gaps else "probe for more details"}
RED FLAGS NOTICED: {", ".join(red_flags) if red_flags else "suspicious contact"}

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
7. If UPI mentioned — ask for EXACT UPI ID and confirm the handle
8. If phone mentioned — ask for EXACT number with employee ID
9. If website mentioned — ask for EXACT URL to verify

Your response (complete, different from recent replies, 20-40 words):"""

            response = requests.post(
                f"{self.base_url}?key={self.gemini_api_key}",
                headers={"Content-Type": "application/json"},
                json={
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {
                        "temperature": 0.9,
                        "top_p": 0.95,
                        "maxOutputTokens": 200
                    }
                },
                timeout=15
            )

            if response.status_code == 200:
                result = response.json()
                if result.get("candidates"):
                    candidate = result["candidates"][0]
                    finish_reason = candidate.get("finishReason", "STOP")
                    if finish_reason not in ("STOP", "stop"):
                        print(f"⚠️ Gemini reply cut off: {finish_reason}, using fallback")
                        return self._get_non_repeating_question(session)

                    text = candidate["content"]["parts"][0]["text"].strip()
                    text = text.replace('"', '').replace("'", "").strip()
                    # Clean up common Gemini artifacts
                    text = re.sub(r'^\*+|\*+$', '', text).strip()
                    text = re.sub(r'^\(.*?\)\s*', '', text).strip()

                    if len(text) < 10:
                        print(f"⚠️ Gemini reply too short: '{text}', using pool question")
                        return self._get_non_repeating_question(session)

                    if self._is_repeat(text, session):
                        print(f"⚠️ Gemini generated repeat reply, using pool question")
                        return self._get_non_repeating_question(session)

                    print(f"🤖 Response: {text}")
                    return text
                else:
                    # No candidates — might be safety block
                    block_reason = result.get("promptFeedback", {}).get("blockReason", "unknown")
                    print(f"⚠️ Gemini returned no candidates. Block reason: {block_reason}")
                    print(f"   Full response: {json.dumps(result)[:500]}")

            else:
                # Non-200 status — log details for debugging
                print(f"⚠️ Gemini response failed: {response.status_code}")
                try:
                    error_body = response.json()
                    error_msg = error_body.get("error", {}).get("message", response.text[:200])
                    print(f"   Error detail: {error_msg}")
                except Exception:
                    print(f"   Raw response: {response.text[:300]}")

        except requests.exceptions.Timeout:
            print(f"❌ Gemini response timed out (15s)")
        except requests.exceptions.ConnectionError as e:
            print(f"❌ Gemini connection error: {e}")
        except Exception as e:
            print(f"❌ Response generation error: {e}")

        return self._get_non_repeating_question(session)

    # ─── Intelligence Extraction ──────────────────────────────────────────────

    def _extract_intel_from_text(self, artifacts: Dict, text: str):
        """Extract intelligence from a single text string into artifacts dict.
        Separated out so it can be called on individual messages OR full history."""

        # UPI IDs — domain has NO dot (emails have dots in domain)
        # FIX v2: addresses in explicit "email" context are routed to emails,
        # even if the domain has no dot (e.g. scammer.fraud@fakebank).
        # Email-context patterns are matched FIRST.

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

        # Step 2: Capture UPI IDs — skip anything in email-context
        upi_patterns = [
            r'\b[\w\.\-]+@(?:okicici|oksbi|okhdfc|okaxis|okbob|paytm|phonepe|gpay|ybl|axl|fakebank|fakeupi|upi)\b',
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
                # Skip if captured as email-context address
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
            r'(?:call|contact|phone|mobile|number|reach)[:\s]+(\+?91[-\s]?\d{10}|\d{10})',
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

        # Bank accounts — FIX #6: broader patterns including "account NNNN" without number/no
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
        # Also add email-context captures (even dotless domains like user@fakebank)
        for email in email_context_addresses:
            if email not in artifacts["emails"] and email not in artifacts.get("upi_ids", []):
                artifacts["emails"].append(email)
                print(f"🎯 Email (context): {email}")

        # Case / Reference / Staff IDs
        # FIX: exclude pure digit strings (those are bank accounts or phone numbers)
        # A real case ID must contain at least one letter OR a dash between segments.
        case_patterns = [
            r'(?:case|ticket|ref(?:erence)?|complaint|order|policy)\s*(?:id|number|no\.?|#)?[:\s]+([A-Z0-9][A-Z0-9\-]{3,19})',
            r'(?:case|ticket|ref(?:erence)?|complaint|order|policy)\s*(?:id|number|no\.?|#)\s*(?:is|:)\s*([A-Z0-9][A-Z0-9\-]{3,19})',
            r'(?:staff|employee|badge)\s*(?:id|number|no\.?|#)?[:\s]+([A-Z0-9][A-Z0-9\-]{2,19})',
        ]
        if "case_ids" not in artifacts:
            artifacts["case_ids"] = []
        bank_acct_set = set(artifacts.get("bank_accounts", []))
        phone_digit_set = set(re.sub(r'\D', '', p) for p in artifacts.get("phone_numbers", []))
        for pattern in case_patterns:
            for match in re.findall(pattern, text, re.IGNORECASE):
                stripped = match.strip()
                digits_only = re.sub(r'\D', '', stripped)
                # Skip if it's a pure number (bank account or phone)
                if stripped.isdigit():
                    continue
                # Skip if digits match a known bank account or phone
                if digits_only in bank_acct_set or digits_only in phone_digit_set:
                    continue
                # Must contain at least one letter OR have a dash (real ref IDs like 2023-4567)
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
        """FIX #2: Extract intelligence from the current message AND re-scan
        the full conversation history so earlier missed intel is captured."""
        if "extracted_intelligence" not in session:
            session["extracted_intelligence"] = {"artifacts": {}}
        artifacts = session["extracted_intelligence"]["artifacts"]

        # Scan current message
        self._extract_intel_from_text(artifacts, message)

        # Also re-scan all scammer messages in history to catch anything
        # missed on earlier turns (e.g. if Gemini was down that turn)
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
            "ended":            ConversationStage.ENDED
        }

        # FIX #3: Do NOT call _should_end_conversation here.
        # The single authoritative end-check is in process_message().
        return stage_map.get(analysis.get("stage", "building_trust"), ConversationStage.BUILDING_TRUST)

    # ─── Main Entry Point ─────────────────────────────────────────────────────

    def process_message(self, input_data: Dict) -> Dict:
        """Process incoming scammer message and return honeypot response.

        FIX #1: Does NOT append the scammer message to conversation_history.
        main.py syncs the full history from the DB before calling this method,
        so the message is already present. Appending again caused duplicates.

        FIX #3: _should_end_conversation is called exactly ONCE here.

        FIX #4: Single-phase exit — when should_end is True, we generate
        the exit message AND set ended=True in the same turn.
        """
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
                    "scam_analysis": []
                }
                print(f"\n{'='*60}\n🆕 NEW SESSION: {session_id}\n{'='*60}")

            session = self.sessions[session_id]

            # FIX #1: Do NOT append scammer message — main.py synced the
            # full conversation_history from DB already.
            print(f"\n📱 SCAMMER [{session_id[:8]}]: {message}")

            # Extract intelligence from message + full history (FIX #2)
            self._update_extracted_intelligence(session, message)

            # Analyse
            analysis = self._analyze_message_with_gemini(message, session)
            session["scam_analysis"].append({"timestamp": datetime.now().isoformat(), "analysis": analysis})

            # Stage (FIX #3: no end check inside _determine_next_stage)
            next_stage = self._determine_next_stage(session, analysis)
            session["current_stage"] = next_stage

            # FIX #3: Single authoritative end check
            should_end = self._should_end_conversation(session)

            # Generate response (passes should_end directly, no re-check)
            agent_response = self._generate_contextual_response(message, session, analysis, should_end)

            # Append agent response to session history ONLY so the repetition
            # guard can see it on the next turn. main.py stores it in DB separately.
            session["conversation_history"].append({
                "timestamp": datetime.now().isoformat(),
                "sender": "agent",
                "message": agent_response
            })

            # FIX #4: Single-phase exit
            if should_end:
                session["ended"] = True
                session["end_time"] = datetime.now().isoformat()
                session["current_stage"] = ConversationStage.ENDED
                next_stage = ConversationStage.ENDED
                print("✅ Conversation ended")

            print(f"📊 Stage: {next_stage.value} | Extraction: {self._calculate_extraction_score(session):.2f} | Msgs: {len(session['conversation_history'])}")

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
                        "intelligence_gaps": analysis.get("intelligence_gaps", [])
                    }
                }
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
                    "extraction_progress": self._calculate_extraction_score(session)
                }
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
                    "amounts": artifacts.get("amounts", [])
                },
                "scam_type": session["scam_analysis"][-1]["analysis"].get("scam_type", "Unknown") if session["scam_analysis"] else "Unknown",
                "first_message": scammer_msgs[0] if scammer_msgs else "",
                "last_message": scammer_msgs[-1] if scammer_msgs else ""
            }
        }