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


class AgenticHoneypot:
    def __init__(self, gemini_api_key: str):
        self.gemini_api_key = gemini_api_key
        self.base_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
        self.sessions: Dict[str, Any] = {}
        self.min_messages_before_end = 10   # FIX: raised from 8
        self.max_messages_per_session = 20

        # Pool of fallback questions to avoid repeating the same line
        self.fallback_questions = [
            "Can you share your official company email and branch address?",
            "What bank department exactly are you calling from?",
            "Is there a supervisor I can speak to for verification?",
            "Can you send me an official SMS from SBI number to confirm?",
            "What is your staff ID and which branch are you calling from?",
            "Can you tell me the exact name of your manager and department?",
            "What is the official RBI helpline number I can cross-check with?",
        ]

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

    def _get_last_agent_reply(self, session: Dict) -> str:
        """Return the most recent agent message text"""
        for msg in reversed(session.get("conversation_history", [])):
            if msg.get("sender") == "agent":
                return self._get_msg_text(msg).strip()
        return ""

    def _should_end_conversation(self, session: Dict) -> bool:
        history = session.get("conversation_history", [])
        scammer_messages = [m for m in history if m.get("sender") == "scammer"]

        # Hard minimum — never end before this
        if len(scammer_messages) < self.min_messages_before_end:
            return False

        # Hard maximum
        if len(history) >= self.max_messages_per_session:
            return True

        # Only end if scammer has been VERY aggressively pushing credentials
        # across ALL recent messages, not just any mention
        recent = [self._get_msg_text(m).lower() for m in scammer_messages[-3:]]
        sensitive = ["pin", "password", "otp", "aadhaar", "pan", "cvv"]
        if sum(1 for m in recent if any(k in m for k in sensitive)) >= 3:
            if len(scammer_messages) >= 12:
                return True

        # Raise extraction threshold and require more messages
        extraction_score = self._calculate_extraction_score(session)
        if extraction_score > 0.85 and len(scammer_messages) >= 12:
            return True

        return False

    # ─── Gemini: Analyse Message ──────────────────────────────────────────────

    def _analyze_message_with_gemini(self, message: str, session: Dict) -> Dict:
        """Use Gemini to analyse scammer message and plan response strategy"""
        context = self._get_conversation_context(session)
        scammer_count = len([m for m in session.get("conversation_history", []) if m.get("sender") == "scammer"])
        artifacts = session.get("extracted_intelligence", {}).get("artifacts", {})

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

CURRENT STAGE: {session.get("current_stage", ConversationStage.INITIAL).value}
SCAMMER MESSAGES SO FAR: {scammer_count}

Analyze and return ONLY valid JSON:
{{
    "stage": "initial|building_trust|extracting|deep_extraction|exit_preparation",
    "scam_type": "specific scam type",
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
    "specific_question_to_ask": "exact investigative question to ask",
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

                    # FIX: Check finish reason before parsing
                    finish_reason = candidate.get("finishReason", "STOP")
                    if finish_reason not in ("STOP", "stop"):
                        print(f"⚠️ Gemini analysis cut off: {finish_reason}, using fallback")
                        return self._fallback_analysis(message, session)

                    raw = candidate["content"]["parts"][0]["text"].strip()

                    # FIX: Strip markdown code fences if Gemini wraps in ```json
                    raw = re.sub(r'^```(?:json)?\s*', '', raw, flags=re.MULTILINE)
                    raw = re.sub(r'```\s*$', '', raw, flags=re.MULTILINE)
                    raw = raw.strip()

                    # FIX: Safe JSON extraction with proper error handling
                    match = re.search(r'\{.*\}', raw, re.DOTALL)
                    if match:
                        try:
                            analysis = json.loads(match.group())
                            print(f"✅ Gemini Analysis: stage={analysis.get('stage')} | {analysis.get('victim_response_strategy', '')[:60]}")
                            return analysis
                        except json.JSONDecodeError as e:
                            print(f"⚠️ JSON parse failed: {e} | raw: {raw[:200]}")
                            return self._fallback_analysis(message, session)
                    else:
                        print(f"⚠️ No JSON found in Gemini response: {raw[:200]}")
                        return self._fallback_analysis(message, session)

            print(f"⚠️ Gemini analysis returned {response.status_code}")
        except Exception as e:
            print(f"❌ Gemini analysis error: {e}")

        return self._fallback_analysis(message, session)

    def _fallback_analysis(self, message: str, session: Dict) -> Dict:
        """Rule-based fallback when Gemini is unavailable"""
        msg_lower = message.lower()
        scammer_count = len([m for m in session.get("conversation_history", []) if m.get("sender") == "scammer"])
        artifacts = session.get("extracted_intelligence", {}).get("artifacts", {})

        if scammer_count <= 1:
            stage, question = "initial", "Sorry, which account are you referring to? Can you give me your reference number?"
        elif scammer_count <= 3:
            stage, question = "building_trust", "Can I get your employee ID and the official helpline number please?"
        elif scammer_count <= 6:
            if any(w in msg_lower for w in ["send", "transfer", "payment", "upi"]):
                stage, question = "extracting", "What is the exact UPI ID I should send to? And your phone number?"
            else:
                stage, question = "extracting", "What is your official website and helpline number I can verify with?"
        else:
            stage, question = "deep_extraction", "Can you give me your branch address and manager name to verify?"

        gaps = []
        if not artifacts.get("upi_ids"):       gaps.append("UPI ID needed")
        if not artifacts.get("phone_numbers"):  gaps.append("Phone number needed")
        if not artifacts.get("urls"):           gaps.append("Website URL needed")
        if not artifacts.get("bank_accounts"):  gaps.append("Bank account number needed")

        red_flags = []
        if any(w in msg_lower for w in ["urgent", "immediately", "block"]): red_flags.append("urgency pressure tactics")
        if any(w in msg_lower for w in ["otp", "pin", "password"]):         red_flags.append("requesting sensitive credentials")
        if any(w in msg_lower for w in ["send", "transfer", "pay"]):        red_flags.append("unsolicited payment demand")
        if not red_flags: red_flags = ["unverified caller", "unsolicited contact", "pressure tactics"]

        return {
            "stage": stage,
            "scam_type": "Unknown",
            "urgency_level": "high" if any(w in msg_lower for w in ["urgent", "immediately"]) else "medium",
            "scammer_tactic": "urgency with payment request",
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
        """Generate honeypot response using Gemini"""

        self._update_extracted_intelligence(session, message)

        context = self._get_conversation_context(session)
        stage = session.get("current_stage", ConversationStage.INITIAL)
        artifacts = session.get("extracted_intelligence", {}).get("artifacts", {})

        # FIX: Track last reply to prevent repetition
        last_reply = self._get_last_agent_reply(session)

        if self._should_end_conversation(session) and not session.get("ending_sent", False):
            ending_conversation = True
            session["ending_sent"] = True

        try:
            if ending_conversation:
                prompt = f"""You are a victim in a scam conversation who needs to end the chat naturally.

CONVERSATION:
{context}

SCAMMER'S LATEST MESSAGE: "{message}"

Write a short natural excuse to leave. Must be a complete sentence, 10-15 words, casual Indian English.
Examples: "Phone battery dying, will message you later", "My boss just called, speak later", "Network is very bad here, talk later"

Your response (complete sentence only):"""

            else:
                strategy = analysis.get("victim_response_strategy", "Ask for more details")
                specific_question = analysis.get("specific_question_to_ask", "Can you explain more?")
                gaps = analysis.get("intelligence_gaps", [])
                red_flags = analysis.get("red_flags", [])

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

STILL NEED: {", ".join(gaps) if gaps else "probe for more details"}
RED FLAGS NOTICED: {", ".join(red_flags) if red_flags else "suspicious contact"}

YOUR STRATEGY: {strategy}
ASK THIS SPECIFIC QUESTION: {specific_question}

LAST THING YOU SAID: "{last_reply}"

CRITICAL RULES:
1. NEVER repeat or closely paraphrase what you said last time
2. Never say "scam", "fraud", "suspicious", "fake" — stay in character as a worried victim
3. Sound like a real Indian person — casual, simple English, slight anxiety
4. Ask the suggested question above to extract missing intelligence
5. Also ask ONE investigative question about: company name / employee ID / official address
6. Mention ONE red flag (e.g. "why is this so urgent?", "this seems very unusual")
7. Your response MUST be a complete sentence, 20-35 words maximum
8. Do NOT start a sentence you cannot finish
9. If payment/UPI mentioned — ask for EXACT UPI ID
10. If phone mentioned — ask for EXACT number with employee ID

Your response (complete sentence, 20-35 words):"""

            response = requests.post(
                f"{self.base_url}?key={self.gemini_api_key}",
                headers={"Content-Type": "application/json"},
                json={
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {
                        "temperature": 0.85,
                        "top_p": 0.95,
                        "maxOutputTokens": 200   # FIX: prevents Gemini cutting off mid-sentence
                    }
                },
                timeout=15
            )

            if response.status_code == 200:
                result = response.json()
                if result.get("candidates"):
                    candidate = result["candidates"][0]

                    # FIX: Check finish reason — cut-off response is unusable
                    finish_reason = candidate.get("finishReason", "STOP")
                    if finish_reason not in ("STOP", "stop"):
                        print(f"⚠️ Gemini reply cut off: {finish_reason}, using fallback")
                        return self._get_non_repeating_fallback(last_reply, analysis)

                    text = candidate["content"]["parts"][0]["text"].strip()
                    text = text.replace('"', '').replace("'", "").strip()

                    # FIX: Guard against empty or suspiciously short replies
                    if len(text) < 10:
                        print(f"⚠️ Gemini reply too short: '{text}', using fallback")
                        return self._get_non_repeating_fallback(last_reply, analysis)

                    # FIX: Guard against repeating exact same reply
                    if text.strip().lower() == last_reply.strip().lower():
                        print(f"⚠️ Gemini repeated last reply, using fallback")
                        return self._get_non_repeating_fallback(last_reply, analysis)

                    print(f"🤖 Response: {text}")
                    return text

            print(f"⚠️ Gemini response failed: {response.status_code}")
        except Exception as e:
            print(f"❌ Response generation error: {e}")

        return self._get_non_repeating_fallback(last_reply, analysis)

    def _get_non_repeating_fallback(self, last_reply: str, analysis: Dict) -> str:
        """Return a fallback question that is different from the last reply"""
        # Try the analysis suggested question first
        suggested = analysis.get("specific_question_to_ask", "")
        if suggested and suggested.strip().lower() != last_reply.strip().lower():
            return suggested

        # Pick a random fallback that doesn't match the last reply
        options = [q for q in self.fallback_questions if q.strip().lower() != last_reply.strip().lower()]
        if options:
            return random.choice(options)

        # Last resort
        return "Can you please share your official company website and branch address for my records?"

    # ─── Intelligence Extraction ──────────────────────────────────────────────

    def _update_extracted_intelligence(self, session: Dict, message: str):
        """Extract intelligence from scammer message into session artifacts"""
        if "extracted_intelligence" not in session:
            session["extracted_intelligence"] = {"artifacts": {}}
        artifacts = session["extracted_intelligence"]["artifacts"]

        # UPI IDs
        upi_patterns = [
            r'\b[\w\.-]+@(?:okicici|oksbi|okhdfc|okaxis|okbob|paytm|phonepe|gpay|ybl|axl|fakebank|fakeupi|upi)\b',
            r'send\s+(?:to\s+)?([a-zA-Z0-9\._-]+@[a-zA-Z0-9]+)',
            r'transfer\s+(?:to\s+)?([a-zA-Z0-9\._-]+@[a-zA-Z0-9]+)',
            r'UPI\s*ID[:\s]+([a-zA-Z0-9\._-]+@[a-zA-Z0-9]+)',
            r'pay\s+(?:to\s+)?([a-zA-Z0-9\._-]+@[a-zA-Z0-9]+)',
            r'\b([a-zA-Z0-9\._-]{4,}@[a-zA-Z0-9]{3,})\b',  # FIX: min 4 chars before @
        ]
        if "upi_ids" not in artifacts:
            artifacts["upi_ids"] = []
        legit_email_domains = ['gmail', 'yahoo', 'hotmail', 'outlook', 'sbi.co', 'hdfcbank', 'icicibank']
        for pattern in upi_patterns:
            for match in re.finditer(pattern, message, re.IGNORECASE):
                upi = match.group(1) if match.lastindex else match.group(0)
                upi = upi.strip().lower()
                if '@' in upi and not any(d in upi for d in legit_email_domains):
                    if upi not in artifacts["upi_ids"]:
                        artifacts["upi_ids"].append(upi)
                        print(f"🎯 UPI: {upi}")

        # URLs — only suspicious ones
        url_pattern = r'https?://[^\s<>"\']+|(?:www\.)[^\s<>"\']+'
        legit_domains = [
            'google', 'facebook', 'twitter', 'linkedin', 'youtube', 'wikipedia',
            'sbi.co.in', 'hdfcbank.com', 'icicibank.com', 'axisbank.com',
            'rbi.org.in', 'incometax.gov.in', 'uidai.gov.in', 'npci.org.in'
        ]
        if "urls" not in artifacts:
            artifacts["urls"] = []
        for url in re.findall(url_pattern, message, re.IGNORECASE):
            url = url.rstrip('.,)')
            if not any(d in url.lower() for d in legit_domains) and url not in artifacts["urls"]:
                artifacts["urls"].append(url)
                print(f"🎯 URL: {url}")

        # Phone numbers — FIX: use negative lookbehind to avoid matching inside long numbers
        phone_patterns = [
            r'\+91[-\s]?\d{10}',
            r'(?<!\d)91(\d{10})(?!\d)',
            r'(?<!\d)([6-9]\d{9})(?!\d)',
            r'(?:call|contact|phone|mobile|reach)[:\s]+(\+?91[-\s]?\d{10}|\d{10})',
        ]
        if "phone_numbers" not in artifacts:
            artifacts["phone_numbers"] = []
        for pattern in phone_patterns:
            for match in re.findall(pattern, message, re.IGNORECASE):
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

        # Bank accounts — require contextual keywords to avoid false positives
        bank_patterns = [
            r'account\s*(?:number|no\.?|#)[:\s]+(\d{9,18})',
            r'a/?c\s*(?:no\.?|#)?[:\s]+(\d{9,18})',
            r'(?:bank|savings|current)\s*(?:account|a/?c)[:\s]*(\d{9,18})',
        ]
        if "bank_accounts" not in artifacts:
            artifacts["bank_accounts"] = []
        for pattern in bank_patterns:
            for match in re.findall(pattern, message, re.IGNORECASE):
                clean = re.sub(r'\D', '', str(match))
                if 9 <= len(clean) <= 18 and clean not in artifacts["bank_accounts"]:
                    # FIX: make sure it doesn't overlap with a known phone number
                    is_phone = any(clean in re.sub(r'\D', '', p) for p in artifacts.get("phone_numbers", []))
                    if not is_phone:
                        artifacts["bank_accounts"].append(clean)
                        print(f"🎯 Bank Account: {clean}")

        # Emails
        email_pattern = r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
        if "emails" not in artifacts:
            artifacts["emails"] = []
        for email in re.findall(email_pattern, message, re.IGNORECASE):
            email = email.lower()
            if '.' in email.split('@')[1] and email not in artifacts["emails"] and email not in artifacts["upi_ids"]:
                artifacts["emails"].append(email)
                print(f"🎯 Email: {email}")

        # Amounts
        amount_patterns = [r'₹\s*(\d[\d,]*)', r'rs\.?\s*(\d[\d,]*)', r'(\d[\d,]*)\s*rupees?']
        if "amounts" not in artifacts:
            artifacts["amounts"] = []
        for pattern in amount_patterns:
            for match in re.findall(pattern, message, re.IGNORECASE):
                clean = int(re.sub(r'[^\d]', '', str(match)))
                if clean > 0 and clean not in artifacts["amounts"]:
                    artifacts["amounts"].append(clean)

    def _calculate_extraction_score(self, session: Dict) -> float:
        """Score how much intelligence has been extracted"""
        score = 0.0
        artifacts = session.get("extracted_intelligence", {}).get("artifacts", {})
        if artifacts.get("upi_ids"):        score += 0.35
        if artifacts.get("urls"):           score += 0.25
        if artifacts.get("phone_numbers"):  score += 0.20
        if artifacts.get("bank_accounts"):  score += 0.15
        if artifacts.get("emails"):         score += 0.10
        if artifacts.get("amounts"):        score += 0.05
        return min(score, 1.0)

    # ─── Stage Management ─────────────────────────────────────────────────────

    def _determine_next_stage(self, session: Dict, analysis: Dict) -> ConversationStage:
        if session.get("ending_sent") or session.get("ended"):
            return ConversationStage.ENDED

        stage_map = {
            "initial":          ConversationStage.INITIAL,
            "building_trust":   ConversationStage.BUILDING_TRUST,
            "extracting":       ConversationStage.EXTRACTING,
            "deep_extraction":  ConversationStage.DEEP_EXTRACTION,
            "exit_preparation": ConversationStage.EXIT_PREPARATION,
            "ended":            ConversationStage.ENDED
        }

        if self._should_end_conversation(session):
            return ConversationStage.EXIT_PREPARATION

        return stage_map.get(analysis.get("stage", "building_trust"), ConversationStage.BUILDING_TRUST)

    # ─── Main Entry Point ─────────────────────────────────────────────────────

    def process_message(self, input_data: Dict) -> Dict:
        """Process incoming scammer message and return honeypot response"""
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
                    "ending_sent": False,
                    "ended": False,
                    "scam_analysis": []
                }
                print(f"\n{'='*60}\n🆕 NEW SESSION: {session_id}\n{'='*60}")

            session = self.sessions[session_id]

            session["conversation_history"].append({
                "timestamp": datetime.now().isoformat(),
                "sender": "scammer",
                "message": message
            })
            print(f"\n📱 SCAMMER [{session_id[:8]}]: {message}")

            analysis = self._analyze_message_with_gemini(message, session)
            session["scam_analysis"].append({"timestamp": datetime.now().isoformat(), "analysis": analysis})

            next_stage = self._determine_next_stage(session, analysis)
            session["current_stage"] = next_stage

            should_end = self._should_end_conversation(session)
            agent_response = self._generate_contextual_response(message, session, analysis, should_end)

            session["conversation_history"].append({
                "timestamp": datetime.now().isoformat(),
                "sender": "agent",
                "message": agent_response
            })

            print(f"📊 Stage: {next_stage.value} | Extraction: {self._calculate_extraction_score(session):.2f} | Msgs: {len(session['conversation_history'])}")

            if should_end and session.get("ending_sent"):
                session["ended"] = True
                session["end_time"] = datetime.now().isoformat()
                print("✅ Conversation ended")

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
                    "amounts": artifacts.get("amounts", [])
                },
                "scam_type": session["scam_analysis"][-1]["analysis"].get("scam_type", "Unknown") if session["scam_analysis"] else "Unknown",
                "first_message": scammer_msgs[0] if scammer_msgs else "",
                "last_message": scammer_msgs[-1] if scammer_msgs else ""
            }
        }