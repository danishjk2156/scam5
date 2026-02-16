import json
import re
import requests
from typing import Dict, List, Any, Optional
from datetime import datetime
from enum import Enum
import random

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
        # Conversation parameters
        self.min_messages_for_extraction = 3
        self.max_messages_per_session = 20
        self.extraction_threshold = 0.5
    
    def _get_conversation_context(self, session: Dict) -> str:
        """Format conversation history for context"""
        context = []
        for msg in session.get("conversation_history", []):
            role = "Scammer" if msg.get("sender") == "scammer" else "You"
            context.append(f"{role}: {msg['message']}")
        return "\n".join(context[-10:])  # Last 10 messages for better context
    
    def _should_end_conversation(self, session: Dict) -> bool:
        """Determine if conversation should end based on logical criteria"""
        history = session.get("conversation_history", [])
        scammer_messages = [msg for msg in history if msg.get("sender") == "scammer"]
        
        # Don't end too early
        if len(scammer_messages) < 5:
            return False
        
        # End if max messages reached
        if len(history) >= self.max_messages_per_session:
            return True
        
        # Check for repeated sensitive info requests (scammer is getting aggressive)
        recent_messages = [msg["message"].lower() for msg in scammer_messages[-3:]]
        sensitive_keywords = ["pin", "password", "otp", "aadhaar", "pan", "cvv"]
        sensitive_count = sum(1 for msg in recent_messages if any(kw in msg for kw in sensitive_keywords))
        
        if sensitive_count >= 2:
            return True
        
        # End if we've extracted significant intelligence
        extraction_score = self._calculate_extraction_score(session)
        if extraction_score > 0.6 and len(scammer_messages) >= 8:
            return True
        
        return False
    
    def _analyze_message_with_gemini(self, message: str, session: Dict) -> Dict:
        """Use Gemini to deeply analyze the scammer's message and conversation context"""
        
        context = self._get_conversation_context(session)
        scammer_messages_count = len([msg for msg in session.get("conversation_history", []) if msg.get("sender") == "scammer"])
        
        # Get extracted intelligence so far
        artifacts = session.get("extracted_intelligence", {}).get("artifacts", {})
        extracted_info = {
            "upi_ids": artifacts.get("upi_ids", []),
            "phone_numbers": artifacts.get("phone_numbers", []),
            "urls": artifacts.get("urls", []),
            "amounts": artifacts.get("amounts", [])
        }
        
        prompt = f"""You are analyzing a scam conversation to help an AI agent respond naturally and extract intelligence.

CONVERSATION CONTEXT:
{context}

SCAMMER'S LATEST MESSAGE: "{message}"

INTELLIGENCE EXTRACTED SO FAR:
- UPI IDs: {extracted_info['upi_ids']}
- Phone Numbers: {extracted_info['phone_numbers']}
- URLs: {extracted_info['urls']}
- Amounts: {extracted_info['amounts']}

CURRENT STAGE: {session.get('current_stage', ConversationStage.INITIAL).value}
SCAMMER MESSAGES SO FAR: {scammer_messages_count}

ANALYZE AND PROVIDE:

1. **CONVERSATION_STAGE**: Based on the conversation flow, what stage should we be in?
   - initial: First 1-2 messages, victim is confused/curious
   - building_trust: Scammer establishing legitimacy (messages 2-4)
   - extracting: Victim asking questions to extract info (messages 4-7)
   - deep_extraction: Scammer pushing hard, victim extracting critical data (messages 7+)
   - exit_preparation: Time to end naturally (after sufficient extraction)

2. **SCAM_TYPE**: Identify the specific scam type

3. **KEY_ELEMENTS**: What are the key elements in scammer's message?
   - Is there a UPI ID?
   - Is there urgency/threat?
   - Is there a request for sensitive information?
   - Is there a payment instruction?
   - Is there contact information?

4. **VICTIM_RESPONSE_STRATEGY**: How should the victim respond to extract MORE intelligence?
   - What specific question should be asked?
   - What confusion or concern should be expressed?
   - What additional details should be requested?

5. **INTELLIGENCE_GAPS**: What intelligence is still missing?
   - Need UPI ID?
   - Need phone number?
   - Need website URL?
   - Need transaction details?

Return ONLY valid JSON in this exact format:
{{
    "stage": "initial|building_trust|extracting|deep_extraction|exit_preparation",
    "scam_type": "specific scam type",
    "urgency_level": "low|medium|high",
    "scammer_tactic": "description",
    "key_elements": {{
        "has_upi_id": true/false,
        "has_urgency": true/false,
        "requests_sensitive_info": true/false,
        "requests_payment": true/false,
        "has_contact_info": true/false
    }},
    "victim_response_strategy": "specific strategy for this message",
    "specific_question_to_ask": "exact question victim should ask",
    "intelligence_gaps": ["list of missing intelligence"],
    "confidence_score": 0.0-1.0
}}
"""
        
        try:
            headers = {"Content-Type": "application/json"}
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {
                    "temperature": 0.4,
                    "top_p": 0.95,
                    "top_k": 40,
                    "response_mime_type": "application/json"
                }
            }
            
            response = requests.post(
                f"{self.base_url}?key={self.gemini_api_key}",
                headers=headers,
                json=payload,
                timeout=15
            )
            
            if response.status_code == 200:
                result = response.json()
                if 'candidates' in result and len(result['candidates']) > 0:
                    text = result['candidates'][0]['content']['parts'][0]['text'].strip()
                    # Extract JSON from response
                    json_match = re.search(r'\{.*\}', text, re.DOTALL)
                    if json_match:
                        analysis = json.loads(json_match.group())
                        print(f"✅ Gemini Analysis: {analysis.get('stage', 'unknown')} - {analysis.get('victim_response_strategy', 'unknown')}")
                        return analysis
            
            print(f"⚠️ Gemini API returned status {response.status_code}")
        except Exception as e:
            print(f"❌ Gemini analysis error: {e}")
        
        # Enhanced fallback analysis
        return self._enhanced_fallback_analysis(message, session)
    
    def _enhanced_fallback_analysis(self, message: str, session: Dict) -> Dict:
        """Enhanced fallback analysis with logical reasoning"""
        message_lower = message.lower()
        scammer_messages_count = len([msg for msg in session.get("conversation_history", []) if msg.get("sender") == "scammer"])
        
        # Determine stage logically
        if scammer_messages_count == 1:
            stage = "initial"
            strategy = "Express confusion and ask what this is about"
            question = "Sorry, which order/account are you referring to?"
        elif scammer_messages_count <= 3:
            stage = "building_trust"
            strategy = "Show interest but ask for verification details"
            question = "Can you tell me your reference number or transaction ID?"
        elif scammer_messages_count <= 6:
            stage = "extracting"
            if any(word in message_lower for word in ["send", "transfer", "payment"]):
                strategy = "Ask for exact payment details to extract UPI ID"
                question = "What is the exact UPI ID I should send to?"
            else:
                strategy = "Request specific contact information"
                question = "What's your helpline number so I can call back?"
        else:
            stage = "deep_extraction"
            strategy = "Act stressed but willing to comply, extract final details"
            question = "Please confirm the exact details one more time, I'm worried about making a mistake"
        
        # Detect key elements
        has_upi = bool(re.search(r'@(okicici|oksbi|okhdfc|paytm|phonepe|gpay|ybl)', message_lower))
        has_urgency = any(word in message_lower for word in ["urgent", "immediately", "hurry", "quick", "now", "last chance"])
        requests_sensitive = any(word in message_lower for word in ["pin", "password", "otp", "cvv", "pan"])
        requests_payment = any(word in message_lower for word in ["send", "transfer", "pay", "₹"])
        has_contact = bool(re.search(r'\d{10}', message))
        
        # Determine intelligence gaps
        artifacts = session.get("extracted_intelligence", {}).get("artifacts", {})
        gaps = []
        if not artifacts.get("upi_ids"):
            gaps.append("UPI ID needed")
        if not artifacts.get("phone_numbers"):
            gaps.append("Phone number needed")
        if not artifacts.get("urls"):
            gaps.append("Website URL needed")
        
        return {
            "stage": stage,
            "scam_type": "UPI Fraud" if has_upi else "Phishing",
            "urgency_level": "high" if has_urgency else "medium",
            "scammer_tactic": "urgency with payment request" if has_urgency and requests_payment else "trust building",
            "key_elements": {
                "has_upi_id": has_upi,
                "has_urgency": has_urgency,
                "requests_sensitive_info": requests_sensitive,
                "requests_payment": requests_payment,
                "has_contact_info": has_contact
            },
            "victim_response_strategy": strategy,
            "specific_question_to_ask": question,
            "intelligence_gaps": gaps,
            "confidence_score": 0.7
        }
    
    def _determine_next_stage(self, session: Dict, analysis: Dict) -> ConversationStage:
        """Determine the next stage based on analysis"""
        
        if session.get("ending_sent", False) or session.get("ended", False):
            return ConversationStage.ENDED
        
        # Map string to enum
        stage_map = {
            "initial": ConversationStage.INITIAL,
            "building_trust": ConversationStage.BUILDING_TRUST,
            "extracting": ConversationStage.EXTRACTING,
            "deep_extraction": ConversationStage.DEEP_EXTRACTION,
            "exit_preparation": ConversationStage.EXIT_PREPARATION,
            "ended": ConversationStage.ENDED
        }
        
        suggested_stage = analysis.get("stage", "building_trust")
        new_stage = stage_map.get(suggested_stage, ConversationStage.BUILDING_TRUST)
        
        # Check if we should end
        if self._should_end_conversation(session):
            return ConversationStage.EXIT_PREPARATION
        
        return new_stage
    
    def _generate_contextual_response(self, message: str, session: Dict, analysis: Dict, ending_conversation: bool = False) -> str:
        """Generate highly contextual response using Gemini with detailed instructions"""
        
        # Update intelligence from this message
        self._update_extracted_intelligence(session, message)
        
        # Build context
        context = self._get_conversation_context(session)
        stage = session.get("current_stage", ConversationStage.INITIAL)
        
        # Get what we've extracted so far
        artifacts = session.get("extracted_intelligence", {}).get("artifacts", {})
        
        # Check if we should end
        if self._should_end_conversation(session) and not session.get("ending_sent", False):
            ending_conversation = True
            session["ending_sent"] = True
        
        # Generate response using Gemini with detailed context
        try:
            if ending_conversation:
                prompt = f"""You are a victim in a scam conversation who needs to end the chat naturally.

FULL CONVERSATION:
{context}

SCAMMER'S LATEST MESSAGE: "{message}"

WHAT YOU'VE EXTRACTED:
- UPI IDs: {artifacts.get('upi_ids', [])}
- Phone Numbers: {artifacts.get('phone_numbers', [])}
- URLs: {artifacts.get('urls', [])}

Generate a natural, believable excuse to end the conversation. Be brief (10-20 words).

Examples of good excuses:
- "Phone battery dying, will msg later"
- "Family calling me, talk tomorrow"
- "Network problem, can't type properly now"
- "Boss came to desk, will check after work"
- "Child needs attention, will call back"

Your excuse (10-20 words, casual Indian English):"""
            
            else:
                # Get the specific strategy from analysis
                strategy = analysis.get("victim_response_strategy", "Ask for more details")
                specific_question = analysis.get("specific_question_to_ask", "Can you explain more?")
                gaps = analysis.get("intelligence_gaps", [])
                
                prompt = f"""You are a victim in a scam conversation. You need to respond naturally while extracting intelligence.

FULL CONVERSATION SO FAR:
{context}

SCAMMER'S LATEST MESSAGE: "{message}"

YOUR CURRENT STAGE: {stage.value}

ANALYSIS OF SCAMMER'S MESSAGE:
- Tactic: {analysis.get('scammer_tactic', 'unknown')}
- Urgency Level: {analysis.get('urgency_level', 'medium')}
- Key Elements: {analysis.get('key_elements', {})}

WHAT YOU'VE EXTRACTED SO FAR:
- UPI IDs: {artifacts.get('upi_ids', [])}
- Phone Numbers: {artifacts.get('phone_numbers', [])}
- URLs: {artifacts.get('urls', [])}
- Amounts: {artifacts.get('amounts', [])}

INTELLIGENCE YOU STILL NEED: {', '.join(gaps) if gaps else 'None'}

YOUR RESPONSE STRATEGY: {strategy}

SPECIFIC QUESTION TO ASK: {specific_question}

CRITICAL INSTRUCTIONS:
1. Never use words like "scam", "fraud", "suspicious", "fake"
2. Sound like a real Indian person (casual tone, simple English)
3. Make small typos occasionally (typ0s, missing punctuation)
4. Act confused/worried if they're being aggressive
5. Ask the specific question suggested above
6. Focus on extracting the missing intelligence
7. Keep response 15-25 words
8. If they mention UPI/payment, ask for EXACT UPI ID
9. If they mention calling, ask for the EXACT phone number
10. If they mention website, ask for the EXACT URL

Generate your response (15-25 words, natural chat style):"""
            
            headers = {"Content-Type": "application/json"}
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {
                    "temperature": 0.85,
                    "top_p": 0.95,
                    "max_output_tokens": 100
                }
            }
            
            response = requests.post(
                f"{self.base_url}?key={self.gemini_api_key}",
                headers=headers,
                json=payload,
                timeout=15
            )
            
            if response.status_code == 200:
                result = response.json()
                if 'candidates' in result and len(result['candidates']) > 0:
                    generated_response = result['candidates'][0]['content']['parts'][0]['text'].strip()
                    # Clean up the response
                    generated_response = generated_response.replace('"', '').replace("'", "").strip()
                    print(f"✅ Generated Response: {generated_response}")
                    return generated_response
            
            print(f"⚠️ Gemini API failed with status {response.status_code}")
        
        except Exception as e:
            print(f"❌ Response generation error: {e}")
        
        # If Gemini fails, use the specific question from analysis
        return analysis.get("specific_question_to_ask", "Can you give me more details?")
    
    def _update_extracted_intelligence(self, session: Dict, message: str):
        """Extract intelligence from the message"""
        if "extracted_intelligence" not in session:
            session["extracted_intelligence"] = {"artifacts": {}}
        
        artifacts = session["extracted_intelligence"]["artifacts"]
        
        # Extract UPI IDs - comprehensive patterns
        upi_patterns = [
            r'\b[\w\.-]+@(okicici|oksbi|okhdfc|okaxis|okbob|okciti|okkotak|paytm|okhdfcbank|phonepe|gpay|googlepay|ybl|axl|icici|ibl|sbi|hdfc)\b',
            r'send\s+(?:to\s+)?([a-zA-Z0-9\._-]+@[a-zA-Z0-9]+)',
            r'transfer\s+(?:to\s+)?([a-zA-Z0-9\._-]+@[a-zA-Z0-9]+)',
            r'UPI\s+ID[:\s]+([a-zA-Z0-9\._-]+@[a-zA-Z0-9]+)',
            r'pay\s+(?:to\s+)?([a-zA-Z0-9\._-]+@[a-zA-Z0-9]+)'
        ]
        
        if "upi_ids" not in artifacts:
            artifacts["upi_ids"] = []
        
        for pattern in upi_patterns:
            matches = re.finditer(pattern, message, re.IGNORECASE)
            for match in matches:
                # Get the UPI ID (might be in group 0 or 1)
                upi_id = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
                # Clean it up
                upi_id = upi_id.strip().lower()
                if '@' in upi_id and upi_id not in artifacts["upi_ids"]:
                    artifacts["upi_ids"].append(upi_id)
                    print(f"🎯 Extracted UPI ID: {upi_id}")
        
        # Extract URLs
        url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.\-?=&%#]*|(?:www\.)?[-\w]+\.(?:com|in|org|net)[/\w\.\-?=&%#]*'
        urls = re.findall(url_pattern, message, re.IGNORECASE)
        if "urls" not in artifacts:
            artifacts["urls"] = []
        for url in urls:
            url = url.strip()
            if url not in artifacts["urls"]:
                artifacts["urls"].append(url)
                print(f"🎯 Extracted URL: {url}")
        
        # Extract phone numbers
        phone_patterns = [
            r'\b(\d{10})\b',
            r'\b(\d{5}[-\s]?\d{5})\b',
            r'(?:call|contact|phone|mobile|number)[:\s]+(\d{10})',
            r'(\+91[-\s]?\d{10})'
        ]
        if "phone_numbers" not in artifacts:
            artifacts["phone_numbers"] = []
        for pattern in phone_patterns:
            numbers = re.findall(pattern, message, re.IGNORECASE)
            for num in numbers:
                num = re.sub(r'[-\s+]', '', str(num))
                if len(num) == 10 and num not in artifacts["phone_numbers"]:
                    artifacts["phone_numbers"].append(num)
                    print(f"🎯 Extracted Phone: {num}")
        
        # Extract amounts
        amount_patterns = [
            r'₹\s*(\d+[,\d]*)',
            r'rs\.?\s*(\d+[,\d]*)',
            r'rupees?\s*(\d+[,\d]*)',
            r'(\d+[,\d]*)\s*rupees?',
            r'amount[:\s]+₹?\s*(\d+[,\d]*)'
        ]
        if "amounts" not in artifacts:
            artifacts["amounts"] = []
        for pattern in amount_patterns:
            amounts = re.findall(pattern, message, re.IGNORECASE)
            for amt in amounts:
                clean_amt = int(re.sub(r'[^\d]', '', str(amt)))
                if clean_amt > 0 and clean_amt not in artifacts["amounts"]:
                    artifacts["amounts"].append(clean_amt)
                    print(f"🎯 Extracted Amount: ₹{clean_amt}")
    
    def _calculate_extraction_score(self, session: Dict) -> float:
        """Calculate extraction progress"""
        score = 0.0
        artifacts = session.get("extracted_intelligence", {}).get("artifacts", {})
        
        # UPI IDs are most valuable
        if artifacts.get("upi_ids"):
            score += 0.4 + (0.1 * min(len(artifacts["upi_ids"]), 3))
        
        # URLs are valuable
        if artifacts.get("urls"):
            score += 0.25 + (0.1 * min(len(artifacts["urls"]), 2))
        
        # Phone numbers
        if artifacts.get("phone_numbers"):
            score += 0.2 + (0.05 * min(len(artifacts["phone_numbers"]), 2))
        
        # Amounts
        if artifacts.get("amounts"):
            score += 0.15
        
        return min(score, 1.0)
    
    def process_message(self, input_data: Dict) -> Dict:
        """Process incoming message with logical conversation flow"""
        try:
            session_id = input_data["session_id"]
            message = input_data["message"]
            
            # Initialize session if new
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
                print(f"\n{'='*60}")
                print(f"🆕 NEW SESSION: {session_id}")
                print(f"{'='*60}")
            
            session = self.sessions[session_id]
            
            # Add scammer message
            session["conversation_history"].append({
                "timestamp": datetime.now().isoformat(),
                "sender": "scammer",
                "message": message
            })
            
            print(f"\n📱 SCAMMER: {message}")
            
            # Analyze message deeply
            analysis = self._analyze_message_with_gemini(message, session)
            session["scam_analysis"].append({
                "timestamp": datetime.now().isoformat(),
                "analysis": analysis
            })
            
            # Determine stage
            next_stage = self._determine_next_stage(session, analysis)
            session["current_stage"] = next_stage
            
            # Generate contextual response
            should_end = self._should_end_conversation(session)
            agent_response = self._generate_contextual_response(message, session, analysis, should_end)
            
            # Add agent response
            session["conversation_history"].append({
                "timestamp": datetime.now().isoformat(),
                "sender": "agent",
                "message": agent_response
            })
            
            print(f"🤖 AGENT: {agent_response}")
            print(f"📊 Stage: {next_stage.value} | Extraction: {self._calculate_extraction_score(session):.2f}")
            
            # Mark as ended if needed
            if should_end and session.get("ending_sent"):
                session["ended"] = True
                session["end_time"] = datetime.now().isoformat()
                print(f"✅ Conversation ended naturally")
            
            # Prepare response
            return {
                "success": True,
                "data": {
                    "reply": agent_response,
                    "session_id": session_id,
                    "message_number": len([msg for msg in session["conversation_history"] if msg.get("sender") == "scammer"]),
                    "conversation_stage": next_stage.value,
                    "extraction_progress": self._calculate_extraction_score(session),
                    "conversation_active": not session["ended"],
                    "should_get_report": session["ended"],
                    "analysis": {
                        "scam_type": analysis.get("scam_type", "Unknown"),
                        "urgency": analysis.get("urgency_level", "medium"),
                        "tactic": analysis.get("scammer_tactic", "unknown"),
                        "confidence": analysis.get("confidence_score", 0.5),
                        "intelligence_gaps": analysis.get("intelligence_gaps", [])
                    }
                }
            }
            
        except Exception as e:
            print(f"❌ ERROR: {str(e)}")
            import traceback
            traceback.print_exc()
            return {
                "success": False,
                "error": str(e),
                "data": None
            }
    
    def get_intelligence_report(self, session_id: str) -> Dict:
        """Generate intelligence report"""
        if session_id not in self.sessions:
            return {"success": False, "error": "Session not found"}
        
        session = self.sessions[session_id]
        
        if not session.get("ended", False):
            return {
                "success": False,
                "error": "Conversation still active",
                "data": {
                    "conversation_active": True,
                    "message_count": len([msg for msg in session["conversation_history"] if msg.get("sender") == "scammer"]),
                    "extraction_progress": self._calculate_extraction_score(session)
                }
            }
        
        artifacts = session.get("extracted_intelligence", {}).get("artifacts", {})
        scammer_messages = [msg["message"] for msg in session["conversation_history"] if msg.get("sender") == "scammer"]
        
        report = {
            "session_id": session_id,
            "duration_minutes": 0,
            "total_messages": len(session["conversation_history"]),
            "extraction_score": self._calculate_extraction_score(session),
            "extracted_intelligence": {
                "upi_ids": artifacts.get("upi_ids", []),
                "phone_numbers": artifacts.get("phone_numbers", []),
                "urls": artifacts.get("urls", []),
                "amounts": artifacts.get("amounts", [])
            },
            "scam_type": session["scam_analysis"][-1]["analysis"].get("scam_type", "Unknown") if session["scam_analysis"] else "Unknown",
            "conversation_excerpt": {
                "first_message": scammer_messages[0] if scammer_messages else "",
                "last_message": scammer_messages[-1] if scammer_messages else ""
            }
        }
        
        return {"success": True, "data": report}