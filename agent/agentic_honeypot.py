import json
import re
import requests
from typing import Dict, List, Any, Optional
from datetime import datetime
from enum import Enum
import random
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

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

class ChatMessage(BaseModel):
    session_id: str
    message: str
    confidence: Optional[float] = 0.8
    sender_id: Optional[str] = "unknown"
    channel: Optional[str] = "sms"

class AgenticHoneypot:
    def __init__(self, gemini_api_key: str):
        self.gemini_api_key = gemini_api_key
        self.base_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
        self.sessions: Dict[str, Any] = {}
        # Conversation parameters
        self.min_messages_for_extraction = 2
        self.max_messages_per_session = 15
        self.extraction_threshold = 0.5
    
    def _get_conversation_context(self, session: Dict) -> str:
        """Format conversation history for context"""
        context = []
        for msg in session.get("conversation_history", []):
            role = "Scammer" if msg["from"] == "scammer" else "You"
            context.append(f"{role}: {msg['message']}")
        return "\n".join(context[-8:])  # Increased context window
    
    def _should_end_conversation(self, session: Dict) -> bool:
        """Determine if conversation should end"""
        history = session.get("conversation_history", [])
        scammer_messages = [msg for msg in history if msg["from"] == "scammer"]
        
        if len(scammer_messages) < 4:
            return False
        
        if len(history) >= self.max_messages_per_session:
            return True
        
        # Check for sensitive info requests
        sensitive_count = 0
        for msg in scammer_messages:
            message_text = msg["message"].lower()
            sensitive_keywords = ["pin", "password", "otp", "aadhaar", "pan", "cvv"]
            if any(keyword in message_text for keyword in sensitive_keywords):
                sensitive_count += 1
        
        if sensitive_count >= 2:
            return True
        
        extraction_score = self._calculate_extraction_score(session)
        if extraction_score > 0.7 and len(history) >= 10:
            return True
        
        return False
    
    def _analyze_message_with_gemini(self, message: str, session: Dict) -> Dict:
        """Use Gemini to analyze the scammer's message and determine the appropriate stage"""
        
        context = self._get_conversation_context(session)
        scammer_messages_count = len([msg for msg in session.get("conversation_history", []) if msg["from"] == "scammer"])
        
        prompt = f"""You are analyzing a conversation with a potential scammer. Based on the scammer's message, determine:

1. CONVERSATION_STAGE: What stage of the conversation should the agent be in?
   - initial: Just starting, scammer sent first message, agent should be confused/unsure
   - building_trust: Scammer is trying to build trust, agent should be cooperative but cautious
   - extracting: Scammer is asking for basic info, agent should ask for details
   - deep_extraction: Scammer is pushing hard, agent should play along but extract maximum intel
   - exit_preparation: Time to end conversation naturally

2. SCAM_TYPE: What type of scam is this?
3. URGENCY_LEVEL: low, medium, high
4. SCAMMER_TACTIC: What tactic is the scammer using? (urgency, threat, reward, impersonation, etc.)
5. INFORMATION_REQUESTED: What specific information is the scammer asking for?
6. CONFIDENCE_SCORE: 0-1

Conversation history:
{context}

Current stage: {session.get('current_stage', ConversationStage.INITIAL).value}
Messages from scammer so far: {scammer_messages_count}

Scammer's latest message: "{message}"

Return your analysis in JSON format:
{{
    "stage": "one of the stage values",
    "scam_type": "scam type description",
    "urgency_level": "low/medium/high",
    "scammer_tactic": "description of tactic",
    "information_requested": ["list", "of", "requested", "info"],
    "confidence_score": 0.0,
    "reasoning": "brief explanation"
}}
"""
        
        try:
            headers = {"Content-Type": "application/json"}
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {
                    "temperature": 0.3,
                    "top_p": 0.95,
                    "top_k": 40
                }
            }
            
            response = requests.post(
                f"{self.base_url}?key={self.gemini_api_key}",
                headers=headers,
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                if 'candidates' in result and len(result['candidates']) > 0:
                    text = result['candidates'][0]['content']['parts'][0]['text'].strip()
                    # Extract JSON from response
                    json_match = re.search(r'\{.*\}', text, re.DOTALL)
                    if json_match:
                        return json.loads(json_match.group())
        except Exception as e:
            print(f"Gemini analysis error: {e}")
        
        # Fallback analysis
        return self._fallback_analysis(message, session)
    
    def _fallback_analysis(self, message: str, session: Dict) -> Dict:
        """Fallback analysis when Gemini fails"""
        message_lower = message.lower()
        scammer_messages_count = len([msg for msg in session.get("conversation_history", []) if msg["from"] == "scammer"])
        
        # Determine stage based on message content and conversation length
        if scammer_messages_count < 2:
            stage = ConversationStage.INITIAL
        elif any(word in message_lower for word in ["urgent", "immediately", "now", "quick", "hurry"]):
            if "pin" in message_lower or "password" in message_lower or "otp" in message_lower:
                stage = ConversationStage.DEEP_EXTRACTION
            else:
                stage = ConversationStage.EXTRACTING
        elif any(word in message_lower for word in ["refund", "cashback", "reward", "offer"]):
            stage = ConversationStage.BUILDING_TRUST
        elif any(word in message_lower for word in ["send", "transfer", "pay", "upi"]):
            if scammer_messages_count > 5:
                stage = ConversationStage.DEEP_EXTRACTION
            else:
                stage = ConversationStage.EXTRACTING
        else:
            stage = ConversationStage.BUILDING_TRUST
        
        # Determine scam type
        scam_type = ScamType.UNKNOWN
        if any(word in message_lower for word in ["upi", "@ok", "send ₹", "transfer ₹"]):
            scam_type = ScamType.UPI_FRAUD
        elif any(word in message_lower for word in ["http://", "https://", "click link"]):
            scam_type = ScamType.PHISHING
        
        return {
            "stage": stage.value,
            "scam_type": scam_type.value,
            "urgency_level": "high" if any(word in message_lower for word in ["urgent", "immediately", "now"]) else "medium",
            "scammer_tactic": "urgency" if "urgent" in message_lower else "reward",
            "information_requested": [],
            "confidence_score": 0.7,
            "reasoning": "Fallback analysis based on keywords"
        }
    
    def _determine_next_stage(self, session: Dict, analysis: Dict) -> ConversationStage:
        """Dynamically determine the next stage based on message analysis"""
        
        # Don't change stage if conversation is ending
        if session.get("ending_sent", False) or session.get("ended", False):
            return ConversationStage.ENDED
        
        # Get suggested stage from analysis
        suggested_stage = analysis.get("stage", ConversationStage.INITIAL.value)
        
        # Map string to enum
        stage_map = {
            "initial": ConversationStage.INITIAL,
            "building_trust": ConversationStage.BUILDING_TRUST,
            "extracting": ConversationStage.EXTRACTING,
            "deep_extraction": ConversationStage.DEEP_EXTRACTION,
            "exit_preparation": ConversationStage.EXIT_PREPARATION,
            "ended": ConversationStage.ENDED
        }
        
        new_stage = stage_map.get(suggested_stage, ConversationStage.BUILDING_TRUST)
        
        # Logic to prevent going backwards in stages
        current_stage_value = self._stage_to_int(session.get("current_stage", ConversationStage.INITIAL))
        new_stage_value = self._stage_to_int(new_stage)
        
        if new_stage_value < current_stage_value:
            # Don't go backwards, stay at current stage or move forward
            if new_stage_value <= self._stage_to_int(ConversationStage.BUILDING_TRUST):
                return session.get("current_stage", ConversationStage.BUILDING_TRUST)
        
        # Check if we should move to exit preparation
        if self._should_end_conversation(session):
            return ConversationStage.EXIT_PREPARATION
        
        return new_stage
    
    def _stage_to_int(self, stage: ConversationStage) -> int:
        """Convert stage to integer for comparison"""
        stage_order = {
            ConversationStage.INITIAL: 1,
            ConversationStage.BUILDING_TRUST: 2,
            ConversationStage.EXTRACTING: 3,
            ConversationStage.DEEP_EXTRACTION: 4,
            ConversationStage.EXIT_PREPARATION: 5,
            ConversationStage.ENDED: 6
        }
        return stage_order.get(stage, 1)
    
    def _generate_agent_response(self, message: str, session: Dict, analysis: Dict, ending_conversation: bool = False) -> str:
        """Generate natural sounding response based on message analysis"""
        
        # Update intelligence from this message
        self._update_extracted_intelligence(session, message)
        
        # Build context
        context = self._get_conversation_context(session)
        stage = session.get("current_stage", ConversationStage.INITIAL)
        
        # Check if we should end conversation
        if self._should_end_conversation(session) and not session.get("ending_sent", False):
            ending_conversation = True
            session["ending_sent"] = True
        
        # Use Gemini for natural responses with stage-specific prompting
        try:
            if ending_conversation:
                prompt = f"""You are ending a conversation with a potential scammer naturally.
                
                Conversation so far:
                {context}
                
                Their latest message: "{message}"
                
                Give a natural excuse to end the conversation (battery dying, family calling, network issues, etc.)
                Be brief and casual like a real Indian person would text.
                
                Write a natural, casual response as a real person. Use 10-15 words. Keep it sounding like a chat message. Response:"""
            
            elif stage == ConversationStage.INITIAL:
                prompt = f"""You are talking to someone who sent you a suspicious message.
                Act like a normal Indian person who is confused but cooperative.
                
                Their message: "{message}"
                
                Analysis of scammer: {analysis.get('scammer_tactic', 'unknown')} tactic, 
                urgency: {analysis.get('urgency_level', 'medium')}
                
                Guidelines:
                1. Sound confused and ask for clarification
                2. Don't sound too knowledgeable
                3. Use simple Indian English
                4. Response should be 10-15 words
                
                Your response:"""
            
            elif stage == ConversationStage.BUILDING_TRUST:
                prompt = f"""You are building trust with someone who claims to be from customer service.
                
                Conversation so far:
                {context}
                
                Their message: "{message}"
                They are using {analysis.get('scammer_tactic', 'unknown')} tactic.
                
                Guidelines:
                1. Act like you believe them but are cautious
                2. Ask for more details about the offer/issue
                3. Sound interested but slightly hesitant
                4. Response should be 10-15 words
                
                Your response:"""
            
            elif stage == ConversationStage.EXTRACTING:
                prompt = f"""You are extracting information from a potential scammer.
                
                Their message: "{message}"
                They are asking for: {analysis.get('information_requested', ['unknown'])}
                
                Your goal: Ask specific questions to get UPI IDs, phone numbers, or other details.
                Act like you're trying to help but need more information.
                
                Write a natural response asking for specific details. 10-15 words.
                
                Your response:"""
            
            elif stage == ConversationStage.DEEP_EXTRACTION:
                prompt = f"""You are in deep extraction mode with a scammer who is pushing hard.
                
                Their message: "{message}"
                Urgency level: {analysis.get('urgency_level', 'high')}
                
                Your goal: Play along but extract maximum intelligence.
                Ask for exact UPI IDs, reference numbers, or transaction details.
                Sound slightly stressed/confused but cooperative.
                
                Write a natural response asking for specific information. 10-15 words.
                
                Your response:"""
            
            else:
                prompt = f"""Continue the conversation naturally.
                
                Conversation:
                {context}
                
                Their message: "{message}"
                
                Write a natural, casual response as a real person. Use 10-15 words. Response:"""
            
            headers = {"Content-Type": "application/json"}
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {
                    "temperature": 0.8 if stage == ConversationStage.BUILDING_TRUST else 0.7,
                }
            }
            
            response = requests.post(
                f"{self.base_url}?key={self.gemini_api_key}",
                headers=headers,
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                if 'candidates' in result and len(result['candidates']) > 0:
                    return result['candidates'][0]['content']['parts'][0]['text'].strip()
        
        except Exception as e:
            print(f"API Error: {e}")
        
        # Fallback responses
        return self._get_fallback_response(stage, ending_conversation)
    
    def _get_fallback_response(self, stage: ConversationStage, ending_conversation: bool) -> str:
        """Get fallback responses based on stage"""
        if ending_conversation:
            excuses = [
                "My phone battery is dying, need to charge. Will message later.",
                "Family calling me for dinner, talk tomorrow.",
                "Network is very poor here, messages not sending.",
                "Have to attend urgent work, will contact you in evening.",
                "My child took the phone to play games, will get back."
            ]
            return random.choice(excuses)
        
        fallback_responses = {
            ConversationStage.INITIAL: [
                "Hello, which order is this for? I don't remember any failed payment.",
                "Sorry, I didn't understand. Can you explain?",
                "Which Amazon order? I have multiple orders."
            ],
            ConversationStage.BUILDING_TRUST: [
                "Okay, let me check my Amazon account.",
                "I see. What should I do exactly?",
                "My PhonePe app is working. Which UPI ID should I send to?"
            ],
            ConversationStage.EXTRACTING: [
                "Which UPI ID exactly? refund@okicici?",
                "What's the transaction ID again?",
                "Can you send the details again? I'm not understanding."
            ],
            ConversationStage.DEEP_EXTRACTION: [
                "My UPI app is asking for the exact UPI ID. Is it refund@okicici?",
                "What time will I get the refund?",
                "Do I need to share any screenshot after payment?"
            ]
        }
        
        return random.choice(fallback_responses.get(stage, ["Okay, let me check."]))
    
    def _update_extracted_intelligence(self, session: Dict, message: str):
        """Update intelligence from new message"""
        if "extracted_intelligence" not in session:
            session["extracted_intelligence"] = {"artifacts": {}}
        
        artifacts = session["extracted_intelligence"]["artifacts"]
        
        # Extract UPI IDs
        upi_patterns = [
            r'\b[\w\.-]+@(okicici|oksbi|okhdfc|okaxis|okbob|okciti|okkotak|paytm|okhdfcbank|phonepe|gpay|googlepay|ybl|axl)\b',
            r'send\s+to\s+([\w\.-]+@[\w\.-]+)',
            r'transfer\s+to\s+([\w\.-]+@[\w\.-]+)'
        ]
        for pattern in upi_patterns:
            matches = re.finditer(pattern, message, re.IGNORECASE)
            if "upi_ids" not in artifacts:
                artifacts["upi_ids"] = []
            for match in matches:
                upi_id = match.group()
                if 'send to' in upi_id.lower():
                    upi_id = upi_id.split()[-1]
                elif 'transfer to' in upi_id.lower():
                    upi_id = upi_id.split()[-1]
                if upi_id not in artifacts["upi_ids"]:
                    artifacts["upi_ids"].append(upi_id)
        
        # Extract URLs
        url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.\-?=&%#]*'
        urls = re.findall(url_pattern, message)
        if "urls" not in artifacts:
            artifacts["urls"] = []
        for url in urls:
            if url not in artifacts["urls"]:
                artifacts["urls"].append(url)
        
        # Extract phone numbers
        phone_patterns = [
            r'\b\d{10}\b',
            r'\b\d{5}[-]?\d{5}\b',
            r'call\s+(\d{10})',
            r'contact\s+(\d{10})'
        ]
        if "phone_numbers" not in artifacts:
            artifacts["phone_numbers"] = []
        for pattern in phone_patterns:
            numbers = re.findall(pattern, message)
            for num in numbers:
                if isinstance(num, tuple):
                    num = num[0]
                if num not in artifacts["phone_numbers"]:
                    artifacts["phone_numbers"].append(num)
        
        # Extract bank names
        banks = ["sbi", "hdfc", "icici", "axis", "kotak", "pnb", "boi", "canara", "yes bank"]
        if "banks_mentioned" not in artifacts:
            artifacts["banks_mentioned"] = []
        for bank in banks:
            if bank in message.lower() and bank.upper() not in artifacts["banks_mentioned"]:
                artifacts["banks_mentioned"].append(bank.upper())
        
        # Extract amounts
        amount_patterns = [
            r'₹\s*(\d+[,\d]*)',
            r'rs\.?\s*(\d+[,\d]*)',
            r'rupees?\s*(\d+[,\d]*)',
            r'(\d+[,\d]*)\s*rupees?'
        ]
        if "amounts" not in artifacts:
            artifacts["amounts"] = []
        for pattern in amount_patterns:
            amounts = re.findall(pattern, message, re.IGNORECASE)
            for amt in amounts:
                if isinstance(amt, tuple):
                    amt = amt[0]
                clean_amt = int(re.sub(r'[^\d]', '', amt))
                if clean_amt not in artifacts["amounts"]:
                    artifacts["amounts"].append(clean_amt)
    
    def _calculate_extraction_score(self, session: Dict) -> float:
        """Calculate how much intelligence we've extracted"""
        score = 0.0
        artifacts = session.get("extracted_intelligence", {}).get("artifacts", {})
        
        if artifacts.get("upi_ids"):
            score += 0.3 + (0.1 * min(len(artifacts["upi_ids"]), 3))
        
        if artifacts.get("urls"):
            score += 0.25 + (0.1 * min(len(artifacts["urls"]), 3))
        
        if artifacts.get("phone_numbers"):
            score += 0.2 + (0.1 * min(len(artifacts["phone_numbers"]), 3))
        
        if artifacts.get("banks_mentioned"):
            score += 0.15
        
        if artifacts.get("amounts"):
            score += 0.1
        
        return min(score, 1.0)
    
    def process_message(self, input_data: Dict) -> Dict:
        """Process a message from scammer with dynamic stage selection"""
        try:
            session_id = input_data["session_id"]
            message = input_data["message"]
            
            # Initialize or get session
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
            
            session = self.sessions[session_id]
            
            # Add scammer message to history
            session["conversation_history"].append({
                "timestamp": datetime.now().isoformat(),
                "from": "scammer",
                "message": message
            })
            
            # Analyze the message with Gemini
            analysis = self._analyze_message_with_gemini(message, session)
            
            # Store analysis in session
            session["scam_analysis"].append({
                "timestamp": datetime.now().isoformat(),
                "analysis": analysis
            })
            
            # Determine if should end
            should_end = self._should_end_conversation(session)
            
            # Determine next stage dynamically based on analysis
            next_stage = self._determine_next_stage(session, analysis)
            session["current_stage"] = next_stage
            
            # Generate response
            agent_response = self._generate_agent_response(message, session, analysis, should_end)
            
            # Add agent response to history
            session["conversation_history"].append({
                "timestamp": datetime.now().isoformat(),
                "from": "agent",
                "message": agent_response
            })
            
            # Mark as ended if we sent ending message
            if should_end and session.get("ending_sent"):
                session["ended"] = True
                session["end_time"] = datetime.now().isoformat()
            
            # Calculate extraction score
            extraction_score = self._calculate_extraction_score(session)
            
            # Prepare response
            response_data = {
                "reply": agent_response,
                "session_id": session_id,
                "message_number": len([msg for msg in session["conversation_history"] if msg["from"] == "scammer"]),
                "conversation_stage": session["current_stage"].value,
                "extraction_progress": extraction_score,
                "conversation_active": not session["ended"],
                "should_get_report": session["ended"],
                "analysis": {
                    "scam_type": analysis.get("scam_type", "Unknown"),
                    "urgency": analysis.get("urgency_level", "medium"),
                    "tactic": analysis.get("scammer_tactic", "unknown"),
                    "confidence": analysis.get("confidence_score", 0.5)
                }
            }
            
            return {
                "success": True,
                "data": response_data
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "data": None
            }
    
    def get_intelligence_report(self, session_id: str) -> Dict:
        """Generate final intelligence report"""
        if session_id not in self.sessions:
            return {"success": False, "error": "Session not found"}
        
        session = self.sessions[session_id]
        
        if not session.get("ended", False):
            return {
                "success": False,
                "error": "Conversation still active",
                "data": {
                    "conversation_active": True,
                    "message_count": len([msg for msg in session["conversation_history"] if msg["from"] == "scammer"]),
                    "extraction_progress": self._calculate_extraction_score(session)
                }
            }
        
        # Get all scammer messages
        scammer_messages = [
            msg["message"] for msg in session["conversation_history"]
            if msg["from"] == "scammer"
        ]
        
        # Get artifacts
        artifacts = session.get("extracted_intelligence", {}).get("artifacts", {})
        
        # Get scam analysis history
        scam_analysis = session.get("scam_analysis", [])
        
        # Determine primary scam type from analyses
        scam_types = [a["analysis"].get("scam_type", "Unknown") for a in scam_analysis if "analysis" in a]
        from collections import Counter
        primary_scam_type = Counter(scam_types).most_common(1)[0][0] if scam_types else "Unknown"
        
        # Calculate risk score
        risk_score = self._calculate_extraction_score(session)
        
        # Calculate duration
        try:
            start = datetime.fromisoformat(session["start_time"])
            end = datetime.fromisoformat(session.get("end_time", datetime.now().isoformat()))
            duration_minutes = (end - start).total_seconds() / 60
        except:
            duration_minutes = 0
        
        # Generate report
        report = {
            "session_summary": {
                "session_id": session_id,
                "start_time": session["start_time"],
                "end_time": session.get("end_time"),
                "duration_minutes": round(duration_minutes, 2),
                "total_messages": len(session["conversation_history"]),
                "scammer_messages": len(scammer_messages),
                "agent_messages": len(session["conversation_history"]) - len(scammer_messages),
                "scam_type": primary_scam_type,
                "risk_score": round(risk_score, 2),
                "risk_level": "CRITICAL" if risk_score > 0.8 else "HIGH" if risk_score > 0.6 else "MEDIUM" if risk_score > 0.4 else "LOW"
            },
            "extracted_intelligence": {
                "contact_information": {
                    "upi_ids": artifacts.get("upi_ids", []),
                    "phone_numbers": artifacts.get("phone_numbers", []),
                    "urls": artifacts.get("urls", []),
                    "email_addresses": artifacts.get("emails", [])
                },
                "financial_details": {
                    "amounts_mentioned": artifacts.get("amounts", []),
                    "banks_impersonated": artifacts.get("banks_mentioned", []),
                    "highest_amount": max(artifacts.get("amounts", [0])),
                    "total_amounts_mentioned": sum(artifacts.get("amounts", []))
                },
                "conversation_insights": self._generate_conversation_insights(session, scammer_messages),
                "scammer_tactics": self._analyze_scammer_tactics(scam_analysis)
            },
            "recommendations": self._generate_recommendations(artifacts, risk_score, primary_scam_type),
            "conversation_excerpt": {
                "first_scammer_message": scammer_messages[0] if scammer_messages else "",
                "last_scammer_message": scammer_messages[-1] if scammer_messages else "",
                "key_extracted_phrases": self._extract_key_phrases(scammer_messages)
            }
        }
        
        return {
            "success": True,
            "data": report
        }
    
    def _generate_conversation_insights(self, session: Dict, scammer_messages: List[str]) -> Dict:
        """Generate detailed conversation insights"""
        all_text = " ".join(scammer_messages).lower()
        
        return {
            "total_scammer_messages": len(scammer_messages),
            "urgency_detected": any(word in all_text for word in ["urgent", "immediately", "hurry", "now", "quick", "fast"]),
            "personal_info_requested": any(word in all_text for word in ["pin", "password", "otp", "aadhaar", "pan", "cvv", "card number"]),
            "threats_made": any(word in all_text for word in ["block", "suspend", "arrest", "police", "case", "legal"]),
            "time_pressure": "yes" if "minutes" in all_text or "hours" in all_text or "today" in all_text else "no",
            "payment_requests": sum(1 for msg in scammer_messages if "send" in msg.lower() or "pay" in msg.lower() or "transfer" in msg.lower()),
            "sensitive_info_requests": sum(1 for msg in scammer_messages if "pin" in msg.lower() or "otp" in msg.lower() or "password" in msg.lower())
        }
    
    def _analyze_scammer_tactics(self, scam_analysis: List[Dict]) -> Dict:
        """Analyze the tactics used by the scammer over time"""
        tactics = []
        urgency_levels = []
        
        for analysis_entry in scam_analysis:
            if "analysis" in analysis_entry:
                analysis = analysis_entry["analysis"]
                tactics.append(analysis.get("scammer_tactic", "unknown"))
                urgency_levels.append(analysis.get("urgency_level", "medium"))
        
        from collections import Counter
        tactic_counts = Counter(tactics)
        urgency_counts = Counter(urgency_levels)
        
        return {
            "primary_tactic": tactic_counts.most_common(1)[0][0] if tactic_counts else "unknown",
            "tactic_evolution": tactics[-5:] if len(tactics) > 5 else tactics,
            "urgency_pattern": urgency_counts.most_common(1)[0][0] if urgency_counts else "medium",
            "tactic_changes": len(set(tactics)) > 1
        }
    
    def _generate_recommendations(self, artifacts: Dict, risk_score: float, scam_type: str) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        if artifacts.get("upi_ids"):
            upi_list = artifacts["upi_ids"]
            rec = f"🚨 IMMEDIATE ACTION: Report and block UPI ID(s): {', '.join(upi_list[:3])}"
            if len(upi_list) > 3:
                rec += f" and {len(upi_list) - 3} more"
            recommendations.append(rec)
            recommendations.append("📱 Notify NPCI about fraudulent UPI IDs")
        
        if artifacts.get("urls"):
            recommendations.append("🌐 Report phishing URL(s) to Google Safe Browsing and PhishTank")
            for url in artifacts["urls"][:2]:
                domain = url.split('/')[2] if len(url.split('/')) > 2 else url
                recommendations.append(f"   - Block domain: {domain}")
        
        if artifacts.get("phone_numbers"):
            numbers = artifacts["phone_numbers"]
            recommendations.append(f"📞 Report phone number(s) via TRAI DND app")
            for num in numbers[:3]:
                recommendations.append(f"   - {num}")
        
        if risk_score > 0.7:
            recommendations.append("👮 Share intelligence with Cyber Crime Police (https://cybercrime.gov.in)")
        
        if scam_type == ScamType.UPI_FRAUD.value:
            recommendations.append("💳 Alert UPI apps (PhonePe, Google Pay, Paytm) about this scam pattern")
        
        recommendations.append("📊 Update internal scam database with this new pattern")
        
        return recommendations
    
    def _extract_key_phrases(self, messages: List[str]) -> List[str]:
        """Extract key phrases from conversation"""
        key_phrases = []
        common_scam_phrases = [
            "send money", "urgent", "immediately", "hurry", 
            "last chance", "block account", "verify now",
            "click link", "share otp", "processing fee",
            "refund", "won prize", "lottery", "limited time"
        ]
        
        for msg in messages:
            msg_lower = msg.lower()
            for phrase in common_scam_phrases:
                if phrase in msg_lower and phrase not in key_phrases:
                    key_phrases.append(phrase)
        
        return key_phrases[:5]

# Initialize the honeypot globally
honeypot = None

def initialize_honeypot():
    """Initialize honeypot for testing"""
    global honeypot
    gemini_api_key = os.getenv("GEMINI_API_KEY", "your-api-key")
    honeypot = AgenticHoneypot(gemini_api_key)
    print(f"✅ Honeypot agent initialized with Gemini 1.5 Flash")
    return honeypot

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for FastAPI"""
    global honeypot
    initialize_honeypot()
    yield
    print("🔴 Honeypot agent shutting down")

# Create FastAPI app with lifespan
app = FastAPI(title="Agentic Honeypot", version="2.0", lifespan=lifespan)

@app.get("/")
async def root():
    """Health check endpoint"""
    global honeypot
    return {
        "status": "active",
        "service": "Agentic Honeypot System (Dynamic Stage Selection)",
        "version": "2.0",
        "active_sessions": len(honeypot.sessions) if honeypot else 0,
        "endpoints": {
            "chat": "POST /chat - Send scammer message",
            "report": "GET /report/{session_id} - Get intelligence report",
            "status": "GET /session/{session_id}/status - Check conversation status"
        }
    }

@app.post("/chat")
async def chat_with_scammer(chat_message: ChatMessage):
    """Process a chat message from scammer"""
    global honeypot
    result = honeypot.process_message(chat_message.dict())
    
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["error"])
    
    response_data = result["data"]
    
    if not response_data["conversation_active"]:
        response_data["message"] = "Conversation ended naturally. Use GET /report/{session_id} to get intelligence report."
    
    return {
        "success": True,
        "data": response_data
    }

@app.get("/report/{session_id}")
async def get_intelligence_report(session_id: str):
    """Get intelligence report for a completed conversation"""
    global honeypot
    result = honeypot.get_intelligence_report(session_id)
    
    if not result["success"]:
        if result.get("error") == "Conversation still active":
            raise HTTPException(
                status_code=400, 
                detail="Conversation still active. Continue chatting or wait for natural end."
            )
        raise HTTPException(status_code=404, detail=result["error"])
    
    return {
        "success": True,
        "data": result["data"]
    }

@app.get("/session/{session_id}/status")
async def get_session_status(session_id: str):
    """Check conversation status"""
    global honeypot
    if session_id not in honeypot.sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    
    session = honeypot.sessions[session_id]
    
    return {
        "success": True,
        "data": {
            "session_id": session_id,
            "message_count": len([msg for msg in session.get("conversation_history", []) if msg["from"] == "scammer"]),
            "conversation_active": not session.get("ended", False),
            "current_stage": session.get("current_stage", ConversationStage.INITIAL).value,
            "extraction_progress": honeypot._calculate_extraction_score(session),
            "has_ended": session.get("ended", False),
            "extracted_upi_ids": session.get("extracted_intelligence", {}).get("artifacts", {}).get("upi_ids", [])
        }
    }

@app.delete("/session/{session_id}")
async def delete_session(session_id: str):
    """Delete a session"""
    global honeypot
    if session_id in honeypot.sessions:
        del honeypot.sessions[session_id]
        return {"success": True, "message": f"Session {session_id} deleted"}
    else:
        raise HTTPException(status_code=404, detail="Session not found")

def run_test_conversation():
    """Run a test conversation to demonstrate dynamic stage selection"""
    print("🚀 Starting Test Conversation with Dynamic Stage Selection")
    print("=" * 70)
    
    initialize_honeypot()
    
    test_messages = [
        "Your Amazon order payment failed. Send ₹1 to refund@okicici to get refund of ₹5000.",
        "Yes, send ₹1 to refund@okicici using PhonePe or Google Pay.",
        "Transaction ID: AMZ789456123. Do it quickly, offer valid for 30 minutes only.",
        "Did you send? The ₹5000 refund is waiting. Hurry up!",
        "Share screenshot of payment for confirmation.",
        "Your UPI PIN is required for verification. Send PIN.",
        "This is last warning! Send PIN or account will be blocked.",
        "Call 9876543210 for immediate support.",
        "Visit http://amazon-refund-verify.com for online verification.",
        "Final chance! Send ₹1 and PIN to refund@okicici now."
    ]
    
    session_id = "dynamic_test_" + datetime.now().strftime("%H%M%S")
    
    print(f"Session ID: {session_id}")
    print("-" * 70)
    
    for i, scammer_msg in enumerate(test_messages, 1):
        print(f"\n📱 Scammer Message {i}:")
        print(f"   '{scammer_msg}'")
        
        result = honeypot.process_message({
            "session_id": session_id,
            "message": scammer_msg,
            "confidence": 0.9,
            "sender_id": "SCAMMER001",
            "channel": "whatsapp"
        })
        
        if result["success"]:
            data = result["data"]
            print(f"\n🤖 Agent Response {i}:")
            print(f"   '{data['reply']}'")
            print(f"\n   Stage: {data['conversation_stage']}")
            print(f"   Analysis: {data.get('analysis', {}).get('scam_type', 'Unknown')} - {data.get('analysis', {}).get('tactic', 'unknown')}")
            print(f"   Extraction Progress: {data['extraction_progress']:.2f}")
            print(f"   Active: {data['conversation_active']}")
            
            if not data["conversation_active"]:
                print("\n💤 Conversation ended naturally!")
                break
        else:
            print(f"\n❌ Error: {result['error']}")
            break
    
    print("\n" + "=" * 70)
    print("📊 Getting Dynamic Intelligence Report...")
    
    report_result = honeypot.get_intelligence_report(session_id)
    
    if report_result["success"]:
        report = report_result["data"]
        print("\n" + "=" * 70)
        print("✅ COMPREHENSIVE INTELLIGENCE REPORT")
        print("=" * 70)
        
        summary = report['session_summary']
        print(f"\n📋 SESSION SUMMARY:")
        print(f"   ID: {summary['session_id']}")
        print(f"   Duration: {summary['duration_minutes']} minutes")
        print(f"   Total Messages: {summary['total_messages']}")
        print(f"   Scam Type: {summary['scam_type']}")
        print(f"   Risk Level: {summary['risk_level']} (Score: {summary['risk_score']})")
        
        intel = report['extracted_intelligence']
        print(f"\n🔍 EXTRACTED INTELLIGENCE:")
        
        if intel['contact_information']['upi_ids']:
            print(f"   UPI IDs: {', '.join(intel['contact_information']['upi_ids'])}")
        if intel['contact_information']['phone_numbers']:
            print(f"   Phone Numbers: {', '.join(intel['contact_information']['phone_numbers'])}")
        if intel['contact_information']['urls']:
            print(f"   URLs: {', '.join(intel['contact_information']['urls'])}")
        
        print(f"\n📊 SCAMMER TACTICS:")
        tactics = intel.get('scammer_tactics', {})
        print(f"   Primary Tactic: {tactics.get('primary_tactic', 'Unknown')}")
        print(f"   Urgency Pattern: {tactics.get('urgency_pattern', 'medium')}")
        print(f"   Tactic Evolution: {tactics.get('tactic_evolution', [])}")
        
        print(f"\n🎯 ACTIONABLE RECOMMENDATIONS:")
        for i, rec in enumerate(report['recommendations'], 1):
            print(f"   {i}. {rec}")
        
    else:
        print(f"\n⚠️  Report not ready: {report_result['error']}")
    
    print("\n" + "=" * 70)

if __name__ == "__main__":
    # Run test conversation first
    run_test_conversation()
    
    # Then start the server
    print("\n🚀 Starting FastAPI server with Dynamic Stage Selection...")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")