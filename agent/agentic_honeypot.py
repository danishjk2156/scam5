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
        self.max_messages_per_session = 15  # Increased for longer conversations
        self.extraction_threshold = 0.5
    
    def _get_conversation_context(self, session: Dict) -> str:
        """Format conversation history for context"""
        context = []
        for msg in session.get("conversation_history", []):
            role = "Scammer" if msg["from"] == "scammer" else "You"
            context.append(f"{role}: {msg['message']}")
        return "\n".join(context[-6:])
    
    def _should_end_conversation(self, session: Dict) -> bool:
        """Determine if conversation should end - FIXED LOGIC"""
        history = session.get("conversation_history", [])
        scammer_messages = [msg for msg in history if msg["from"] == "scammer"]
        
        # Don't end too early - need at least 3 scammer messages
        if len(scammer_messages) < 4:
            return False
        
        # End if we have enough messages
        if len(history) >= self.max_messages_per_session:
            return True
        
        # End if scammer asks for sensitive info multiple times
        sensitive_count = 0
        for msg in scammer_messages:
            message_text = msg["message"].lower()
            sensitive_keywords = ["pin", "password", "otp", "aadhaar", "pan", "cvv"]
            if any(keyword in message_text for keyword in sensitive_keywords):
                sensitive_count += 1
        
        if sensitive_count >= 2:
            return True
        
        # End if extraction score is high and we have at least 5 messages
        extraction_score = self._calculate_extraction_score(session)
        if extraction_score > 0.7 and len(history) >= 10:
            return True
        
        return False
    
    def _update_extracted_intelligence(self, session: Dict, message: str):
        """Update intelligence from new message"""
        if "extracted_intelligence" not in session:
            session["extracted_intelligence"] = {"artifacts": {}}
        
        artifacts = session["extracted_intelligence"]["artifacts"]
        
        # Extract UPI IDs - IMPROVED REGEX
        upi_patterns = [
            r'\b[\w\.-]+@(okicici|oksbi|okhdfc|okaxis|okbob|okciti|okkotak|paytm|okhdfcbank|phonepe|gpay|googlepay)\b',
            r'\b[\w\.-]+@(ok\w+|axl\w+|ybl\w+)\b',
            r'send\s+to\s+([\w\.-]+@[\w\.-]+)',
            r'transfer\s+to\s+([\w\.-]+@[\w\.-]+)'
        ]
        for pattern in upi_patterns:
            matches = re.finditer(pattern, message, re.IGNORECASE)
            if "upi_ids" not in artifacts:
                artifacts["upi_ids"] = []
            for match in matches:
                upi_id = match.group()
                # Clean up the UPI ID
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
            r'\+\d{1,3}[-]?\d{10}\b',
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
        banks = ["sbi", "hdfc", "icici", "axis", "kotak", "pnb", "boi", "canara", "yes bank", "bank of india"]
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
            r'(\d+[,\d]*)\s*rupees?',
            r'(\d+[,\d]*)\s*₹'
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
    
    def _generate_agent_response(self, message: str, session: Dict, ending_conversation: bool = False) -> str:
        """Generate natural sounding response"""
        
        # Update intelligence from this message
        self._update_extracted_intelligence(session, message)
        
        # Build context
        context = self._get_conversation_context(session)
        stage = session.get("current_stage", ConversationStage.INITIAL)
        
        # Check if we should end conversation
        if self._should_end_conversation(session) and not session.get("ending_sent", False):
            ending_conversation = True
            session["ending_sent"] = True
        
        # Natural ending excuses - ONLY if ending_conversation is True
        
        
        # Use Gemini for natural responses
        try:
            # Different prompts based on stage
             if ending_conversation:
                        excuses = [
                            "My phone battery is dying, need to charge. Will message later.",
                            "Family calling me for dinner, talk tomorrow.",
                            "Network is very poor here, messages not sending.",
                            "Have to attend urgent work, will contact you in evening.",
                            "My child took the phone to play games, will get back.",
                            "Going out of city, network will be poor for few days."
                        ]
            return random.choice(excuses)
                 
            elif stage == ConversationStage.INITIAL:
                prompt = f"""You are talking to someone who sent you a suspicious message.
                Act like a normal Indian person who is confused but cooperative.
                
                Their message: "{message}"
                
                Guidelines:
                1. Sound natural and human
                2. Ask for clarification
                3. Don't be too eager or suspicious
                4. Use simple Indian English
                5. Keep response short (1-2 sentences)
                
                Your response:"""
            
            elif stage == ConversationStage.BUILDING_TRUST:
                prompt = f"""You are talking to someone who might be a scammer.
                Act like a trusting but slightly confused person.
                
                Conversation so far:
                {context}
                
                Their latest message: "{message}"
                
                Your goal: Build trust to get more information
                
                Your response (1-2 sentences):"""
            
            elif stage == ConversationStage.EXTRACTING:
                prompt = f"""You are extracting information from a potential scammer.
                Act natural while trying to get details.
                
                Conversation:
                {context}
                
                Their message: "{message}"
                
                Your goal: Ask specific questions to get UPI IDs, phone numbers, or other details
                
                Your response (ask for details):"""
            
            else:
                prompt = f"""Continue the conversation naturally.
                
                Conversation:
                {context}
                
                Their message: "{message}"
                
                Your response (1-2 sentences):"""
            
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
            pass

        
        
        # Fallback responses - BETTER FLOW
        fallback_responses = {
            ConversationStage.INITIAL: [
                "Hello, which order is this for? I don't remember any failed payment.",
                "Sorry, I didn't understand. Can you explain?",
                "Which Amazon order? I have multiple orders.",
                "Is this from Amazon? Can you send order details?"
            ],
            ConversationStage.BUILDING_TRUST: [
                "Okay, let me check my Amazon account.",
                "I see. What should I do exactly?",
                "My PhonePe app is working. Which UPI ID should I send to?",
                "The amount is ₹1 only? And I'll get ₹5000 back?"
            ],
            ConversationStage.EXTRACTING: [
                "Which UPI ID exactly? refund@okicici?",
                "What's the transaction ID again?",
                "Can you send the details in Hindi? My English is not good.",
                "Is there any reference number I should mention?"
            ],
            ConversationStage.DEEP_EXTRACTION: [
                "My UPI app is asking for the exact UPI ID. Is it refund@okicici or something else?",
                "What time will I get the refund?",
                "Do I need to share any screenshot after payment?",
                "Which bank is this UPI ID linked to?"
            ]
        }
        
        return random.choice(fallback_responses.get(stage, ["Okay, let me check."]))
    
    def _determine_next_stage(self, session: Dict) -> ConversationStage:
        """Determine next conversation stage - FIXED LOGIC"""
        current_stage = session.get("current_stage", ConversationStage.INITIAL)
        history = session.get("conversation_history", [])
        scammer_messages = [msg for msg in history if msg["from"] == "scammer"]
        
        # Only move to next stage after enough messages
        if current_stage == ConversationStage.INITIAL and len(scammer_messages) >= 1:
            return ConversationStage.BUILDING_TRUST
        
        elif current_stage == ConversationStage.BUILDING_TRUST and len(scammer_messages) >= 3:
            return ConversationStage.EXTRACTING
        
        elif current_stage == ConversationStage.EXTRACTING and len(scammer_messages) >= 6:
            return ConversationStage.DEEP_EXTRACTION
        
        elif self._should_end_conversation(session):
            return ConversationStage.EXIT_PREPARATION
        
        elif current_stage == ConversationStage.EXIT_PREPARATION:
            return ConversationStage.ENDED
        
        return current_stage
    
    def process_message(self, input_data: Dict) -> Dict:
        """Process a message from scammer"""
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
                    "ended": False
                }
            
            session = self.sessions[session_id]
            
            # Add scammer message to history
            session["conversation_history"].append({
                "timestamp": datetime.now().isoformat(),
                "from": "scammer",
                "message": message
            })
            
            # Determine if should end BEFORE generating response
            should_end = self._should_end_conversation(session) and len(session["conversation_history"]) >= 8
            
            # Generate response
            agent_response = self._generate_agent_response(message, session, should_end)
            
            # Add agent response to history
            session["conversation_history"].append({
                "timestamp": datetime.now().isoformat(),
                "from": "agent",
                "message": agent_response
            })
            
            # Update stage
            session["current_stage"] = self._determine_next_stage(session)
            
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
                "should_get_report": session["ended"]
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
        
        # Determine scam type
        all_text = " ".join(scammer_messages).lower()
        scam_type = ScamType.UNKNOWN
        if any(word in all_text for word in ["upi", "@ok", "send ₹", "transfer ₹"]):
            scam_type = ScamType.UPI_FRAUD
        elif any(word in all_text for word in ["http://", "https://", "click link", "verify link"]):
            scam_type = ScamType.PHISHING
        elif any(word in all_text for word in ["loan", "approved", "processing fee"]):
            scam_type = ScamType.LOAN_SCAM
        elif any(word in all_text for word in ["won", "prize", "lottery", "gift"]):
            scam_type = ScamType.LOTTERY
        
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
                "scam_type": scam_type.value,
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
                "conversation_insights": {
                    "total_scammer_messages": len(scammer_messages),
                    "urgency_detected": any(word in all_text for word in ["urgent", "immediately", "hurry", "now", "quick", "fast"]),
                    "personal_info_requested": any(word in all_text for word in ["pin", "password", "otp", "aadhaar", "pan", "cvv", "card number"]),
                    "threats_made": any(word in all_text for word in ["block", "suspend", "arrest", "police", "case", "legal"]),
                    "time_pressure": "yes" if "minutes" in all_text or "hours" in all_text or "today" in all_text else "no"
                }
            },
            "recommendations": self._generate_recommendations(artifacts, risk_score, scam_type),
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
    
    def _generate_recommendations(self, artifacts: Dict, risk_score: float, scam_type: ScamType) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        if artifacts.get("upi_ids"):
            upi_list = artifacts["upi_ids"]
            rec = f"🚨 IMMEDIATE ACTION: Report and block UPI ID(s): {', '.join(upi_list[:3])}"
            if len(upi_list) > 3:
                rec += f" and {len(upi_list) - 3} more"
            recommendations.append(rec)
            recommendations.append("📱 Notify NPCI (National Payments Corporation of India) about fraudulent UPI IDs")
        
        if artifacts.get("urls"):
            recommendations.append("🌐 Report phishing URL(s) to:")
            recommendations.append("   - Google Safe Browsing (https://safebrowsing.google.com)")
            recommendations.append("   - PhishTank (https://www.phishtank.com)")
            for url in artifacts["urls"][:2]:
                domain = url.split('/')[2] if len(url.split('/')) > 2 else url
                recommendations.append(f"   - Block domain: {domain}")
        
        if artifacts.get("phone_numbers"):
            numbers = artifacts["phone_numbers"]
            recommendations.append(f"📞 Report phone number(s) to telecom providers:")
            for num in numbers[:3]:
                recommendations.append(f"   - {num} (Report via TRAI DND app)")
        
        if risk_score > 0.7:
            recommendations.append("👮 Share intelligence with:")
            recommendations.append("   - Cyber Crime Police Station")
            recommendations.append("   - https://cybercrime.gov.in")
            recommendations.append("   - Local bank fraud departments")
        
        if scam_type == ScamType.UPI_FRAUD:
            recommendations.append("💳 Alert all major UPI apps (PhonePe, Google Pay, Paytm) about this scam pattern")
        
        if artifacts.get("banks_mentioned"):
            recommendations.append("🏦 Notify impersonated banks about the scam:")
            for bank in artifacts["banks_mentioned"][:3]:
                recommendations.append(f"   - {bank} Bank Fraud Department")
        
        recommendations.append("📊 Update internal scam database with this new pattern")
        recommendations.append("🔍 Monitor for similar scams in honeypot network")
        
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
        
        return key_phrases[:5]  # Return top 5 key phrases

# Initialize the honeypot globally
honeypot = None

# Initialize honeypot before running tests
def initialize_honeypot():
    """Initialize honeypot for testing"""
    global honeypot
    # Get API key from environment variable or use default
    gemini_api_key = os.getenv("GEMINI_API_KEY", "Your API KEY")  # Replace with your key
    honeypot = AgenticHoneypot(gemini_api_key)
    print(f"✅ Honeypot agent initialized with API key: {gemini_api_key[:15]}...")
    return honeypot

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for FastAPI"""
    global honeypot
    # Initialize on startup
    initialize_honeypot()
    yield
    # Cleanup on shutdown
    print("🔴 Honeypot agent shutting down")

# Create FastAPI app with lifespan
app = FastAPI(title="Agentic Honeypot", version="1.0", lifespan=lifespan)

@app.get("/")
async def root():
    """Health check endpoint"""
    global honeypot
    return {
        "status": "active",
        "service": "Agentic Honeypot System",
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
    
    # If conversation ended, suggest getting report
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
    """Run a test conversation"""
    print("🚀 Starting Extended Test Conversation")
    print("=" * 60)
    
    # Initialize honeypot first
    initialize_honeypot()
    
    # Extended test conversation flow
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
    
    session_id = "extended_test_" + datetime.now().strftime("%H%M%S")
    
    print(f"Session ID: {session_id}")
    print("-" * 60)
    
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
            print(f"   Extraction Progress: {data['extraction_progress']:.2f}")
            print(f"   Active: {data['conversation_active']}")
            
            if not data["conversation_active"]:
                print("\n💤 Conversation ended naturally!")
                break
        else:
            print(f"\n❌ Error: {result['error']}")
            break
    
    print("\n" + "=" * 60)
    print("📊 Getting Detailed Intelligence Report...")
    
    # Try to get report
    report_result = honeypot.get_intelligence_report(session_id)
    
    if report_result["success"]:
        report = report_result["data"]
        print("\n" + "=" * 60)
        print("✅ COMPREHENSIVE INTELLIGENCE REPORT")
        print("=" * 60)
        
        # Session Summary
        summary = report['session_summary']
        print(f"\n📋 SESSION SUMMARY:")
        print(f"   ID: {summary['session_id']}")
        print(f"   Duration: {summary['duration_minutes']} minutes")
        print(f"   Total Messages: {summary['total_messages']} ({summary['scammer_messages']} scammer, {summary['agent_messages']} agent)")
        print(f"   Scam Type: {summary['scam_type']}")
        print(f"   Risk Level: {summary['risk_level']} (Score: {summary['risk_score']})")
        
        # Extracted Intelligence
        intel = report['extracted_intelligence']
        print(f"\n🔍 EXTRACTED INTELLIGENCE:")
        
        if intel['contact_information']['upi_ids']:
            print(f"   UPI IDs: {', '.join(intel['contact_information']['upi_ids'])}")
        if intel['contact_information']['phone_numbers']:
            print(f"   Phone Numbers: {', '.join(intel['contact_information']['phone_numbers'])}")
        if intel['contact_information']['urls']:
            print(f"   URLs: {', '.join(intel['contact_information']['urls'])}")
        
        print(f"\n💰 FINANCIAL DETAILS:")
        if intel['financial_details']['amounts_mentioned']:
            amounts = intel['financial_details']['amounts_mentioned']
            print(f"   Amounts: ₹{', ₹'.join(map(str, amounts))}")
            print(f"   Highest Amount: ₹{intel['financial_details']['highest_amount']}")
            print(f"   Total Mentioned: ₹{intel['financial_details']['total_amounts_mentioned']}")
        if intel['financial_details']['banks_impersonated']:
            print(f"   Banks Impersonated: {', '.join(intel['financial_details']['banks_impersonated'])}")
        
        print(f"\n📊 CONVERSATION INSIGHTS:")
        insights = intel['conversation_insights']
        print(f"   Urgency Detected: {insights['urgency_detected']}")
        print(f"   Personal Info Requested: {insights['personal_info_requested']}")
        print(f"   Threats Made: {insights['threats_made']}")
        print(f"   Time Pressure: {insights['time_pressure']}")
        
        print(f"\n🎯 ACTIONABLE RECOMMENDATIONS:")
        for i, rec in enumerate(report['recommendations'], 1):
            print(f"   {i}. {rec}")
        
        print(f"\n💬 CONVERSATION EXCERPT:")
        excerpt = report['conversation_excerpt']
        print(f"   First Message: '{excerpt['first_scammer_message'][:80]}...'")
        print(f"   Last Message: '{excerpt['last_scammer_message'][:80]}...'")
        if excerpt['key_extracted_phrases']:
            print(f"   Key Phrases: {', '.join(excerpt['key_extracted_phrases'])}")
        
    else:
        print(f"\n⚠️  Report not ready: {report_result['error']}")
        if report_result.get('data'):
            print(f"   Messages: {report_result['data']['message_count']}")
            print(f"   Progress: {report_result['data']['extraction_progress']:.2f}")
    
    print("\n" + "=" * 60)
    print("💡 API ENDPOINTS:")
    print("1. POST /chat - Send scammer message")
    print("2. GET  /report/{session_id} - Get intelligence report")
    print("3. GET  /session/{session_id}/status - Check conversation status")
    print("4. GET  / - Health check")
    print("=" * 60)
    print("\n🌐 Server starting at: http://localhost:8000")
    print("   Use Ctrl+C to stop the server")
    print("=" * 60)

if __name__ == "__main__":
    # Run test conversation first
    run_test_conversation()
    
    # Then start the server
    print("\n🚀 Starting FastAPI server...")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")

    # ===== SIMPLE WRAPPER FOR REST API =====

def run_agent(session_id: str, message: str) -> dict:
    global honeypot

    if honeypot is None:
        initialize_honeypot()

    result = honeypot.process_message({
        "session_id": session_id,
        "message": message
    })

    if not result["success"]:
        return {"reply": "Error", "conversation_active": False}

    data = result["data"]

    return {
        "reply": data["reply"],
        "conversation_active": data["conversation_active"],
        "stage": data["conversation_stage"],
        "extraction_progress": data["extraction_progress"],
        "should_get_report": data["should_get_report"]
    }
