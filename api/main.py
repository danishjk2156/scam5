import sys
import os
from contextlib import asynccontextmanager
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

# Now the rest of your imports
import sys
from contextlib import asynccontextmanager
# ... rest of imports
# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, field_validator
from typing import List, Optional, Dict, Union, Any
from datetime import datetime
import requests
import os

from agent.agentic_honeypot import AgenticHoneypot
from nlp_module import detect_scam_intent, detect_scam_type, extract_intelligence

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for FastAPI"""
    # Startup
    initialize_honeypot()
    yield
    # Shutdown
    print("🔴 Shutting down honeypot")

app = FastAPI(lifespan=lifespan)
SECRET_KEY = os.getenv("SECRET_KEY", "my_secret_key")

# Initialize the honeypot
honeypot = None

def initialize_honeypot():
    global honeypot
    import os
    gemini_key = os.getenv("GEMINI_API_KEY", "your_gemini_key")
    honeypot = AgenticHoneypot(gemini_api_key=gemini_key)

# Pydantic models matching the API specification
class Message(BaseModel):
    sender: str  # "scammer" or "user"
    text: str
    timestamp: Any  # Accepts both string OR number
   
    
    @field_validator('timestamp')
    @classmethod
    def validate_timestamp(cls, v):
        if isinstance(v, int):
            # Convert Unix timestamp (milliseconds) to ISO string
            dt = datetime.fromtimestamp(v / 1000)
            return dt.isoformat().replace("+00:00", "Z")
        elif isinstance(v, str):
            return v
        else:
            # If neither, use current time
            return datetime.now().isoformat().replace("+00:00", "Z")

class Metadata(BaseModel):
    channel: Optional[str] = "SMS"
    language: Optional[str] = "English"
    locale: Optional[str] = "IN"

class HoneypotRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Message] = []
    metadata: Optional[Metadata] = None

class ExtractedIntelligence(BaseModel):
    bankAccounts: List[str] = []
    upiIds: List[str] = []
    phishingLinks: List[str] = []
    phoneNumbers: List[str] = []
    suspiciousKeywords: List[str] = []

class EngagementMetrics(BaseModel):
    engagementDurationSeconds: int
    totalMessagesExchanged: int

class HoneypotResponse(BaseModel):
    status: str
    sessionId: str
    scamDetected: bool
    scamType: Optional[str] = None
    reply: str
    conversationActive: bool
    stage: str
    extractionProgress: float
    shouldGetReport: bool
    engagementMetrics: Optional[EngagementMetrics] = None
    extractedIntelligence: Optional[ExtractedIntelligence] = None
    agentNotes: Optional[str] = None

# Session tracking for calculating duration
session_start_times = {}
session_message_counts = {}



@app.post("/honeypot/message", response_model=HoneypotResponse)
def receive_message(payload: HoneypotRequest, x_api_key: str = Header(None)):
    """
    Main endpoint that receives scam messages and responds with agent reply
    Follows the exact API specification from the problem statement
    """
    
    # 1️⃣ Authentication
    if x_api_key != SECRET_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    # 2️⃣ Extract data
    session_id = payload.sessionId
    message_text = payload.message.text
    message_sender = payload.message.sender
    conversation_history = payload.conversationHistory
    
    if not session_id:
        raise HTTPException(status_code=400, detail="sessionId missing")

    # Track session start time
    if session_id not in session_start_times:
        session_start_times[session_id] = datetime.now()
        session_message_counts[session_id] = 0
    
    # Increment message count (only count scammer messages)
    if message_sender == "scammer":
        session_message_counts[session_id] += 1

    # 3️⃣ NLP checks - pass conversation history for better detection
    # Convert conversation_history to format expected by NLP module
    history_for_nlp = []
    for msg in conversation_history:
        history_for_nlp.append({
            "sender": msg.sender,
            "text": msg.text,
            "timestamp": msg.timestamp
        })
    
    scam_detected = detect_scam_intent(message_text, history_for_nlp)
    scam_type = detect_scam_type(message_text, history_for_nlp)
    intelligence = extract_intelligence(message_text, history_for_nlp)

    # 4️⃣ Process with agentic honeypot
    # Convert conversation history to the format expected by the agent
    # The agent expects the history to be already stored in its session
    # So we need to update the session with the conversation history
    
    if session_id not in honeypot.sessions and conversation_history:
        # Initialize session with history
        honeypot.sessions[session_id] = {
            "conversation_history": [],
            "started_at": datetime.now(),
            "current_stage": honeypot.ConversationStage.INITIAL,
            "extracted_intelligence": {"artifacts": {}},
            "scam_type": scam_type,
            "ended": False
        }
        
        # Add conversation history to session
        for hist_msg in conversation_history:
            honeypot.sessions[session_id]["conversation_history"].append({
                "from": hist_msg.sender,
                "message": hist_msg.text,
                "timestamp": hist_msg.timestamp
            })
    
    # Process the current message
    agent_result = honeypot.process_message({
        "session_id": session_id,
        "message": message_text,
        "sender_id": message_sender,
        "channel": payload.metadata.channel if payload.metadata else "SMS"
    })

    if not agent_result["success"]:
        raise HTTPException(status_code=500, detail=agent_result.get("error", "Agent processing failed"))
    
    data = agent_result["data"]
    
    # Calculate engagement duration
    duration_seconds = int((datetime.now() - session_start_times[session_id]).total_seconds())
    
    # Get extracted intelligence from session
    session = honeypot.sessions.get(session_id, {})
    artifacts = session.get("extracted_intelligence", {}).get("artifacts", {})
    
    # Merge intelligence from NLP module and agent's session
    # NLP module analyzes conversation history for patterns
    # Agent extracts artifacts during conversation
    all_upi_ids = list(set(artifacts.get("upi_ids", []) + intelligence.get("upiIds", [])))
    all_phone_numbers = list(set(artifacts.get("phone_numbers", []) + intelligence.get("phoneNumbers", [])))
    all_links = list(set(artifacts.get("urls", []) + intelligence.get("phishingLinks", [])))
    all_keywords = list(set(intelligence.get("suspiciousKeywords", [])))
    
    # Format extracted intelligence to match API spec
    extracted_intel = ExtractedIntelligence(
        bankAccounts=artifacts.get("banks_mentioned", []),  # Use banks from agent
        upiIds=all_upi_ids,
        phishingLinks=all_links,
        phoneNumbers=all_phone_numbers,
        suspiciousKeywords=all_keywords
    )
    
    # Engagement metrics
    engagement_metrics = EngagementMetrics(
        engagementDurationSeconds=duration_seconds,
        totalMessagesExchanged=len(session.get("conversation_history", []))
    )
    
    # Check if conversation ended and should send final report
    conversation_ended = not data["conversation_active"]
    should_send_final_report = conversation_ended and scam_detected
    
    # 5️⃣ Send final report to GUVI if conversation ended
    if should_send_final_report:
        send_final_report_to_guvi(
            session_id=session_id,
            scam_detected=scam_detected,
            total_messages=engagement_metrics.totalMessagesExchanged,
            extracted_intelligence=extracted_intel,
            agent_notes=generate_agent_notes(session)
        )
    print(f"🔍 Processing session: {session_id}")
    print(f"📨 Message: {message_text}")
    print(f"🤖 Scam detected: {scam_detected}, Type: {scam_type}")
    
    # Add this before processing
    print(f"🎯 Agent result: {agent_result}")
    
    # Check what the agent returned
    if not agent_result["success"]:
        print(f"❌ Agent error: {agent_result.get('error')}")
    # 6️⃣ Return response - SIMPLIFIED FOR TESTER
    return HoneypotResponse(
        status="success",
        sessionId=session_id,
        scamDetected=scam_detected,
        scamType=scam_type,
        reply=data["reply"],
        conversationActive=data["conversation_active"],
        stage=data["conversation_stage"],
        extractionProgress=data["extraction_progress"],
        shouldGetReport=data["should_get_report"],
        engagementMetrics=engagement_metrics,
        extractedIntelligence=extracted_intel,
        agentNotes=generate_agent_notes(session) if conversation_ended else None
    )

def generate_agent_notes(session: Dict) -> str:
    """Generate summary notes about scammer behavior"""
    if not session:
        return "Session data not available"
    
    notes = []
    
    # Analyze conversation for patterns
    history = session.get("conversation_history", [])
    scammer_messages = [msg for msg in history if msg["from"] == "scammer"]
    
    # Check for urgency tactics
    urgency_keywords = ["urgent", "immediately", "now", "quickly", "hurry", "last chance"]
    urgency_count = sum(1 for msg in scammer_messages 
                       if any(keyword in msg["message"].lower() for keyword in urgency_keywords))
    if urgency_count > 0:
        notes.append(f"Used urgency tactics in {urgency_count} messages")
    
    # Check for threats
    threat_keywords = ["blocked", "suspended", "legal action", "police", "arrest"]
    threat_count = sum(1 for msg in scammer_messages 
                      if any(keyword in msg["message"].lower() for keyword in threat_keywords))
    if threat_count > 0:
        notes.append(f"Made threats in {threat_count} messages")
    
    # Check for payment requests
    payment_keywords = ["send", "pay", "transfer", "deposit"]
    payment_count = sum(1 for msg in scammer_messages 
                       if any(keyword in msg["message"].lower() for keyword in payment_keywords))
    if payment_count > 0:
        notes.append(f"Requested payment {payment_count} times")
    
    # Check for personal info requests
    personal_keywords = ["pin", "password", "otp", "aadhaar", "pan", "cvv", "account number"]
    personal_count = sum(1 for msg in scammer_messages 
                        if any(keyword in msg["message"].lower() for keyword in personal_keywords))
    if personal_count > 0:
        notes.append(f"Requested sensitive information {personal_count} times")
    
    # Check extracted artifacts
    artifacts = session.get("extracted_intelligence", {}).get("artifacts", {})
    if artifacts.get("upi_ids"):
        notes.append(f"Provided {len(artifacts['upi_ids'])} UPI ID(s)")
    if artifacts.get("phone_numbers"):
        notes.append(f"Shared {len(artifacts['phone_numbers'])} phone number(s)")
    if artifacts.get("urls"):
        notes.append(f"Sent {len(artifacts['urls'])} suspicious link(s)")
    
    return "; ".join(notes) if notes else "No significant patterns detected"

def send_final_report_to_guvi(
    session_id: str,
    scam_detected: bool,
    total_messages: int,
    extracted_intelligence: ExtractedIntelligence,
    agent_notes: str
):
    """
    Send final report to GUVI evaluation endpoint
    This is MANDATORY for evaluation
    """
    callback_url = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
    
    payload = {
        "sessionId": session_id,
        "scamDetected": scam_detected,
        "totalMessagesExchanged": total_messages,
        "extractedIntelligence": {
            "bankAccounts": extracted_intelligence.bankAccounts,
            "upiIds": extracted_intelligence.upiIds,
            "phishingLinks": extracted_intelligence.phishingLinks,
            "phoneNumbers": extracted_intelligence.phoneNumbers,
            "suspiciousKeywords": extracted_intelligence.suspiciousKeywords
        },
        "agentNotes": agent_notes
    }
    
    try:
        response = requests.post(
            callback_url,
            json=payload,
            timeout=5,
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code == 200:
            print(f"✅ Final report sent to GUVI for session {session_id}")
        else:
            print(f"⚠️  GUVI callback failed with status {response.status_code}")
            print(f"   Response: {response.text}")
    
    except requests.exceptions.RequestException as e:
        print(f"❌ Failed to send final report to GUVI: {str(e)}")
        # Don't raise exception - we don't want to fail the API call if GUVI is down

@app.get("/")
def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "Agentic Honeypot API",
        "version": "1.0.0"
    }

@app.get("/session/{session_id}/status")
def get_session_status(session_id: str, x_api_key: str = Header(None)):
    """Get status of a specific session"""
    if x_api_key != SECRET_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    if session_id not in honeypot.sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    
    session = honeypot.sessions[session_id]
    
    return {
        "status": "success",
        "sessionId": session_id,
        "conversationActive": not session.get("ended", False),
        "stage": session.get("current_stage").value if hasattr(session.get("current_stage"), "value") else "unknown",
        "messageCount": len(session.get("conversation_history", [])),
        "extractionProgress": honeypot._calculate_extraction_score(session)
    }

# Note: Remove the __main__ block at the bottom for Vercel deployment
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
