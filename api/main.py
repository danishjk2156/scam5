import sys
import os
from contextlib import asynccontextmanager
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, field_validator
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
import requests
import re

from agent.agentic_honeypot import AgenticHoneypot, ConversationStage
from nlp_module import detect_scam_intent, detect_scam_type, extract_intelligence

# Supabase imports
from supabase_db import SupabaseService, get_supabase

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for FastAPI"""
    # Startup
    print("🟢 Starting honeypot service...")
    
    # Test Supabase connection
    supabase = get_supabase()
    if supabase:
        print("✅ Supabase connected")
    else:
        print("⚠️  Supabase not available - check SUPABASE_URL and SUPABASE_KEY")
    
    initialize_honeypot()
    yield
    # Shutdown
    print("🔴 Shutting down honeypot")

app = FastAPI(lifespan=lifespan)
SECRET_KEY = os.getenv("SECRET_KEY", "my_secret_key")
from fastapi.middleware.cors import CORSMiddleware

# Add this RIGHT AFTER: app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)
# Initialize the honeypot
honeypot = None

def initialize_honeypot():
    global honeypot
    gemini_key = os.getenv("GEMINI_API_KEY", "your_gemini_key")
    honeypot = AgenticHoneypot(gemini_api_key=gemini_key)

# Pydantic models
class Message(BaseModel):
    sender: str
    text: str
    timestamp: Any
   
    @field_validator('timestamp')
    @classmethod
    def validate_timestamp(cls, v):
        # FIXED: Use timezone-aware datetime
        if isinstance(v, int):
            dt = datetime.fromtimestamp(v / 1000, tz=timezone.utc)
            return dt.isoformat().replace("+00:00", "Z")
        elif isinstance(v, str):
            return v
        else:
            return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

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

# Session tracking - FIXED: Added cleanup mechanism
session_start_times = {}
MAX_SESSION_CACHE = 1000  # Prevent unbounded growth

def cleanup_old_sessions():
    """Clean up ended sessions to prevent memory leak"""
    if len(session_start_times) > MAX_SESSION_CACHE:
        # Get sessions that have ended
        ended_sessions = []
        for sid in list(session_start_times.keys()):
            if sid in honeypot.sessions and honeypot.sessions[sid].get("ended", False):
                ended_sessions.append(sid)
        
        # Remove oldest half of ended sessions
        for sid in ended_sessions[:len(ended_sessions)//2]:
            session_start_times.pop(sid, None)
            honeypot.sessions.pop(sid, None)


@app.post("/honeypot/message", response_model=HoneypotResponse)
def receive_message(payload: HoneypotRequest, x_api_key: str = Header(None)):
    """
    Main endpoint - FULLY FIXED VERSION with all bugs corrected
    """
    
    # Authentication
    if x_api_key != SECRET_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    # FIXED: Validate session_id format
    session_id = payload.sessionId
    if not session_id or not isinstance(session_id, str):
        raise HTTPException(status_code=400, detail="sessionId missing or invalid")
    
    # FIXED: Validate session_id format (alphanumeric, dash, underscore only)
    if not re.match(r'^[a-zA-Z0-9_-]+$', session_id):
        raise HTTPException(status_code=400, detail="sessionId contains invalid characters")
    
    if len(session_id) > 100:
        raise HTTPException(status_code=400, detail="sessionId too long (max 100 chars)")
    
    message_text = payload.message.text
    message_sender = payload.message.sender
    conversation_history = payload.conversationHistory
    
    # FIXED: Normalize sender comparison
    message_sender_normalized = message_sender.lower() if message_sender else "unknown"

    # Get or create session in Supabase
    db_session = SupabaseService.get_session(session_id)
    
    if not db_session:
        # Create new session
        db_session = SupabaseService.create_session(
            session_id=session_id,
            channel=payload.metadata.channel if payload.metadata else "SMS",
            language=payload.metadata.language if payload.metadata else "English",
            locale=payload.metadata.locale if payload.metadata else "IN"
        )
        # FIXED: Use timezone-aware datetime
        session_start_times[session_id] = datetime.now(timezone.utc)
        
        # FIXED: Record session start analytics
        SupabaseService.record_metric(
            metric_name="session_started",
            metric_value=1.0,
            session_id=session_id,
            metadata={
                "channel": payload.metadata.channel if payload.metadata else "SMS",
                "language": payload.metadata.language if payload.metadata else "English",
                "locale": payload.metadata.locale if payload.metadata else "IN"
            }
        )
        print(f"✨ New session started: {session_id}")
    else:
        if session_id not in session_start_times:
            # FIXED: Parse timezone-aware datetime from Supabase
            started_at_str = db_session['started_at']
            if started_at_str.endswith('Z'):
                started_at_str = started_at_str.replace('Z', '+00:00')
            session_start_times[session_id] = datetime.fromisoformat(started_at_str)

    # Add message to Supabase
    SupabaseService.add_message(
        session_id=session_id,
        sender=message_sender_normalized,  # FIXED: Use normalized sender
        message=message_text,
        timestamp=payload.message.timestamp
    )

    # FIXED: Get UPDATED conversation history from Supabase (includes current message)
    db_session_updated = SupabaseService.get_session(session_id)
    full_conversation = db_session_updated.get("conversation_history", [])
    
    # NLP analysis with COMPLETE history including current message
    scam_detected = detect_scam_intent(message_text, full_conversation)
    scam_type = detect_scam_type(message_text, full_conversation)
    intelligence = extract_intelligence(message_text, full_conversation)

    # FIXED: Initialize or update agent session with conversation history from DB
    if session_id not in honeypot.sessions:
        honeypot.sessions[session_id] = {
            "session_id": session_id,
            "conversation_history": full_conversation,  # FIXED: Load from DB
            "started_at": session_start_times[session_id],
            "start_time": session_start_times[session_id].isoformat(),
            "current_stage": ConversationStage.INITIAL,
            "extracted_intelligence": {"artifacts": {}},
            "scam_type": scam_type,
            "scam_analysis": [],  # FIXED: Added missing field
            "ending_sent": False,  # FIXED: Added missing field
            "ended": False
        }
    else:
        # FIXED: Update conversation history from DB to keep in sync
        honeypot.sessions[session_id]["conversation_history"] = full_conversation
        # FIXED: Ensure scam_analysis exists even for existing sessions
        if "scam_analysis" not in honeypot.sessions[session_id]:
            honeypot.sessions[session_id]["scam_analysis"] = []
        if "ending_sent" not in honeypot.sessions[session_id]:
            honeypot.sessions[session_id]["ending_sent"] = False
    
    # FIXED: Pass conversation history to agent
    agent_result = honeypot.process_message({
        "session_id": session_id,
        "message": message_text,
        "sender_id": message_sender_normalized,
        "channel": payload.metadata.channel if payload.metadata else "SMS",
        "conversation_history": full_conversation  # FIXED: Pass full history
    })

    # DEBUG: Print agent result
    print(f"\n{'='*60}")
    print(f"📊 AGENT RESULT DEBUG")
    print(f"{'='*60}")
    print(f"Success: {agent_result.get('success')}")
    print(f"Error: {agent_result.get('error')}")
    print(f"Data keys: {list(agent_result.get('data', {}).keys()) if agent_result.get('data') else 'NO DATA'}")
    if agent_result.get('data'):
        for key, value in agent_result['data'].items():
            print(f"  - {key}: {type(value).__name__} = {str(value)[:100]}")
    print(f"{'='*60}\n")

    if not agent_result["success"]:
        raise HTTPException(status_code=500, detail=agent_result.get("error", "Agent processing failed"))
    
    data = agent_result["data"]
    
    # FIXED: Calculate metrics using timezone-aware datetime
    duration_seconds = int((datetime.now(timezone.utc) - session_start_times[session_id]).total_seconds())
    
    # FIXED: Count only scammer messages correctly
    scammer_messages = [msg for msg in full_conversation if msg.get("sender", "").lower() == "scammer"]
    total_messages = len(full_conversation)
    
    engagement_metrics = EngagementMetrics(
        engagementDurationSeconds=duration_seconds,
        totalMessagesExchanged=total_messages
    )
    
    # Extract intelligence from agent's artifacts
    artifacts = honeypot.sessions[session_id].get("extracted_intelligence", {}).get("artifacts", {})
    
    extracted_intel = ExtractedIntelligence(
        upiIds=intelligence.get("upiIds", []) + artifacts.get("upi_ids", []),
        phoneNumbers=intelligence.get("phoneNumbers", []) + artifacts.get("phone_numbers", []),
        phishingLinks=intelligence.get("phishingLinks", []) + artifacts.get("urls", []),
        bankAccounts=artifacts.get("bank_accounts", []),
        suspiciousKeywords=intelligence.get("suspiciousKeywords", [])
    )
    
    # Deduplicate extracted intelligence
    extracted_intel.upiIds = list(set(extracted_intel.upiIds))
    extracted_intel.phoneNumbers = list(set(extracted_intel.phoneNumbers))
    extracted_intel.phishingLinks = list(set(extracted_intel.phishingLinks))
    extracted_intel.bankAccounts = list(set(extracted_intel.bankAccounts))
    
    # Save intelligence to Supabase
    SupabaseService.save_intelligence(
        session_id=session_id,
        upi_ids=extracted_intel.upiIds,
        phone_numbers=extracted_intel.phoneNumbers,
        phishing_links=extracted_intel.phishingLinks,
        bank_accounts=extracted_intel.bankAccounts,
        suspicious_keywords=extracted_intel.suspiciousKeywords
    )
    
    # Update session in Supabase
    conversation_ended = not data["conversation_active"]
    
    session_updates = {
        "current_stage": data["conversation_stage"],
        "extraction_progress": data["extraction_progress"],
        "scam_detected": scam_detected,
        "scam_type": scam_type,
        "total_messages": total_messages,
        "scammer_messages": len(scammer_messages)
    }
    
    SupabaseService.update_session(session_id, session_updates)
    
    # FIXED: Record analytics metrics for each message
    SupabaseService.record_metric(
        metric_name="message_processed",
        metric_value=1.0,
        session_id=session_id,
        metadata={
            "sender": message_sender_normalized,
            "scam_detected": scam_detected,
            "scam_type": scam_type,
            "stage": data["conversation_stage"]
        }
    )
    
    # Record extraction progress
    SupabaseService.record_metric(
        metric_name="extraction_progress",
        metric_value=data["extraction_progress"],
        session_id=session_id,
        metadata={
            "stage": data["conversation_stage"],
            "upi_ids_count": len(extracted_intel.upiIds),
            "phone_numbers_count": len(extracted_intel.phoneNumbers)
        }
    )
    
    # If conversation ended, create report
    if conversation_ended:
        # End session in Supabase
        session = honeypot.sessions.get(session_id, {})
        agent_notes = generate_agent_notes(session)
        
        SupabaseService.end_session(session_id, agent_notes=agent_notes)
        
        # Create intelligence summary
        intel_summary = {
            "upi_ids": extracted_intel.upiIds,
            "phone_numbers": extracted_intel.phoneNumbers,
            "bank_accounts": extracted_intel.bankAccounts,
            "phishing_links": extracted_intel.phishingLinks,
            "suspicious_keywords": extracted_intel.suspiciousKeywords
        }
        
        # Create scam report
        report = SupabaseService.create_report(
            session_id=session_id,
            scam_detected=scam_detected,
            total_messages=total_messages,
            duration_seconds=duration_seconds,
            intelligence_summary=intel_summary,
            agent_notes=agent_notes
        )
        
        print(f"📊 Report created for session {session_id}: {report}")
        
        # FIXED: Record comprehensive analytics when conversation ends
        analytics_batch = [
            {
                "metric_name": "conversation_completed",
                "metric_value": 1.0,
                "session_id": session_id,
                "metric_metadata": {
                    "scam_detected": scam_detected,
                    "scam_type": scam_type,
                    "duration_seconds": duration_seconds
                }
            },
            {
                "metric_name": "total_messages",
                "metric_value": float(total_messages),
                "session_id": session_id,
                "metric_metadata": {
                    "scammer_messages": len(scammer_messages),
                    "agent_messages": total_messages - len(scammer_messages)
                }
            },
            {
                "metric_name": "intelligence_extracted",
                "metric_value": float(len(extracted_intel.upiIds) + len(extracted_intel.phoneNumbers) + len(extracted_intel.phishingLinks)),
                "session_id": session_id,
                "metric_metadata": {
                    "upi_ids": len(extracted_intel.upiIds),
                    "phone_numbers": len(extracted_intel.phoneNumbers),
                    "phishing_links": len(extracted_intel.phishingLinks),
                    "bank_accounts": len(extracted_intel.bankAccounts)
                }
            },
            {
                "metric_name": "engagement_duration",
                "metric_value": float(duration_seconds),
                "session_id": session_id,
                "metric_metadata": {
                    "minutes": round(duration_seconds / 60, 2)
                }
            }
        ]
        
        success = SupabaseService.batch_record_metrics(analytics_batch)
        print(f"📈 Analytics recorded: {success}")
        
        # Send to GUVI
        guvi_result = send_final_report_to_guvi(
            session_id=session_id,
            scam_detected=scam_detected,
            total_messages=total_messages,
            extracted_intelligence=extracted_intel,
            agent_notes=agent_notes
        )
        
        if guvi_result and guvi_result.get("status_code") == 200:
            SupabaseService.mark_report_sent(session_id, api_response=guvi_result)
        
        # FIXED: Cleanup old sessions periodically
        cleanup_old_sessions()
    
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
    history = session.get("conversation_history", [])
    # FIXED: Changed "from" to "sender"
    scammer_messages = [msg for msg in history if msg.get("sender", "").lower() == "scammer"]
    
    urgency_keywords = ["urgent", "immediately", "now", "quickly", "hurry", "last chance"]
    urgency_count = sum(1 for msg in scammer_messages 
                       if any(keyword in msg.get("message", "").lower() for keyword in urgency_keywords))
    if urgency_count > 0:
        notes.append(f"Used urgency tactics in {urgency_count} messages")
    
    threat_keywords = ["blocked", "suspended", "legal action", "police", "arrest"]
    threat_count = sum(1 for msg in scammer_messages 
                      if any(keyword in msg.get("message", "").lower() for keyword in threat_keywords))
    if threat_count > 0:
        notes.append(f"Made threats in {threat_count} messages")
    
    payment_keywords = ["send", "pay", "transfer", "deposit"]
    payment_count = sum(1 for msg in scammer_messages 
                       if any(keyword in msg.get("message", "").lower() for keyword in payment_keywords))
    if payment_count > 0:
        notes.append(f"Requested payment {payment_count} times")
    
    personal_keywords = ["pin", "password", "otp", "aadhaar", "pan", "cvv", "account number"]
    personal_count = sum(1 for msg in scammer_messages 
                        if any(keyword in msg.get("message", "").lower() for keyword in personal_keywords))
    if personal_count > 0:
        notes.append(f"Requested sensitive information {personal_count} times")
    
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
) -> Optional[Dict]:
    """Send final report to GUVI"""
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
        response = requests.post(callback_url, json=payload, timeout=5)
        
        if response.status_code == 200:
            print(f"✅ Report sent to GUVI for {session_id}")
            return {"status_code": response.status_code, "response": response.text}
        else:
            print(f"⚠️  GUVI callback failed: {response.status_code}")
            return {"status_code": response.status_code, "error": response.text}
    except Exception as e:
        print(f"❌ Failed to send report: {e}")
        return {"error": str(e)}


@app.get("/")
def health_check():
    """Health check"""
    supabase = get_supabase()
    return {
        "status": "healthy",
        "service": "Agentic Honeypot API - FULLY FIXED VERSION",
        "version": "2.2-fixed",
        "database": "connected" if supabase else "disconnected",
        "active_sessions": len(honeypot.sessions) if honeypot else 0
    }


@app.get("/session/{session_id}/status")
def get_session_status(session_id: str, x_api_key: str = Header(None)):
    """Get session status from Supabase"""
    if x_api_key != SECRET_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    db_session = SupabaseService.get_session(session_id)
    
    if db_session:
        return {
            "status": "success",
            "sessionId": session_id,
            "conversationActive": db_session["is_active"],
            "stage": db_session.get("current_stage", "initial"),
            "messageCount": db_session["total_messages"],
            "extractionProgress": db_session["extraction_progress"],
            "scamDetected": db_session["scam_detected"],
            "scamType": db_session.get("scam_type", "Unknown")
        }
    
    raise HTTPException(status_code=404, detail="Session not found")


@app.post("/session/{session_id}/force-report")
def force_create_report(session_id: str, x_api_key: str = Header(None)):
    """Force create a report for active session (for testing/monitoring)"""
    if x_api_key != SECRET_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    # Get session
    db_session = SupabaseService.get_session(session_id)
    if not db_session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Get intelligence
    intelligence = SupabaseService.get_intelligence(session_id)
    
    # Calculate duration
    start_time_str = db_session['started_at']
    if start_time_str.endswith('Z'):
        start_time_str = start_time_str.replace('Z', '+00:00')
    start_time = datetime.fromisoformat(start_time_str)
    duration_seconds = int((datetime.now(timezone.utc) - start_time).total_seconds())
    
    # Generate report
    session = honeypot.sessions.get(session_id, {})
    agent_notes = generate_agent_notes(session) if session else "Session in progress"
    
    intel_summary = {
        "upi_ids": intelligence.get("upi_ids", []) if intelligence else [],
        "phone_numbers": intelligence.get("phone_numbers", []) if intelligence else [],
        "bank_accounts": intelligence.get("bank_accounts", []) if intelligence else [],
        "phishing_links": intelligence.get("phishing_links", []) if intelligence else [],
        "suspicious_keywords": intelligence.get("suspicious_keywords", []) if intelligence else []
    }
    
    # Create report
    report = SupabaseService.create_report(
        session_id=session_id,
        scam_detected=db_session.get('scam_detected', False),
        total_messages=db_session.get('total_messages', 0),
        duration_seconds=duration_seconds,
        intelligence_summary=intel_summary,
        agent_notes=f"[FORCED REPORT] {agent_notes}"
    )
    
    return {
        "status": "success",
        "message": "Force report created",
        "report": report
    }


@app.get("/stats")
def get_statistics(x_api_key: str = Header(None)):
    """Get statistics from Supabase or fallback to in-memory"""
    if x_api_key != SECRET_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    try:
        # Try Supabase first
        stats = SupabaseService.get_statistics()
        return {"status": "success", "data": stats}
    except Exception as e:
        # Fallback to in-memory honeypot stats
        print(f"⚠️ Supabase stats failed, using in-memory: {e}")
        
        if not honeypot:
            return {
                "status": "success",
                "data": {
                    "active_sessions": 0,
                    "total_scams": 0,
                    "total_intelligence": 0,
                    "extraction_rate": 0
                }
            }
        
        # Calculate from honeypot sessions
        active_sessions = len([s for s in honeypot.sessions.values() if not s.get('ended', False)])
        total_scams = len([s for s in honeypot.sessions.values() if s.get('scam_detected', False)])
        
        # Count intelligence
        total_intel = 0
        for session in honeypot.sessions.values():
            artifacts = session.get('extracted_intelligence', {}).get('artifacts', {})
            total_intel += len(artifacts.get('upi_ids', []))
            total_intel += len(artifacts.get('phone_numbers', []))
            total_intel += len(artifacts.get('urls', []))
            total_intel += len(artifacts.get('bank_accounts', []))
        
        extraction_rate = round((total_intel / total_scams * 100) if total_scams > 0 else 0, 1)
        
        return {
            "status": "success",
            "data": {
                "active_sessions": active_sessions,
                "total_scams": total_scams,
                "total_intelligence": total_intel,
                "extraction_rate": extraction_rate
            }
        }

"""
Add this new endpoint to your main.py (after the /stats endpoint)
This gives dashboard the session data it needs in the right format
"""

@app.get("/sessions/intelligence")
def get_sessions_intelligence(x_api_key: str = Header(None)):
    """Get intelligence data from sessions table for dashboard"""
    if x_api_key != SECRET_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    try:
        supabase = get_supabase()
        if not supabase:
            return {"status": "success", "count": 0, "sessions": []}
        
        # Get all sessions with their intelligence
        result = supabase.table("sessions").select(
            "session_id, scam_detected, total_messages, extracted_intelligence, created_at, is_active"
        ).order("created_at", desc=True).limit(100).execute()
        
        sessions_data = []
        all_upi = set()
        all_phones = set()
        all_urls = set()
        all_banks = set()
        
        for session in result.data:
            intel = session.get('extracted_intelligence', {})
            
            # Handle if intelligence is stored as JSON string
            if isinstance(intel, str):
                try:
                    intel = json.loads(intel)
                except:
                    intel = {}
            
            # Extract arrays from intelligence
            upi_ids = intel.get('upi_ids', []) or []
            phone_numbers = intel.get('phone_numbers', []) or []
            phishing_links = intel.get('phishing_links', []) or intel.get('urls', []) or []
            bank_accounts = intel.get('bank_accounts', []) or []
            
            # Add to global sets
            for upi in upi_ids:
                all_upi.add(upi)
            for phone in phone_numbers:
                all_phones.add(phone)
            for url in phishing_links:
                all_urls.add(url)
            for bank in bank_accounts:
                all_banks.add(bank)
            
            # Build session data
            sessions_data.append({
                "sessionId": session.get('session_id'),
                "scamDetected": session.get('scam_detected', False),
                "totalMessages": session.get('total_messages', 0),
                "intelligence": {
                    "upi_ids": upi_ids,
                    "phone_numbers": phone_numbers,
                    "phishing_links": phishing_links,
                    "bank_accounts": bank_accounts
                },
                "createdAt": session.get('created_at'),
                "isActive": session.get('is_active', False)
            })
        
        return {
            "status": "success",
            "count": len(sessions_data),
            "sessions": sessions_data,
            "summary": {
                "total_upi_ids": len(all_upi),
                "total_phones": len(all_phones),
                "total_urls": len(all_urls),
                "total_banks": len(all_banks),
                "total_intelligence": len(all_upi) + len(all_phones) + len(all_urls) + len(all_banks)
            }
        }
    
    except Exception as e:
        print(f"❌ Error fetching sessions intelligence: {e}")
        import traceback
        traceback.print_exc()
        return {"status": "error", "error": str(e), "count": 0, "sessions": []}

@app.get("/reports/recent")
def get_recent_reports(limit: int = 20, x_api_key: str = Header(None)):
    """Get recent reports from Supabase or in-memory"""
    if x_api_key != SECRET_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    try:
        # Try Supabase first
        reports = SupabaseService.get_recent_reports(limit=limit)
        
        return {
            "status": "success",
            "count": len(reports),
            "reports": [
                {
                    "sessionId": r["session_id"],
                    "scamDetected": r["scam_detected"],
                    "totalMessages": r["total_messages_exchanged"],
                    "duration": r["engagement_duration_seconds"],
                    "intelligence": r["extracted_intelligence_summary"],
                    "generatedAt": r["report_generated_at"],
                    "sentToAPI": r["sent_to_external_api"]
                }
                for r in reports
            ]
        }
    except Exception as e:
        # Fallback to in-memory honeypot sessions
        print(f"⚠️ Supabase reports failed, using in-memory: {e}")
        
        if not honeypot:
            return {"status": "success", "count": 0, "reports": []}
        
        # Build reports from honeypot sessions
        reports = []
        for session_id, session in list(honeypot.sessions.items())[:limit]:
            artifacts = session.get('extracted_intelligence', {}).get('artifacts', {})
            
            reports.append({
                "sessionId": session_id,
                "scamDetected": session.get('scam_detected', False),
                "totalMessages": len(session.get('conversation_history', [])),
                "duration": 0,  # Not tracked in memory
                "intelligence": {
                    "upi_ids": artifacts.get('upi_ids', []),
                    "phone_numbers": artifacts.get('phone_numbers', []),
                    "phishing_links": artifacts.get('urls', []),
                    "bank_accounts": artifacts.get('bank_accounts', [])
                },
                "generatedAt": datetime.now(timezone.utc).isoformat(),
                "sentToAPI": False
            })
        
        return {
            "status": "success",
            "count": len(reports),
            "reports": reports
        }


@app.get("/analytics/metrics")
def get_analytics_metrics(
    session_id: Optional[str] = None,
    metric_name: Optional[str] = None,
    limit: int = 100,
    x_api_key: str = Header(None)
):
    """Get analytics metrics from Supabase"""
    if x_api_key != SECRET_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    try:
        supabase = get_supabase()
        query = supabase.table("analytics_metrics").select("*")
        
        if session_id:
            query = query.eq("session_id", session_id)
        if metric_name:
            query = query.eq("metric_name", metric_name)
        
        query = query.order("recorded_at", desc=True).limit(limit)
        result = query.execute()
        
        return {
            "status": "success",
            "count": len(result.data),
            "metrics": result.data
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "metrics": []
        }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)