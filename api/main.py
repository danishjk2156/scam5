"""
Honeypot API — v4.0

Key improvements over v3:
  - GUVI payload now includes scamType and confidenceLevel (scoring fields!)
  - Richer agent notes with red-flag descriptions
  - caseIds included in extracted intelligence merge
  - Improved confidence calculation
"""

import sys
import os
import json
from contextlib import asynccontextmanager
from dotenv import load_dotenv

load_dotenv()

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, field_validator
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
import requests
import re

from agent.agentic_honeypot import AgenticHoneypot, ConversationStage
from nlp_module import (
    detect_scam_intent, detect_scam_type, extract_intelligence,
    detect_red_flags,
)

from supabase_db import SupabaseService, get_supabase


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🟢 Starting honeypot service v4.0...")
    supabase = get_supabase()
    if supabase:
        print("✅ Supabase connected")
    else:
        print("⚠️  Supabase not available - check SUPABASE_URL and SUPABASE_KEY")
    initialize_honeypot()
    yield
    print("🔴 Shutting down honeypot")


app = FastAPI(lifespan=lifespan)
SECRET_KEY = os.getenv("SECRET_KEY", "my_secret_key")

from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

honeypot = None


def initialize_honeypot():
    global honeypot
    gemini_key = os.getenv("GEMINI_API_KEY", "your_gemini_key")
    honeypot = AgenticHoneypot(gemini_api_key=gemini_key)


# ══════════════════════════════════════════════════════════════════════════════
# Pydantic Models
# ══════════════════════════════════════════════════════════════════════════════

class Message(BaseModel):
    sender: str
    text: str
    timestamp: Any

    @field_validator('timestamp')
    @classmethod
    def validate_timestamp(cls, v):
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
    phoneNumbers: List[str] = []
    bankAccounts: List[str] = []
    upiIds: List[str] = []
    phishingLinks: List[str] = []
    emailAddresses: List[str] = []
    caseIds: List[str] = []


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


# ══════════════════════════════════════════════════════════════════════════════
# Session Tracking
# ══════════════════════════════════════════════════════════════════════════════

session_start_times = {}
MAX_SESSION_CACHE = 1000


def cleanup_old_sessions():
    if len(session_start_times) > MAX_SESSION_CACHE:
        ended_sessions = []
        for sid in list(session_start_times.keys()):
            if sid in honeypot.sessions and honeypot.sessions[sid].get("ended", False):
                ended_sessions.append(sid)
        for sid in ended_sessions[:len(ended_sessions) // 2]:
            session_start_times.pop(sid, None)
            honeypot.sessions.pop(sid, None)


# ══════════════════════════════════════════════════════════════════════════════
# Main Endpoint
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/honeypot/message", response_model=HoneypotResponse)
def receive_message(payload: HoneypotRequest, x_api_key: str = Header(None)):
    """
    Main honeypot endpoint — v4.0
    Key fixes over v3:
    1. scamType and confidenceLevel included in GUVI final report
    2. caseIds extracted and sent
    3. Red flags detected and included in agent notes
    4. Richer agent notes for conversation quality scoring
    """

    if x_api_key != SECRET_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    session_id = payload.sessionId
    if not session_id or not isinstance(session_id, str):
        raise HTTPException(status_code=400, detail="sessionId missing or invalid")

    if not re.match(r'^[a-zA-Z0-9_\-]+$', session_id):
        raise HTTPException(status_code=400, detail="sessionId contains invalid characters")

    if len(session_id) > 100:
        raise HTTPException(status_code=400, detail="sessionId too long (max 100 chars)")

    message_text = payload.message.text
    message_sender = payload.message.sender
    conversation_history = payload.conversationHistory
    message_sender_normalized = message_sender.lower() if message_sender else "unknown"

    # ── Session management ────────────────────────────────────────────────────
    db_session = SupabaseService.get_session(session_id)

    if not db_session:
        db_session = SupabaseService.create_session(
            session_id=session_id,
            channel=payload.metadata.channel if payload.metadata else "SMS",
            language=payload.metadata.language if payload.metadata else "English",
            locale=payload.metadata.locale if payload.metadata else "IN",
        )
        session_start_times[session_id] = datetime.now(timezone.utc)
        SupabaseService.record_metric(
            metric_name="session_started",
            metric_value=1.0,
            session_id=session_id,
            metadata={
                "channel": payload.metadata.channel if payload.metadata else "SMS",
                "language": payload.metadata.language if payload.metadata else "English",
                "locale": payload.metadata.locale if payload.metadata else "IN",
            },
        )
        print(f"✨ New session started: {session_id}")
    else:
        if session_id not in session_start_times:
            started_at_str = db_session['started_at']
            if started_at_str.endswith('Z'):
                started_at_str = started_at_str.replace('Z', '+00:00')
            session_start_times[session_id] = datetime.fromisoformat(started_at_str)

    # ── Add message to DB ─────────────────────────────────────────────────────
    SupabaseService.add_message(
        session_id=session_id,
        sender=message_sender_normalized,
        message=message_text,
        timestamp=payload.message.timestamp,
    )

    db_session_updated = SupabaseService.get_session(session_id)
    full_conversation = db_session_updated.get("conversation_history", [])

    # ── NLP Analysis ──────────────────────────────────────────────────────────
    scam_detected = detect_scam_intent(message_text, full_conversation)
    scam_type = detect_scam_type(message_text, full_conversation)
    intelligence = extract_intelligence(message_text, full_conversation)
    red_flags = detect_red_flags(message_text, full_conversation)

    # ── Initialize / sync agent session ───────────────────────────────────────
    if session_id not in honeypot.sessions:
        honeypot.sessions[session_id] = {
            "session_id": session_id,
            "conversation_history": full_conversation,
            "started_at": session_start_times[session_id],
            "start_time": session_start_times[session_id].isoformat(),
            "current_stage": ConversationStage.INITIAL,
            "extracted_intelligence": {"artifacts": {}},
            "scam_type": scam_type,
            "scam_analysis": [],
            "ended": False,
            "detected_red_flags": [],
        }
    else:
        honeypot.sessions[session_id]["conversation_history"] = full_conversation
        honeypot.sessions[session_id]["scam_type"] = scam_type
        if "scam_analysis" not in honeypot.sessions[session_id]:
            honeypot.sessions[session_id]["scam_analysis"] = []
        if "detected_red_flags" not in honeypot.sessions[session_id]:
            honeypot.sessions[session_id]["detected_red_flags"] = []

    # Sync NLP red flags into session
    session_flags = honeypot.sessions[session_id].get("detected_red_flags", [])
    for rf in red_flags:
        flag_desc = rf.get("description", rf.get("flag", ""))
        if flag_desc and flag_desc not in session_flags:
            session_flags.append(flag_desc)
    honeypot.sessions[session_id]["detected_red_flags"] = session_flags

    # ── Agent processing ──────────────────────────────────────────────────────
    agent_result = honeypot.process_message({
        "session_id": session_id,
        "message": message_text,
        "sender_id": message_sender_normalized,
        "channel": payload.metadata.channel if payload.metadata else "SMS",
        "conversation_history": full_conversation,
    })

    if not agent_result["success"]:
        raise HTTPException(status_code=500, detail=agent_result.get("error", "Agent processing failed"))

    data = agent_result["data"]

    # ── Metrics ───────────────────────────────────────────────────────────────
    duration_seconds = int((datetime.now(timezone.utc) - session_start_times[session_id]).total_seconds())
    scammer_messages = [msg for msg in full_conversation if msg.get("sender", "").lower() == "scammer"]
    total_messages = len(full_conversation)

    engagement_metrics = EngagementMetrics(
        engagementDurationSeconds=duration_seconds,
        totalMessagesExchanged=total_messages,
    )

    # ── Merge intelligence from NLP + agent artifacts ─────────────────────────
    artifacts = honeypot.sessions[session_id].get("extracted_intelligence", {}).get("artifacts", {})

    def fmt_phone(p: str) -> str:
        clean = re.sub(r'[^\d]', '', p)
        if len(clean) == 12 and clean.startswith('91'):
            return f"+91-{clean[2:]}"
        if len(clean) == 10:
            return f"+91-{clean}"
        return p

    raw_phones = list(set(intelligence.get("phoneNumbers", []) + artifacts.get("phone_numbers", [])))
    all_phones = [fmt_phone(p) for p in raw_phones]
    all_upi = list(set(intelligence.get("upiIds", []) + artifacts.get("upi_ids", [])))
    all_links = list(set(intelligence.get("phishingLinks", []) + artifacts.get("urls", [])))
    all_banks = list(set(intelligence.get("bankAccounts", []) + artifacts.get("bank_accounts", [])))
    all_emails = list(set(
        intelligence.get("emailAddresses", [])
        + artifacts.get("emails", [])
        + artifacts.get("email_addresses", [])
    ))
    all_case_ids = list(set(
        intelligence.get("caseIds", [])
        + artifacts.get("case_ids", [])
    ))

    extracted_intel = ExtractedIntelligence(
        phoneNumbers=all_phones,
        upiIds=all_upi,
        phishingLinks=all_links,
        bankAccounts=all_banks,
        emailAddresses=all_emails,
        caseIds=all_case_ids,
    )

    # ── Save intelligence to Supabase ─────────────────────────────────────────
    SupabaseService.save_intelligence(
        session_id=session_id,
        upi_ids=extracted_intel.upiIds,
        phone_numbers=extracted_intel.phoneNumbers,
        phishing_links=extracted_intel.phishingLinks,
        bank_accounts=extracted_intel.bankAccounts,
    )

    # ── Update session in Supabase ────────────────────────────────────────────
    conversation_ended = not data["conversation_active"]

    session_updates = {
        "current_stage": data["conversation_stage"],
        "extraction_progress": data["extraction_progress"],
        "scam_detected": scam_detected,
        "scam_type": scam_type,
        "total_messages": total_messages,
        "scammer_messages": len(scammer_messages),
    }
    SupabaseService.update_session(session_id, session_updates)

    # ── Analytics ─────────────────────────────────────────────────────────────
    SupabaseService.record_metric(
        metric_name="message_processed",
        metric_value=1.0,
        session_id=session_id,
        metadata={
            "sender": message_sender_normalized,
            "scam_detected": scam_detected,
            "scam_type": scam_type,
            "stage": data["conversation_stage"],
        },
    )

    # ── Agent notes (richer with red flags) ───────────────────────────────────
    session = honeypot.sessions.get(session_id, {})
    agent_notes = generate_agent_notes(session, red_flags)

    # ── Confidence calculation ────────────────────────────────────────────────
    confidence = 0.0
    if extracted_intel.upiIds:          confidence += 0.25
    if extracted_intel.phoneNumbers:    confidence += 0.20
    if extracted_intel.phishingLinks:   confidence += 0.20
    if extracted_intel.bankAccounts:    confidence += 0.15
    if extracted_intel.emailAddresses:  confidence += 0.10
    if extracted_intel.caseIds:         confidence += 0.10
    if scam_detected:                   confidence += 0.10
    if len(session.get("detected_red_flags", [])) >= 3: confidence += 0.10
    confidence = round(min(confidence, 1.0), 2)

    # ── Send final output to GUVI on EVERY turn (upsert) ─────────────────────
    send_final_report_to_guvi(
        session_id=session_id,
        scam_detected=scam_detected,
        total_messages=total_messages,
        duration_seconds=duration_seconds,
        extracted_intelligence=extracted_intel,
        agent_notes=agent_notes,
        scam_type=scam_type,
        confidence_level=confidence,
    )

    # ── If conversation ended, also create DB report ──────────────────────────
    if conversation_ended:
        SupabaseService.end_session(session_id, agent_notes=agent_notes)

        intel_summary = {
            "upi_ids": extracted_intel.upiIds,
            "phone_numbers": extracted_intel.phoneNumbers,
            "bank_accounts": extracted_intel.bankAccounts,
            "phishing_links": extracted_intel.phishingLinks,
            "email_addresses": extracted_intel.emailAddresses,
            "case_ids": extracted_intel.caseIds,
        }

        SupabaseService.create_report(
            session_id=session_id,
            scam_detected=scam_detected,
            total_messages=total_messages,
            duration_seconds=duration_seconds,
            intelligence_summary=intel_summary,
            agent_notes=agent_notes,
        )

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
        agentNotes=agent_notes,
    )


# ══════════════════════════════════════════════════════════════════════════════
# Helper Functions
# ══════════════════════════════════════════════════════════════════════════════

def generate_agent_notes(session: Dict, red_flags: List[Dict] = None) -> str:
    """Generate rich summary notes about scammer behavior and red flags.

    v4.0 improvements:
    - Includes detected red flag categories with descriptions
    - More detailed behavioral analysis
    - Better scam type resolution
    """
    if not session:
        return "Session data not available"

    def _msg_text(msg):
        return msg.get("text") or msg.get("message") or ""

    notes = []
    history = session.get("conversation_history", [])
    scammer_messages = [msg for msg in history if msg.get("sender", "").lower() == "scammer"]

    # ── Red Flags Section ─────────────────────────────────────────────────────
    all_red_flags = session.get("detected_red_flags", [])
    if all_red_flags:
        notes.append(f"RED FLAGS IDENTIFIED ({len(all_red_flags)}): {'; '.join(all_red_flags[:8])}")

    # ── Behavioral Analysis ───────────────────────────────────────────────────
    urgency_keywords = ["urgent", "immediately", "now", "quickly", "hurry", "last chance", "act fast"]
    urgency_count = sum(1 for msg in scammer_messages
                        if any(kw in _msg_text(msg).lower() for kw in urgency_keywords))
    if urgency_count > 0:
        notes.append(f"Used urgency/pressure tactics in {urgency_count} message(s) — red flag: scammers create artificial time pressure")

    threat_keywords = ["blocked", "suspended", "legal action", "police", "arrest", "court", "warrant", "fir"]
    threat_count = sum(1 for msg in scammer_messages
                       if any(kw in _msg_text(msg).lower() for kw in threat_keywords))
    if threat_count > 0:
        notes.append(f"Made threats/intimidation in {threat_count} message(s) — red flag: legitimate institutions do not threaten customers")

    payment_keywords = ["send", "pay", "transfer", "deposit", "processing fee", "registration fee"]
    payment_count = sum(1 for msg in scammer_messages
                        if any(kw in _msg_text(msg).lower() for kw in payment_keywords))
    if payment_count > 0:
        notes.append(f"Requested payment/transfer {payment_count} time(s) — red flag: unsolicited payment demand")

    otp_keywords = ["otp", "pin", "password", "cvv", "mpin"]
    otp_count = sum(1 for msg in scammer_messages
                    if any(kw in _msg_text(msg).lower() for kw in otp_keywords))
    if otp_count > 0:
        notes.append(f"Requested OTP/PIN/password {otp_count} time(s) — red flag: no legitimate organization asks for OTP over phone/chat")

    identity_keywords = ["aadhaar", "pan card", "pan number", "voter id", "passport"]
    identity_count = sum(1 for msg in scammer_messages
                         if any(kw in _msg_text(msg).lower() for kw in identity_keywords))
    if identity_count > 0:
        notes.append(f"Requested government identity documents {identity_count} time(s) — red flag: identity theft attempt")

    # ── Extracted Intelligence Summary ────────────────────────────────────────
    artifacts = session.get("extracted_intelligence", {}).get("artifacts", {})
    if artifacts.get("upi_ids"):
        notes.append(f"Provided {len(artifacts['upi_ids'])} UPI ID(s): {', '.join(artifacts['upi_ids'])}")
    if artifacts.get("phone_numbers"):
        fmt_phones = []
        for p in artifacts["phone_numbers"]:
            clean = re.sub(r'[^\d]', '', p)
            if len(clean) == 12 and clean.startswith('91'):
                fmt_phones.append(f"+91-{clean[2:]}")
            elif len(clean) == 10:
                fmt_phones.append(f"+91-{clean}")
            else:
                fmt_phones.append(p)
        notes.append(f"Shared {len(fmt_phones)} phone number(s): {', '.join(fmt_phones)}")
    if artifacts.get("urls"):
        notes.append(f"Sent {len(artifacts['urls'])} suspicious link(s): {', '.join(artifacts['urls'][:3])}")
    if artifacts.get("bank_accounts"):
        notes.append(f"Revealed {len(artifacts['bank_accounts'])} bank account number(s): {', '.join(artifacts['bank_accounts'])}")
    if artifacts.get("emails"):
        notes.append(f"Shared email address(es): {', '.join(artifacts['emails'])}")
    if artifacts.get("case_ids"):
        notes.append(f"Provided case/reference/policy ID(s): {', '.join(artifacts['case_ids'])}")
    if artifacts.get("amounts"):
        notes.append(f"Mentioned monetary amount(s): {', '.join(str(a) for a in artifacts['amounts'])}")

    # ── Scam Type ─────────────────────────────────────────────────────────────
    scam_analysis = session.get("scam_analysis", [])
    resolved_scam_type = "Unknown"
    if scam_analysis:
        last = scam_analysis[-1].get("analysis", {})
        resolved_scam_type = last.get("scam_type", "Unknown")
    if resolved_scam_type == "Unknown":
        resolved_scam_type = session.get("scam_type", "Unknown")

    notes.append(f"Identified scam type: {resolved_scam_type}")

    # ── Engagement Summary ────────────────────────────────────────────────────
    notes.append(f"Total messages analyzed: {len(history)}, scammer messages: {len(scammer_messages)}")

    return "; ".join(notes) if notes else "No significant patterns detected"


def send_final_report_to_guvi(
    session_id: str,
    scam_detected: bool,
    total_messages: int,
    duration_seconds: int,
    extracted_intelligence: ExtractedIntelligence,
    agent_notes: str,
    scam_type: str = "Unknown",
    confidence_level: float = 0.0,
) -> Optional[Dict]:
    """
    Called on EVERY turn (upsert) so the evaluator always has the latest report.

    v4.0: Now includes scamType and confidenceLevel — these are optional scoring
    fields worth 1 point each in the Response Structure category.
    """
    callback_url = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

    payload = {
        "sessionId": session_id,
        "scamDetected": scam_detected,
        "totalMessagesExchanged": total_messages,
        "engagementDurationSeconds": duration_seconds,
        "extractedIntelligence": {
            "phoneNumbers": extracted_intelligence.phoneNumbers,
            "bankAccounts": extracted_intelligence.bankAccounts,
            "upiIds": extracted_intelligence.upiIds,
            "phishingLinks": extracted_intelligence.phishingLinks,
            "emailAddresses": extracted_intelligence.emailAddresses,
            "caseIds": extracted_intelligence.caseIds,
        },
        "agentNotes": agent_notes,
        # ── NEW in v4.0: optional fields for extra scoring points ──
        "scamType": scam_type,
        "confidenceLevel": confidence_level,
    }

    try:
        response = requests.post(callback_url, json=payload, timeout=5)
        if response.status_code == 200:
            print(f"✅ Report sent to GUVI for {session_id} (turn upsert, scamType={scam_type}, confidence={confidence_level})")
            return {"status_code": response.status_code, "response": response.text}
        else:
            print(f"⚠️  GUVI callback failed: {response.status_code} — {response.text}")
            return {"status_code": response.status_code, "error": response.text}
    except Exception as e:
        print(f"❌ Failed to send report: {e}")
        return {"error": str(e)}


# ══════════════════════════════════════════════════════════════════════════════
# Additional Endpoints
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/")
def health_check():
    supabase = get_supabase()
    return {
        "status": "healthy",
        "service": "Agentic Honeypot API v4.0",
        "version": "4.0",
        "database": "connected" if supabase else "disconnected",
        "active_sessions": len(honeypot.sessions) if honeypot else 0,
    }


@app.get("/session/{session_id}/status")
def get_session_status(session_id: str, x_api_key: str = Header(None)):
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
            "scamType": db_session.get("scam_type", "Unknown"),
        }
    raise HTTPException(status_code=404, detail="Session not found")


@app.post("/session/{session_id}/force-report")
def force_create_report(session_id: str, x_api_key: str = Header(None)):
    if x_api_key != SECRET_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    db_session = SupabaseService.get_session(session_id)
    if not db_session:
        raise HTTPException(status_code=404, detail="Session not found")

    intelligence = SupabaseService.get_intelligence(session_id)

    start_time_str = db_session['started_at']
    if start_time_str.endswith('Z'):
        start_time_str = start_time_str.replace('Z', '+00:00')
    start_time = datetime.fromisoformat(start_time_str)
    duration_seconds = int((datetime.now(timezone.utc) - start_time).total_seconds())

    session = honeypot.sessions.get(session_id, {})
    agent_notes = generate_agent_notes(session) if session else "Session in progress"

    intel_summary = {
        "upi_ids": intelligence.get("upi_ids", []) if intelligence else [],
        "phone_numbers": intelligence.get("phone_numbers", []) if intelligence else [],
        "bank_accounts": intelligence.get("bank_accounts", []) if intelligence else [],
        "phishing_links": intelligence.get("phishing_links", []) if intelligence else [],
        "suspicious_keywords": intelligence.get("suspicious_keywords", []) if intelligence else [],
    }

    report = SupabaseService.create_report(
        session_id=session_id,
        scam_detected=db_session.get('scam_detected', False),
        total_messages=db_session.get('total_messages', 0),
        duration_seconds=duration_seconds,
        intelligence_summary=intel_summary,
        agent_notes=f"[FORCED REPORT] {agent_notes}",
    )

    return {"status": "success", "message": "Force report created", "report": report}


@app.get("/stats")
def get_statistics(x_api_key: str = Header(None)):
    if x_api_key != SECRET_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    try:
        stats = SupabaseService.get_statistics()
        return {"status": "success", "data": stats}
    except Exception as e:
        if not honeypot:
            return {"status": "success", "data": {"active_sessions": 0, "total_scams": 0, "total_intelligence": 0, "extraction_rate": 0}}

        active_sessions = len([s for s in honeypot.sessions.values() if not s.get('ended', False)])
        total_scams = len([s for s in honeypot.sessions.values() if s.get('scam_detected', False)])
        total_intel = 0
        for sess in honeypot.sessions.values():
            a = sess.get('extracted_intelligence', {}).get('artifacts', {})
            total_intel += sum(len(a.get(k, [])) for k in ['upi_ids', 'phone_numbers', 'urls', 'bank_accounts'])

        return {"status": "success", "data": {
            "active_sessions": active_sessions,
            "total_scams": total_scams,
            "total_intelligence": total_intel,
            "extraction_rate": round((total_intel / total_scams * 100) if total_scams > 0 else 0, 1),
        }}


@app.get("/reports/recent")
def get_recent_reports(limit: int = 20, x_api_key: str = Header(None)):
    if x_api_key != SECRET_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    try:
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
                    "sentToAPI": r["sent_to_external_api"],
                }
                for r in reports
            ],
        }
    except Exception as e:
        print(f"⚠️ Supabase reports failed: {e}")
        return {"status": "success", "count": 0, "reports": []}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)