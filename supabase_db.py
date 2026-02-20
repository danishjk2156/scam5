"""
Supabase Database Configuration
Optimized for Supabase PostgreSQL with their client library
FULLY FIXED VERSION - All timezone issues resolved
"""

import os
from supabase import create_client, Client
from typing import Optional, Dict, List, Any
from datetime import datetime, timezone
import json

# Supabase configuration
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")  # Use service_role key for server-side

# Initialize Supabase client
supabase: Optional[Client] = None

def init_supabase():
    """Initialize Supabase client"""
    global supabase
    if SUPABASE_URL and SUPABASE_KEY:
        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
        print("✅ Supabase client initialized")
        return True
    else:
        print("⚠️  Supabase credentials not configured")
        return False

def get_supabase() -> Client:
    """Get Supabase client instance"""
    if supabase is None:
        init_supabase()
    return supabase


class SupabaseService:
    """Service class for Supabase database operations"""
    
    @staticmethod
    def create_session(
        session_id: str,
        channel: str = "SMS",
        language: str = "English",
        locale: str = "IN"
    ) -> Optional[Dict]:
        """Create a new honeypot session"""
        try:
            data = {
                "session_id": session_id,
                "channel": channel,
                "language": language,
                "locale": locale,
                "is_active": True,
                "conversation_history": [],
                "total_messages": 0,
                "scammer_messages": 0,
                "extraction_progress": 0.0,
                "scam_detected": False
            }
            
            result = supabase.table("honeypot_sessions").insert(data).execute()
            return result.data[0] if result.data else None
        except Exception as e:
            print(f"Error creating session: {e}")
            return None
    
    @staticmethod
    def get_session(session_id: str) -> Optional[Dict]:
        """Get a session by ID"""
        try:
            result = supabase.table("honeypot_sessions")\
                .select("*")\
                .eq("session_id", session_id)\
                .execute()
            return result.data[0] if result.data else None
        except Exception as e:
            print(f"Error getting session: {e}")
            return None
    
    @staticmethod
    def update_session(session_id: str, updates: Dict) -> Optional[Dict]:
        """Update session fields"""
        try:
            # FIXED: Use timezone-aware datetime
            updates["updated_at"] = datetime.now(timezone.utc).isoformat()
            result = supabase.table("honeypot_sessions")\
                .update(updates)\
                .eq("session_id", session_id)\
                .execute()
            return result.data[0] if result.data else None
        except Exception as e:
            print(f"Error updating session: {e}")
            return None
    
    @staticmethod
    def add_message(
        session_id: str,
        sender: str,
        message: str,
        timestamp: Optional[str] = None
    ) -> Optional[Dict]:
        """Add a message to session conversation history"""
        try:
            # Get current session
            session = SupabaseService.get_session(session_id)
            if not session:
                return None
            
            # Add message to history
            history = session.get("conversation_history", [])
            history.append({
                "sender": sender,  # FIXED: Standardized to "sender" instead of "from"
                "message": message,
                "timestamp": timestamp or datetime.now(timezone.utc).isoformat()  # FIXED: timezone-aware
            })
            
            # Update counts
            updates = {
                "conversation_history": history,
                "total_messages": len(history)
            }
            
            if sender == "scammer":
                updates["scammer_messages"] = session.get("scammer_messages", 0) + 1
            
            return SupabaseService.update_session(session_id, updates)
        except Exception as e:
            print(f"Error adding message: {e}")
            return None
    
    @staticmethod
    def end_session(session_id: str, agent_notes: Optional[str] = None) -> Optional[Dict]:
        """End a conversation session"""
        try:
            updates = {
                "is_active": False,
                "ended_at": datetime.now(timezone.utc).isoformat()  # FIXED: timezone-aware
            }
            if agent_notes:
                updates["agent_notes"] = agent_notes
            
            return SupabaseService.update_session(session_id, updates)
        except Exception as e:
            print(f"Error ending session: {e}")
            return None
    
    
    @staticmethod
    def record_metric(
        metric_name: str,
        metric_value: float,
        session_id: Optional[str] = None,
        metadata: Optional[Dict] = None
    ) -> Optional[Dict]:
        """Record an analytics metric"""
        try:
            data = {
                "metric_name": metric_name,
                "metric_value": metric_value,
                "session_id": session_id,
                "metric_metadata": metadata or {}
            }
            
            result = supabase.table("analytics_metrics").insert(data).execute()
            return result.data[0] if result.data else None
        except Exception as e:
            print(f"Error recording metric: {e}")
            return None

    @staticmethod
    def batch_record_metrics(metrics: List[Dict]) -> bool:
        """Record multiple metrics at once"""
        try:
            result = supabase.table("analytics_metrics").insert(metrics).execute()
            return len(result.data) > 0
        except Exception as e:
            print(f"Error batch recording metrics: {e}")
            return False

    @staticmethod
    def save_intelligence(
        session_id: str,
        upi_ids: List[str] = None,
        phone_numbers: List[str] = None,
        bank_accounts: List[str] = None,
        phishing_links: List[str] = None,
        suspicious_keywords: List[str] = None,
        email_addresses: List[str] = None
    ) -> Optional[Dict]:
        """Save or update extracted intelligence"""
        try:
            # Check if intelligence record exists
            existing = supabase.table("extracted_intelligence")\
                .select("*")\
                .eq("session_id", session_id)\
                .execute()
            
            data = {
                "session_id": session_id,
                "upi_ids": upi_ids or [],
                "phone_numbers": phone_numbers or [],
                "bank_accounts": bank_accounts or [],
                "phishing_links": phishing_links or [],
                "suspicious_keywords": suspicious_keywords or [],
                "email_addresses": email_addresses or []
            }
            
            if existing.data:
                # Update existing
                data["updated_at"] = datetime.now(timezone.utc).isoformat()  # FIXED: timezone-aware
                result = supabase.table("extracted_intelligence")\
                    .update(data)\
                    .eq("session_id", session_id)\
                    .execute()
            else:
                # Insert new
                result = supabase.table("extracted_intelligence")\
                    .insert(data)\
                    .execute()
            
            return result.data[0] if result.data else None
        except Exception as e:
            print(f"Error saving intelligence: {e}")
            return None
    
    @staticmethod
    def get_intelligence(session_id: str) -> Optional[Dict]:
        """Get extracted intelligence for a session"""
        try:
            result = supabase.table("extracted_intelligence")\
                .select("*")\
                .eq("session_id", session_id)\
                .execute()
            return result.data[0] if result.data else None
        except Exception as e:
            print(f"Error getting intelligence: {e}")
            return None
    
    @staticmethod
    def create_report(
        session_id: str,
        scam_detected: bool,
        total_messages: int,
        duration_seconds: int,
        intelligence_summary: Dict,
        agent_notes: Optional[str] = None
    ) -> Optional[Dict]:
        """Create a final scam report"""
        try:
            data = {
                "session_id": session_id,
                "scam_detected": scam_detected,
                "total_messages_exchanged": total_messages,
                "engagement_duration_seconds": duration_seconds,
                "extracted_intelligence_summary": intelligence_summary,
                "agent_notes": agent_notes,
                "sent_to_external_api": False
            }
            
            result = supabase.table("scam_reports")\
                .insert(data)\
                .execute()
            return result.data[0] if result.data else None
        except Exception as e:
            print(f"Error creating report: {e}")
            return None
    
    @staticmethod
    def mark_report_sent(session_id: str, api_response: Optional[Dict] = None) -> Optional[Dict]:
        """Mark a report as sent to external API"""
        try:
            updates = {
                "sent_to_external_api": True,
                "sent_at": datetime.now(timezone.utc).isoformat()  # FIXED: timezone-aware
            }
            if api_response:
                updates["external_api_response"] = api_response

            # FIX: Cannot chain .order().limit() after .update() in Supabase client.
            # First fetch the latest report id, then update it.
            latest = supabase.table("scam_reports")\
                .select("id")\
                .eq("session_id", session_id)\
                .order("report_generated_at", desc=True)\
                .limit(1)\
                .execute()

            if not latest.data:
                return None

            report_id = latest.data[0]["id"]
            result = supabase.table("scam_reports")\
                .update(updates)\
                .eq("id", report_id)\
                .execute()
            return result.data[0] if result.data else None
        except Exception as e:
            print(f"Error marking report sent: {e}")
            return None
    
    @staticmethod
    def get_active_sessions(limit: int = 100) -> List[Dict]:
        """Get all active sessions"""
        try:
            result = supabase.table("honeypot_sessions")\
                .select("*")\
                .eq("is_active", True)\
                .order("started_at", desc=True)\
                .limit(limit)\
                .execute()
            return result.data or []
        except Exception as e:
            print(f"Error getting active sessions: {e}")
            return []
    
    @staticmethod
    def get_statistics() -> Dict[str, Any]:
        """Get overall statistics"""
        try:
            # Total sessions
            total_result = supabase.table("honeypot_sessions")\
                .select("*", count="exact")\
                .execute()
            total_sessions = total_result.count or 0
            
            # Active sessions
            active_result = supabase.table("honeypot_sessions")\
                .select("*", count="exact")\
                .eq("is_active", True)\
                .execute()
            active_sessions = active_result.count or 0
            
            # Scams detected
            scams_result = supabase.table("honeypot_sessions")\
                .select("*", count="exact")\
                .eq("scam_detected", True)\
                .execute()
            scams_detected = scams_result.count or 0
            
            # Scam types distribution
            scam_types_result = supabase.table("honeypot_sessions")\
                .select("scam_type")\
                .not_.is_("scam_type", "null")\
                .execute()
            
            scam_type_dist = {}
            for row in scam_types_result.data or []:
                scam_type = row.get("scam_type")
                scam_type_dist[scam_type] = scam_type_dist.get(scam_type, 0) + 1
            
            return {
                "total_sessions": total_sessions,
                "active_sessions": active_sessions,
                "scams_detected": scams_detected,
                "detection_rate": scams_detected / total_sessions if total_sessions > 0 else 0,
                "scam_type_distribution": scam_type_dist
            }
        except Exception as e:
            print(f"Error getting statistics: {e}")
            return {
                "total_sessions": 0,
                "active_sessions": 0,
                "scams_detected": 0,
                "detection_rate": 0,
                "scam_type_distribution": {}
            }
    
    @staticmethod
    def get_recent_reports(limit: int = 50) -> List[Dict]:
        """Get recent scam reports"""
        try:
            result = supabase.table("scam_reports")\
                .select("*")\
                .order("report_generated_at", desc=True)\
                .limit(limit)\
                .execute()
            return result.data or []
        except Exception as e:
            print(f"Error getting recent reports: {e}")
            return []


# Lazy initialization - will be called on first use via get_supabase()
# init_supabase()  # Commented out to prevent crashes during import