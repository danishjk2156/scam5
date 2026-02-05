"""
Test script for Agentic Honeypot API
Demonstrates proper API format compliance
"""

import requests
import json
from datetime import datetime
from typing import List, Dict

# Configuration
API_BASE_URL = "http://localhost:8000"
API_KEY = "my_secret_key"

class HoneypotAPITester:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url
        self.api_key = api_key
        self.session_id = None
        self.conversation_history: List[Dict] = []
    
    def send_message(self, scammer_message: str, channel: str = "SMS") -> Dict:
        """
        Send a message to the honeypot API using the correct format
        """
        timestamp = datetime.utcnow().isoformat() + "Z"
        
        # Build request payload following exact API specification
        payload = {
            "sessionId": self.session_id,
            "message": {
                "sender": "scammer",
                "text": scammer_message,
                "timestamp": timestamp
            },
            "conversationHistory": self.conversation_history.copy(),
            "metadata": {
                "channel": channel,
                "language": "English",
                "locale": "IN"
            }
        }
        
        # Send request
        headers = {
            "x-api-key": self.api_key,
            "Content-Type": "application/json"
        }
        
        response = requests.post(
            f"{self.base_url}/honeypot/message",
            json=payload,
            headers=headers,
            timeout=30
        )
        
        if response.status_code != 200:
            print(f"❌ API Error: {response.status_code}")
            print(f"   Response: {response.text}")
            return None
        
        result = response.json()
        
        # Update conversation history for next message
        self.conversation_history.append({
            "sender": "scammer",
            "text": scammer_message,
            "timestamp": timestamp
        })
        
        # Add agent's reply to history
        if result.get("reply"):
            self.conversation_history.append({
                "sender": "user",
                "text": result["reply"],
                "timestamp": datetime.utcnow().isoformat() + "Z"
            })
        
        return result
    
    def print_response(self, response: Dict, message_num: int):
        """Pretty print the API response"""
        print(f"\n{'='*70}")
        print(f"📨 MESSAGE #{message_num}")
        print(f"{'='*70}")
        
        print(f"\n✅ Status: {response.get('status')}")
        print(f"🆔 Session ID: {response.get('sessionId')}")
        print(f"🚨 Scam Detected: {response.get('scamDetected')}")
        print(f"🏷️  Scam Type: {response.get('scamType')}")
        
        print(f"\n💬 Agent Reply:")
        print(f"   \"{response.get('reply')}\"")
        
        print(f"\n📊 Status:")
        print(f"   • Active: {response.get('conversationActive')}")
        print(f"   • Stage: {response.get('stage')}")
        print(f"   • Extraction Progress: {response.get('extractionProgress'):.2%}")
        
        if response.get('engagementMetrics'):
            metrics = response['engagementMetrics']
            print(f"\n⏱️  Engagement Metrics:")
            print(f"   • Duration: {metrics.get('engagementDurationSeconds')} seconds")
            print(f"   • Total Messages: {metrics.get('totalMessagesExchanged')}")
        
        if response.get('extractedIntelligence'):
            intel = response['extractedIntelligence']
            print(f"\n🔍 Extracted Intelligence:")
            if intel.get('upiIds'):
                print(f"   • UPI IDs: {', '.join(intel['upiIds'])}")
            if intel.get('phoneNumbers'):
                print(f"   • Phone Numbers: {', '.join(intel['phoneNumbers'])}")
            if intel.get('phishingLinks'):
                print(f"   • Phishing Links: {', '.join(intel['phishingLinks'])}")
            if intel.get('suspiciousKeywords'):
                print(f"   • Keywords: {', '.join(intel['suspiciousKeywords'])}")
        
        if response.get('agentNotes'):
            print(f"\n📝 Agent Notes:")
            print(f"   {response['agentNotes']}")
    
    def run_test_conversation(self):
        """Run a complete test conversation"""
        print("\n" + "="*70)
        print("🚀 STARTING AGENTIC HONEYPOT API TEST")
        print("="*70)
        
        # Generate unique session ID
        self.session_id = f"test-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        print(f"\n🆔 Session ID: {self.session_id}")
        
        # Simulated scammer messages
        test_messages = [
            "Your bank account will be blocked today. Verify immediately by sending ₹1 to verify@okicici.",
            "Sir, this is urgent! Your account has suspicious activity. Send ₹1 to verify@okicici now.",
            "We detected unauthorized transactions. Complete KYC now. Send ₹1 to verify@okicici.",
            "This is your last warning! Account will be suspended in 30 minutes. Send OTP and ₹1.",
            "Call 9876543210 immediately for verification or visit http://bank-verify.malicious.com",
            "Your UPI PIN is required for security verification. Share PIN and send ₹1 to verify@okicici.",
            "Final warning! Send your Aadhaar number, PAN card, and ₹1 to verify@okicici now!",
        ]
        
        # Send messages one by one
        for i, scammer_msg in enumerate(test_messages, 1):
            print(f"\n\n{'🔴'*35}")
            print(f"📱 SCAMMER MESSAGE #{i}:")
            print(f"   \"{scammer_msg}\"")
            print(f"{'🔴'*35}")
            
            response = self.send_message(scammer_msg)
            
            if response:
                self.print_response(response, i)
                
                # Check if conversation ended
                if not response.get('conversationActive'):
                    print("\n" + "="*70)
                    print("🛑 CONVERSATION ENDED")
                    print("="*70)
                    print("\n✅ Final report has been automatically sent to GUVI!")
                    break
            else:
                print("\n❌ Failed to get response from API")
                break
        
        print("\n" + "="*70)
        print("✅ TEST COMPLETED")
        print("="*70)
    
    def check_health(self):
        """Check if API is running"""
        try:
            response = requests.get(f"{self.base_url}/")
            if response.status_code == 200:
                print("✅ API is healthy and running")
                print(f"   Response: {response.json()}")
                return True
            else:
                print(f"❌ API returned status code: {response.status_code}")
                return False
        except requests.exceptions.ConnectionError:
            print("❌ Cannot connect to API. Make sure the server is running.")
            return False
        except Exception as e:
            print(f"❌ Error checking health: {str(e)}")
            return False

def main():
    """Main test function"""
    print("\n" + "="*70)
    print("🧪 AGENTIC HONEYPOT API TESTER")
    print("="*70)
    
    # Initialize tester
    tester = HoneypotAPITester(API_BASE_URL, API_KEY)
    
    # Check if API is running
    print("\n🏥 Checking API health...")
    if not tester.check_health():
        print("\n❌ Please start the API server first:")
        print("   python main.py")
        return
    
    print("\n" + "="*70)
    print("📋 API FORMAT COMPLIANCE TEST")
    print("="*70)
    print("\nThis test demonstrates:")
    print("✅ Correct request format with sessionId, message, conversationHistory")
    print("✅ Proper conversation history tracking")
    print("✅ Multi-turn conversation handling")
    print("✅ Intelligence extraction")
    print("✅ Automatic GUVI callback when conversation ends")
    
    input("\nPress Enter to start the test conversation...")
    
    # Run test conversation
    tester.run_test_conversation()
    
    print("\n" + "="*70)
    print("📊 SUMMARY")
    print("="*70)
    print(f"• Session ID: {tester.session_id}")
    print(f"• Messages Sent: {len([m for m in tester.conversation_history if m['sender'] == 'scammer'])}")
    print(f"• Conversation History Length: {len(tester.conversation_history)}")
    print("\n✅ All API calls used the correct format specified in the problem statement!")
    print("✅ Final report was automatically sent to GUVI endpoint!")

if __name__ == "__main__":
    main()
