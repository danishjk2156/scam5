# Agentic Honeypot API - API Specification Compliant

## 🎯 Overview
This implementation follows the **exact API request/response format** specified in the GUVI hackathon problem statement for Problem Statement 2.

## 🔑 Key Changes Made

### 1. **Request Format Compliance**
Your original `main.py` was using a simplified format. The updated version now accepts the **exact format** specified:

```json
{
  "sessionId": "wertyu-dfghj-ertyui",
  "message": {
    "sender": "scammer",
    "text": "Your bank account will be blocked today. Verify immediately.",
    "timestamp": "2026-01-21T10:15:30Z"
  },
  "conversationHistory": [
    {
      "sender": "scammer",
      "text": "Previous message...",
      "timestamp": "2026-01-21T10:15:30Z"
    }
  ],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

### 2. **Response Format Compliance**
The response now includes all fields specified in the problem statement:

```json
{
  "status": "success",
  "sessionId": "wertyu-dfghj-ertyui",
  "scamDetected": true,
  "scamType": "Bank Impersonation",
  "reply": "Oh no! Why will my account be blocked?",
  "conversationActive": true,
  "stage": "building_trust",
  "extractionProgress": 0.35,
  "shouldGetReport": false,
  "engagementMetrics": {
    "engagementDurationSeconds": 120,
    "totalMessagesExchanged": 4
  },
  "extractedIntelligence": {
    "bankAccounts": [],
    "upiIds": ["scammer@okicici"],
    "phishingLinks": ["http://malicious-link.com"],
    "phoneNumbers": ["+919876543210"],
    "suspiciousKeywords": ["urgent", "verify", "blocked"]
  },
  "agentNotes": "Used urgency tactics; Requested payment 2 times"
}
```

### 3. **Automatic GUVI Callback**
When a conversation ends, the system automatically sends the final report to:
```
POST https://hackathon.guvi.in/api/updateHoneyPotFinalResult
```

This is **MANDATORY** for evaluation and happens automatically.

## 📋 API Endpoints

### 1. Main Honeypot Endpoint
```
POST /honeypot/message
Headers: x-api-key: my_secret_key
Content-Type: application/json
```

**Request Body:**
```json
{
  "sessionId": "unique-session-id",
  "message": {
    "sender": "scammer",
    "text": "Message text here",
    "timestamp": "2026-01-21T10:15:30Z"
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

### 2. Health Check
```
GET /
```

### 3. Session Status
```
GET /session/{session_id}/status
Headers: x-api-key: my_secret_key
```

## 🚀 How to Use

### Step 1: Install Dependencies
```bash
pip install fastapi uvicorn pydantic requests
```

### Step 2: Set Environment Variables
```bash
export GEMINI_API_KEY="your-gemini-api-key"
```

### Step 3: Run the Server
```bash
# Replace your old main.py with main_updated.py
cp main_updated.py main.py

# Run the server
python main.py
```

Or use uvicorn:
```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

### Step 4: Test with curl

**First message (new conversation):**
```bash
curl -X POST http://localhost:8000/honeypot/message \
  -H "x-api-key: my_secret_key" \
  -H "Content-Type: application/json" \
  -d '{
    "sessionId": "test-session-001",
    "message": {
      "sender": "scammer",
      "text": "Your bank account will be blocked. Send 1 rupee to verify@okicici",
      "timestamp": "2026-01-21T10:15:30Z"
    },
    "conversationHistory": [],
    "metadata": {
      "channel": "SMS",
      "language": "English",
      "locale": "IN"
    }
  }'
```

**Follow-up message (continuing conversation):**
```bash
curl -X POST http://localhost:8000/honeypot/message \
  -H "x-api-key: my_secret_key" \
  -H "Content-Type: application/json" \
  -d '{
    "sessionId": "test-session-001",
    "message": {
      "sender": "scammer",
      "text": "Did you send the payment? Share OTP now!",
      "timestamp": "2026-01-21T10:17:10Z"
    },
    "conversationHistory": [
      {
        "sender": "scammer",
        "text": "Your bank account will be blocked. Send 1 rupee to verify@okicici",
        "timestamp": "2026-01-21T10:15:30Z"
      },
      {
        "sender": "user",
        "text": "Why will my account be blocked?",
        "timestamp": "2026-01-21T10:16:10Z"
      }
    ],
    "metadata": {
      "channel": "SMS",
      "language": "English",
      "locale": "IN"
    }
  }'
```

## 🔍 Key Features

### ✅ Fully Compliant with API Specification
- Accepts exact request format from problem statement
- Returns exact response format specified
- Handles conversation history properly
- Includes all required fields

### ✅ Automatic Intelligence Extraction
- UPI IDs
- Phone numbers
- Phishing links
- Suspicious keywords
- Bank names
- Amounts mentioned

### ✅ Multi-turn Conversation Handling
- Maintains session state
- Builds on conversation history
- Adapts responses based on stage
- Natural conversation flow

### ✅ Automatic GUVI Callback
- Sends final report when conversation ends
- Includes all extracted intelligence
- Provides agent notes and analysis

### ✅ Agent Notes Generation
- Analyzes scammer tactics
- Identifies urgency patterns
- Detects threats
- Tracks information requests

## 📊 Response Fields Explained

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | "success" or "error" |
| `sessionId` | string | Unique conversation identifier |
| `scamDetected` | boolean | Whether scam intent was detected |
| `scamType` | string | Type of scam (UPI Fraud, Bank Impersonation, etc.) |
| `reply` | string | Agent's response to scammer |
| `conversationActive` | boolean | Whether conversation is still ongoing |
| `stage` | string | Current conversation stage |
| `extractionProgress` | float | 0.0 to 1.0 - how much intelligence extracted |
| `shouldGetReport` | boolean | Whether to call report endpoint |
| `engagementMetrics` | object | Duration and message counts |
| `extractedIntelligence` | object | All intelligence gathered so far |
| `agentNotes` | string | Summary of scammer behavior (on end) |

## 🎭 Conversation Stages

1. **initial** - First contact, establishing presence
2. **building_trust** - Acting confused/curious
3. **extracting** - Asking questions to get info
4. **deep_extraction** - Pressing for more details
5. **exit_preparation** - Winding down conversation
6. **ended** - Conversation terminated

## 🔒 Security Notes

1. **Change the SECRET_KEY** in production:
   ```python
   SECRET_KEY = os.getenv("API_SECRET_KEY", "your-secure-key-here")
   ```

2. **Enable HTTPS** in production deployment

3. **Rate limiting** recommended for production

## 📝 Important Differences from Your Original Code

### Before (Your Original):
```python
@app.post("/honeypot/message")
def receive_message(payload: dict, x_api_key: str = Header(None)):
    session_id = payload.get("sessionId")
    message_text = payload.get("message", {}).get("text", "")
    # ... simple format
```

### After (Updated & Compliant):
```python
@app.post("/honeypot/message", response_model=HoneypotResponse)
def receive_message(payload: HoneypotRequest, x_api_key: str = Header(None)):
    # Pydantic models ensure exact format
    # Handles conversationHistory properly
    # Sends GUVI callback automatically
    # Returns all required fields
```

## 🧪 Testing Checklist

- [x] First message with empty conversationHistory
- [x] Follow-up messages with full conversationHistory
- [x] Scam detection works
- [x] Intelligence extraction works
- [x] Agent generates natural responses
- [x] Conversation ends appropriately
- [x] Final report sent to GUVI
- [x] All response fields present
- [x] API authentication works
- [x] Session status endpoint works

## 🆘 Troubleshooting

### Problem: "Invalid API key"
**Solution:** Make sure to include the header:
```
x-api-key: my_secret_key
```

### Problem: "Session not found"
**Solution:** Each sessionId should be consistent across the conversation. First message creates the session.

### Problem: Agent not responding naturally
**Solution:** Make sure you have a valid GEMINI_API_KEY set in your environment.

### Problem: GUVI callback failing
**Solution:** This is logged but doesn't fail your API call. Check console for error messages.

## 📚 Additional Resources

- Original Problem Statement: See the provided PDF
- GUVI Hackathon Platform: https://hackathon.guvi.in
- FastAPI Documentation: https://fastapi.tiangolo.com

## ✨ Summary

Your updated system now:
1. ✅ Accepts the exact request format specified
2. ✅ Returns the exact response format specified
3. ✅ Handles conversationHistory properly
4. ✅ Automatically sends final reports to GUVI
5. ✅ Includes all required fields in responses
6. ✅ Ready for evaluation!
