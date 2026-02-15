"""
Debug script to test API endpoints and see what data is returned
"""
import requests
import json

# Configuration
API_ENDPOINT = "http://localhost:8000"
API_KEY = input("Enter your API key: ").strip()

print("\n" + "="*70)
print("🔍 DEBUGGING API ENDPOINTS")
print("="*70)

# Test 1: Health Check
print("\n1️⃣ Testing Health Endpoint: GET /")
print("-" * 70)
try:
    response = requests.get(f"{API_ENDPOINT}/")
    print(f"Status Code: {response.status_code}")
    print(f"Response:")
    print(json.dumps(response.json(), indent=2))
except Exception as e:
    print(f"❌ Error: {e}")

# Test 2: Stats Endpoint
print("\n2️⃣ Testing Stats Endpoint: GET /stats")
print("-" * 70)
try:
    response = requests.get(
        f"{API_ENDPOINT}/stats",
        headers={"x-api-key": API_KEY}
    )
    print(f"Status Code: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print(f"Response:")
        print(json.dumps(data, indent=2))
    else:
        print(f"Error Response: {response.text}")
except Exception as e:
    print(f"❌ Error: {e}")

# Test 3: Recent Reports
print("\n3️⃣ Testing Reports Endpoint: GET /reports/recent")
print("-" * 70)
try:
    response = requests.get(
        f"{API_ENDPOINT}/reports/recent?limit=10",
        headers={"x-api-key": API_KEY}
    )
    print(f"Status Code: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print(f"Response:")
        print(json.dumps(data, indent=2))
        print(f"\n📊 Summary:")
        print(f"   Total reports: {data.get('count', 0)}")
        if data.get('reports'):
            for report in data['reports'][:3]:
                print(f"\n   Session: {report.get('sessionId')}")
                print(f"   Scam Detected: {report.get('scamDetected')}")
                print(f"   Intelligence: {report.get('intelligence')}")
    else:
        print(f"Error Response: {response.text}")
except Exception as e:
    print(f"❌ Error: {e}")

# Test 4: Send a test message
print("\n4️⃣ Testing Message Endpoint: POST /honeypot/message")
print("-" * 70)
print("Sending test scam message...")

test_payload = {
    "sessionId": "debug_test_session",
    "message": {
        "sender": "scammer",
        "text": "Send ₹1 to fraud@paytm for ₹5000 refund!",
        "timestamp": "2026-02-14T10:00:00Z"
    },
    "conversationHistory": [],
    "metadata": {
        "channel": "SMS",
        "language": "English",
        "locale": "IN"
    }
}

try:
    response = requests.post(
        f"{API_ENDPOINT}/honeypot/message",
        headers={
            "Content-Type": "application/json",
            "x-api-key": API_KEY
        },
        json=test_payload
    )
    print(f"Status Code: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print(f"\n✅ Message sent successfully!")
        print(f"   Agent Reply: {data.get('reply')}")
        print(f"   Scam Detected: {data.get('scamDetected')}")
        print(f"   Stage: {data.get('stage')}")
        print(f"   Extraction Progress: {data.get('extractionProgress')}")
        
        intel = data.get('extractedIntelligence', {})
        if intel:
            print(f"\n   💎 Extracted Intelligence:")
            print(f"      UPI IDs: {intel.get('upiIds', [])}")
            print(f"      Phones: {intel.get('phoneNumbers', [])}")
            print(f"      URLs: {intel.get('phishingLinks', [])}")
    else:
        print(f"Error Response: {response.text}")
except Exception as e:
    print(f"❌ Error: {e}")

# Test 5: Check stats again after sending message
print("\n5️⃣ Checking Stats Again (After Test Message)")
print("-" * 70)
try:
    response = requests.get(
        f"{API_ENDPOINT}/stats",
        headers={"x-api-key": API_KEY}
    )
    if response.status_code == 200:
        data = response.json()
        stats = data.get('data', {})
        print(f"Active Sessions: {stats.get('active_sessions', 0)}")
        print(f"Total Scams: {stats.get('total_scams', 0)}")
        print(f"Total Intelligence: {stats.get('total_intelligence', 0)}")
        print(f"Extraction Rate: {stats.get('extraction_rate', 0)}%")
    else:
        print(f"Error: {response.status_code}")
except Exception as e:
    print(f"❌ Error: {e}")

print("\n" + "="*70)
print("🎯 DIAGNOSIS:")
print("="*70)

print("""
Based on the results above:

✅ If Test 1 passed → Server is running
✅ If Test 2 passed → Stats endpoint works
✅ If Test 3 passed → Reports endpoint works  
✅ If Test 4 passed → Can send messages
✅ If Test 5 shows non-zero → Data is being tracked

❌ If stats are still zero after Test 5:
   → Data might not be persisting in honeypot.sessions
   → Supabase might not be storing data
   → Need to check honeypot initialization

Share the output above and I'll tell you exactly what's wrong!
""")