import streamlit as st
import requests
import re
from log_manager import log_email_activity, log_website_activity  # Import logging functions
from config import (
    LEAKCHECK_API_KEY,
    MAILBOXLAYER_API_KEY,
    GOOGLE_SAFE_BROWSING_API_KEY,
    TELEGRAM_BOT_TOKEN,
    TELEGRAM_CHAT_ID,
)

# ✅ Function to Check Email Breach
def check_email_breach(email):
    if not is_valid_email(email):
        log_email_activity(email, "Invalid", "Blocked", "Invalid email format")
        return "❌ Invalid email format."

    url = "https://leakcheck.io/api/public"
    params = {"key": LEAKCHECK_API_KEY, "check": email}

    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        data = response.json()

        if data.get("status") == "found":
            log_email_activity(email, "Breached", "Blocked", "Found in data leaks")
            return f"⚠️ {email} found in {len(data['sources'])} data leaks! 🚨 BLOCKED!"
        else:
            log_email_activity(email, "Safe", "Allowed", "No breaches found")
            return f"✅ {email} is **SAFE** (No breaches found)."

    except requests.exceptions.RequestException as e:
        log_email_activity(email, "Error", "Blocked", f"API Error: {e}")
        return f"❌ API Error: {e}"

# ✅ Function to Check Website Safety
def check_website_safety(url):
    if url.startswith("http://"):  # 🚨 Block all HTTP sites immediately
        log_website_activity(url, "Blocked", "Blocked", "HTTP website detected")
        return "🚨 **Unsafe HTTP Website Detected! BLOCKED!**"

    google_safe_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
    
    request_payload = {
        "client": {"clientId": "streamlit-app", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(google_safe_url, json=request_payload)
        response.raise_for_status()
        data = response.json()

        if "matches" in data:
            log_website_activity(url, "Unsafe", "Blocked", "Google flagged as unsafe")
            return f"🚨 **WARNING: {url} is flagged as UNSAFE!** 🚨"
        else:
            log_website_activity(url, "Safe", "Allowed", "No threats detected")
            return f"✅ {url} is **SAFE** (No threats detected)."

    except requests.exceptions.RequestException as e:
        log_website_activity(url, "Error", "Blocked", f"API Error: {e}")
        return f"❌ API Error: {e}"
