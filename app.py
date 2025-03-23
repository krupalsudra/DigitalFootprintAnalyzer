import streamlit as st
import requests
import re
import json
import pandas as pd
from datetime import datetime
from log_manager import (
    log_email_activity, log_website_activity, get_logs, send_telegram_alert, handle_telegram_messages
)
from config import (
    LEAKCHECK_API_KEY,
    GOOGLE_SAFE_BROWSING_API_KEY,
    TELEGRAM_BOT_TOKEN,
    TELEGRAM_CHAT_ID
)

# ✅ Run Telegram Message Handler when the app starts
handle_telegram_messages()

# ✅ Function to Validate Email Format
def is_valid_email(email):
    email = email.strip().lower()
    regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.(com|org|net|edu|gov|mil|co|in|us)$'
    return re.match(regex, email)

# ✅ Function to Check Email Breach
def check_email_breach(email):
    email = email.strip().lower()

    if not is_valid_email(email):
        log_email_activity(email, "Invalid", "Alerted", "Invalid email format")
        send_telegram_alert(f"🚨 ALERT: {email} is an INVALID email format!")
        return "❌ Invalid email format. Please enter a valid email (e.g., example@gmail.com)."

    url = "https://leakcheck.io/api/public"
    params = {"key": LEAKCHECK_API_KEY, "check": email}

    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        data = response.json()

        if data.get("status") == "found":
            log_email_activity(email, "Malicious", "Alerted", "Found in data leaks")
            send_telegram_alert(f"⚠️ ALERT: {email} found in {len(data['sources'])} data leaks! Take action!")
            return f"⚠️ ALERT: {email} found in {len(data['sources'])} data leaks! Take action!"
        else:
            log_email_activity(email, "Safe", "Monitored", "No breaches found")
            return f"✅ {email} is SAFE (No breaches found)."

    except requests.exceptions.RequestException as e:
        log_email_activity(email, "Error", "Alerted", f"API Error: {e}")
        return f"❌ API Error: {e}"

# ✅ Function to Detect Phishing Websites
def detect_phishing(url):
    common_tricks = ["bank-login", "secure-update", "verify-account", "reset-password", "free-gift"]
    return any(trick in url for trick in common_tricks)

# ✅ Function to Check Website Safety
def check_website_safety(url):
    if url.startswith("http://"):  
        log_website_activity(url, "Malicious", "Alerted", "Insecure HTTP website detected")
        send_telegram_alert(f"🚨 ALERT: {url} is using **HTTP**. It is not secure!")
        return "🚨 ALERT: This website is using **HTTP**. It is not secure!"

    if detect_phishing(url):
        log_website_activity(url, "Malicious", "Alerted", "Possible phishing attempt detected")
        send_telegram_alert(f"🚨 ALERT: {url} looks like a phishing website! Be cautious!")
        return "🚨 ALERT: This looks like a phishing website! Be cautious!"

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
            log_website_activity(url, "Malicious", "Alerted", "Google flagged as unsafe")
            send_telegram_alert(f"🚨 ALERT: {url} is flagged as **MALICIOUS**!")
            return f"🚨 ALERT: {url} is flagged as **MALICIOUS**!"
        else:
            log_website_activity(url, "Safe", "Monitored", "No threats detected")
            return f"✅ {url} is SAFE (No threats detected)."

    except requests.exceptions.RequestException as e:
        log_website_activity(url, "Error", "Alerted", f"API Error: {e}")
        return f"❌ API Error: {e}"
