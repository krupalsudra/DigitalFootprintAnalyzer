import streamlit as st
import requests
import re
import json
import pandas as pd
import pyperclip  # To auto-detect copied text (email/link)
import time
from datetime import datetime
from log_manager import log_email_activity, log_website_activity, get_logs, send_telegram_alert
from config import (
    LEAKCHECK_API_KEY,
    GOOGLE_SAFE_BROWSING_API_KEY,
    TELEGRAM_BOT_TOKEN,  
    TELEGRAM_CHAT_ID      
)

# ✅ List of Temporary Email Domains
TEMP_EMAIL_DOMAINS = {
    "tempmail.com", "mailinator.com", "yopmail.com", "guerrillamail.com", 
    "trashmail.com", "10minutemail.com", "dispostable.com", "getnada.com"
}

# ✅ Function to Validate Email Format
def is_valid_email(email):
    email = email.strip().lower()  
    regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.(com|org|net|edu|gov|mil|co|in|us)$'
    return re.match(regex, email)

# ✅ Function to Show Blocking Alert That Stops User Input
def show_blocking_alert(message):
    st.warning(message)  # Display alert message in Streamlit
    st.session_state["alert_active"] = True  # Set flag to block input

# ✅ Function to Check Email Breach & Temporary Emails
def check_email_breach(email):
    email = email.strip().lower()
    domain = email.split("@")[-1]

    if domain in TEMP_EMAIL_DOMAINS:
        log_email_activity(email, "Malicious", "Alerted", "Temporary Email Detected")
        send_telegram_alert(f"🚨 ALERT: {email} is a **TEMPORARY EMAIL**! It is unsafe.")
        show_blocking_alert("🚨 Temporary Email Detected! You cannot continue until you acknowledge this alert.")
        return f"🚨 ALERT: {email} is a **TEMPORARY EMAIL**! It is unsafe."

    if not is_valid_email(email):
        log_email_activity(email, "Invalid", "Alerted", "Invalid email format")
        send_telegram_alert(f"🚨 ALERT: {email} is an **INVALID email format**!")
        show_blocking_alert("❌ Invalid Email Format! Please enter a valid email.")
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
            show_blocking_alert("⚠️ Email Found in Data Breaches! Take Action before continuing.")
            return f"⚠️ ALERT: {email} found in {len(data['sources'])} data leaks! Take action!"
        else:
            log_email_activity(email, "Safe", "Monitored", "No breaches found")
            return f"✅ {email} is SAFE (No breaches found)."

    except requests.exceptions.RequestException as e:
        log_email_activity(email, "Error", "Alerted", f"API Error: {e}")
        show_blocking_alert("❌ API Error: Could not check email safety.")
        return f"❌ API Error: {e}"

# ✅ Function to Detect Phishing Websites
def detect_phishing(url):
    """Checks if a URL contains common phishing patterns."""
    common_tricks = ["bank-login", "secure-update", "verify-account", "reset-password", "free-gift"]
    return any(trick in url for trick in common_tricks)

# ✅ Function to Check Website Safety
def check_website_safety(url):
    if url.startswith("http://"):  
        log_website_activity(url, "Malicious", "Alerted", "Insecure HTTP website detected")
        send_telegram_alert(f"🚨 ALERT: {url} is using **HTTP**. It is not secure!")
        show_blocking_alert("🚨 ALERT: This website is using HTTP. It is not secure!")
        return "🚨 ALERT: This website is using **HTTP**. It is not secure!"

    if detect_phishing(url):
        log_website_activity(url, "Malicious", "Alerted", "Possible phishing attempt detected")
        send_telegram_alert(f"🚨 ALERT: {url} looks like a phishing website! Be cautious!")
        show_blocking_alert("🚨 ALERT: This looks like a phishing website! Be cautious!")
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
            show_blocking_alert(f"🚨 ALERT: {url} is flagged as MALICIOUS! Do not proceed.")
            return f"🚨 ALERT: {url} is flagged as **MALICIOUS**!"
        else:
            log_website_activity(url, "Safe", "Monitored", "No threats detected")
            return f"✅ {url} is SAFE (No threats detected)."

    except requests.exceptions.RequestException as e:
        log_website_activity(url, "Error", "Alerted", f"API Error: {e}")
        show_blocking_alert("❌ API Error: Could not check website safety.")
        return f"❌ API Error: {e}"

# ✅ Auto-Check Copied Text for Emails & Links
def check_clipboard():
    clipboard_data = pyperclip.paste()
    if "@" in clipboard_data:
        return check_email_breach(clipboard_data)
    elif "http" in clipboard_data:
        return check_website_safety(clipboard_data)
    return None

# ✅ Streamlit UI
st.set_page_config(page_title="Email & Website Security Checker", layout="wide")
st.title("🕵️‍♂️ Digital Footprint Analyzer")
st.markdown("**Auto-scans emails & links from notifications, detects threats, and blocks access!**")

# **Auto-Scan Clipboard**
st.write("🔍 **Clipboard Scan Result:**", check_clipboard())

