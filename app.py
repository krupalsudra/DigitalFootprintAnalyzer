import streamlit as st
import requests
import re
import json
import pandas as pd
import os
from datetime import datetime
from log_manager import log_email_activity, log_website_activity, get_logs, send_telegram_alert
from config import (
    LEAKCHECK_API_KEY,
    GOOGLE_SAFE_BROWSING_API_KEY,
    TELEGRAM_BOT_TOKEN,  
    TELEGRAM_CHAT_ID    
)

# ✅ Blocked Emails & Websites (Manually Defined)
BLOCKED_EMAILS = ["testmail.com", "tempmail.com", "yopmail.com", "guerrillamail.com"]
BLOCKED_WEBSITES = ["phishing-site.com", "malicious-site.com", "fake-login.com"]

# ✅ Function to Validate Email Format
def is_valid_email(email):
    email = email.strip().lower()
    regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.(com|org|net|edu|gov|mil|co|in|us)$'
    return re.match(regex, email)

# ✅ Function to Show Forced Alert Before Continuing
def force_user_acknowledge(alert_message):
    st.warning(alert_message)  # Warning Message
    st.session_state["alert_acknowledged"] = False
    while not st.session_state.get("alert_acknowledged", False):
        if st.button("OK, I Understand"):
            st.session_state["alert_acknowledged"] = True
            st.rerun()  # Refresh the UI to allow further inputs

# ✅ Function to Check Email Breach
def check_email_breach(email):
    email = email.strip().lower()
    domain = email.split("@")[-1]

    if domain in BLOCKED_EMAILS:
        log_email_activity(email, "Manually Blocked", "Alerted", "Blocked by system rules")
        send_telegram_alert(f"🚨 ALERT: {email} is blocked manually! Do NOT use this email.")
        force_user_acknowledge("⚠️ This email domain is manually blocked! You must acknowledge before continuing.")
        return "🚨 ALERT: This email is blocked manually!"

    if not is_valid_email(email):
        log_email_activity(email, "Invalid", "Alerted", "Invalid email format")
        send_telegram_alert(f"🚨 ALERT: {email} is an INVALID email format!")
        force_user_acknowledge("⚠️ Invalid email format detected! You must acknowledge before continuing.")
        return "❌ Invalid email format. Please enter a valid email."

    url = "https://leakcheck.io/api/public"
    params = {"key": LEAKCHECK_API_KEY, "check": email}

    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        data = response.json()

        if data.get("status") == "found":
            log_email_activity(email, "Malicious", "Alerted", "Found in data leaks")
            send_telegram_alert(f"⚠️ ALERT: {email} found in {len(data['sources'])} data leaks! Take action!")
            force_user_acknowledge("🚨 Malicious email detected! You must acknowledge before continuing.")
            return f"⚠️ ALERT: {email} found in {len(data['sources'])} data leaks!"
        else:
            log_email_activity(email, "Safe", "Monitored", "No breaches found")
            return f"✅ {email} is SAFE (No breaches found)."

    except requests.exceptions.RequestException as e:
        log_email_activity(email, "Error", "Alerted", f"API Error: {e}")
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
        force_user_acknowledge("🚨 ALERT: This website is insecure (HTTP detected)! You must acknowledge this before continuing.")
        return "🚨 ALERT: This website is using **HTTP**. It is not secure!"

    if url in BLOCKED_WEBSITES:
        log_website_activity(url, "Manually Blocked", "Alerted", "Blocked by system rules")
        send_telegram_alert(f"🚨 ALERT: {url} is manually blocked! Avoid using this website.")
        force_user_acknowledge("⚠️ This website is manually blocked! You must acknowledge before continuing.")
        return "🚨 ALERT: This website is blocked manually!"

    if detect_phishing(url):
        log_website_activity(url, "Malicious", "Alerted", "Possible phishing attempt detected")
        send_telegram_alert(f"🚨 ALERT: {url} looks like a phishing website! Be cautious!")
        force_user_acknowledge("⚠️ Possible phishing detected! You must acknowledge before continuing.")
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
            force_user_acknowledge("🚨 Google flagged this website as malicious! You must acknowledge this before continuing.")
            return f"🚨 ALERT: {url} is flagged as **MALICIOUS**!"
        else:
            log_website_activity(url, "Safe", "Monitored", "No threats detected")
            return f"✅ {url} is SAFE (No threats detected)."

    except requests.exceptions.RequestException as e:
        log_website_activity(url, "Error", "Alerted", f"API Error: {e}")
        return f"❌ API Error: {e}"

# ✅ Streamlit UI
st.set_page_config(page_title="Email & Website Security Checker", layout="wide")

st.title("🕵️‍♂️ Digital Footprint Analyzer")
st.markdown("**Monitor user activity, detect unsafe emails & links, and log everything!**")

option = st.radio("🔍 What do you want to check?", ("Email Breach", "Website Safety", "Live Logs"))

if option == "Email Breach":
    email = st.text_input("📧 Enter email:")
    if st.button("🔍 Check Email Breach"):
        if email:
            result = check_email_breach(email.strip())
            st.write(result)

elif option == "Website Safety":
    website = st.text_input("🌐 Enter website URL (e.g., https://example.com):")
    if st.button("🔍 Check Website Safety"):
        if website:
            result = check_website_safety(website.strip())
            st.write(result)

elif option == "Live Logs":
    logs = get_logs()
    st.dataframe(pd.DataFrame(logs))  
