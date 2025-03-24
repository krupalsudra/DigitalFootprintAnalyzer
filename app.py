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

# ✅ Blocked Temporary Email Domains
TEMP_EMAIL_DOMAINS = {"tempmail.com", "yopmail.com", "guerrillamail.com", "mailinator.com", "disposablemail.com"}

# ✅ Function to Validate Email Format
def is_valid_email(email):
    email = email.strip().lower()
    regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.(com|org|net|edu|gov|mil|co|in|us)$'
    return re.match(regex, email)

# ✅ Function to Show Forced Alert Before Continuing
def force_user_acknowledge(alert_message, button_key):
    if "alert_acknowledged" not in st.session_state:
        st.session_state["alert_acknowledged"] = False

    st.warning(alert_message)  # Warning Message
    
    if st.button("OK, I Understand", key=button_key):
        st.session_state["alert_acknowledged"] = True
        st.rerun()  # Refresh UI after acknowledging

# ✅ Function to Check Email Breach
def check_email_breach(email):
    email = email.strip().lower()
    domain = email.split("@")[-1]

    if domain in TEMP_EMAIL_DOMAINS:
        log_email_activity(email, "Temporary Email", "Alerted", "Blocked as disposable email")
        send_telegram_alert(f"🚨 ALERT: {email} is a temporary/disposable email! Avoid using it.")
        force_user_acknowledge("🚨 ALERT: This is a temporary/disposable email! Avoid using it!", "temp_email_alert")
        return "🚨 ALERT: This email is from a **temporary/disposable** provider!"

    if not is_valid_email(email):
        log_email_activity(email, "Invalid", "Alerted", "Invalid email format")
        send_telegram_alert(f"🚨 ALERT: {email} is an INVALID email format!")
        force_user_acknowledge("⚠️ Invalid email format detected! You must acknowledge before continuing.", "invalid_email")
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
            force_user_acknowledge("🚨 Malicious email detected! You must acknowledge before continuing.", "email_breach")
            return f"⚠️ ALERT: {email} found in {len(data['sources'])} data leaks!"
        else:
            log_email_activity(email, "Safe", "Monitored", "No breaches found")
            return f"✅ {email} is SAFE (No breaches found)."

    except requests.exceptions.RequestException as e:
        log_email_activity(email, "Error", "Alerted", f"API Error: {e}")
        return f"❌ API Error: {e}"

# ✅ Streamlit UI
st.set_page_config(page_title="Email & Website Security Checker", layout="wide")

st.title("🕵️‍♂️ Digital Footprint Analyzer")
st.markdown("**Monitor user activity, detect unsafe emails & links, and log everything!**")

option = st.radio("🔍 What do you want to check?", ("Email Breach", "Live Logs"))

if option == "Email Breach":
    email = st.text_input("📧 Enter email:")
    if st.button("🔍 Check Email Breach"):
        if email:
            result = check_email_breach(email.strip())
            st.write(result)

elif option == "Live Logs":
    logs = get_logs()
    st.dataframe(pd.DataFrame(logs))  
