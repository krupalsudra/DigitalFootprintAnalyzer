import streamlit as st
import requests
import re
import json
import os
from datetime import datetime
from log_manager import log_email_activity, log_website_activity, log_phone_activity, send_telegram_alert
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

# ✅ Function to Validate Phone Number
def is_valid_phone(phone):
    return phone.isdigit() and len(phone) == 10

# ✅ Function to Force User Acknowledgment (Popup Alert)
def force_user_acknowledge(alert_message, button_key):
    if "alert_acknowledged" not in st.session_state:
        st.session_state["alert_acknowledged"] = False

    st.warning(alert_message)  # Warning Message
    if st.button("OK, I Understand", key=button_key):
        st.session_state["alert_acknowledged"] = True
        st.rerun()  # Refresh UI after acknowledgment

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

# ✅ Function to Check Website Safety
def check_website_safety(url):
    if url.startswith("http://"):
        log_website_activity(url, "Malicious", "Alerted", "Insecure HTTP website detected")
        send_telegram_alert(f"🚨 ALERT: {url} is using **HTTP**. It is not secure!")
        force_user_acknowledge("🚨 ALERT: This website is using **HTTP**. It is not secure!", "http_alert")
        return "🚨 ALERT: This website is using **HTTP**. It is not secure!"

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
            force_user_acknowledge("🚨 ALERT: This website is flagged as **MALICIOUS**! Avoid it.", "malicious_site")
            return f"🚨 ALERT: {url} is flagged as **MALICIOUS**!"
        else:
            log_website_activity(url, "Safe", "Monitored", "No threats detected")
            return f"✅ {url} is SAFE (No threats detected)."

    except requests.exceptions.RequestException as e:
        log_website_activity(url, "Error", "Alerted", f"API Error: {e}")
        return f"❌ API Error: {e}"

# ✅ Function to Check Phone Number
def check_phone_number(phone):
    if not is_valid_phone(phone):
        log_phone_activity(phone, "Invalid", "Alerted", "Invalid phone number detected")
        send_telegram_alert(f"🚨 ALERT: {phone} is an INVALID phone number!")
        force_user_acknowledge("⚠️ Invalid phone number detected! You must acknowledge before continuing.", "invalid_phone")
        return "❌ Invalid phone number! Must be exactly 10 digits."

    log_phone_activity(phone, "Safe", "Monitored", "Valid phone number")
    return f"✅ {phone} is a SAFE phone number."

# ✅ Streamlit UI
st.set_page_config(page_title="Digital Security Analyzer", layout="wide")

st.title("🕵️‍♂️ Digital Security Analyzer")
st.markdown("**Monitor & Block Fake Emails, Phishing Links, and Fake Calls in Real Time!**")

option = st.radio("🔍 What do you want to check?", ("Email Breach", "Website Safety", "Phone Number"))

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

elif option == "Phone Number":
    phone = st.text_input("📞 Enter phone number:")
    if st.button("🔍 Check Phone Number"):
        if phone:
            result = check_phone_number(phone.strip())
            st.write(result)
