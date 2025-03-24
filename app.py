import streamlit as st
import requests
import re
import json
import pandas as pd
from datetime import datetime
from log_manager import log_email_activity, log_website_activity, get_logs, send_telegram_alert
from config import (
    LEAKCHECK_API_KEY,
    GOOGLE_SAFE_BROWSING_API_KEY,
    TELEGRAM_BOT_TOKEN,  
    TELEGRAM_CHAT_ID      
)

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
        st.toast("⚠️ Invalid Email Format Detected!", icon="🚨")
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
            st.toast("⚠️ Malicious Email Detected!", icon="🚨")
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
        st.toast("⚠️ Insecure HTTP Website Detected!", icon="🚨")
        return "🚨 ALERT: This website is using **HTTP**. It is not secure!"

    if detect_phishing(url):
        log_website_activity(url, "Malicious", "Alerted", "Possible phishing attempt detected")
        send_telegram_alert(f"🚨 ALERT: {url} looks like a phishing website! Be cautious!")
        st.toast("⚠️ Possible Phishing Website Detected!", icon="🚨")
        return "🚨 ALERT: This looks like a phishing website! Be cautious!"

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
    website = st.text_input("🌐 Enter website URL:")
    if st.button("🔍 Check Website Safety"):
        if website:
            result = check_website_safety(website.strip())
            st.write(result)

elif option == "Live Logs":
    logs = get_logs()
    st.dataframe(pd.DataFrame(logs))
