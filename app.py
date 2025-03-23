import streamlit as st
import requests
import re
import json
import pandas as pd
from datetime import datetime
from log_manager import log_login_attempt, log_email_activity, log_website_activity, get_logs
from config import (
    LEAKCHECK_API_KEY,
    GOOGLE_SAFE_BROWSING_API_KEY,
    TELEGRAM_BOT_TOKEN,
    TELEGRAM_CHAT_ID,  
)

# ✅ Function to Send Telegram Alert to User
def send_telegram_alert(message):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {"chat_id": TELEGRAM_CHAT_ID, "text": message}
    try:
        requests.post(url, data=data)
    except Exception as e:
        st.error(f"⚠️ Telegram alert failed: {e}")

# ✅ Function to Validate Email Format
def is_valid_email(email):
    regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(regex, email)

# ✅ Function to Simulate Login (For Logging Purpose)
def login():
    st.sidebar.subheader("🔐 User Login")
    username = st.sidebar.text_input("Username")
    password = st.sidebar.text_input("Password", type="password")
    if st.sidebar.button("Login"):
        if username == "admin" and password == "admin123":  
            log_login_attempt(username, "Success", "User logged in successfully")
            st.sidebar.success("✅ Login Successful")
        else:
            log_login_attempt(username, "Failed", "Incorrect Password")
            st.sidebar.error("❌ Login Failed: Incorrect Password")

# ✅ Function to Check Email Breach
def check_email_breach(user, email):
    if not is_valid_email(email):
        log_email_activity(user, email, "Invalid", "Warning", "Invalid email format")
        send_telegram_alert(f"⚠️ WARNING: The email '{email}' is **INVALID**. Do not trust this source!")
        return "⚠️ Invalid email format."

    url = "https://leakcheck.io/api/public"
    params = {"key": LEAKCHECK_API_KEY, "check": email}

    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        data = response.json()

        if data.get("status") == "found":
            log_email_activity(user, email, "Breached", "Warning", "Found in data leaks")
            send_telegram_alert(f"🚨 ALERT: The email '{email}' has been found in a data breach! Avoid using it.")
            return f"⚠️ **WARNING:** {email} found in {len(data['sources'])} data leaks!"
        else:
            log_email_activity(user, email, "Safe", "Info", "No breaches found")
            return f"✅ {email} is **SAFE** (No breaches found)."

    except requests.exceptions.RequestException as e:
        log_email_activity(user, email, "Error", "Warning", f"API Error: {e}")
        return f"⚠️ API Error: {e}"

# ✅ Function to Check Website Safety
def check_website_safety(user, url):
    if url.startswith("http://"):  
        log_website_activity(user, url, "Unsafe", "Warning", "HTTP website detected")
        send_telegram_alert(f"⚠️ WARNING: You tried to visit an unsafe website '{url}'. Please avoid it!")
        return "⚠️ **Unsafe HTTP Website Detected! Be careful!**"

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
            log_website_activity(user, url, "Unsafe", "Warning", "Google flagged as unsafe")
            send_telegram_alert(f"🚨 ALERT: The website '{url}' is **MALICIOUS**. Do NOT visit!")
            return f"⚠️ **WARNING:** {url} is flagged as **UNSAFE** by Google!"
        else:
            log_website_activity(user, url, "Safe", "Info", "No threats detected")
            return f"✅ {url} is **SAFE** (No threats detected)."

    except requests.exceptions.RequestException as e:
        log_website_activity(user, url, "Error", "Warning", f"API Error: {e}")
        return f"⚠️ API Error: {e}"

# ✅ Streamlit UI
st.set_page_config(page_title="Email & Website Security Checker", layout="wide")

st.title("🕵️‍♂️ Digital Footprint Analyzer")
st.markdown("**Monitor user activity, detect unsafe emails & links, and log everything!**")

login()  # Call login function

option = st.radio("🔍 What do you want to check?", ("Email Breach", "Website Safety", "Live Logs"))

if option == "Email Breach":
    email = st.text_input("📧 Enter email:")
    if st.button("🔍 Check Email Breach"):
        if email:
            result = check_email_breach("Admin", email.strip())  
            st.write(result)

elif option == "Website Safety":
    website = st.text_input("🌐 Enter website URL (e.g., https://example.com):")
    if st.button("🔍 Check Website Safety"):
        if website:
            result = check_website_safety("Admin", website.strip())  
            st.write(result)

elif option == "Live Logs":
    logs = get_logs()
    st.dataframe(pd.DataFrame(logs))  
