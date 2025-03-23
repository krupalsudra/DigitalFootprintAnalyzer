import streamlit as st
import requests
import re
import json
import pandas as pd
from datetime import datetime
from log_manager import log_email_activity, log_website_activity, get_logs
from config import (
    LEAKCHECK_API_KEY,
    GOOGLE_SAFE_BROWSING_API_KEY,
)

# ✅ Function to Validate Email Format
def is_valid_email(email):
    email = email.strip().lower()  # Convert to lowercase
    regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.(com|org|net|edu|gov|mil|co|in|us)$'
    return re.match(regex, email)

# ✅ Function to Check Email Breach
def check_email_breach(email):
    email = email.strip().lower()  # Convert to lowercase

    if not is_valid_email(email):
        log_email_activity(email, "Invalid", "Blocked", "Invalid email format")
        return "❌ Invalid email format. Please enter a valid email (e.g., example@gmail.com)."

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
    if url.startswith("http://"):  
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
    st.dataframe(pd.DataFrame(logs))  # Show logs in a table
