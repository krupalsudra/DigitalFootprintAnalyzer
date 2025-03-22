import streamlit as st
import requests
import re
import os
from log_manager import log_email_activity, log_website_activity  # Logging functions
from config import (
    LEAKCHECK_API_KEY,
    MAILBOXLAYER_API_KEY,
    GOOGLE_SAFE_BROWSING_API_KEY,
    TELEGRAM_BOT_TOKEN,
    TELEGRAM_CHAT_ID,
)

# ✅ Function to Validate Email Format
def is_valid_email(email):
    regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(regex, email)

# ✅ Function to Check Email Breach
def check_email_breach(email):
    if not is_valid_email(email):
        log_email_activity(email, "Invalid", "Blocked", "Invalid email format")
        return "❌ Invalid email format."

    if not LEAKCHECK_API_KEY:
        return "❌ API Error: LEAKCHECK_API_KEY is missing."

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

# ✅ Function to Check Email Reputation (Fake & Temporary Email Detection)
def check_email_reputation(email):
    if not is_valid_email(email):
        log_email_activity(email, "Invalid", "Blocked", "Invalid email format")
        return "❌ Invalid email format."

    if not MAILBOXLAYER_API_KEY:
        return "❌ API Error: MAILBOXLAYER_API_KEY is missing."

    url = f"http://apilayer.net/api/check?access_key={MAILBOXLAYER_API_KEY}&email={email}&smtp=1&format=1"

    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        email_status = data.get("format_valid", False)
        mx_found = data.get("mx_found", False)
        smtp_check = data.get("smtp_check", False)
        disposable = data.get("disposable", False)

        if disposable:
            log_email_activity(email, "Temporary Email", "Blocked", "Disposable email detected")
            return f"🚨 **Fake or Temporary Email Detected! BLOCKED!**\n❌ **{email} is Disposable.**"

        log_email_activity(email, "Valid", "Allowed", "Passed reputation check")
        return f"""
        ✅ **Email Format Valid:** {email_status}  
        📌 **MX Records Found:** {mx_found}  
        📬 **SMTP Check Passed:** {smtp_check}  
        ✅ **Email is NOT Fake or Temporary**  
        """

    except requests.exceptions.RequestException as e:
        log_email_activity(email, "Error", "Blocked", f"API Error: {e}")
        return f"❌ API Error: {e}"

# ✅ Function to Check Website Safety
def check_website_safety(url):
    if url.startswith("http://"):  # 🚨 Block all HTTP sites immediately
        log_website_activity(url, "Blocked", "Blocked", "HTTP website detected")
        return "🚨 **Unsafe HTTP Website Detected! BLOCKED!**"

    if not GOOGLE_SAFE_BROWSING_API_KEY:
        return "❌ API Error: GOOGLE_SAFE_BROWSING_API_KEY is missing."

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

st.title("🕵️‍♂️ Email & Website Security Checker")
st.markdown("**Protect yourself from fake emails, breached accounts, and unsafe websites!**")

option = st.radio("🔍 What do you want to check?", ("Email Breach", "Email Reputation", "Website Safety"))

# 📌 Email Breach Check
if option == "Email Breach":
    email = st.text_input("📧 Enter email:")
    if st.button("🔍 Check Email Breach"):
        if email:
            result = check_email_breach(email.strip())
            st.write(result)

# 📌 Email Reputation Check
elif option == "Email Reputation":
    email = st.text_input("📧 Enter email:")
    if st.button("🔍 Check Email Reputation"):
        if email:
            result = check_email_reputation(email.strip())
            st.write(result)

# 📌 Website Safety Check
elif option == "Website Safety":
    website = st.text_input("🌐 Enter website URL (e.g., https://example.com):")
    if st.button("🔍 Check Website Safety"):
        if website:
            result = check_website_safety(website.strip())
            st.write(result)
