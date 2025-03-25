import streamlit as st
import requests
import re
import json
import pandas as pd
import os
from datetime import datetime
from log_manager import log_email_activity, log_website_activity, log_phone_activity, get_logs, send_telegram_alert
from config import (
    LEAKCHECK_API_KEY,
    GOOGLE_SAFE_BROWSING_API_KEY,
    TELEGRAM_BOT_TOKEN,
    TELEGRAM_CHAT_ID
)

# ✅ Admin Credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "password123"

# ✅ Blocked Temporary Email Domains
TEMP_EMAIL_DOMAINS = {"tempmail.com", "yopmail.com", "guerrillamail.com", "disposablemail.com"}

# ✅ Function to Validate Email Format
def is_valid_email(email):
    email = email.strip().lower()
    regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.(com|org|net|edu|gov|mil|co|in|us)$'
    return re.match(regex, email)

# ✅ Function to Validate Phone Number
def is_valid_phone(phone):
    return phone.isdigit() and len(phone) == 10  # Only 10-digit numbers are valid

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
        force_user_acknowledge("🚨 ALERT: This is a temporary/disposable email!", "temp_email_alert")
        return "🚨 ALERT: This email is from a **temporary/disposable** provider!"

    if not is_valid_email(email):
        log_email_activity(email, "Invalid", "Alerted", "Invalid email format")
        send_telegram_alert(f"🚨 ALERT: {email} is an INVALID email format!")
        force_user_acknowledge("⚠️ Invalid email format detected!", "invalid_email")
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
            force_user_acknowledge("🚨 Malicious email detected!", "email_breach")
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

    return "✅ SAFE: No threats detected."

# ✅ Function to Check Phone Number
def check_phone_number(phone):
    if not is_valid_phone(phone):
        log_phone_activity(phone, "Invalid", "Alerted", "Invalid phone number format")
        send_telegram_alert(f"🚨 ALERT: {phone} is an INVALID phone number!")
        force_user_acknowledge("🚨 ALERT: Invalid phone number detected!", "invalid_phone")
        return "❌ Invalid phone number. Must be exactly 10 digits."

    return "✅ SAFE: Phone number is valid."

# ✅ Streamlit UI
st.set_page_config(page_title="Security Checker", layout="wide")

st.title("🕵️‍♂️ Digital Footprint Analyzer")
st.markdown("**Monitor user activity, detect unsafe emails & links, and log everything!**")

# ✅ Admin Login (Auto-Opens Logs & Can Check Everything)
st.sidebar.title("🔑 Admin Login")
username = st.sidebar.text_input("Username", key="username")
password = st.sidebar.text_input("Password", type="password", key="password")

if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
    st.sidebar.success("✅ Login Successful! Logs & Tools Activated.")

    # ✅ Auto-Show Logs
    st.title("📊 **Admin Log Panel** - Live User Activity")
    logs = get_logs()
    if logs:
        st.dataframe(pd.DataFrame(logs))  # Show logs in a table
    else:
        st.write("🔍 No logs found.")

    # ✅ Admin can use all tools
    st.subheader("🔍 **Check Email, Website, and Phone Safety**")
    tab1, tab2, tab3 = st.tabs(["📧 Email Breach", "🌐 Website Safety", "📞 Phone Number"])

    with tab1:
        email = st.text_input("📧 Enter email (Admin Panel):")
        if st.button("🔍 Check Email Breach (Admin)", key="email_admin"):
            st.write(check_email_breach(email.strip()))

    with tab2:
        website = st.text_input("🌐 Enter website URL (Admin Panel):")
        if st.button("🔍 Check Website Safety (Admin)", key="website_admin"):
            st.write(check_website_safety(website.strip()))

    with tab3:
        phone = st.text_input("📞 Enter phone number (Admin Panel):")
        if st.button("🔍 Check Phone Number (Admin)", key="phone_admin"):
            st.write(check_phone_number(phone.strip()))

# ✅ Normal User Options (Email, Website, Phone Checks)
else:
    option = st.radio("🔍 What do you want to check?", ("Email Breach", "Website Safety", "Phone Number"))

    if option == "Email Breach":
        email = st.text_input("📧 Enter email:")
        if st.button("🔍 Check Email Breach"):
            st.write(check_email_breach(email.strip()))

    elif option == "Website Safety":
        website = st.text_input("🌐 Enter website URL:")
        if st.button("🔍 Check Website Safety"):
            st.write(check_website_safety(website.strip()))

    elif option == "Phone Number":
        phone = st.text_input("📞 Enter phone number:")
        if st.button("🔍 Check Phone Number"):
            st.write(check_phone_number(phone.strip()))
