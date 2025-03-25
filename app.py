import streamlit as st
import requests
import re
import json
import pandas as pd
import os
from datetime import datetime
from log_manager import log_email_activity, log_website_activity, log_phone_activity, send_telegram_alert, get_logs
from config import (
    LEAKCHECK_API_KEY,
    GOOGLE_SAFE_BROWSING_API_KEY,
    TELEGRAM_BOT_TOKEN,
    TELEGRAM_CHAT_ID
)

# ✅ Admin Credentials (Set your username & password)
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

# ✅ Function to Validate Email Format
def is_valid_email(email):
    email = email.strip().lower()
    regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.(com|org|net|edu|gov|mil|co|in|us)$'
    return re.match(regex, email)

# ✅ Login System
st.sidebar.title("🔑 Admin Login")
username = st.sidebar.text_input("Username", key="username")
password = st.sidebar.text_input("Password", type="password", key="password")

# ✅ Check if Admin is Logged In
if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
    st.sidebar.success("✅ Login Successful! Logs Loading...")

    # ✅ Auto-Show Logs Immediately (No Need to Press Any Button)
    st.title("📊 **Admin Log Panel** - Live User Activity")
    logs = get_logs()
    if logs:
        st.dataframe(pd.DataFrame(logs))  # Show logs in a table
    else:
        st.write("🔍 No logs found.")
else:
    st.sidebar.error("❌ Incorrect Username or Password")

