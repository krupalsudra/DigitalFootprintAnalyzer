import streamlit as st
import requests
import re
from config import (
    LEAKCHECK_API_KEY,
    MAILBOXLAYER_API_KEY,
    GOOGLE_SAFE_BROWSING_API_KEY,
    TELEGRAM_BOT_TOKEN,
    TELEGRAM_CHAT_ID,
)

# List of Known Temporary Email Domains
TEMP_EMAIL_DOMAINS = {
    "10minutemail.com", "tempmail.com", "temp-mail.org", "yopmail.com",
    "guerrillamail.com", "mailinator.com", "disposablemail.com", "maildrop.cc",
    "fakeinbox.com", "sharklasers.com", "mailsac.com", "burnermail.io"
}

# Function to Validate Email Format
def is_valid_email(email):
    regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(regex, email)

# Function to Send Telegram Alert
def send_telegram_alert(message):
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        data = {"chat_id": TELEGRAM_CHAT_ID, "text": message}
        response = requests.post(url, data=data)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        st.error(f"Telegram alert failed: {e}")

# Function to Check Email Breach
def check_email_breach(email):
    if not is_valid_email(email):
        return "❌ Invalid email format."

    url = "https://leakcheck.io/api/public"
    params = {"key": LEAKCHECK_API_KEY, "check": email}

    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        data = response.json()

        if data.get("status") == "found":
            send_telegram_alert(f"🚨 Breached Email Detected: {email}. BLOCKED IMMEDIATELY! 🚨")
            return f"⚠️ {email} found in {len(data['sources'])} data leaks! 🚨 BLOCKED!"
        return f"✅ {email} is **SAFE** (No breaches found)."

    except requests.exceptions.RequestException as e:
        return f"❌ API Error: {e}"

# Function to Check Email Reputation
def check_email_reputation(email):
    if not is_valid_email(email):
        return "❌ Invalid email format."

    domain = email.split("@")[-1].lower()

    # Check Custom List of Temporary Email Domains
    if domain in TEMP_EMAIL_DOMAINS:
        send_telegram_alert(f"🚨 TEMPORARY Email Detected: {email}. BLOCKED IMMEDIATELY!")
        return f"🚨 **Temporary Email Detected! BLOCKED!**\n❌ **{email} is from a known temporary email provider.**"

    # API Check (Backup Verification)
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
            send_telegram_alert(f"🚨 TEMPORARY/Fake Email Detected: {email}. BLOCKED IMMEDIATELY!")
            return f"🚨 **Fake or Temporary Email Detected! BLOCKED!**\n❌ **{email} is Disposable.**"

        return f"""
        ✅ **Email Format Valid:** {email_status}  
        📌 **MX Records Found:** {mx_found}  
        📬 **SMTP Check Passed:** {smtp_check}  
        ✅ **Email is NOT Fake or Temporary**  
        """

    except requests.exceptions.RequestException as e:
        return f"❌ API Error: {e}"

# Function to Check Website Safety
def check_website_safety(url):
    google_safe_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"

    request_payload = {
        "client": {"clientId": "streamlit-app", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
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
            send_telegram_alert(f"🚨 Malicious Website Detected: {url}. BLOCKED IMMEDIATELY! 🚨")
            return f"🚨 **WARNING: {url} is flagged as UNSAFE!** 🚨"

        return f"✅ {url} is **SAFE** (No threats detected)."

    except requests.exceptions.RequestException as e:
        return f"❌ API Error: {e}"

# Streamlit UI
st.set_page_config(page_title="Email & Website Security Checker", layout="wide")

st.title("🕵️‍♂️ Email & Website Security Checker")
st.markdown("**Protect yourself from fake emails, breached accounts, and unsafe websites!**")

option = st.radio("🔍 What do you want to check?", ("Email Breach", "Email Reputation", "Website Safety"))

# Email Breach Check
if option == "Email Breach":
    emails = st.text_area("📧 Enter emails (one per line):").split("\n")
    if st.button("🔍 Check Email Breach"):
        for email in emails:
            email = email.strip()
            if email:
                result = check_email_breach(email)
                st.write(f"**{email}**: {result}")

# Email Reputation Check
elif option == "Email Reputation":
    email = st.text_input("📧 Enter email:")
    if st.button("🔍 Check Email Reputation"):
        if email:
            result = check_email_reputation(email.strip())
            st.write(result)

# Website Safety Check
elif option == "Website Safety":
    website = st.text_input("🌐 Enter website URL (e.g., https://example.com):")
    if st.button("🔍 Check Website Safety"):
        if website:
            result = check_website_safety(website.strip())
            st.write(result)

# Helpful Links
st.markdown("🔗 **Manually check your email reputation here:** [MailboxLayer](https://mailboxlayer.com/)")
st.markdown("🔗 **Manually check website safety here:** [Google Safe Browsing](https://transparencyreport.google.com/safe-browsing/search)")
