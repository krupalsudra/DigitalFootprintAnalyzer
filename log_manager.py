import logging
import json
import csv
import os
import requests
from datetime import datetime
from config import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID  # Import API Keys

# 📂 Ensure logs directory exists
LOG_DIR = "logs"
LOG_FILE_TEXT = os.path.join(LOG_DIR, "activity.log")
LOG_FILE_JSON = os.path.join(LOG_DIR, "activity.json")
LOG_FILE_CSV = os.path.join(LOG_DIR, "activity.csv")

os.makedirs(LOG_DIR, exist_ok=True)  # Create logs folder if it doesn't exist

# ✅ Setup Logging (for .log file)
logging.basicConfig(filename=LOG_FILE_TEXT, level=logging.INFO, format="%(asctime)s - %(message)s")

# ✅ Function to Send Telegram Alerts
def send_telegram_alert(message):
    """Send real-time alerts to admin when a risky activity is detected."""
    if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
            data = {"chat_id": TELEGRAM_CHAT_ID, "text": message}
            requests.post(url, data=data)
        except Exception as e:
            logging.error(f"Failed to send Telegram alert: {e}")

# ✅ Function to Log Activity in JSON
def log_activity_json(event_type, user, entity, status, action, details=""):
    log_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "event_type": event_type,
        "user": user,
        "entity": entity,
        "status": status,
        "action": action,
        "details": details
    }
    with open(LOG_FILE_JSON, "a") as log_file:
        json.dump(log_entry, log_file)
        log_file.write("\n")  # New line for each entry
    logging.info(json.dumps(log_entry))  # Log entry in text file

# ✅ Function to Log Activity in CSV
def log_activity_csv(event_type, user, entity, status, action, details=""):
    log_entry = [
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        event_type,
        user,
        entity,
        status,
        action,
        details
    ]
    with open(LOG_FILE_CSV, "a", newline="") as log_file:
        writer = csv.writer(log_file)
        writer.writerow(log_entry)
    logging.info(", ".join(log_entry))  # Log entry in text file

# ✅ Function to Log Email Activity
def log_email_activity(user, email, status, action, details=""):
    log_activity_json("Email Scan", user, email, status, action, details)
    log_activity_csv("Email Scan", user, email, status, action, details)

    # 🚨 Send Telegram Alert for Malicious Email
    if status == "Breached":
        send_telegram_alert(f"⚠️ ALERT: {user} received a **breached email**: {email}. 🚨 BLOCKED!")

# ✅ Function to Log Website Activity
def log_website_activity(user, website, status, action, details=""):
    log_activity_json("Website Scan", user, website, status, action, details)
    log_activity_csv("Website Scan", user, website, status, action, details)

    # 🚨 Send Telegram Alert for Unsafe Website
    if status == "Unsafe":
        send_telegram_alert(f"⚠️ ALERT: {user} tried to visit **unsafe website**: {website}. 🚨 BLOCKED!")

# ✅ Function to Log Login Attempts
def log_login_attempt(user, status, details=""):
    log_activity_json("Login Attempt", user, "-", status, "Login", details)
    log_activity_csv("Login Attempt", user, "-", status, "Login", details)

    # 🚨 Send Alert for Failed Login
    if status == "Failed":
        send_telegram_alert(f"⚠️ ALERT: **Failed Login Attempt** for user: {user}.")

# ✅ Function to Get Logs for Live Monitoring in Streamlit
def get_logs():
    logs = []
    if os.path.exists(LOG_FILE_JSON):
        with open(LOG_FILE_JSON, "r") as log_file:
            for line in log_file:
                logs.append(json.loads(line.strip()))
    return logs
