import logging
import json
import os
import requests
from datetime import datetime
from config import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID

# 📂 Ensure logs directory exists
LOG_DIR = "logs"
LOG_FILE_JSON = os.path.join(LOG_DIR, "activity.json")
os.makedirs(LOG_DIR, exist_ok=True)

# ✅ Setup Logging
logging.basicConfig(filename=os.path.join(LOG_DIR, "activity.log"), level=logging.INFO, format="%(asctime)s - %(message)s")

# ✅ Function to Send Telegram Alerts
def send_telegram_alert(message):
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        data = {"chat_id": TELEGRAM_CHAT_ID, "text": message}
        response = requests.post(url, data=data)
        response.raise_for_status()
    except Exception as e:
        logging.error(f"Failed to send Telegram alert: {e}")

# ✅ Function to Log Activity in JSON
def log_activity(event_type, entity, status, action, details=""):
    log_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "event_type": event_type,
        "entity": entity,
        "status": status,
        "action": action,
        "details": details
    }
    with open(LOG_FILE_JSON, "a") as log_file:
        json.dump(log_entry, log_file)
        log_file.write("\n")
    logging.info(log_entry)

# ✅ Function to Get Logs
def get_logs():
    logs = []
    if os.path.exists(LOG_FILE_JSON) and os.path.getsize(LOG_FILE_JSON) > 0:
        try:
            with open(LOG_FILE_JSON, "r") as log_file:
                for line in log_file:
                    logs.append(json.loads(line.strip()))
        except json.JSONDecodeError:
            logging.error("Error reading JSON log file")
    return logs

# ✅ Function to Log Email Activity
def log_email_activity(email, status, action, details=""):
    log_activity("Email Scan", email, status, action, details)

# ✅ Function to Log Website Activity
def log_website_activity(website, status, action, details=""):
    log_activity("Website Scan", website, status, action, details)

# ✅ Function to Log Phone Activity
def log_phone_activity(phone, status, action, details=""):
    log_activity("Phone Scan", phone, status, action, details)
