import logging
import json
import os
import csv
import requests
from datetime import datetime
from config import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID

# 📂 Ensure logs directory exists
LOG_DIR = "logs"
LOG_FILE_JSON = os.path.join(LOG_DIR, "activity.json")
LOG_FILE_CSV = os.path.join(LOG_DIR, "activity.csv")

os.makedirs(LOG_DIR, exist_ok=True)  # Create logs folder if it doesn't exist

# ✅ Setup Logging
logging.basicConfig(filename=os.path.join(LOG_DIR, "activity.log"), level=logging.INFO, format="%(asctime)s - %(message)s")

# ✅ Function to Send Mobile Alerts (Telegram)
def send_telegram_alert(message):
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        data = {"chat_id": TELEGRAM_CHAT_ID, "text": message}
        requests.post(url, data=data)
        log_activity_json("Alert Sent", "Telegram", "Success", "Alert Sent", message)
    except Exception as e:
        logging.error(f"Failed to send Telegram alert: {e}")

# ✅ Function to Log Activity in JSON
def log_activity_json(event_type, entity, status, action, details=""):
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

# ✅ Function to Log Activity in CSV
def log_activity_csv(event_type, entity, status, action, details=""):
    log_entry = [datetime.now().strftime("%Y-%m-%d %H:%M:%S"), event_type, entity, status, action, details]
    with open(LOG_FILE_CSV, "a", newline="") as log_file:
        writer = csv.writer(log_file)
        writer.writerow(log_entry)
    logging.info(log_entry)

# ✅ Function to Get Logs
def get_logs():
    logs = []
    try:
        with open(LOG_FILE_JSON, "r") as log_file:
            for line in log_file:
                logs.append(json.loads(line.strip()))
    except (FileNotFoundError, json.JSONDecodeError):
        logging.warning("No logs found.")
    return logs

# ✅ Function to Log Email & Website Activity
def log_email_activity(email, status, action, details=""):
    log_activity_json("Email Scan", email, status, action, details)
    log_activity_csv("Email Scan", email, status, action, details)

def log_website_activity(website, status, action, details=""):
    log_activity_json("Website Scan", website, status, action, details)
    log_activity_csv("Website Scan", website, status, action, details)
