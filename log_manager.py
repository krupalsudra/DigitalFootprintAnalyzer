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

# ✅ Function to Handle Telegram Messages (Auto Replies)
def handle_telegram_messages():
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getUpdates"
    response = requests.get(url)
    data = response.json()

    for update in data.get("result", []):
        if "message" in update:
            chat_id = update["message"]["chat"]["id"]
            text = update["message"]["text"].lower()

            # Bot Response Logic
            if text == "/start":
                reply = "🤖 Hello! I am your security bot. Send /help to see what I can do."
            elif text == "/help":
                reply = "📌 You can use the following commands:\n🔍 /check_email [email] - Check if an email is safe\n🌐 /check_website [URL] - Check website safety"
            else:
                reply = "❓ I don't understand that command. Try /help."

            # Send Reply
            requests.post(f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                          data={"chat_id": chat_id, "text": reply})

# ✅ Function to Get Logs Safely
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

# ✅ Function to Log Email & Website Activity
def log_email_activity(email, status, action, details=""):
    log_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "event_type": "Email Scan",
        "entity": email,
        "status": status,
        "action": action,
        "details": details
    }
    with open(LOG_FILE_JSON, "a") as log_file:
        json.dump(log_entry, log_file)
        log_file.write("\n")
    logging.info(log_entry)

def log_website_activity(website, status, action, details=""):
    log_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "event_type": "Website Scan",
        "entity": website,
        "status": status,
        "action": action,
        "details": details
    }
    with open(LOG_FILE_JSON, "a") as log_file:
        json.dump(log_entry, log_file)
        log_file.write("\n")
    logging.info(log_entry)
