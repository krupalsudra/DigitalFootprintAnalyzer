import logging
import json
import csv
import os
from datetime import datetime

LOG_DIR = "logs"
LOG_FILE_JSON = os.path.join(LOG_DIR, "activity.json")
LOG_FILE_CSV = os.path.join(LOG_DIR, "activity.csv")

os.makedirs(LOG_DIR, exist_ok=True)  # Ensure logs folder exists

# ✅ Setup Logging
logging.basicConfig(filename=os.path.join(LOG_DIR, "activity.log"), level=logging.INFO, format="%(asctime)s - %(message)s")

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

def log_email_activity(email, status, action, details=""):
    log_activity("Email Scan", email, status, action, details)

def log_website_activity(website, status, action, details=""):
    log_activity("Website Scan", website, status, action, details)

def get_logs():
    logs = []
    if os.path.exists(LOG_FILE_JSON):
        with open(LOG_FILE_JSON, "r") as file:
            for line in file:
                logs.append(json.loads(line))
    return logs
