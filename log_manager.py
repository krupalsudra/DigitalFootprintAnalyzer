import os
import json
import csv
from datetime import datetime

# 📂 Ensure logs directory exists
LOG_DIR = "logs"
LOG_FILE_JSON = os.path.join(LOG_DIR, "activity.json")
LOG_FILE_CSV = os.path.join(LOG_DIR, "activity.csv")

os.makedirs(LOG_DIR, exist_ok=True)  # Create logs folder if not exist

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
        log_file.write("\n")  # New line for each entry

# ✅ Function to Log Activity in CSV
def log_activity_csv(event_type, entity, status, action, details=""):
    log_entry = [
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        event_type,
        entity,
        status,
        action,
        details
    ]
    with open(LOG_FILE_CSV, "a", newline="") as log_file:
        writer = csv.writer(log_file)
        writer.writerow(log_entry)

# ✅ Function to Log Email Activity
def log_email_activity(email, status, action, details=""):
    log_activity_json("Email Scan", email, status, action, details)
    log_activity_csv("Email Scan", email, status, action, details)

# ✅ Function to Log Website Activity
def log_website_activity(website, status, action, details=""):
    log_activity_json("Website Scan", website, status, action, details)
    log_activity_csv("Website Scan", website, status, action, details)

# ✅ Function to Retrieve Logs
def get_logs():
    logs = []
    if os.path.exists(LOG_FILE_JSON):
        with open(LOG_FILE_JSON, "r") as file:
            for line in file:
                try:
                    logs.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return logs
