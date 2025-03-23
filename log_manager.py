import logging
import json
import csv
import os
from datetime import datetime

# 📂 Ensure logs directory exists
LOG_DIR = "logs"
LOG_FILE_TEXT = os.path.join(LOG_DIR, "activity.log")
LOG_FILE_JSON = os.path.join(LOG_DIR, "activity.json")
LOG_FILE_CSV = os.path.join(LOG_DIR, "activity.csv")

os.makedirs(LOG_DIR, exist_ok=True)  # Create logs folder if it does not exist

# ✅ Setup Logging (for .log file)
logging.basicConfig(filename=LOG_FILE_TEXT, level=logging.INFO, format="%(asctime)s - %(message)s")

# ✅ Function to Log Activity in JSON
def log_activity_json(user, event_type, entity, status, action, details=""):
    log_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "user": user,
        "event_type": event_type,
        "entity": entity,
        "status": status,
        "action": action,
        "details": details
    }
    with open(LOG_FILE_JSON, "a") as log_file:
        json.dump(log_entry, log_file)
        log_file.write("\n")  # New line for each entry
    logging.info(log_entry)

# ✅ Function to Log Activity in CSV
def log_activity_csv(user, event_type, entity, status, action, details=""):
    log_entry = [
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        user,
        event_type,
        entity,
        status,
        action,
        details
    ]
    with open(LOG_FILE_CSV, "a", newline="") as log_file:
        writer = csv.writer(log_file)
        writer.writerow(log_entry)
    logging.info(log_entry)

# ✅ Function to Log Login Attempts
def log_login_attempt(user, status, details=""):
    log_activity_json(user, "Login Attempt", "Authentication", status, "User Login", details)
    log_activity_csv(user, "Login Attempt", "Authentication", status, "User Login", details)

# ✅ Function to Log Email Activity
def log_email_activity(user, email, status, action, details=""):
    log_activity_json(user, "Email Scan", email, status, action, details)
    log_activity_csv(user, "Email Scan", email, status, action, details)

# ✅ Function to Log Website Activity
def log_website_activity(user, website, status, action, details=""):
    log_activity_json(user, "Website Scan", website, status, action, details)
    log_activity_csv(user, "Website Scan", website, status, action, details)

# ✅ Function to Get Logs for Display
def get_logs():
    logs = []
    try:
        with open(LOG_FILE_JSON, "r") as log_file:
            for line in log_file:
                logs.append(json.loads(line.strip()))
    except FileNotFoundError:
        logs.append({"error": "No logs found"})

    return logs
