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

os.makedirs(LOG_DIR, exist_ok=True)  # Create logs folder if not exist

# ✅ Setup Logging (for .log file)
logging.basicConfig(filename=LOG_FILE_TEXT, level=logging.INFO, format="%(asctime)s - %(message)s")

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
    logging.info(log_entry)

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
    logging.info(log_entry)

# ✅ Function to Log Email Activity
def log_email_activity(email, status, action, details=""):
    log_activity_json("Email Scan", email, status, action, details)
    log_activity_csv("Email Scan", email, status, action, details)

# ✅ Function to Log Website Activity
def log_website_activity(website, status, action, details=""):
    log_activity_json("Website Scan", website, status, action, details)
    log_activity_csv("Website Scan", website, status, action, details)
