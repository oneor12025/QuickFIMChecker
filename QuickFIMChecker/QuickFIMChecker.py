import os
import time
import json
import hashlib
import logging
import getpass
import smtplib
from email.message import EmailMessage
from cryptography.fernet import Fernet
from concurrent.futures import ThreadPoolExecutor, as_completed
import win32security  # For getting file owner info

# Load encryption key
with open("secret.key", "rb") as key_file:
    key = key_file.read()

# Decrypt password
f = Fernet(key)
with open("encrypted_password.bin", "rb") as file:
    encrypted_password = file.read()

# Constants
MONITOR_FOLDER = r"C:\users\rjohnson\downloads"
BASELINE_FILE = r"C:\QuickFIMChecker\baseline.json"
LAST_RUN_FILE = r"C:\QuickFIMChecker\last_run.json"
CHANGES_FILE = r"C:\QuickFIMChecker\changes.json"
LOG_FILE = r"C:\QuickFIMChecker\fim.log"

# Email config
EMAIL_ENABLED = True
SMTP_SERVER = "smtp.office365.com"
SMTP_PORT = 587
EMAIL_SENDER = "you@mycompany.com"
EMAIL_PASSWORD = f.decrypt(encrypted_password).decode()
EMAIL_RECIPIENTS = ["user1@mycompany.com", "user2@mycompany.com"]

# Ensure directories exist
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
os.makedirs(os.path.dirname(CHANGES_FILE), exist_ok=True)

# Logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def get_file_user(file_path):
    """Get the user who last modified the file."""
    try:
        # Fetch the file owner using Windows security API
        security_info = win32security.GetFileSecurity(file_path, win32security.OWNER_SECURITY_INFORMATION)
        owner_sid = security_info.GetSecurityDescriptorOwner()
        owner_name, domain, _ = win32security.LookupAccountSid(None, owner_sid)
        return f"{domain}\\{owner_name}"
    except Exception as e:
        logging.error(f"Error fetching user for {file_path}: {e}")
        return getpass.getuser()  # Fallback to the current user

def calculate_hash(file_path):
    """Calculate SHA-256 hash of a file."""
    try:
        with open(file_path, "rb") as f:
            hasher = hashlib.sha256()
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        logging.error(f"Error hashing file {file_path}: {e}")
        return None

def process_file(file_path):
    """Hash the file and return metadata."""
    file_hash = calculate_hash(file_path)
    if file_hash:
        try:
            file_info = {
                "hash": file_hash,
                "user": get_file_user(file_path),
                "date": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(os.path.getmtime(file_path)))
            }
            return file_path, file_info
        except Exception as e:
            logging.error(f"Metadata error for {file_path}: {e}")
    return None

def scan_files(directory):
    """Scan directory using multithreading."""
    file_paths = []
    for root, _, files in os.walk(directory):
        for filename in files:
            file_path = os.path.join(root, filename)
            file_paths.append(file_path)

    total_files = len(file_paths)
    logging.info(f"Discovered {total_files} files to scan.")
    file_hashes = {}

    with ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as executor:
        futures = {executor.submit(process_file, path): path for path in file_paths}
        for i, future in enumerate(as_completed(futures), start=1):
            result = future.result()
            if result:
                path, info = result
                file_hashes[path] = info

            if i % 10 == 0 or i == total_files:
                logging.info(f"Scanned {i}/{total_files} files")

    logging.info("Completed scanning files.")
    return file_hashes

def load_previous_run(file_path):
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except Exception as e:
        logging.error("Failed to load previous run: %s", e)
        return {}

def save_current_run(file_path, file_data):
    try:
        with open(file_path, "w") as f:
            json.dump(file_data, f, indent=4)
        logging.info("Saved current scan to %s", file_path)
    except Exception as e:
        logging.error("Failed to save current run: %s", e)

def compare_files(previous_data, current_data):
    modified = {}
    deleted = {}
    new = {}

    for path in previous_data:
        if path not in current_data:
            deleted[path] = previous_data[path]  # Keep previous user info
        elif previous_data[path]["hash"] != current_data[path]["hash"]:
            modified[path] = current_data[path]

    for path in current_data:
        if path not in previous_data:
            new[path] = current_data[path]

    return modified, deleted, new

def log_and_report(modified, deleted, new):
    modified_count = len(modified)
    deleted_count = len(deleted)
    new_count = len(new)

    for path in modified:
        info = modified[path]
        logging.warning(f"Modified: {path} (User: {info['user']} at {info['date']})")
        print(f"Modified: {path} (User: {info['user']} at {info['date']})")

    for path in deleted:
        info = deleted[path]
        logging.warning(f"Deleted: {path} (Last known user: {info['user']} at {info['date']})")
        print(f"Deleted: {path} (Last known user: {info['user']} at {info['date']})")

    for path in new:
        info = new[path]
        logging.info(f"New file: {path} (Owner: {info['user']} at {info['date']})")
        print(f"New file: {path} (Owner: {info['user']} at {info['date']})")

    logging.info(f"Modified: {modified_count}, Deleted: {deleted_count}, New: {new_count}")
    print(f"Modified: {modified_count}, Deleted: {deleted_count}, New: {new_count}")

    return modified_count, deleted_count, new_count

def save_changes_to_json(modified, deleted):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    changes = {
        "modified": {
            path: {
                "user": modified[path]["user"],
                "date": modified[path]["date"],
                "timestamp": timestamp
            } for path in modified
        },
        "deleted": {
            path: {
                "user": deleted[path]["user"],
                "date": deleted[path]["date"],
                "timestamp": timestamp
            } for path in deleted
        }
    }

    try:
        with open(CHANGES_FILE, "w") as f:
            json.dump(changes, f, indent=4)
        logging.info("Saved changes to %s", CHANGES_FILE)
    except Exception as e:
        logging.error("Failed to write changes: %s", e)

def send_email(subject, body):
    if not EMAIL_ENABLED or not EMAIL_PASSWORD:
        logging.warning("Email not sent: Missing credentials or disabled.")
        return

    try:
        msg = EmailMessage()
        msg["From"] = EMAIL_SENDER
        msg["To"] = ", ".join(EMAIL_RECIPIENTS)
        msg["Subject"] = subject
        msg.set_content(body)

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)

        logging.info("Email sent.")
    except Exception as e:
        logging.error("Email failed: %s", e)

def generate_email_body(modified, deleted, new):
    # Generate email body with details of changes
    body = f"File Integrity Monitoring Report:\n\n"
    body += f"Modified files: {len(modified)}\n"
    for path, info in modified.items():
        body += f"Modified: {path} (User: {info['user']} at {info['date']})\n"
    
    body += f"\nDeleted files: {len(deleted)}\n"
    for path, info in deleted.items():
        body += f"Deleted: {path} (Last known user: {info['user']} at {info['date']})\n"

    body += f"\nNew files: {len(new)}\n"
    for path, info in new.items():
        body += f"New file: {path} (Owner: {info['user']} at {info['date']})\n"

    return body

def main():
    logging.info("Starting FIM Scan")
    start_time = time.time()

    previous_data = load_previous_run(LAST_RUN_FILE)
    current_data = scan_files(MONITOR_FOLDER)

    modified, deleted, new = compare_files(previous_data, current_data)
    modified_count, deleted_count, new_count = log_and_report(modified, deleted, new)

    save_changes_to_json(modified, deleted)
    save_current_run(LAST_RUN_FILE, current_data)

    # Generate email body
    body = generate_email_body(modified, deleted, new)
    send_email("FIM Report: File Integrity Changes Detected", body)

    duration = time.time() - start_time
    logging.info("FIM Scan finished in %.2f seconds", duration)

if __name__ == "__main__":
    main()
