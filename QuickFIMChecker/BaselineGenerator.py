# Grabs hashes and info for specific folder.

import os
import hashlib
import json
import time
import logging

# === Scanned directory ===
FOLDER_TO_WATCH = r"C:\users\rjohnson\downloads"
BASELINE_FILE = r"C:\QuickFIMChecker\baseline.json"
LOG_FILE = r"C:\QuickFIMChecker\fim_baseline.log"
# === Logging ===
logging.basicConfig(
    filename=LOG_FILE,
    filemode="a",
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO
)

def get_file_hash(path):
    """Make a SHA-256 hash of the file."""
    sha = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha.update(chunk)
        return sha.hexdigest()
    except Exception as e:
        logging.warning(f"Couldn't hash {path}: {e}")
        return None

def gather_file_data(folder):
    """Go through the folder and grab info on every file."""
    logging.info(f"Looking through: {folder}")
    data = {}

    for root, _, files in os.walk(folder):
        for name in files:
            full_path = os.path.join(root, name)
            try:
                hash_val = get_file_hash(full_path)
                if hash_val:
                    stats = os.stat(full_path)
                    data[full_path] = {
                        "hash": hash_val,
                        "size": stats.st_size,
                        "last_modified": stats.st_mtime,
                        "permissions": stats.st_mode
                    }
            except Exception as e:
                logging.warning(f"Skipped {full_path}: {e}")

    return data

def save_baseline(data, out_file):
    """Save all that file info to a JSON file."""
    try:
        with open(out_file, "w") as f:
            json.dump(data, f, indent=4)
        logging.info(f"Baseline saved to {out_file}")
    except Exception as e:
        logging.error(f"Couldn't write baseline file: {e}")

def main():
    logging.info("Starting baseline creation...")
    start = time.time()

    files = gather_file_data(FOLDER_TO_WATCH)
    save_baseline(files, BASELINE_FILE)

    end = time.time()
    logging.info(f"Done! Took {end - start:.2f} seconds.")
    print(f"Baseline saved to: {BASELINE_FILE}")

if __name__ == "__main__":
    main()
