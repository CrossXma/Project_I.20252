import os
import time
import json
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# ==========================================================
# CONFIG
# ==========================================================

API_URL = "https://mb-api.abuse.ch/api/v1/"
HEADER = {"Auth-Key": "YOUR-AUTH-KEY-HERE"}

MALWARE_TYPE = {
    "trojan": ("AgentTesla"),
    "botnet": ("Mirai"),
    "ransomware": ("WannaCry", "LockBit", "Phobos"),
    "spyware": ("RedLineStealer"),
    "worm": ("QakBot", "Emotet"),
    "rat": ("AsyncRAT")}      # Malware families
TARGET_COUNT = 500        # Number of samples wanted each types
MAX_WORKERS = 20

OUTPUT_DIR = "../../dataset/raw/malware"
HASH_FILE = "downloaded_hashes.txt"

ZIP_PASSWORD = b"infected"

# ==========================================================
# SETUP
# ==========================================================

os.makedirs(OUTPUT_DIR, exist_ok=True)

if os.path.exists(HASH_FILE):
    with open(HASH_FILE, "r") as f:
        downloaded_hashes = set(
            line.strip() for line in f if line.strip()
        )
else:
    downloaded_hashes = set()

# ==========================================================
# HELPER FUNCTIONS
# ==========================================================

def save_hash(sha256):
    """
    Persist downloaded hashes.
    """

    with open(HASH_FILE, "a") as f:
        f.write(sha256 + "\n")

    downloaded_hashes.add(sha256)


def is_windows_pe(entry):
    """
    Filter only PE executables.
    """

    file_type = str(entry.get("file_type", "")).lower()
    file_name = str(entry.get("file_name", "")).lower()

    pe_keywords = [
        "exe",
        "dll",
        "pe"
    ]

    if any(x in file_type for x in pe_keywords):
        return True

    if file_name.endswith(".exe"):
        return True

    if file_name.endswith(".dll"):
        return True

    return False


def query_family(signature, limit=100):
    """
    Query MalwareBazaar for a malware family.
    """

    data = {
        "query": "get_siginfo",
        "signature": signature,
        "limit": str(limit)
    }

    r = requests.post(API_URL, headers=HEADER, data=data, timeout=60)
    r.raise_for_status()

    result = r.json()

    if result.get("query_status") != "ok":
        return []

    return result.get("data", [])


def download_sample(sha256, type):
    """
    Download a malware sample.
    """

    output_path = os.path.join(
        OUTPUT_DIR,
        type
    )
    os.makedirs(output_path, exist_ok=True)

    try:

        save_path = os.path.join(
            output_path,
            f"{sha256}.zip"
        )

        if os.path.exists(save_path):
            return "exists", sha256

        payload = {
            "query": "get_file",
            "sha256_hash": sha256
        }

        r = requests.post(
            API_URL,
            headers=HEADER,
            data=payload,
            timeout=120
        )

        if r.status_code != 200:
            return "failed", sha256

        with open(save_path, "wb") as f:
            f.write(r.content)

        save_hash(sha256)

        return "downloaded", sha256

    except Exception:
        return "failed", sha256


# ==========================================================
# MAIN
# ==========================================================

def main():

    for type, signatures in MALWARE_TYPE.items():        

        print("\n==========================================================")
        print(f"Querying type: {type}")
        print("==========================================================")

        target = TARGET_COUNT // len(signatures)

        for signature in signatures:

            print(f"\nQuerying family: {signature}")

            samples = query_family(signature, target * 2)

            if not samples:
                print("No samples returned.")
                return

            print(f"Found {len(samples)} candidate samples")

            candidates = []

            for sample in samples:

                sha256 = sample.get("sha256_hash")

                if not sha256:
                    continue

                if sha256 in downloaded_hashes:
                    continue

                if not is_windows_pe(sample):
                    continue

                candidates.append(sha256)

            print(f"PE candidates: {len(candidates)}")

            remaining = target - len(downloaded_hashes)

            if remaining <= 0:
                print("Target already reached.")
                return

            candidates = candidates[:remaining]

            print(f"Downloading {len(candidates)} samples...\n")

            downloaded = 0

            with ThreadPoolExecutor(
                max_workers=MAX_WORKERS
            ) as executor:

                futures = [
                    executor.submit(
                        download_sample,
                        sha256,
                        type
                    )
                    for sha256 in candidates
                ]

                for future in as_completed(futures):

                    status, sha256 = future.result()

                    if status == "downloaded":
                        downloaded += 1

                        print(
                            f"[{downloaded}] "
                            f"Downloaded {sha256}"
                        )

                    elif status == "exists":
                        print(f"Already exists: {sha256}")

                    else:
                        print(f"Failed: {sha256}")

                    if len(downloaded_hashes) >= target:
                        break

            print("\nDone.")
            print(
                f"Total downloaded: "
                f"{len(downloaded_hashes)}"
            )


if __name__ == "__main__":
    main()