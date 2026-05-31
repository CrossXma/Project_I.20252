import os
import hashlib
import json


def sha256_of_file(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


# 1. Định nghĩa đường dẫn mặc định
DEFAULT_BASE = r"C:\Users\vboxuser\Documents\Project_1\PRJ_Demo\dataset"

# 2. Cho người dùng nhập, nếu nhấn Enter sẽ lấy mặc định
user_input = input(f"Nhập đường dẫn BASE (Ấn Enter để dùng mặc định: {DEFAULT_BASE}): ").strip()
BASE = user_input if user_input else DEFAULT_BASE

# Kiểm tra xem đường dẫn có tồn tại thực tế không
if not os.path.exists(BASE):
    print(f" Thư mục '{BASE}' không tồn tại. Vui lòng kiểm tra lại!")
    exit()

dataset = []

# Index file benign
benign_dirs = [
    ("system32_dlls", os.path.join(BASE, "benign", ".dll")),
    ("common_exe", os.path.join(BASE, "benign", ".exe")),
]
for source, folder in benign_dirs:
    if not os.path.exists(folder):
        print(f"[Cảnh báo] Thư mục không tồn tại: {folder}")
        continue

    for fname in os.listdir(folder):
        fpath = os.path.join(folder, fname)
        if os.path.isfile(fpath):
            dataset.append({
                "path": fpath,
                "label": "benign",  # ← Nhãn cho ML sau này
                "family": "clean",
                "source": source,
                "sha256": sha256_of_file(fpath),
                "filename": fname
            })

# Index file malicious
for family in ["ransomware", "trojan", "botnet", "rat", "rootkit", "spyware", "worm"]:
    folder = os.path.join(BASE, "malware", family)

    if not os.path.exists(folder):
        continue

    for fname in os.listdir(folder):
        fpath = os.path.join(folder, fname)

        if os.path.isfile(fpath):
            dataset.append({
                "path": fpath,
                "label": "malicious",
                "family": family,
                "source": "MalwareBazaar",
                "sha256": sha256_of_file(fpath),
                "filename": fname
            })

# Lưu index
PROJECT_ROOT = os.path.dirname(BASE)
output_dir = os.path.join(PROJECT_ROOT, "output")
os.makedirs(output_dir, exist_ok=True)

output_file = os.path.join(output_dir, "malware_index.json")

with open(output_file, "w") as f:
    json.dump(dataset, f, indent=2)

# Thống kê
benign_count = sum(1 for d in dataset if d["label"] == "benign")
malicious_count = sum(1 for d in dataset if d["label"] == "malicious")
print(f"\n Index hoàn tất tại: {output_file}")
print(f"  Benign:    {benign_count} files")
print(f"  Malicious: {malicious_count} files")
print(f"  Tổng:      {len(dataset)} files")