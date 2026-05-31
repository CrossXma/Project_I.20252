import os
import json
import time
from tqdm import tqdm

# Import các task đã viết
from headers import extract_headers
from sections import analyze_sections
from entropy import analyze_entropy
from iat import analyze_iat
from packer import detect_packer_heuristic, detect_with_die


def analyze_single_file(filepath, label="unknown", family="unknown"):
    """Chạy toàn bộ pipeline trên 1 file"""

    result = {
        "filepath": filepath,
        "label": label,  # "malicious" hoặc "benign"
        "family": family,  # "ransomware", "trojan", "clean"...
        "error": None
    }

    try:
        # Task 1, 2, 3, 4
        headers = extract_headers(filepath)
        sections = analyze_sections(filepath)
        entropy = analyze_entropy(filepath)
        iat = analyze_iat(filepath)

        # Task 5: Packer detection (dùng kết quả trên)
        # Merge entropy vào sections để task 5 dùng
        sections["file_entropy"] = entropy.get("file_entropy", 0)
        for s in sections["sections"]:
            for es in entropy.get("sections", []):
                if s["name"] == es["name"]:
                    s["entropy"] = es["entropy"]

        packer = detect_packer_heuristic(headers, sections, iat)
        die = detect_with_die(filepath)

        result.update({
            "headers": headers.get("headers", {}),
            "sections": sections.get("sections", []),
            "file_entropy": entropy.get("file_entropy", 0),
            "imports": iat.get("imports", {}),
            "total_imports": iat.get("total_imports", 0),
            "suspicious_apis": iat.get("suspicious_apis", []),
            "packer_score": packer["score"],
            "packer_verdict": packer["verdict"],
            "packer_clues": packer["clues"],
            "die_output": die.get("die_output", ""),
        })

    except Exception as e:
        result["error"] = str(e)

    return result


def run_pipeline(index_path, output_path):
    """
    Chạy pipeline trên toàn bộ dataset.
    index_path: đường dẫn đến malware_index.json (từ Tuần 1)
    output_path: nơi lưu kết quả
    """

    # Kiểm tra xem file index có tồn tại không trước khi mở
    if not os.path.exists(index_path):
        print(f"❌ Không tìm thấy file index tại: {index_path}")
        print("Vui lòng chạy file khởi tạo index trước hoặc kiểm tra lại đường dẫn BASE.")
        return

    # Đọc index từ Tuần 1
    with open(index_path) as f:
        dataset = json.load(f)

    print(f"Tổng số file cần phân tích: {len(dataset)}")

    results = []
    errors = []

    for sample in tqdm(dataset, desc="Đang phân tích"):
        filepath = sample["path"]

        # Bỏ qua file ZIP chưa giải nén
        if filepath.endswith(".zip"):
            continue

        # Bỏ qua file không tồn tại
        if not os.path.exists(filepath):
            errors.append(filepath)
            continue

        result = analyze_single_file(
            filepath,
            label=sample.get("label", "unknown"),
            family=sample.get("family", "unknown")
        )
        results.append(result)

        # Tránh overload, nghỉ nhỏ giữa các file
        time.sleep(0.05)

    # Lưu kết quả
    output_dir = os.path.dirname(output_path)
    os.makedirs(output_dir, exist_ok=True)

    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)

    # Thống kê
    packed = sum(1 for r in results if r.get("packer_verdict") == "PACKED")
    errors_n = sum(1 for r in results if r.get("error"))

    print(f"\nHoàn tất:")
    print(f"  Đã phân tích: {len(results)} files")
    print(f"  Phát hiện packed: {packed} files")
    print(f"  Lỗi: {errors_n} files")
    print(f"  Kết quả lưu tại: {output_path}")


if __name__ == "__main__":
    # 1. Định nghĩa đường dẫn gốc mặc định tương ứng với máy của bạn
    DEFAULT_BASE = r"C:\Users\vboxuser\Documents\Project_1\PRJ_Demo"

    # 2. Nhận input từ người dùng
    user_input = input(f"Nhập đường dẫn gốc BASE (Ấn Enter để dùng mặc định: {DEFAULT_BASE}): ").strip()
    BASE = user_input if user_input else DEFAULT_BASE

    # 3. Tự động thiết lập đường dẫn index và output theo cấu trúc thư mục từ BASE
    index_path = os.path.join(BASE, "output", "malware_index.json")
    output_path = os.path.join(BASE, "output", "results.json")

    # Kiểm tra xem thư mục gốc nhập vào có tồn tại không
    if not os.path.exists(BASE):
        print(f"❌ Đường dẫn gốc '{BASE}' không tồn tại. Vui lòng chạy lại!")
        exit()

    print(f"➔ Sử dụng đường dẫn index: {index_path}")
    print(f"➔ Sử dụng đường dẫn output: {output_path}\n")

    # 4. Chạy pipeline
    run_pipeline(index_path=index_path, output_path=output_path)