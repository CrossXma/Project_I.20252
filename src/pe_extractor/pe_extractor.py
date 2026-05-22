import argparse
import hashlib
import json
import logging
import math
import os
import sys
import time
from datetime import datetime
from constants import *

import pefile


   
# LOGGING SETUP
   
def setup_logging(log_file: str) -> logging.Logger:
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    logger = logging.getLogger("pe_extractor")
    logger.setLevel(logging.DEBUG)

    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.WARNING)
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))

    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))

    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger

logger = setup_logging(CONFIG["output"]["log_file"])


   
# MODULE 1 — Shannon Entropy
   
def calc_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    freq = [0] * 256
    for byte in data:
        freq[byte] += 1

    total = len(data)
    entropy = 0.0
    for count in freq:
        if count == 0:
            continue
        p = count / total
        entropy -= p * math.log2(p)

    return round(entropy, 4)

   
# MODULE 2 — Header Features
   
def extract_header_features(pe: pefile.PE) -> dict:
    features = {}
    try:
        features["machine_type"]    = hex(pe.FILE_HEADER.Machine)
        features["num_sections"]    = pe.FILE_HEADER.NumberOfSections
        features["timestamp"]       = pe.FILE_HEADER.TimeDateStamp
        features["characteristics"] = pe.FILE_HEADER.Characteristics

        features["entry_point"]        = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        features["image_base"]         = hex(pe.OPTIONAL_HEADER.ImageBase)
        features["subsystem"]          = pe.OPTIONAL_HEADER.Subsystem
        features["dll_characteristics"] = pe.OPTIONAL_HEADER.DllCharacteristics
        features["size_of_image"]      = pe.OPTIONAL_HEADER.SizeOfImage
        features["size_of_headers"]    = pe.OPTIONAL_HEADER.SizeOfHeaders

        machine_map = {0x014C: "x86", 0x8664: "x64", 0x01C4: "ARM", 0xAA64: "ARM64"}
        features["arch"] = machine_map.get(pe.FILE_HEADER.Machine, "unknown")

        subsystem_map = {1: "Native", 2: "GUI", 3: "Console", 14: "Xbox"}
        features["subsystem_name"] = subsystem_map.get(pe.OPTIONAL_HEADER.Subsystem, "Unknown")

        dll_chars = pe.OPTIONAL_HEADER.DllCharacteristics
        features["has_aslr"] = bool(dll_chars & 0x0040)
        features["has_dep"]  = bool(dll_chars & 0x0100)
        features["has_cfg"]  = bool(dll_chars & 0x4000)

    except AttributeError as e:
        logger.warning(f"Header parse lỗi: {e}")
        features["header_parse_error"] = str(e)

    return features

   
# MODULE 3 — Section Features
   
def extract_section_features(pe: pefile.PE) -> dict:
    cfg = CONFIG["thresholds"]
    limit = CONFIG["limits"]["max_section_bytes_for_entropy"]

    sections_info    = []
    suspicious_flags = []
    ep_address = pe.OPTIONAL_HEADER.AddressOfEntryPoint

    for section in pe.sections:
        try:
            name = section.Name.decode("utf-8", errors="replace").strip("\x00")
        except Exception:
            name = repr(section.Name)

        raw_data = section.get_data()
        if len(raw_data) > limit:
            raw_data = raw_data[:limit]
        entropy = calc_entropy(raw_data)

        chars        = section.Characteristics
        is_exec      = bool(chars & 0x20000000)
        is_write     = bool(chars & 0x80000000)
        is_read      = bool(chars & 0x40000000)

        virtual_size = section.Misc_VirtualSize
        raw_size     = section.SizeOfRawData
        virt_addr    = section.VirtualAddress

        is_ep = virt_addr <= ep_address < (virt_addr + max(virtual_size, 1))

        sections_info.append({
            "name":             name,
            "virtual_address":  hex(virt_addr),
            "virtual_size":     virtual_size,
            "raw_size":         raw_size,
            "entropy":          entropy,
            "executable":       is_exec,
            "writable":         is_write,
            "readable":         is_read,
            "is_entry_point":   is_ep,
        })

        rsrc_threshold = cfg["entropy_rsrc_high"] if name.lower() == ".rsrc" else cfg["entropy_high"]
        if entropy > rsrc_threshold:
            suspicious_flags.append(f"HIGH_ENTROPY:'{name}'={entropy:.2f}")

        if name and name not in KNOWN_SECTIONS:
            suspicious_flags.append(f"UNKNOWN_SECTION:'{name}'")

        if name in (".UPX0", ".UPX1", ".UPX2"):
            suspicious_flags.append(f"PACKER_UPX:'{name}'")
        if any(p in name.lower() for p in (".aspack", ".adata", "themida", "pecompact")):
            suspicious_flags.append(f"PACKER_NAMED:'{name}'")

        if is_write and is_exec:
            suspicious_flags.append(f"WRITE_EXECUTE:'{name}'")

        if virtual_size > 0 and raw_size == 0:
            suspicious_flags.append(f"ZERO_RAW_SIZE:'{name}'(VirtualSize={virtual_size})")

        if raw_size > 0 and virtual_size > 0:
            ratio = virtual_size / raw_size
            if ratio > cfg["size_ratio_anomaly"] and is_write:
                suspicious_flags.append(f"SIZE_ANOMALY:'{name}'(ratio={ratio:.1f}x)")

    unique_flags = list(dict.fromkeys(suspicious_flags))
    ep_section = next((s["name"] for s in sections_info if s["is_entry_point"]), "Unknown")

    return {
        "sections":                sections_info,
        "total_sections":          len(sections_info),
        "entry_point_section":     ep_section,
        "suspicious_section_flags": unique_flags,
        "suspicious_count":        len(unique_flags),
    }

   
# MODULE 4 — Import Address Table (IAT)
   
def extract_iat_features(pe: pefile.PE) -> dict:
    result = {
        "imported_dlls":              [],
        "total_imported_functions":   0,
        "suspicious_api_groups":      {},
        "packer_heuristic_few_imports": False,
        "all_imported_apis":          [],
    }

    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        result["packer_heuristic_few_imports"] = True
        return result

    all_apis = []
    dll_info = []

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        try:
            dll_name = entry.dll.decode("utf-8", errors="replace").lower() if entry.dll else "unknown.dll"
        except Exception:
            dll_name = "unknown.dll"

        functions = []
        for imp in entry.imports:
            try:
                if imp.name:
                    func_name = imp.name.decode("utf-8", errors="replace")
                elif imp.ordinal is not None:
                    func_name = f"Ordinal_{imp.ordinal}"
                else:
                    continue
                functions.append(func_name)
                all_apis.append(func_name)
            except Exception:
                continue

        if functions:
            dll_info.append({
                "dll":            dll_name,
                "function_count": len(functions),
                "functions":      functions,
            })

    api_set = set(all_apis)
    detected_groups = {
        group: sorted(api_set.intersection(apis))
        for group, apis in SUSPICIOUS_API_GROUPS.items()
        if api_set.intersection(apis)
    }

    result.update({
        "imported_dlls":              dll_info,
        "total_imported_functions":   len(all_apis),
        "suspicious_api_groups":      detected_groups,
        "packer_heuristic_few_imports": len(all_apis) < CONFIG["thresholds"]["few_imports_cutoff"],
        "all_imported_apis":          all_apis,
    })
    return result

   
# MODULE 5 — Packer Detection
   
def detect_packer(section_features: dict, iat_features: dict) -> dict:
    cfg      = CONFIG["thresholds"]
    scoring  = CONFIG["scoring"]
    score    = 0
    indicators = []

    sections       = section_features.get("sections", [])
    susp_flags     = section_features.get("suspicious_section_flags", [])
    ep_section     = section_features.get("entry_point_section", "").lower()

    high_entropy_done = False
    for sec in sections:
        name = sec.get("name", "").lower()
        entropy = sec.get("entropy", 0.0)
        threshold = cfg["entropy_rsrc_high"] if name == ".rsrc" else cfg["entropy_high"]
        if entropy > threshold and not high_entropy_done:
            indicators.append(f"Entropy cao ({entropy:.2f}) tại section '{sec['name']}'")
            score += scoring["high_entropy"]
            high_entropy_done = True

    wx_done = False
    for sec in sections:
        if sec.get("executable") and sec.get("writable") and not wx_done:
            indicators.append(f"Section '{sec['name']}' có quyền Write+Execute (W+X)")
            score += scoring["wx_section"]
            wx_done = True

    size_done = False
    for sec in sections:
        r = sec.get("raw_size", 0)
        v = sec.get("virtual_size", 0)
        if r > 0 and v > 0 and (v / r) > cfg["size_ratio_anomaly"] and not size_done:
            indicators.append(f"VirtualSize >> RawSize tại '{sec['name']}' ({v/r:.1f}x)")
            score += scoring["size_anomaly"]
            size_done = True

    packer_flags = [f for f in susp_flags if f.startswith("PACKER_")]
    if packer_flags:
        for f in packer_flags:
            indicators.append(f"Tên section packer: {f}")
        score += scoring["packer_name"]

    if iat_features.get("packer_heuristic_few_imports"):
        n = iat_features.get("total_imported_functions", 0)
        indicators.append(f"Import table rất ít ({n} hàm) — code thật chưa được giải nén")
        score += scoring["few_imports"]

    if ep_section and ep_section not in (".text", ".code", "code", ".textbss"):
        indicators.append(f"Entry Point ở section bất thường: '{ep_section}'")
        score += scoring["ep_outside_text"]

    return {
        "is_packed":    score >= cfg["packer_score_cutoff"],
        "packer_score": score,
        "indicators":   indicators,
    }

   
# CORE — PE file analysis
   
def analyze_pe_file(filepath: str) -> dict | None:
    if not os.path.isfile(filepath):
        logger.warning(f"File không tồn tại: {filepath}")
        return None

    with open(filepath, "rb") as f:
        raw = f.read()

    if raw[:2] != b"MZ":
        logger.debug(f"Bỏ qua (không phải PE): {os.path.basename(filepath)}")
        return None

    sha256 = hashlib.sha256(raw).hexdigest()
    md5    = hashlib.md5(raw).hexdigest()

    try:
        pe = pefile.PE(filepath, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
        ])
    except Exception as e:
        logger.warning(f"PE parse thất bại '{os.path.basename(filepath)}': {e}")
        return None

    try:
        overall_entropy  = calc_entropy(raw)
        header_features  = extract_header_features(pe)
        section_features = extract_section_features(pe)
        iat_features     = extract_iat_features(pe)
        packer_info      = detect_packer(section_features, iat_features)
    except Exception as e:
        logger.error(f"Feature extraction lỗi '{os.path.basename(filepath)}': {e}")
        pe.close()
        return None
    finally:
        pe.close()

    return {
        "filename":         os.path.basename(filepath),
        "filepath":         filepath,
        "sha256":           sha256,
        "md5":              md5,
        "file_size_bytes":  len(raw),
        "overall_entropy":  overall_entropy,
        "header":           header_features,
        "sections":         section_features,
        "iat":              iat_features,
        "packer_detection": packer_info,
    }

   
# BATCH — Chạy trên toàn bộ thư mục
   
def run_batch_analysis(dataset_dir: str, label: str, output_dir: str) -> dict:
    if not os.path.isdir(dataset_dir):
        logger.error(f"Thư mục không tồn tại: {dataset_dir}")
        return {}

    os.makedirs(output_dir, exist_ok=True)

    all_files = [
        f for f in os.listdir(dataset_dir)
        if os.path.isfile(os.path.join(dataset_dir, f))
    ]
    total = len(all_files)

    stats = {
        "label":         label,
        "total_files":   total,
        "success":       0,
        "skipped_non_pe": 0,
        "failed":        0,
        "packed_count":  0,
        "started_at":    datetime.now().isoformat(),
    }

    logger.info(f"{'─'*55}")
    logger.info(f"Bắt đầu batch [{label.upper()}] — {total} file từ '{dataset_dir}'")
    logger.info(f"{'─'*55}")

    t_start = time.time()

    for i, filename in enumerate(all_files, 1):
        filepath = os.path.join(dataset_dir, filename)
        prefix = f"[{i:>4}/{total}]"

        result = analyze_pe_file(filepath)

        if result is None:
            try:
                with open(filepath, "rb") as f:
                    magic = f.read(2)
                if magic != b"MZ":
                    logger.debug(f"{prefix} SKIP  {filename}")
                    stats["skipped_non_pe"] += 1
                else:
                    logger.warning(f"{prefix} FAIL  {filename}")
                    stats["failed"] += 1
            except Exception:
                stats["failed"] += 1
            continue

        result["label"] = label
        stats["success"] += 1

        if result["packer_detection"]["is_packed"]:
            stats["packed_count"] += 1

        out_path = os.path.join(output_dir, f"{result['sha256'][:16]}.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)

        packed_tag = " [PACKED]" if result["packer_detection"]["is_packed"] else ""
        logger.info(f"{prefix} OK    {filename}{packed_tag}")

    elapsed = time.time() - t_start
    stats["elapsed_seconds"] = round(elapsed, 2)
    stats["finished_at"] = datetime.now().isoformat()

    logger.info(f"{'─'*55}")
    logger.info(
        f"Hoàn thành [{label.upper()}]: "
        f"{stats['success']} OK | "
        f"{stats['skipped_non_pe']} skip | "
        f"{stats['failed']} fail | "
        f"{stats['packed_count']} packed | "
        f"{elapsed:.1f}s"
    )
    logger.info(f"{'─'*55}\n")

    return stats

   
# ENTRY POINT
   
def parse_args():
    parser = argparse.ArgumentParser(
        description="PE Feature Extractor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
        VÍ DỤ:
        1. Quét 1 file cụ thể:
           python pe_extractor.py --file sample.exe
        2. Quét thư mục chứa hỗn hợp các file (không phân biệt malware/benign):
           python pe_extractor.py --dir C:/path/to/mixed_folder
        3. Quét riêng thư mục malware:
           python pe_extractor.py --malware-dir C:/path/to/malware
        4. Quét mặc định (quét cả 2 thư mục đã cấu hình trong CONFIG):
           python pe_extractor.py
        """
    )
    parser.add_argument("--file", metavar="PATH",
                        help="Phân tích 1 file PE cụ thể")
    parser.add_argument("--out", metavar="PATH",
                        help="Lưu kết quả ra file JSON (chỉ dùng chung với --file)")
    
    parser.add_argument("--dir", metavar="DIR",
                        help="Thư mục chứa các file hỗn hợp (gán label 'unknown')")
    parser.add_argument("--malware-dir", metavar="DIR",
                        help="Chỉ quét thư mục malware được chỉ định")
    parser.add_argument("--benign-dir", metavar="DIR",
                        help="Chỉ quét thư mục benign được chỉ định")
    return parser.parse_args()


def main():
    args = parse_args()

    # MODE 1: Phân tích 1 file
    if args.file:
        logger.info(f"Phân tích file: {args.file}")
        result = analyze_pe_file(args.file)

        if result is None:
            logger.error("Không thể phân tích file này.")
            sys.exit(1)

        result["label"] = "unknown"

        output = json.dumps(result, indent=2, ensure_ascii=False)
        print(output)

        if args.out:
            os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(output)
            logger.info(f"Đã lưu kết quả ra: {args.out}")
        return

    # MODE BATCH
    logger.info("=== BATCH MODE ===")
    all_stats = []

    # MODE 2: Quét thư mục hỗn hợp (Mixed files)
    if args.dir:
        logger.info(f"Quét thư mục hỗn hợp: {args.dir}")
        mixed_stats = run_batch_analysis(
            dataset_dir=args.dir,
            label="unknown",
            output_dir=CONFIG["output"]["mixed_dir"]
        )
        if mixed_stats:
            all_stats.append(mixed_stats)

    # MODE 3: Quét theo các thư mục được chỉ định cụ thể (Malware hoặc Benign)
    elif args.malware_dir or args.benign_dir:
        if args.malware_dir:
            malware_stats = run_batch_analysis(
                dataset_dir=args.malware_dir,
                label="malware",
                output_dir=CONFIG["output"]["malware_dir"]
            )
            if malware_stats:
                all_stats.append(malware_stats)
        
        if args.benign_dir:
            benign_stats = run_batch_analysis(
                dataset_dir=args.benign_dir,
                label="benign",
                output_dir=CONFIG["output"]["benign_dir"]
            )
            if benign_stats:
                all_stats.append(benign_stats)

    # MODE 4: Default (Lấy đường dẫn từ CONFIG nếu không có argument )
    else:
        logger.info("Không nhận được tham số cụ thể. Chạy bằng đường dẫn mặc định...")
        malware_stats = run_batch_analysis(
            dataset_dir=CONFIG["dataset"]["malware_dir"],
            label="malware",
            output_dir=CONFIG["output"]["malware_dir"]
        )
        if malware_stats:
            all_stats.append(malware_stats)

        benign_stats = run_batch_analysis(
            dataset_dir=CONFIG["dataset"]["benign_dir"],
            label="benign",
            output_dir=CONFIG["output"]["benign_dir"]
        )
        if benign_stats:
            all_stats.append(benign_stats)

    # TÓM TẮT 
    if all_stats:
        summary_path = CONFIG["output"]["summary_file"]
        os.makedirs(os.path.dirname(summary_path), exist_ok=True)
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(all_stats, f, indent=2, ensure_ascii=False)
        logger.info(f"Tóm tắt batch đã lưu: {summary_path}")

        total_ok = sum(s.get("success", 0) for s in all_stats)
        total_packed = sum(s.get("packed_count", 0) for s in all_stats)
        total_all = sum(s.get("total_files", 0) for s in all_stats)
        logger.info(
            f"=== KẾT THÚC === "
            f"Tổng: {total_ok}/{total_all} file OK | "
            f"{total_packed} file bị pack"
        )
    else:
        logger.warning("Không có dữ liệu nào được xử lý.")


if __name__ == "__main__":
    main()