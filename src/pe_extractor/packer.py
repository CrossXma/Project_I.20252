# scripts/week2_task5_packer.py
import subprocess
import json


def detect_packer_heuristic(headers, sections, iat):
    """
    Phát hiện packer bằng Weighted Heuristic.
    Kết hợp kết quả từ task 2, 3, 4.
    """
    score  = 0
    clues  = []
    
    # ── Dấu hiệu từ Sections (Task 2) ────────────────────────
    for s in sections.get("sections", []):
        for flag in s.get("suspicious_flags", []):
            if "Packer section" in flag:
                score += 40
                clues.append(f"Tên section packer: {s['name']} (+40)")
            elif "W+X permissions" in flag:
                score += 20
                clues.append(f"Section W+X: {s['name']} (+20)")
            elif "possible packer" in flag:
                score += 25
                clues.append(f"Virtual/Raw ratio bất thường (+25)")
    
    # ── Dấu hiệu từ Entropy (Task 3) ─────────────────────────
    for s in sections.get("sections", []):
        # Tìm entropy từ kết quả task 3 nếu có
        pass
    
    file_entropy = sections.get("file_entropy", 0)
    if file_entropy > 7.0:
        score += 30
        clues.append(f"File entropy cao: {file_entropy} (+30)")
    elif file_entropy > 6.5:
        score += 15
        clues.append(f"File entropy hơi cao: {file_entropy} (+15)")
    
    # ── Dấu hiệu từ IAT (Task 4) ─────────────────────────────
    total_imports = iat.get("total_imports", 0)
    
    if iat.get("note") and "packed" in iat["note"].lower():
        score += 50
        clues.append("Không có IAT (file packed) (+50)")
    elif total_imports < 5:
        score += 35
        clues.append(f"Rất ít API import: {total_imports} (+35)")
    elif total_imports < 15:
        score += 15
        clues.append(f"Ít API import: {total_imports} (+15)")
    
    # ── Kết luận ─────────────────────────────────────────────
    if score >= 50:
        verdict = "PACKED"
    elif score >= 25:
        verdict = "POSSIBLY PACKED"
    else:
        verdict = "NOT PACKED"
    
    return {
        "score":   score,
        "verdict": verdict,
        "clues":   clues
    }


def detect_with_die(filepath):
    """
    Chạy Detect It Easy (DiE) và lấy kết quả.
    Cần DiE được cài và có trong PATH.
    """
    try:
        result = subprocess.run(
            ["die", filepath],
            capture_output=True,
            text=True,
            timeout=30
        )
        return {
            "die_output": result.stdout.strip(),
            "error":      result.stderr.strip() if result.returncode != 0 else None
        }
    except FileNotFoundError:
        return {"error": "DiE không tìm thấy — kiểm tra cài đặt"}
    except subprocess.TimeoutExpired:
        return {"error": "DiE timeout"}


if __name__ == "__main__":
    import sys
    filepath = sys.argv[1] if len(sys.argv) > 1 else r"C:\Windows\System32\notepad.exe"
    
    # Chạy DiE trước
    print("[DiE] Chạy Detect It Easy...")
    die_result = detect_with_die(filepath)
    print(f"  {die_result.get('die_output', die_result.get('error'))}")