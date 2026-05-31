# scripts/week2_task3_entropy.py
import pefile
import math
import json

def calculate_entropy(data: bytes) -> float:
    """
    Tính Shannon Entropy của một chuỗi bytes.
    Công thức: H = -Σ p(x) × log2(p(x))
    """
    if not data:
        return 0.0
    
    # Đếm tần suất xuất hiện của mỗi byte (0-255)
    frequency = [0] * 256
    for byte in data:
        frequency[byte] += 1
    
    # Tính entropy
    entropy = 0.0
    total   = len(data)
    
    for count in frequency:
        if count == 0:
            continue
        # Xác suất xuất hiện của byte này
        p = count / total
        # Cộng vào entropy
        entropy -= p * math.log2(p)
    
    return round(entropy, 4)


def entropy_verdict(value: float) -> str:
    """Đánh giá mức độ đáng ngờ dựa trên giá trị entropy"""
    if value < 1.0:
        return "Rất thấp (toàn null/repeated bytes)"
    elif value < 5.0:
        return "Bình thường"
    elif value < 6.5:
        return "Hơi cao (code phức tạp)"
    elif value < 7.0:
        return "Cao (nghi ngờ)"
    else:
        return "Rất cao → Có thể bị nén/mã hóa (PACKED)"


def analyze_entropy(filepath):
    """Tính entropy cho từng section và toàn bộ file"""
    
    result = {
        "filepath": filepath,
        "file_entropy": 0.0,
        "sections": [],
        "is_packed_heuristic": False
    }
    
    try:
        pe = pefile.PE(filepath)
        
        # Entropy toàn bộ file
        with open(filepath, "rb") as f:
            raw = f.read()
        result["file_entropy"] = calculate_entropy(raw)
        
        high_entropy_sections = 0
        
        for section in pe.sections:
            name = section.Name.decode("utf-8", errors="replace").rstrip("\x00")
            data = section.get_data()
            ent  = calculate_entropy(data)
            
            section_result = {
                "name":    name,
                "entropy": ent,
                "verdict": entropy_verdict(ent),
                "size":    len(data),
            }
            result["sections"].append(section_result)
            
            if ent > 7.0:
                high_entropy_sections += 1
        
        # Heuristic: nếu có section entropy > 7.0 → nghi là packed
        result["is_packed_heuristic"] = high_entropy_sections > 0
        
        pe.close()
        
    except Exception as e:
        result["error"] = str(e)
    
    return result


if __name__ == "__main__":
    import sys
    filepath = sys.argv[1] if len(sys.argv) > 1 else r"C:\Windows\System32\notepad.exe"
    
    data = analyze_entropy(filepath)
    
    print(f"File entropy: {data['file_entropy']} — {entropy_verdict(data['file_entropy'])}")
    print(f"\nSections:")
    for s in data["sections"]:
        bar = "█" * int(s["entropy"])
        print(f"  {s['name']:12s} {s['entropy']:.4f}  {bar:8s}  {s['verdict']}")
    
    if data["is_packed_heuristic"]:
        print("\n[!] CẢNH BÁO: File có thể đang dùng packer/encryption")