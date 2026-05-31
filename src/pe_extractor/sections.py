import pefile
import json
import os
import argparse

# Các tên section bình thường của Windows PE
NORMAL_SECTIONS = {
    ".text", ".data", ".rdata", ".bss", ".rsrc",
    ".reloc", ".pdata", ".tls", ".idata", ".edata",
    ".didat", ".ndata", ".rodata", "_RDATA" # Thêm các section hợp lệ của compiler đời mới
}

# Tên section liên quan đến packer đã biết
PACKER_SECTIONS = {
    ".upx0", ".upx1", ".upx2", # UPX
    ".aspack", ".adata",       # ASPack
    ".mpress1", ".mpress2",    # MPRESS
    ".nsp0", ".nsp1",          # NsPack
    ".themida",                # Themida
    ".vmp0", ".vmp1", ".vmp2", # VMProtect
    ".enigma1", ".enigma2"     # Enigma Protector
}

def analyze_sections(filepath):
    """Phân tích từng section trong file PE, bổ sung tính năng đo Entropy"""
    
    result = {
        "filepath": filepath,
        "sections": [],
        "suspicious_flags": []
    }
    
    if not os.path.exists(filepath):
        result["error"] = "File không tồn tại."
        return result
        
    try:
        pe = pefile.PE(filepath)
        
        for section in pe.sections:
            # Tên section: decode bytes, bỏ null bytes
            name = section.Name.decode("utf-8", errors="replace").rstrip("\x00")
            
            # Permissions của section
            flags = section.Characteristics
            is_exec  = bool(flags & 0x20000000)  # Executable
            is_read  = bool(flags & 0x40000000)  # Readable
            is_write = bool(flags & 0x80000000)  # Writable
            
            # Kích thước ảo vs kích thước thật
            virtual_size = section.Misc_VirtualSize
            raw_size     = section.SizeOfRawData
            
            # Tính độ hỗn loạn (Entropy)
            entropy = section.get_entropy()
            
            # Tỉ lệ lệch giữa virtual và raw
            size_ratio = (virtual_size / raw_size) if raw_size > 0 else 0
            
            section_info = {
                "name":         name,
                "virtual_addr": hex(section.VirtualAddress),
                "virtual_size": virtual_size,
                "raw_size":     raw_size,
                "entropy":      round(entropy, 2),
                "size_ratio":   round(size_ratio, 2),
                "executable":   is_exec,
                "readable":     is_read,
                "writable":     is_write,
                "flags":        hex(flags),
            }
            
            # ── Phát hiện dấu hiệu đáng ngờ ─────────────────
            flags_list = []
            
            # 1. Tên section bất thường / Packer
            if name.lower() not in NORMAL_SECTIONS:
                if name.lower() in PACKER_SECTIONS:
                    flags_list.append("Packer section signature")
                else:
                    flags_list.append("Unknown section name")
            
            # 2. Section vừa writable vừa executable (W+X) -> Thường là nơi mã độc tự giải nén (Unpacking)
            if is_write and is_exec:
                flags_list.append("W+X permissions")
            
            # 3. Virtual size lớn hơn rất nhiều so với Raw size
            if size_ratio > 5 and raw_size > 1024:
                flags_list.append(f"Virtual/Raw ratio = {size_ratio:.1f}x (Possible unpacking space)")
            
            # 4. Raw size = 0 nhưng virtual size lớn (LOẠI TRỪ .bss vì đây là hành vi bình thường của nó)
            if raw_size == 0 and virtual_size > 0 and name.lower() not in [".bss", ".data"]:
                flags_list.append("Empty raw section (Unpacked at runtime?)")
                
            # 5. Entropy cao -> Dữ liệu bị nén hoặc mã hóa
            if entropy > 7.2:
                flags_list.append(f"High Entropy ({entropy:.2f}) -> Packed/Encrypted")
            
            section_info["suspicious_flags"] = flags_list
            result["sections"].append(section_info)
            
            # Lưu lại cảnh báo kèm theo tên section để dễ đọc ở báo cáo tổng
            if flags_list:
                for f in flags_list:
                    result["suspicious_flags"].append(f"[{name}] {f}")
        
        pe.close()
        
    except Exception as e:
        result["error"] = str(e)
    
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Phân tích PE Sections và phát hiện dấu hiệu Packer/Malware.")
    parser.add_argument("filepath", nargs="?", default=r"C:\Windows\System32\notepad.exe", help="Đường dẫn đến file PE.")
    parser.add_argument("--json", action="store_true", help="Xuất kết quả định dạng JSON.")
    args = parser.parse_args()
    
    data = analyze_sections(args.filepath)
    
    if args.json:
        print(json.dumps(data, indent=4, ensure_ascii=False))
    else:
        if "error" in data:
            print(f"[!] LỖI: {data['error']}")
            exit(1)
            
        print("="*80)
        print(f"[*] Phân tích Sections file: {data['filepath']}")
        print("="*80)
        
        # In tiêu đề bảng
        print(f"  {'NAME':<10} {'VIRTUAL':>10} {'RAW':>10}  {'ENTROPY':<8} {'PERM':<5}  {'WARNINGS'}")
        print("-" * 80)
        
        for s in data["sections"]:
            rwx = f"{'R' if s['readable'] else '-'}{'W' if s['writable'] else '-'}{'X' if s['executable'] else '-'}"
            
            flags_str = ""
            if s["suspicious_flags"]:
                flags_str = "← " + " | ".join(s["suspicious_flags"])
                
            print(f"  {s['name']:<10} "
                  f"{s['virtual_size']:10d} "
                  f"{s['raw_size']:10d}  "
                  f"{s['entropy']:<8.2f} "
                  f"{rwx:<5}  "
                  f"{flags_str}")
        
        # In tổng hợp cảnh báo
        if data["suspicious_flags"]:
            print("\n" + "="*80)
            print(f"[!] KẾT LUẬN: ĐÁNG NGỜ! TÌM THẤY {len(data['suspicious_flags'])} DẤU HIỆU BẤT THƯỜNG:")
            for flag in data["suspicious_flags"]:
                print(f"  - {flag}")
            print("="*80)
        else:
            print("\n[OK] Không phát hiện bất thường nào trong các Section.")