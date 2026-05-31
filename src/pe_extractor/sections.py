# scripts/week2_task2_sections.py
import pefile
import json

# Các tên section bình thường của Windows PE
NORMAL_SECTIONS = {
    ".text", ".data", ".rdata", ".bss", ".rsrc",
    ".reloc", ".pdata", ".tls", ".idata", ".edata"
}

# Tên section liên quan đến packer đã biết
PACKER_SECTIONS = {
    ".upx0", ".upx1", ".upx2",
    ".aspack", ".adata",
    ".mpress1", ".mpress2",
    ".nsp0", ".nsp1",
    ".themida",
}

def analyze_sections(filepath):
    """Phân tích từng section trong file PE"""
    
    result = {
        "filepath": filepath,
        "sections": [],
        "suspicious_flags": []
    }
    
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
            
            # Tỉ lệ lệch giữa virtual và raw (> 0.5 = đáng ngờ)
            if raw_size > 0:
                size_ratio = virtual_size / raw_size
            else:
                size_ratio = 0
            
            section_info = {
                "name":         name,
                "virtual_addr": hex(section.VirtualAddress),
                "virtual_size": virtual_size,
                "raw_size":     raw_size,
                "size_ratio":   round(size_ratio, 2),
                "executable":   is_exec,
                "readable":     is_read,
                "writable":     is_write,
                "flags":        hex(flags),
            }
            
            # ── Phát hiện dấu hiệu đáng ngờ ─────────────────
            flags_list = []
            
            # 1. Tên section bất thường
            if name.lower() not in NORMAL_SECTIONS:
                if name.lower() in PACKER_SECTIONS:
                    flags_list.append(f"Packer section: {name}")
                else:
                    flags_list.append(f"Unknown section name: {name}")
            
            # 2. Section vừa writable vừa executable (W+X)
            if is_write and is_exec:
                flags_list.append("W+X permissions (suspicious)")
            
            # 3. Virtual size >> Raw size (dấu hiệu unpacking)
            if size_ratio > 5:
                flags_list.append(f"Virtual/Raw ratio={size_ratio} (possible packer)")
            
            # 4. Raw size = 0 nhưng virtual size lớn
            if raw_size == 0 and virtual_size > 0:
                flags_list.append("Empty raw section (unpacked at runtime)")
            
            section_info["suspicious_flags"] = flags_list
            result["sections"].append(section_info)
            
            if flags_list:
                result["suspicious_flags"].extend(flags_list)
        
        pe.close()
        
    except Exception as e:
        result["error"] = str(e)
    
    return result


if __name__ == "__main__":
    import sys
    filepath = sys.argv[1] if len(sys.argv) > 1 else r"C:\Windows\System32\notepad.exe"
    
    data = analyze_sections(filepath)
    
    for s in data["sections"]:
        flags_str = " ← " + ", ".join(s["suspicious_flags"]) \
                    if s["suspicious_flags"] else ""
        print(f"  {s['name']:12s} "
              f"virt={s['virtual_size']:8d} "
              f"raw={s['raw_size']:8d} "
              f"rwx={'r' if s['readable'] else '-'}"
              f"{'w' if s['writable'] else '-'}"
              f"{'x' if s['executable'] else '-'}"
              f"{flags_str}")
    
    if data["suspicious_flags"]:
        print(f"\n[!] Cảnh báo: {data['suspicious_flags']}")