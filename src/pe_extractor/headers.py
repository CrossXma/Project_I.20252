# scripts/week2_task1_headers.py
import pefile
import datetime
import json

def extract_headers(filepath):
    """Trích xuất thông tin từ PE Headers"""
    
    result = {
        "filepath": filepath,
        "headers": {}
    }
    
    try:
        pe = pefile.PE(filepath)
        
        # ── File Header ──────────────────────────────────────
        fh = pe.FILE_HEADER
        
        # Machine type: x86 hay x64
        machine_map = {
            0x014c: "x86 (32-bit)",
            0x8664: "x64 (64-bit)",
            0x01c0: "ARM",
        }
        machine = machine_map.get(fh.Machine, f"Unknown ({hex(fh.Machine)})")
        
        # Timestamp: chuyển từ Unix timestamp sang ngày đọc được
        timestamp = datetime.datetime.fromtimestamp(
            fh.TimeDateStamp
        ).strftime("%Y-%m-%d %H:%M:%S")
        
        # Characteristics: EXE hay DLL?
        is_dll = bool(fh.Characteristics & 0x2000)
        is_exe = bool(fh.Characteristics & 0x0002)
        
        result["headers"]["file_header"] = {
            "machine":            machine,
            "compile_timestamp":  timestamp,
            "number_of_sections": fh.NumberOfSections,
            "is_dll":             is_dll,
            "is_exe":             is_exe,
            "characteristics":    hex(fh.Characteristics),
        }
        
        # ── Optional Header ──────────────────────────────────
        oh = pe.OPTIONAL_HEADER
        
        subsystem_map = {
            2: "GUI (Windows)",
            3: "Console (CLI)",
            1: "Native (Driver)",
        }
        subsystem = subsystem_map.get(oh.Subsystem, f"Other ({oh.Subsystem})")
        
        result["headers"]["optional_header"] = {
            "entry_point":   hex(oh.AddressOfEntryPoint),
            "image_base":    hex(oh.ImageBase),
            "image_size":    oh.SizeOfImage,
            "subsystem":     subsystem,
            "dll_characteristics": hex(oh.DllCharacteristics),
            # ASLR bật không? (quan trọng cho bảo mật)
            "aslr_enabled":  bool(oh.DllCharacteristics & 0x0040),
            "dep_enabled":   bool(oh.DllCharacteristics & 0x0100),
        }
        
        pe.close()
        
    except pefile.PEFormatError as e:
        result["error"] = f"Không phải file PE hợp lệ: {e}"
    except Exception as e:
        result["error"] = str(e)
    
    return result


# ── Chạy thử ─────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    filepath = sys.argv[1] if len(sys.argv) > 1 else r"C:\Windows\System32\notepad.exe"
    
    data = extract_headers(filepath)
    print(json.dumps(data, indent=2))