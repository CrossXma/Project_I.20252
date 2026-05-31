# scripts/week2_task4_iat.py
import pefile
import json

# Mapping: API → hành vi độc hại
SUSPICIOUS_APIS = {
    # Process Injection
    "VirtualAllocEx":       ("Process Injection", "HIGH"),
    "WriteProcessMemory":   ("Process Injection", "HIGH"),
    "CreateRemoteThread":   ("Process Injection", "HIGH"),
    "NtCreateThreadEx":     ("Process Injection", "HIGH"),
    "RtlCreateUserThread":  ("Process Injection", "HIGH"),
    
    # Process Hollowing
    "ZwUnmapViewOfSection": ("Process Hollowing", "HIGH"),
    "NtUnmapViewOfSection": ("Process Hollowing", "HIGH"),
    
    # Network
    "URLDownloadToFile":    ("Downloader",        "HIGH"),
    "InternetOpen":         ("Network Activity",  "MEDIUM"),
    "InternetConnect":      ("Network Activity",  "MEDIUM"),
    "HttpSendRequest":      ("Network Activity",  "MEDIUM"),
    "WSAStartup":           ("Network Activity",  "MEDIUM"),
    "connect":              ("Network Activity",  "MEDIUM"),
    
    # Persistence
    "RegSetValueEx":        ("Registry Write",    "MEDIUM"),
    "RegCreateKeyEx":       ("Registry Write",    "MEDIUM"),
    "CreateService":        ("Service Install",   "HIGH"),
    
    # Evasion
    "IsDebuggerPresent":    ("Anti-Debug",        "MEDIUM"),
    "CheckRemoteDebugger":  ("Anti-Debug",        "MEDIUM"),
    "NtQueryInformationProcess": ("Anti-Debug",   "MEDIUM"),
    "GetTickCount":         ("Anti-Sandbox",      "LOW"),
    "Sleep":                ("Anti-Sandbox",      "LOW"),
    
    # Ransomware
    "CryptEncrypt":         ("Encryption",        "HIGH"),
    "CryptGenKey":          ("Encryption",        "HIGH"),
    
    # Keylogger
    "SetWindowsHookEx":     ("Hooking/Keylogger", "HIGH"),
    "GetAsyncKeyState":     ("Keylogger",         "MEDIUM"),
}


def analyze_iat(filepath):
    """Phân tích Import Address Table"""
    
    result = {
        "filepath":          filepath,
        "imports":           {},       # DLL → [functions]
        "suspicious_apis":  [],
        "total_imports":     0,
        "total_dlls":        0,
    }
    
    try:
        pe = pefile.PE(filepath)
        
        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            result["note"] = "Không có IAT — có thể file bị packed"
            return result
        
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode("utf-8", errors="replace")
            functions = []
            
            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode("utf-8", errors="replace")
                else:
                    # Import by ordinal — không có tên
                    func_name = f"Ordinal_{imp.ordinal}"
                
                functions.append(func_name)
                result["total_imports"] += 1
                
                # Kiểm tra có phải API đáng ngờ không
                if func_name in SUSPICIOUS_APIS:
                    behavior, severity = SUSPICIOUS_APIS[func_name]
                    result["suspicious_apis"].append({
                        "api":      func_name,
                        "dll":      dll_name,
                        "behavior": behavior,
                        "severity": severity,
                    })
            
            result["imports"][dll_name] = functions
        
        result["total_dlls"] = len(result["imports"])
        pe.close()
        
    except Exception as e:
        result["error"] = str(e)
    
    return result


if __name__ == "__main__":
    import sys
    filepath = sys.argv[1] if len(sys.argv) > 1 else r"C:\Windows\System32\notepad.exe"
    
    data = analyze_iat(filepath)
    
    print(f"Tổng DLL: {data['total_dlls']} | Tổng hàm: {data['total_imports']}")
    
    if data.get("note"):
        print(f"\n[!] {data['note']}")
    
    print("\nImports:")
    for dll, funcs in data["imports"].items():
        print(f"\n  {dll} ({len(funcs)} functions):")
        for f in funcs[:5]:  # Chỉ in 5 hàm đầu
            print(f"    - {f}")
        if len(funcs) > 5:
            print(f"    ... và {len(funcs)-5} hàm khác")
    
    if data["suspicious_apis"]:
        print(f"\n[!] APIs đáng ngờ ({len(data['suspicious_apis'])}):")
        for api in data["suspicious_apis"]:
            print(f"  [{api['severity']:6s}] {api['api']:30s} → {api['behavior']}")
    else:
        print("\n[OK] Không phát hiện API đáng ngờ")