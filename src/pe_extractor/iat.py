import pefile
import json
import os
import argparse

# Cập nhật và mở rộng Mapping API
SUSPICIOUS_APIS = {
    # Process Injection / Memory
    "VirtualAllocEx":       ("Process Injection", "HIGH"),
    "WriteProcessMemory":   ("Process Injection", "HIGH"),
    "CreateRemoteThread":   ("Process Injection", "HIGH"),
    "NtCreateThreadEx":     ("Process Injection", "HIGH"),
    "RtlCreateUserThread":  ("Process Injection", "HIGH"),
    "VirtualProtect":       ("Memory Manipulation", "MEDIUM"), # Thường dùng để unpack
    
    # Process Hollowing
    "ZwUnmapViewOfSection": ("Process Hollowing", "HIGH"),
    "NtUnmapViewOfSection": ("Process Hollowing", "HIGH"),
    
    # Execution (Thực thi lệnh)
    "CreateProcess":        ("Execution",         "HIGH"),
    "WinExec":              ("Execution",         "HIGH"),
    "ShellExecute":         ("Execution",         "HIGH"),
    
    # Network
    "URLDownloadToFile":    ("Downloader",        "HIGH"),
    "InternetOpen":         ("Network Activity",  "MEDIUM"),
    "InternetConnect":      ("Network Activity",  "MEDIUM"),
    "HttpSendRequest":      ("Network Activity",  "MEDIUM"),
    "WSAStartup":           ("Network Activity",  "MEDIUM"),
    "connect":              ("Network Activity",  "MEDIUM"),
    
    # Persistence (Leo thang & Bám trụ)
    "RegSetValueEx":        ("Registry Write",    "MEDIUM"),
    "RegCreateKeyEx":       ("Registry Write",    "MEDIUM"),
    "CreateService":        ("Service Install",   "HIGH"),
    "StartService":         ("Service Execution", "MEDIUM"),
    
    # Evasion (Né tránh)
    "IsDebuggerPresent":    ("Anti-Debug",        "MEDIUM"),
    "CheckRemoteDebugger":  ("Anti-Debug",        "MEDIUM"),
    "NtQueryInformationProcess": ("Anti-Debug",   "MEDIUM"),
    "GetTickCount":         ("Anti-Sandbox",      "LOW"),
    "Sleep":                ("Anti-Sandbox",      "LOW"),
    
    # Ransomware / Crypto
    "CryptEncrypt":         ("Encryption",        "HIGH"),
    "CryptGenKey":          ("Encryption",        "HIGH"),
    
    # Keylogger / Spyware
    "SetWindowsHookEx":     ("Hooking/Keylogger", "HIGH"),
    "GetAsyncKeyState":     ("Keylogger",         "MEDIUM"),
    "GetForegroundWindow":  ("Spyware",           "LOW"),
    
    # Privilege
    "AdjustTokenPrivileges":("Privilege Esc",     "HIGH"),
}

def check_suspicious_api(func_name):
    """
    Kiểm tra API có nằm trong danh sách đáng ngờ không.
    Xử lý thông minh các hậu tố 'A' (ANSI) và 'W' (Wide).
    """
    if not func_name:
        return None
        
    # 1. Kiểm tra khớp chính xác
    if func_name in SUSPICIOUS_APIS:
        return SUSPICIOUS_APIS[func_name]
        
    # 2. Kiểm tra bỏ hậu tố A hoặc W (ví dụ: CreateProcessA -> CreateProcess)
    if func_name.endswith(('A', 'W')):
        base_name = func_name[:-1]
        if base_name in SUSPICIOUS_APIS:
            return SUSPICIOUS_APIS[base_name]
            
    # 3. Kiểm tra bỏ hậu tố Ex, ExA, ExW (ví dụ: RegCreateKeyExW -> RegCreateKeyEx)
    if func_name.endswith(('ExA', 'ExW')):
        base_name = func_name[:-1] # Thành Ex
        if base_name in SUSPICIOUS_APIS:
            return SUSPICIOUS_APIS[base_name]
            
    return None

def analyze_iat(filepath):
    """Phân tích Import Address Table"""
    
    result = {
        "filepath":          filepath,
        "imports":           {},       
        "suspicious_apis":   [],
        "total_imports":     0,
        "total_dlls":        0,
    }
    
    if not os.path.exists(filepath):
        result["error"] = "File không tồn tại."
        return result
        
    try:
        pe = pefile.PE(filepath)
        
        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            result["note"] = "Không có IAT — có thể file bị packed (nén/mã hóa)."
            return result
        
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode("utf-8", errors="replace").lower() # Đưa về chữ thường để dễ nhìn
            functions = []
            
            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode("utf-8", errors="replace")
                else:
                    func_name = f"Ordinal_{imp.ordinal}"
                
                functions.append(func_name)
                result["total_imports"] += 1
                
                # Kiểm tra API thông minh hơn
                suspicious_match = check_suspicious_api(func_name)
                if suspicious_match:
                    behavior, severity = suspicious_match
                    result["suspicious_apis"].append({
                        "api":      func_name,
                        "dll":      dll_name,
                        "behavior": behavior,
                        "severity": severity,
                    })
            
            result["imports"][dll_name] = functions
        
        result["total_dlls"] = len(result["imports"])
        pe.close() # Đóng file sau khi xử lý
        
    except Exception as e:
        result["error"] = str(e)
    
    return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Trích xuất và phân tích IAT của file PE.")
    parser.add_argument("filepath", nargs="?", default=r"C:\Windows\System32\notepad.exe", help="Đường dẫn đến file PE cần phân tích.")
    parser.add_argument("--json", action="store_true", help="Xuất kết quả ra định dạng JSON thay vì in ra terminal.")
    args = parser.parse_args()
    
    data = analyze_iat(args.filepath)
    
    if args.json:
        # Nếu dùng cờ --json, in ra JSON thuần túy (dùng để pipe sang file hoặc tool khác)
        print(json.dumps(data, indent=4, ensure_ascii=False))
    else:
        # In ra Terminal như cũ
        print("="*50)
        print(f"[*] Phân tích file: {data.get('filepath')}")
        
        if "error" in data:
            print(f"[!] LỖI: {data['error']}")
            exit(1)
            
        print(f"[*] Tổng DLL: {data['total_dlls']} | Tổng hàm: {data['total_imports']}")
        print("="*50)
        
        if data.get("note"):
            print(f"\n[!] {data['note']}")
        
        print("\n[+] Chi tiết Imports (Trích xuất):")
        for dll, funcs in data["imports"].items():
            print(f"\n  {dll} ({len(funcs)} functions):")
            for f in funcs[:3]:  # In 3 hàm đầu cho đỡ dài
                print(f"    - {f}")
            if len(funcs) > 3:
                print(f"    ... và {len(funcs)-3} hàm khác")
        
        if data["suspicious_apis"]:
            print("\n" + "="*50)
            print(f"[!] CẢNH BÁO: Phát hiện {len(data['suspicious_apis'])} APIs đáng ngờ:")
            for api in data["suspicious_apis"]:
                severity_color = api['severity']
                print(f"  [{severity_color:6s}] {api['api']:30s} → {api['behavior']} (từ {api['dll']})")
            print("="*50)
        else:
            print("\n[OK] Không phát hiện API đáng ngờ trong IAT.")