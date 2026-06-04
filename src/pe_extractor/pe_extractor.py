import os
import json
import hashlib
import math
import datetime
import pefile

def calculate_hashes(file_path):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            
    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest()
    }

def calculate_entropy(data):
    if not data:
        return 0.0
    
    entropy = 0

    length = len(data)
    frequencies = [0] * 256

    for byte in data:
        frequencies[byte] += 1

    for count in frequencies:
        if count > 0:
            p = float(count) / length
            entropy -= p * math.log(p, 2)

    return round(entropy, 4)

def extract_pe_info(file_path):
    if not os.path.exists(file_path):
        return {"error": f"File {file_path} khong ton tai."}

    features = {}
    
    # Ten + Kthc + Hash
    features["file_info"] = {
        "file_name": os.path.basename(file_path),
        "file_size_bytes": os.path.getsize(file_path),
        **calculate_hashes(file_path)
    }

    
    pe = pefile.PE(file_path)
    
    # Header
  
    compile_time = datetime.datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp, tz=datetime.timezone.utc).isoformat()
 

    features["headers"] = {
        "machine": pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, f"Unknown ({hex(pe.FILE_HEADER.Machine)})"),
        "compile_time": compile_time,
        "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
        "number_of_sections": pe.FILE_HEADER.NumberOfSections,
        "subsystem": pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem, f"Unknown ({pe.OPTIONAL_HEADER.Subsystem})"),
        "imphash": pe.get_imphash()  # Hash của bảng import --> nhóm các mẫu mã độc
    }

    # Sections
    features["sections"] = []

    for section in pe.sections:
        section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
        section_data = section.get_data()
        
        # Quyen R W X
        characteristics = []
        char_val = section.Characteristics

        if char_val & 0x40000000: characteristics.append("READ")
        if char_val & 0x80000000: characteristics.append("WRITE")
        if char_val & 0x20000000: characteristics.append("EXECUTE")

        features["sections"].append({
            "name": section_name,
            "virtual_address": hex(section.VirtualAddress),
            "virtual_size": section.Misc_VirtualSize,
            "raw_size": section.SizeOfRawData,
            "entropy": calculate_entropy(section_data),
            "characteristics": characteristics
        })

    # IAT
    features["imports"] = {}

    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8', errors='ignore')
            features["imports"][dll_name] = []

            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode('utf-8', errors='ignore')

                else:
                    func_name = f"ordinal_{imp.ordinal}"

                features["imports"][dll_name].append(func_name)

    #  export
    features["exports"] = []

    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                func_name = exp.name.decode('utf-8', errors='ignore')

            else:
                func_name = f"ordinal_{exp.ordinal}"
                
            features["exports"].append({
                "name": func_name,
                "address": hex(pe.OPTIONAL_HEADER.ImageBase + exp.address)
            })

    pe.close()
    return features

def process_multiple_files(file_paths, output_json_path):
    combined_results = {}

    for path in file_paths:
        features = extract_pe_info(path)
        
        
        if "error" in features and not features.get("file_info"):
            key = path #Khong cos sha256 thi dung path
        else:
            key = features["file_info"]["sha256"]

        combined_results[key] = features

    with open(output_json_path, 'w', encoding='utf-8') as f:
        json.dump(combined_results, f, indent=4, ensure_ascii=False)
        


if __name__ == "__main__":

    #Chinh duong dan o day

    folder_path = "./my_malware_samples" #<---
    files_to_analyze = []
    
    if os.path.exists(folder_path):
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                if file.lower().endswith(('.exe', '.dll', '.sys')):
                    files_to_analyze.append(os.path.join(root, file))

    output_file = "pe_features.json" # Ten file tra ve
    
    if files_to_analyze:
        process_multiple_files(files_to_analyze, output_file)
    else:
        print("Cannot find any files")