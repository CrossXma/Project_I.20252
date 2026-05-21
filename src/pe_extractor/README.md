
# PE Extractor





## Execution

To execute the program, run: 
```
  python pe_extractor.py [--OPTION] [PATH/DIRECTORY]
```
#### Options
Analyze a single file
```
 --file [PATH]
```

Save the result into a specific file path
```
 --out [PATH]
```

Malware/Benign directory
```
 --malware-dir [DIRECTORY]
 --benign-dir [DIRECTORY]
```

Help
```
 --help
```
## Output Format

Example JSON structure: 

```bash
  {
  "filename": "sample.exe",
  "sha256": "...",
  "md5": "...",
  "header": {},
  "sections": {},
  "iat": {},
  "packer_detection": {}
  "label: "..."
}
```


## Features

### 1. Shannon Entropy Calculation

The program computes Shannon Entropy to detect:

- Packed binaries
- Encrypted payloads
- Compressed sections

Entropy formula:
```H = −∑p(x)log2​(p(x))```

Typical entropy range:

- Near ```0``` → simple/repetitive data
- Near ```8``` → highly randomized data (packed/encrypted)



### 2. Extract Header Feature

Function:
```
extract_header_features(pe)
```

Extract important metadata from 
```FILE_HEADER```
and ```OPTIONAL_HEADER```

Collect information includes: 
- Architecture (x86, x64, ARM)
- Entry Point
- Image Base
- Number of Sections
- Subsystem type
- Security protections:
    - ASLR
    - DEP/NX
    - CFG
- etc...
### 3. Sections Analysis

Function:
```
extract_section_features(pe)
```

Analyzes all PE sections and extracts:

- Section name
- Virtual address/size
- Raw size
- Memory permissions (readable, writable, executable)
- Entropy
- Entry Point location
- Suspicious Indicators


The function detects:

- High entropy sections
- Unknown section names
- Known packer signatures (UPX, ASPack, Themida, PECompact)
- Write + Execute (W+X) sections
- Runtime unpacking behavior
- Abnormal VirtualSize / RawSize ratio

Returns a dictionary containing detailed information about all PE sections and suspicious section-based indicators.
### 4. Import Address Table (IAT) Analysis

Function:
```
extract_iat_features(pe)
```


Extracts:

- Imported DLLs
- Imported APIs
- Total imported functions
- Suspicious API groups (based on given ```SUSPICIOUS_API_GROUPS```)
### 5. Packer Detection System

Function:
```
def detect_packer(section_features, iat_features)
```
The project uses a heuristic scoring system to determine whether a PE file is packed.

Indicators include:

- High entropy
- W+X sections
- Section size anomalies
- Known packer section names
- Extremely small import tables
- Entry Point outside .text

A file is classified as packed when  ```score ≥ 40```


### 6. PE File Analysis

Function:
```
def analyze_pe_file(filepath)
```

It processes a single PE file and returns a complete feature set used for malware analysis and packer detection.

Analysis Workflow
```
Input File
    ↓
Validate File
    ↓
Check "MZ" Signature
    ↓
Calculate Hashes
    ↓
Parse PE Structure
    ↓
Extract Features
    ├── Header Features
    ├── Section Features
    ├── IAT Features
    └── Packer Detection
    ↓
Generate JSON-Compatible Result
```


Return all extracted information as a structured dictionary

### 7. Batch Processing 
Function:
```
run_batch_analysis(dataset_dir, label, output_dir)
```

Batch Processing Workflow
```
Dataset Directory
    ↓
Enumerate Files
    ↓
Analyze Each File
    ├── Valid PE → Extract Features
    ├── Non-PE → Skip
    └── Parse Failure → Log Error
    ↓
Save JSON Reports
    ↓
Generate Summary Statistics
```