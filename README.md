
# PE Extractor






## File Structure

```

ROOT\                      ←  Root directory of the project (E.g: D:\Documents\Project_1)
│
├── output
|   ├── malware_index.json           ← Created by rebuild_index.py
|   ├── results.json                 ← Created by pipeline.py
│
├── dataset
|   ├── malware\                     ← UNZIPED .exe files  
    |   ├── ransomware\
    │   |   ├── 789xyz...exe
    │   |   └── ...
    |   |
    |   ├── trojan\                      
    |   |   ├── abc123...exe
    |   |   └── ...
    |   |
    |   ├── botnet\                 
    |   |   ├── abc123...exe
    |   |   └── ...
    |   |
    |   ├── rat\ 
    |   |   └── ...
    |   |
    |   ├── rootkit\ 
    |   |   └── ...
    |   |
    |   ├── spyware\ 
    |   |
    |   |   └── ...
    |   |
    |   ├── worm\ 
    |   |   └── ...
    |   |
    ├── benign\                         ← Benign files from System32
    |   ├── .exe
|   |   └── .dll
|   |                    
|── src\                                ← SOURCECODE
        ├──pe_extractor
        |   ├── headers.py
        |   ├── sections.py
        |   ├── entropy.py
        |   ├── iat.py
        |   ├── packer.py
        |   ├── pipeline.py             ← File-to-run
        |
        └── rebuild_index.py            ← File-to-run
```


## Requirements

- Enviroment: Window 10 VM (VirtualBox/VMWare)
- Detect It Easy (DIE) has already added to PATH

#### Open ```powershell``` as ```Administrator```, TURN OFF Window Defender

```
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableBehaviorMonitoring $true
Set-MpPreference -DisableBlockAtFirstSeen $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisablePrivacyMode $true
Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true
Set-MpPreference -DisableArchiveScanning $true
Set-MpPreference -DisableIntrusionPreventionSystem $true
Set-MpPreference -DisableScriptScanning $true
Set-MpPreference -SubmitSamplesConsent NeverSend
```
Confirmation
```
Get-MpPreference | Select-Object DisableRealtimeMonitoring DisableBehaviorMonitoring, DisableIOAVProtection
```

The results displayed must be ```True```

#### Add exclusion path
```
Add-MpPreference -ExclusionPath [ROOT]
```

Example
```
Add-MpPreference -ExclusionPath "D:\Documents\Project_1"
```

Then restart the computer
```
Restart-Computer
```



## Installation
#### Run ```rebuild_index.py```, enter the path of your dataset:
```
[ROOT]\dataset
```

Example:
```
D:\Documents\Project_1\dataset
```

The output is a ```malware_index.json``` file that includes all information of each file saved in ```[ROOT]\output```

------

#### Run ```pipeline.py```, enter the path of your ROOT folder
```
[ROOT]
```

Example
```
D:\Documents\Project_1\Project_1\
```
The output is a ```results.json``` file that includes all pe header information of each file saved in ```[ROOT]\output``` 