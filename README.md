# Project_I.20252
Safety Rules

NEVER:
	Execute on host machine,
  Enable internet,
  Double-click unknown samples

ALWAYS:
  Use password-protected ZIPs,
  Store in isolated VM,
  Keep snapshots

VirtualBox configurations

Recommended Architecture

	Host Machine
	│
	├── VirtualBox
	│   ├── Windows 10 VM (Analysis)
	│   └── Kali Linux VM (Tools/Scripts)

I.Windows VM

1.Recommended Specs

	Component	Recommendation
	RAM:	4–8 GB
	CPU:	2 cores
	Disk:	60 GB
	OS:	Windows 10 x64

2.Important Security Configuration:
Disable Network (VERY IMPORTANT)

Inside VirtualBox:

	Settings → Network
	Disable Adapter

OR use:

	Host-only Adapter

Never allow malware internet access during testing.

3.Disable Shared Features

Turn OFF:

	Shared clipboard
	Drag and drop
	Shared folders

4.Create Snapshots

After Windows installation:

	Machine → Take Snapshot

Snapshot name:

	Clean Windows

This allows instant recovery after malware execution.

II.Kali Linux VM

Download on kali.org

III.Tools

1.Kali Linux

	Python scripting
	PE parsing
	Disassembly
	YARA
	Reverse engineering

2.Windows

| Tool                 | Purpose                 |
| -------------------- | ----------------------- |
| PEStudio             | PE static analysis      |
| Detect It Easy (DIE) | Detect packers/compiler |
| Process Monitor      | Runtime monitoring      |
| Process Explorer     | Process inspection      |
| x64dbg               | Debugging               |
| Wireshark            | Network capture         |
| Strings              | Extract strings         |
