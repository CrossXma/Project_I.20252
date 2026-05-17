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

I.Windows

1.Recommended Architecture

	Host Machine
	│
	├── VirtualBox
	│   ├── Windows 10 VM (Analysis)
	│   └── Kali Linux VM (Tools/Scripts)

2.Recommended Specs

	Component	Recommendation
	RAM:	4–8 GB
	CPU:	2 cores
	Disk:	60 GB
	OS:	Windows 10 x64

3.Important Security Configuration:
Disable Network (VERY IMPORTANT)

Inside VirtualBox:

	Settings → Network
	Disable Adapter

OR use:

	Host-only Adapter

Never allow malware internet access during testing.

4.Disable Shared Features

Turn OFF:

	Shared clipboard
	Drag and drop
	Shared folders

5.Create Snapshots

After Windows installation:

	Machine → Take Snapshot

Snapshot name:

	Clean Windows

This allows instant recovery after malware execution.
