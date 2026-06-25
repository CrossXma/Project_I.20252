; Test decryption and injection assembly source code
global _start

_start:
    ; Anti-debugging
    call IsDebuggerPresent
    
    ; Process Enumeration Loop
    call CreateToolhelp32Snapshot
    call Process32First
    call Process32Next
    
    ; Process Injection / Hollowing
    call VirtualAlloc
    call WriteProcessMemory
    call ResumeThread

    ; Payload defined as raw bytes to be assembled and parsed via Capstone
    ; xor al, 0x5a   (34 5a)
    ; inc ecx        (41)
    ; jnz -6         (75 fa)
    db 0x34, 0x5a, 0x41, 0x75, 0xfa

    ; Suspicious strings defined as raw bytes
    db "vssadmin.exe delete shadows /all /quiet"
    db "cmd.exe"
