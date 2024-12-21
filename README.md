# MistLdr
Evasive AV/EDR Shellcode Loader In GO

All the NtApi calls are made using indirect syscalls using Acheron.
AES Encrypted Shellcode.
Dynamically Shellcode Retrieving

#Acheron Features:
1) Walk the PEB to retrieve the base address of in-memory ntdll.dll
2) Parse the exports directory to retrieve the address of each exported function
3) Calculate the system service number for each Zw* function
4) Enumerate unhooked/clean syscall;ret gadgets in ntdll.dll, to be used as trampolines
5) Creates the proxy instance, which can be used to make indirect (or direct) syscalls

Usage :
- paste shellcode.bin in same folder with aes.py and execute ```python3 aes.py``` it will generate keys and encrypted file. Replace keys in source code.
- Build Exe ``` go build``` build Dll ```go build -buildmode=c-shared -o MistLdr.dll``` i did also used garble to produce obfuscated Dll or EXE ```garble build -buildmode=c-shared -o MistLdr.dll```

Sophos XDR
![]([https://github.com/ZwNagi/MistLdr/blob/main/assets/mistldr.png?raw=true))

TrendMicro ApexOne
![]([https://github.com/ZwNagi/MistLdr/blob/main/assets/apexone.png?raw=true))

McAfee MVISION
![]([https://github.com/ZwNagi/MistLdr/blob/main/assets/mvision.png?raw=true))

#Credit & Refs:
- https://github.com/f1zm0/acheron
