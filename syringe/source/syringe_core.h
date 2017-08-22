#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

#define CREATE_THREAD_ACCESS (PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ)
#define REMOTE_ASSEMBLY_STUB_LENGTH_RELEASE 32

DWORD InjectDLL(PCHAR pDll, DWORD dwProcessID);
DWORD InjectShellcode(PBYTE pShellcode, SIZE_T szShellcodeLength, DWORD dwProcessID);
DWORD ExecuteShellcode(PBYTE pShellcode, SIZE_T szShellcodeLength, BOOL quiet);
DWORD WINAPI RemoteExecPayloadStub(LPVOID lpParameter);
DWORD WINAPI LocalExecPayloadStub(LPVOID lpParameter);
