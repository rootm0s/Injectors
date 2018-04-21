#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>
#include "fheaders.h"

DWORD demoNtCreateThreadEx(PCWSTR pszLibFile, DWORD dwProcessId)
{
	HANDLE hRemoteThread = NULL;
	NtCreateThreadExBuffer ntbuffer;
	LARGE_INTEGER dwTmp1 = { 0 };
	LARGE_INTEGER dwTmp2 = { 0 };

	memset(&ntbuffer, 0, sizeof(NtCreateThreadExBuffer));

	DWORD dwSize = (lstrlenW(pszLibFile) + 1) * sizeof(wchar_t);

	HANDLE hProcess = OpenProcess(
		PROCESS_QUERY_INFORMATION |
		PROCESS_CREATE_THREAD |
		PROCESS_VM_OPERATION |
		PROCESS_VM_WRITE,
		FALSE, dwProcessId);

	if (hProcess == NULL)
	{
		wprintf(TEXT("[-] Error: Could not open process for PID (%d).\n"), dwProcessId);
		return(1);
	}

	LPVOID pszLibFileRemote = (PWSTR)VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
	if (pszLibFileRemote == NULL)
	{
		wprintf(TEXT("[-] Error: Could not allocate memory inside PID (%d).\n"), dwProcessId);
		return(1);
	}

	int n = WriteProcessMemory(hProcess, pszLibFileRemote, (LPVOID)pszLibFile, dwSize, NULL);
	if (n == 0)
	{
		wprintf(TEXT("[-] Error: Could not write any bytes into the PID (%d) address space.\n"), dwProcessId);
		return(1);
	}

	PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");
	if (pfnThreadRtn == NULL)
	{
		wprintf(TEXT("[-] Error: Could not find LoadLibraryA function inside kernel32.dll library.\n"));
		return(1);
	}

	PTHREAD_START_ROUTINE ntCreateThreadExAddr = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtCreateThreadEx");
	if (pfnThreadRtn == NULL)
	{
		wprintf(TEXT("[-] Error: Could not find NtCreateThreadEx function inside ntdll.dll library.\n"));
		return(1);
	}

	if (ntCreateThreadExAddr)
	{
		ntbuffer.Size = sizeof(struct NtCreateThreadExBuffer);
		ntbuffer.Unknown1 = 0x10003;
		ntbuffer.Unknown2 = 0x8;
		ntbuffer.Unknown3 = (DWORD*)&dwTmp2;
		ntbuffer.Unknown4 = 0;
		ntbuffer.Unknown5 = 0x10004;
		ntbuffer.Unknown6 = 4;
		ntbuffer.Unknown7 = (DWORD*)&dwTmp1;
		ntbuffer.Unknown8 = 0;

		LPFUN_NtCreateThreadEx funNtCreateThreadEx = (LPFUN_NtCreateThreadEx)ntCreateThreadExAddr;

		NTSTATUS status = funNtCreateThreadEx(
			&hRemoteThread,
			0x1FFFFF,
			NULL,
			hProcess,
			pfnThreadRtn,
			(LPVOID)pszLibFileRemote,
			FALSE,
			NULL,
			NULL,
			NULL,
			NULL
			);

#ifdef _DEBUG
		wprintf(TEXT("[+] Status: %s\n"), status);
#endif
		if (status != NULL)		// FIXME: always returns NULL even when it suceeds. Go figure.
		{
			wprintf(TEXT("[-] NtCreateThreadEx Failed! [%d][%08x]\n"), GetLastError(), status);
			return(1);
		}
		else
		{
			wprintf(TEXT("[+] Success: DLL injected via NtCreateThreadEx().\n"));
			WaitForSingleObject(hRemoteThread, INFINITE);
		}
	}

	if (pszLibFileRemote != NULL)
		VirtualFreeEx(hProcess, pszLibFileRemote, 0, MEM_RELEASE);

	if (hRemoteThread != NULL)
		CloseHandle(hRemoteThread);

	if (hProcess != NULL)
		CloseHandle(hProcess);

	return(0);
}