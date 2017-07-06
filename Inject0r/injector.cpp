#include "injector.h"

bool FindProcessByName(string strProcessname, DWORD &_dwProcessID)
{
	std::wstring szTempName = std::wstring(strProcessname.begin(), strProcessname.end());
	const wchar_t* wszName = szTempName.c_str();

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	PROCESSENTRY32 ProcEntry;
	ProcEntry.dwSize = sizeof(ProcEntry);

	do
		if (!wcscmp(ProcEntry.szExeFile, wszName))
		{
			CloseHandle(hSnapshot);
			_dwProcessID = ProcEntry.th32ProcessID;
			return true;
		}
	while (Process32Next(hSnapshot, &ProcEntry));

	return false;
}

bool Injector::Inject(string strProcessName, string strDLLPath)
{
	DWORD dwProcessID, dwMemSize;
	HANDLE hProcess;
	LPVOID lpRemoteMemory, lpLoadLibrary;
	char szPath[MAX_PATH];

	if (!FindProcessByName(strProcessName, dwProcessID))
		return false;

	GetFullPathNameA(strDLLPath.c_str(), MAX_PATH, szPath, NULL);

	if (_access(szPath, 0) != 0)
		return false;

	dwMemSize = strlen(szPath) + 1;
	hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, FALSE, dwProcessID);
	lpRemoteMemory = VirtualAllocEx(hProcess, NULL, dwMemSize, MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(hProcess, lpRemoteMemory, (LPCVOID)szPath, dwMemSize, NULL);
	lpLoadLibrary = GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryA");

	if (CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)lpLoadLibrary, lpRemoteMemory, NULL, NULL))
	{
		VirtualFreeEx( hProcess, ( LPVOID ) lpRemoteMemory, 0, MEM_RELEASE );
		CloseHandle(hProcess);
		return true;
	}
	else 
		return false;
}