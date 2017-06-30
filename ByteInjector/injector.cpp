#include "injector.h"

// Static templated members must be explicitly declared in a source file
CInjector::ProcessMap_t CInjector::processes;
CInjector::ProcessList_t CInjector::processNames;

CInjector::CInjector()
{

}

CInjector::~CInjector()
{

}

// Injects the dll specified by dllPath into the target process
int CInjector::Inject(std::wstring dllPath, std::wstring processName, DWORD pId)
{
	HANDLE hProc, hThread;
	HMODULE hModule;
	int len;
	void* pRemoteString;
	FARPROC pLoadLibrary;
	std::wstring dllName = StripPath(dllPath);

	try {
		// if pId not already specified, look for it
		if (!pId) {
			pId = GetProcessIdByName(processName);
		}
		
		// if its still not found, serious error, abort
		if (!pId) {
			throw std::exception("Process ID not found");
		}

		// Open the process & get the process handle
		hProc = OpenProcess(CREATE_THREAD_ACCESS, 0, pId);

		if (!hProc) {
			throw std::exception("Could not open process!");
		}

		// Allocate remote memory for remote string
		len = dllPath.length() + 2;
		
		pRemoteString = VirtualAllocEx(hProc, 0, len * sizeof(wchar_t), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (!pRemoteString) {
			throw std::exception("Could not allocate remote memory!");
		}

		// Write a remote string of the dll path
		if (!WriteProcessMemory(hProc, pRemoteString, (void*)dllPath.c_str(), len * sizeof(wchar_t), 0)) {
			throw std::exception("Could not write remote string!");
		}

		// Create remote thread of loadlibrary with path as paramater
		pLoadLibrary = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
		if (!pLoadLibrary) {
			throw std::exception("Could not find address of LoadLibraryW!");
		}

		hThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, pRemoteString, 0, 0);
		if (!hThread) {
			throw std::exception("Could not create remote thread!");
		}

		// Wait for the thread return code (HMODULE of loaded module)
		WaitForSingleObject(hThread, INFINITE);
		GetExitCodeThread(hThread, (DWORD*)&hModule);

		// Add the module to the process's module map
		if (hModule) {
			processes[processName].hProc = hProc;
			processes[processName].name = processName;
			processes[processName].modules[dllName] = hModule;
		}

		// Clean up
		VirtualFreeEx(hProc, pRemoteString, len * sizeof(wchar_t), MEM_FREE);
		CloseHandle(hProc);

		// Return true if module loaded succesfully, false otherwise
		return reinterpret_cast<int>(hModule);
	}
	catch (std::exception e) {
		VirtualFreeEx(hProc, pRemoteString, len * sizeof(wchar_t), MEM_FREE);
		CloseHandle(hProc);

		throw;
	}
}

// Injects the dll specified by dllPath after creating the target process
int CInjector::InjectAuto(std::wstring dllPath, std::wstring processPath)
{
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&pi, sizeof(pi));
	ZeroMemory(&si, sizeof(si));

	si.cb = sizeof(si);

	try {
		std::wstring exeDirectory = StripFile(processPath);
		SetCurrentDirectoryW(exeDirectory.c_str());

		// Create the process
		if (!CreateProcessW(0,
			const_cast<LPWSTR>(processPath.c_str()),
			0,
			0,
			false,
			CREATE_SUSPENDED,
			0,
			0,
			&si,
			&pi)) throw std::exception("Could not create process");

		// Inject the dll by specific process Id
		std::wstring processName = StripPath(processPath);
		int bInjected = Inject(dllPath, processName, pi.dwProcessId);

		// Resume
		ResumeThread(pi.hThread);

		return bInjected;
	}
	catch (std::exception e) {
		TerminateProcess(pi.hProcess, 0);
		throw;
	}
}

// Unloads an injected (not arbitrary) dll from the target process
int CInjector::Unload(std::wstring dllName, std::wstring processName)
{
	dllName = StripPath(dllName);
	HMODULE hModule = processes[processName].modules[dllName];

	// That dll hasnt been loaded, dont unload
	if (!hModule) {
		return 0;
	}

	// Unload the dll

	HANDLE hProc, hThread;
	DWORD pId, dwExit = 0;
	FARPROC pFreeLibrary;

	try {
		// if pId not already specified, look for it
		pId = GetProcessIdByName(processName);
		
		// if its still not found, serious error, abort
		if (!pId) {
			throw std::exception("Process ID not found");
		}

		// Open the process & get the process handle
		hProc = OpenProcess(CREATE_THREAD_ACCESS, 0, pId);

		if (!hProc) {
			throw std::exception("Could not open process!");
		}

		// Create remote thread of loadlibrary with path as paramater
		pFreeLibrary = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "FreeLibrary");
		if (!pFreeLibrary) {
			throw std::exception("Could not find address of FreeLibrary!");
		}

		hThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)pFreeLibrary, (void*)hModule, 0, 0);
		if (!hThread) {
			throw std::exception("Could not create remote thread!");
		}

		// Wait for the thread return code (result of FreeLibrary)
		WaitForSingleObject(hThread, INFINITE);
		GetExitCodeThread(hThread, &dwExit);

		// Remove the module from the process module map
		if (dwExit) {
			processes[processName].modules[dllName] = 0;
		}

		// Clean up
		CloseHandle(hProc);

		// Return true if module unloaded succesfully, false otherwise
		return dwExit;
	}
	catch (std::exception e) {
		CloseHandle(hProc);

		throw;
	}

	return 1;
}

// Scans all processes in the system and stores them in a list (by name)
int CInjector::RefreshProcessList()
{
	// Clear the old list to make space for updated one
	processNames.clear();

	HANDLE hSnap;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	try {
		// Create a system wide snapshot of all processes
		hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (!hSnap) {
			throw std::exception("Could not create process snapshot");
		}

		// Iterate the process list and add the names to our list
		if (!Process32FirstW(hSnap, &pe32)) {
			throw std::exception("Enumerating processes failed");
		}

		do {
			processNames.push_back(pe32.szExeFile);
		} while (Process32NextW(hSnap, &pe32));

		CloseHandle(hSnap);
		return 1;
	}
	catch (std::exception e) {
		CloseHandle(hSnap);
		throw;
	}
}

// Returns a string list of all processes since the last refresh
CInjector::ProcessList_t CInjector::GetProcessList()
{
	RefreshProcessList();

	return processNames;
}

// Returns a process id based on the process name eg notepad.exe
DWORD CInjector::GetProcessIdByName(std::wstring processName)
{
	HANDLE hSnap;
	DWORD pId = 0;
	PROCESSENTRY32W pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	try {
		// Create a system wide snapshot of all processes
		hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (!hSnap) {
			throw std::exception("Could not create process snapshot");
		}

		// Iterate the process list and add the names to our list
		if (!Process32FirstW(hSnap, &pe32)) {
			throw std::exception("Enumerating processes failed");
		}

		do {
			if (std::wstring(pe32.szExeFile) == processName) {
				pId = pe32.th32ProcessID;
				break;
			}
		} while (Process32NextW(hSnap, &pe32));

		CloseHandle(hSnap);
		return pId;
	}
	catch (std::exception e) {
		CloseHandle(hSnap);
		throw;
	}
}

// Strips the leading path and returns only the filename
std::wstring CInjector::StripPath(std::wstring filePath)
{
	unsigned int pos = -1;
	unsigned int k = 0;
	for (k = 0; k < filePath.length(); k++)
		if (filePath[k] == L'\\')
			pos = k;

	if (pos != -1) {
		return filePath.substr(pos+1, filePath.length() - pos);
	} else {
		return filePath;
	}
}

// Strips the filename and leaves the path
std::wstring CInjector::StripFile(std::wstring filePath)
{
	unsigned int pos = -1;
	unsigned int k = 0;
	for (k = 0; k < filePath.length(); k++)
		if (filePath[k] == L'\\')
			pos = k;

	if (pos != -1) {
		return filePath.substr(0, pos+1);
	} else {
		return L"";
	}
}