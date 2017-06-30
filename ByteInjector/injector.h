#ifndef INC_INJECTOR
#define INC_INJECTOR

#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <sstream>
#include <map>
#include <list>

class CInjector {
	enum { CREATE_THREAD_ACCESS = (PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
								PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_OPERATION |
								PROCESS_VM_WRITE | PROCESS_VM_READ) };

	typedef std::map<std::wstring,HMODULE> ModuleMap_t;			// Map of all injected modules (by name) in a process

	struct Process_t {											// Structure to describe a process
		HANDLE hProc;			// Process handle
		std::wstring name;		// eg. notepad.exe
		ModuleMap_t modules;	// All injected modules
	};

	typedef std::map<std::wstring,Process_t> ProcessMap_t;		// Map (by name) of processes with injected dll's

	public:
		typedef std::list<std::wstring> ProcessList_t;			// List of all process names

	public:
		CInjector();
		~CInjector();

		int Inject(std::wstring dllPath, std::wstring processName, DWORD pId = 0);
		int InjectAuto(std::wstring dllPath, std::wstring processPath);
		int Unload(std::wstring dllName, std::wstring processName);
		int RefreshProcessList();
		ProcessList_t GetProcessList();

	private:
		DWORD GetProcessIdByName(std::wstring processName);
		std::wstring StripPath(std::wstring filePath);
		std::wstring StripFile(std::wstring fullPath);
		int SetDebugPrivilege();

		static ProcessMap_t processes;
		static ProcessList_t processNames;


};

#endif