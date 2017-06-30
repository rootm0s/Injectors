// ncloader.c: A dll loading utility
// Nicolas Guigo
// iSECPartners 2014

#pragma warning( disable : 4711) // disable informational warning. Leaving inlining up to compiler.
// #pragma warning( disable : 4191) /* uncomment to compile as c++ with /Wall and no warnings */

#define WIN32_LEAN_AND_MEAN
#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>
#include <Windows.h>
#include <Psapi.h>

#ifdef UNICODE
#define LOADLIBRARY "LoadLibraryW"
#else
#define LOADLIBRARY "LoadLibraryA"
#endif
#define TIMEOUT_10SEC 10000
#define QUITE_LARGE_NB_PROCESSES 256
#define SOME_SYSTEM_PROCESS_IN_CURRENT_SESSION _T("winlogon.exe")
#define INJECTION_RIGHTS (PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|PROCESS_VM_OPERATION|PROCESS_VM_READ|PROCESS_VM_WRITE)
#define IDENTIFICATION_RIGHTS (PROCESS_QUERY_INFORMATION|PROCESS_VM_OPERATION|PROCESS_VM_READ)

// Function prototypes
VOID Usage(LPTSTR);
BOOL IsPrivilegePresent(HANDLE, LUID);
BOOL ToggleDebugPrivilege(BOOL);
BOOL FillProcessesListWithAlloc(PDWORD*, DWORD, PDWORD);
DWORD FillProcessesList(PDWORD*, DWORD);
BOOL GetProcessbyNameOrId(LPTSTR, PHANDLE, DWORD);
BOOL TogglePrivilege(HANDLE, LPTSTR, BOOL);
BOOL IsProcessInSession0(HANDLE);
DWORD InjectDll(LPTSTR, LPTSTR);
DWORD CreateProcessInSession0(LPTSTR);
BOOL CraftSession0Token(HANDLE, PHANDLE);
BOOL ImpersonateSystem(HANDLE);
DWORD GetProcessSession(HANDLE);
BOOL GetSystemToken(PHANDLE);

// Usage
VOID Usage(LPTSTR path)
{
  TCHAR exename[_MAX_FNAME];

  _tsplitpath_s(path, (LPTSTR)NULL, 0, (LPTSTR)NULL, 0, (LPTSTR)&exename, _MAX_FNAME, (LPTSTR)NULL, 0);
  _tprintf(_T("%s [process name | pid] [dll full path] [1]\nnote: the optional trailing '1' disables elevation attempt"), exename);
  return;
}

// Returns handle to existing system token from winlogon
BOOL GetSystemToken(PHANDLE phSystemToken)
{
    BOOL bResult=FALSE;
    HANDLE hWinlogonProcess, hWinlogonToken;

    // In theory only PROCESS_QUERY_INFORMATION is necessary (but that's in theory)
    bResult = GetProcessbyNameOrId(SOME_SYSTEM_PROCESS_IN_CURRENT_SESSION, &hWinlogonProcess, PROCESS_ALL_ACCESS);
    if(bResult) {
      bResult = OpenProcessToken(hWinlogonProcess, TOKEN_DUPLICATE, &hWinlogonToken);
      if(bResult) {
        *phSystemToken = hWinlogonToken;
      }
      else {
        _tprintf(_T("Failed to get winlogon token handle with error %#.8x\n"), GetLastError());
      }
      CloseHandle(hWinlogonProcess);
    }
    else {
      _tprintf(_T("Failed to get handle to winlogon with error %#.8x\n"), GetLastError());
    }
    return bResult;
}

// The system token used by the session 0 process
BOOL CraftSession0Token(HANDLE hSystemToken, PHANDLE phSession0Token)
{
  BOOL bResult=FALSE;
  HANDLE hSession0Token;
  DWORD session0=0;

  // Clone the primary system token...
  // TODO: ALL ACCESS -> minimum necessary
  bResult = DuplicateTokenEx(hSystemToken, TOKEN_ALL_ACCESS, NULL, SecurityAnonymous, TokenPrimary, &hSession0Token);
  if(bResult) {
    // And switch the clone to session 0
    bResult = SetTokenInformation(hSession0Token, TokenSessionId, &session0, sizeof(session0));
    if(bResult) {
      *phSession0Token=hSession0Token;
    }
    else {
      CloseHandle(hSession0Token);
      _tprintf(_T("Failed to adjust session id in process token with error %#.8x\n"), GetLastError());
    }
  }
  else {
    _tprintf(_T("Failed to duplicate token with error %#.8x\n"), GetLastError());
  }
  return bResult;
}

// Impersonate system and enable 2 privileges
BOOL ImpersonateSystem(HANDLE hSystemToken)
{
  BOOL bResult=FALSE;
  HANDLE hSystemImpersonationToken;

  // Create an impersonation token from the primary system token
  bResult = DuplicateTokenEx(hSystemToken, TOKEN_READ|TOKEN_IMPERSONATE|TOKEN_ADJUST_PRIVILEGES, NULL, SecurityImpersonation, TokenImpersonation, &hSystemImpersonationToken);
  if(bResult) {
    // This privilege is needed to adjust token's session id (it should already be enabled)
    bResult = TogglePrivilege(hSystemImpersonationToken, SE_TCB_NAME, TRUE);
    if(bResult) {
      // Both privileges are required to create process in session 0 ("increase quota" should already be enabled)
      bResult = TogglePrivilege(hSystemImpersonationToken, SE_ASSIGNPRIMARYTOKEN_NAME, TRUE);
      if(bResult) {
        bResult = TogglePrivilege(hSystemImpersonationToken, SE_INCREASE_QUOTA_NAME, TRUE);
        if(bResult) {
          bResult = ImpersonateLoggedOnUser(hSystemImpersonationToken);
          if(!bResult) {
            _tprintf(_T("Failed to impersonate system with error %#.8x\n"), GetLastError());
          }
        }
        else {
          _tprintf(_T("Failed to enable increase quota privilege with error %#.8x\n"), GetLastError());
        }
      }
      else {
        _tprintf(_T("Failed to enable assign primary token privilege with error %#.8x\n"), GetLastError());
      }
    }
    CloseHandle(hSystemImpersonationToken);
  } // if duplicatetokenex
  else {
    _tprintf(_T("Failed to create impersonation system token with error %#.8x\n"), GetLastError());
  }
  return bResult;
}

// Creates the session 0 process that will perform the injection
DWORD CreateProcessInSession0(LPTSTR lpCommandLine)
{
  BOOL bResult=FALSE;
  HANDLE hSystemToken, hSystemSession0PrimaryToken;
  STARTUPINFO si;
  PROCESS_INFORMATION pi;
  DWORD waitResult, dwResult=ERROR_UNIDENTIFIED_ERROR;

  bResult = GetSystemToken(&hSystemToken);
  if(bResult) {
    // Impersonate system with enough privileges to create process in sessions 0
    bResult = ImpersonateSystem(hSystemToken);
    if(bResult) {
      // This thread is now running as system
      bResult = CraftSession0Token(hSystemToken, &hSystemSession0PrimaryToken);
      if(bResult) {
        ZeroMemory(&si, sizeof(STARTUPINFO));
        si.cb = sizeof(STARTUPINFO);
        // Use our system impersation privileges to create a process with a session 0 token
        bResult = CreateProcessAsUser(hSystemSession0PrimaryToken, NULL, lpCommandLine, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
        if(bResult) {
          waitResult = WaitForSingleObject(pi.hProcess, TIMEOUT_10SEC);
          if(waitResult==WAIT_OBJECT_0) {
            bResult = GetExitCodeProcess(pi.hProcess, &dwResult);
            if(!(bResult&&dwResult==ERROR_SUCCESS)) {
              if(bResult) {
                _tprintf(_T("Session 0 DLL injection failed with error %#.8x\n"), dwResult);
              }
              else {
                dwResult = GetLastError();
                _tprintf(_T("Could not get session 0 process return code, error %#.8x\n"), dwResult);
              }
            }
          }
          else {
            _tprintf(_T("Aborting: %s\n"), waitResult==WAIT_TIMEOUT ? _T("remote thread has been hung for 10 secs") : _T("wait failed"));
          }
          CloseHandle(pi.hProcess);
          CloseHandle(pi.hThread);
        } // if createprocessasuser
        else {
          dwResult = GetLastError();
          _tprintf(_T("Process creation in session 0 failed with error %#.8x\n"), dwResult);
        }
        CloseHandle(hSystemSession0PrimaryToken);
      }
      // End impersonation
      RevertToSelf();
    }
    else {
      dwResult = GetLastError();
      _tprintf(_T("Failed to impersonate system with error %#.8x\n"), dwResult);
    }
    CloseHandle(hSystemToken);
  } // if getsystemtoken
  return dwResult;
}

// Checks if privilege LUID is present in token
BOOL IsPrivilegePresent(HANDLE hToken, LUID luid)
{
  BOOL bResult=FALSE;
  PTOKEN_PRIVILEGES ptp=NULL;
  DWORD i, len=0, error;

  // This call cannot succeed
  bResult = GetTokenInformation(hToken, TokenPrivileges, ptp, len, &len);
  error = GetLastError();
  if(error==ERROR_INSUFFICIENT_BUFFER) {
    ptp = (PTOKEN_PRIVILEGES)HeapAlloc(GetProcessHeap(), 0, len);
    if(ptp) {
      bResult = GetTokenInformation(hToken, TokenPrivileges, ptp, len, &len);
      if(bResult) {
        bResult=FALSE;
        for(i=0; !bResult && i<ptp->PrivilegeCount; i++) {
          bResult = (ptp->Privileges[i].Luid.LowPart==luid.LowPart)&&(ptp->Privileges[i].Luid.HighPart==luid.HighPart);
        }
      } // if gettokeninformation
      else {
        _tprintf(_T("Failed to get token privileges with error %#.8x\n"), error);
      }
      HeapFree(GetProcessHeap(), 0, ptp);
    }
    else {
      _tprintf(_T("Failed to allocate memory for privileges list\n"));
    }
  }
  else {
    _tprintf(_T("Failed token privileges list size with error %#.8x\n"), error);
  }
  return bResult;
}

// Enable or disable privilege if present in target token 
BOOL TogglePrivilege(HANDLE hToken, LPTSTR priv, BOOL enable)
{
  BOOL bResult=FALSE;
  DWORD error;
  LUID luid;
  TOKEN_PRIVILEGES tp;

  bResult = LookupPrivilegeValue(NULL, priv, &luid);
  if(bResult) {
    // Only attempt to enable privilege if present in token
    if(IsPrivilegePresent(hToken, luid)) {
      // Setup TP struct
      tp.PrivilegeCount = 1;
      tp.Privileges[0].Luid = luid;
      tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0; // zero for disabled, not removed
      // Adjust the token
      bResult = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL);
      bResult &= (ERROR_SUCCESS==(error=GetLastError()));
      if((!bResult)) {
        _tprintf(_T("Adjusting token privileges failed with error %#.8x\n"), error);
      }
    }
    else {
      bResult = FALSE;
    }
  }
  else {
    _tprintf(_T("Privilege LUID lookup failed with error %#.8x\n"), GetLastError());
  }
  return bResult;
}

// Enables/Disables the debug privilege in current process' token
BOOL ToggleDebugPrivilege(BOOL enable)
{
  BOOL bResult=FALSE;
  HANDLE hProcess, hToken;

  // Get current process (pseudo-handle, no need to close)
  hProcess = GetCurrentProcess();
  // Get current process's token
  bResult = OpenProcessToken(hProcess, TOKEN_QUERY|TOKEN_ADJUST_PRIVILEGES, &hToken);
  if(bResult) {
    bResult = TogglePrivilege(hToken, SE_DEBUG_NAME, enable);
    CloseHandle(hToken);
  }
  else {
    _tprintf(_T("Access to current process' token failed with error %#.8x\n"), GetLastError());
  }
  return bResult;
}

// Either returns true (for a retry) or false (success or failure)
// Failure: pnbProcesses is 0 and there is no buffer to free
// Success: pnbProcesses is greater than 0 and *pprocesses contains a pointer to be freed
BOOL FillProcessesListWithAlloc(PDWORD *pprocesses, DWORD size, PDWORD pnbProcesses)
{
  DWORD *processes, bytes=0, result=0;
  BOOL retry=FALSE, realloc=FALSE;

  // Attempt allocation or reallocation
  if(!(*pprocesses)) {
    processes = (PDWORD)HeapAlloc(GetProcessHeap(), 0, size);
  }
  else {
    processes = (PDWORD)HeapReAlloc(GetProcessHeap(), 0, *pprocesses, size);
    realloc=TRUE;
  }
  // If allocation for requested size succeeded
  if(processes) {
    if(EnumProcesses(processes, size, &bytes)) {
      // Success
      if(bytes<size) {
        result = bytes/sizeof(DWORD);
      }
      else {
        // Buffer too small to list all processIDs
        retry=TRUE;
      }
      // Writes the allocation pointer back in case of success or retry
      *pprocesses = processes;
    }
    else {
      HeapFree(GetProcessHeap(), 0, processes);
      _tprintf(_T("EnumProcesses() failure, error %#.8x\n"), GetLastError());
    }
  } // if processes
  else {
    // Allocation failure handling
    _tprintf(_T("Allocation failure (requested %#.8x bytes), aborting\n"), size);
    // If realloc failed, a free is necessary
    if(realloc) {
      HeapFree(GetProcessHeap(), 0, *pprocesses);
    }
  }
  // Write back nb of processe only if we are done
  if(!retry) {
    *pnbProcesses = result;
  }
  return retry;
}

// Attemps to fill the stack buffer if large enough, otherwise move on to allocations
DWORD FillProcessesList(PDWORD *pprocesses, DWORD bufsize)
{
  DWORD nb_processes=0, bytes, size=bufsize;
  BOOL retry;

  // First attemps on stack buffer
  if(EnumProcesses(*pprocesses, size, &bytes)) {
    if(bytes>=size) {
      // Not large enough, allocating
      *pprocesses=NULL;
      do {
        size *= 2;    // doubling size of buffer for processIDs list
        retry =  FillProcessesListWithAlloc(pprocesses, size, &nb_processes);
      }
      while(retry);
    }
    else {
      nb_processes = bytes/sizeof(DWORD);
    }
  } // if enumProcesses
  else {
    _tprintf(_T("EnumProcesses failed with error %#.8x\n"), GetLastError());
  }
  return nb_processes;
}

// Returns success boolean and outputs process handle with requested rights
BOOL GetProcessbyNameOrId(LPTSTR searchstring, PHANDLE phProcess, DWORD rights)
{
  BOOL found=FALSE;
  HMODULE hMod;
  DWORD *processes, lpProcesses[QUITE_LARGE_NB_PROCESSES], bytes, processId;
  SIZE_T nbProcesses, i;
  HANDLE hProcess;
  TCHAR processname[MAX_PATH+1], *stop;

  processId = _tcstoul(searchstring, &stop, 0);
  if(processId && *stop==L'\0') {
    hProcess = OpenProcess(rights, FALSE, processId);
    if(hProcess) {
      *phProcess = hProcess;
      found=TRUE;
    }
  }
  else {
    processes = lpProcesses;
    nbProcesses = FillProcessesList(&processes, sizeof(lpProcesses));
    if(nbProcesses) {
      for(i=0; i<nbProcesses && !found; i++) {
        hProcess = OpenProcess(IDENTIFICATION_RIGHTS, FALSE, processes[i]);
        if(hProcess) {
          if(EnumProcessModules(hProcess, &hMod, sizeof(hMod), &bytes)) {
            if(GetModuleBaseName(hProcess, hMod, processname, sizeof(processname)/sizeof(TCHAR))) {
              // Found the process by that name
              if(!_tcsicmp(searchstring, processname)) {
                // Close the handle and attempt reopenning with requested rights
                CloseHandle(hProcess);
                hProcess = OpenProcess(rights, FALSE, processes[i]);
                if(hProcess) {
                  *phProcess = hProcess;
                  found=TRUE;
                }
              } // if _tcsicmp
            } // if GetModuleBaseName
          } // if EnumProcessModules
          if(!found) {
            // Only close this process handle if it is not the one we are looking for
            CloseHandle(hProcess);
          }
        } // if hProcess
      } // for all processes
      if(processes!=lpProcesses) {
        HeapFree(GetProcessHeap(), 0, processes);
      }
    } // if nbProcesses
  }
  return found;
}

INT _tmain(INT argc, _TCHAR* argv[])
{
  BOOL debugPrivEnabled=FALSE, bResult=FALSE, needSession0=FALSE;
  DWORD dwResult=ERROR_UNIDENTIFIED_ERROR;
  HANDLE hProcess;
  DWORD targetProcessSession=(DWORD)(-1);
  TCHAR lpCommandLine[MAX_PATH]; // Not the absolute max (32k) but should be enough

  // Check for valid usage
  if(argc==3 || (argc==4&&!_tcscmp(argv[3], _T("1")))) {
    // First things first
    if(argc==3) {
      // Attempt to acquire debug privilege if present
      debugPrivEnabled = ToggleDebugPrivilege(TRUE);
    }
    // Find process
    bResult = GetProcessbyNameOrId(argv[1], &hProcess, PROCESS_QUERY_INFORMATION);
    if(bResult) {
      // Identify process session
      targetProcessSession = GetProcessSession(hProcess);
      // _tprintf(_T("Process %u found in session %u\n"), GetProcessId(hProcess), targetProcessSession);
      CloseHandle(hProcess);
      // If we have found the target process and we are the instance running in session 0
      // If this is the interactive session instance
      if(argc==3) {
        // If the process target is in session 0
        if(!targetProcessSession) {
          // We have the debug privilege enabled
          if(debugPrivEnabled) {
            needSession0 = TRUE;
          }
          else {
            _tprintf(_T("Unable to inject into session 0 process without debug privilege...\n"));
          }
        }
      }
      if(needSession0) {
        // The tailing '1' will skip to dll injection logic directly
        if(-1!=_sntprintf_s(lpCommandLine, _countof(lpCommandLine),  _TRUNCATE, _T("%s %s %s 1"), argv[0], argv[1], argv[2], _T("1"))) {
          dwResult = CreateProcessInSession0(lpCommandLine);
        }
        else {
          _tprintf(_T("Command line longuer than MAX_PATH, aborting session 0 injection\n"));
        }
      } 
      else {
        // Only do regular injection
        dwResult = InjectDll(argv[1], argv[2]);
      }
    }
    else {
      _tprintf(_T("Process %s not found - or failed to access with minimum rights, aborting. Perhaps try as elevated admin (which grants debug privilege)?\n"), argv[1]);
    }
    // Disable debug privilege
    if(debugPrivEnabled) {
      ToggleDebugPrivilege(FALSE);
    }
    // Display success message
    if(dwResult==ERROR_SUCCESS) {
      _tprintf(_T("Dll %s successfully injected in session %u process %s %s\n"), argv[2], targetProcessSession, argv[1], debugPrivEnabled ? _T("(debug privilege was enabled)") : _T(""));
    }
  }
  else {
    Usage(argv[0]);
  }
  return dwResult;
}

// Just returns process session
DWORD GetProcessSession(HANDLE hProcess)
{
  DWORD sessionId=(DWORD)(-1);

  if(!ProcessIdToSessionId(GetProcessId(hProcess), &sessionId)) {
    _tprintf(_T("Getting target process session id failed with error %#.8x\n"), GetLastError());
  }
  return sessionId;
}

// Actual dll injection logic. Returns error code or ERROR_SUCCESS (0) if successful
DWORD InjectDll(LPTSTR process, LPTSTR dll)
{
  BOOL bResult;
  DWORD dwResult;
  LPVOID pMem=NULL;
  HANDLE hProcess=NULL, hThread=NULL;
  DWORD threadId, waitResult, threadExitCode;
  SIZE_T sizerequired, dllpathlen, byteswritten;
  LPTHREAD_START_ROUTINE pLoadLibrary;

  // Find the FIRST process by that name
  bResult = GetProcessbyNameOrId(process, &hProcess, INJECTION_RIGHTS);
  if(bResult) {
    // Get required size, including terminating character
    dllpathlen = _tcsnlen(dll, MAX_PATH);
    if(dllpathlen<MAX_PATH) {
      sizerequired = sizeof(TCHAR)*(dllpathlen+1);
      // Allocate a page in the target process
      pMem = VirtualAllocEx(hProcess, 0x0, sizerequired, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
      if(pMem) {
        // Copy dll path to target process
        bResult = WriteProcessMemory(hProcess, pMem, dll, sizerequired, &byteswritten);
        if(bResult) {
          // Get address to LoadLibrary function
          pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(_T("kernel32.dll")), LOADLIBRARY);
          if(pLoadLibrary) {
            // Create remote thread pointing to LoadLibrary[A|W]
            hThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibrary, pMem, 0, &threadId);
            if(hThread) {
              waitResult = WaitForSingleObject(hThread, TIMEOUT_10SEC);
              if(waitResult==WAIT_OBJECT_0) {
                bResult = GetExitCodeThread(hThread, &threadExitCode);
                if(bResult && threadExitCode) {
                  dwResult = ERROR_SUCCESS;
                }
                else {
                  if(bResult) {
                    dwResult = ERROR_UNIDENTIFIED_ERROR;
                    _tprintf(_T("LoadLibrary failed, check for dll file presence and x86/x64 mismatch\n"));
                  }
                  else {
                    dwResult = GetLastError();
                    _tprintf(_T("Could not check LoadLibrary return value in remote thread, error %#.8x\n"), dwResult);
                  }
                }
              } // if waitResult==WAIT_OBJECT_0
              else {
                dwResult = waitResult;
                _tprintf(_T("Aborting: %s\n"), waitResult==WAIT_TIMEOUT ? _T("remote thread has been hung for 10 secs") : _T("wait failed"));
              }
              CloseHandle(hThread);
            } // if hThread
            else {
              dwResult = GetLastError();
              _tprintf(_T("Creating remote thread in process %u failed with error %#.8x\n"), GetProcessId(hProcess), dwResult);
            }
          } // if pLoadLibrary
          else {
            dwResult = GetLastError();
            _tprintf(_T("Failed to get LoadLibrary function address with error %#.8x\n"), dwResult);
          }
        } // if bResult
        else {
          dwResult = GetLastError();
          _tprintf(_T("Writing remote process %u memory failed with error %#.8x\n"), GetProcessId(hProcess), dwResult);
        }
        if(!VirtualFreeEx(hProcess, pMem, 0, MEM_RELEASE)) {
          dwResult = GetLastError();
          _tprintf(_T("Failed to free remote process' allocated memory, error %#.8x\n"), dwResult);
        }
      } // if pMem
      else {
        dwResult = GetLastError();
        _tprintf(_T("Remote process %u allocation failed with error %#.8x\n"), GetProcessId(hProcess), dwResult);
      }
    } // if pathlen valid
    else {
      dwResult = ERROR_BUFFER_OVERFLOW;
      _tprintf(_T("Dll path too long\n"));
    }
    CloseHandle(hProcess);
  } // if getProcessbyNameOrId
  else {
    dwResult=ERROR_NOT_FOUND;
  }
  return dwResult;
}
