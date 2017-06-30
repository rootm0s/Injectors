#include "System.h"

namespace System {

std::wstring GetSystemError()
{
	std::wstring result;

	wchar_t lpMsgBuf[500] = {0};
	FormatMessageW( 
		FORMAT_MESSAGE_FROM_SYSTEM | 
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		GetLastError(),
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
		lpMsgBuf,
		sizeof(lpMsgBuf),
		NULL 
	);

	result = lpMsgBuf;
	LocalFree(lpMsgBuf);

	return result;
}

int SetDebugPrivilege()
{
	  TOKEN_PRIVILEGES tp;
	  HANDLE hToken;
	  LUID luid;
	 
     if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &hToken ))
        return 0;
    
     if(!LookupPrivilegeValueW(L"", L"SeDebugPrivilege", &luid))
        return 0;
   
     tp.PrivilegeCount         = 1;
     tp.Privileges[0].Luid     = luid;
     tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
 
	 return AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL );
}

}