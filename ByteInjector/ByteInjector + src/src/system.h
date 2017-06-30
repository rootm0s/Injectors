#ifndef INC_SYSTEM
#define INC_SYSTEM

#include <windows.h>
#include <string>

namespace System {

std::wstring GetSystemError();
int SetDebugPrivilege();

}

#endif