#include "ReflectiveLoader.h"
#include <stdio.h>

DLLEXPORT BOOL
MyFunction(LPVOID lpUserdata, DWORD nUserdataLen)
{
	LPSTR str = malloc(32 + nUserdataLen);
	sprintf_s(str, 32 + nUserdataLen, "Hello from MyFunction: %s!", lpUserdata);
	MessageBoxA(NULL, str, (LPCSTR)lpUserdata, MB_OK);
	free(str);
	return TRUE;
}
