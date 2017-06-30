// Copyright (c) 2015, Dan Staples

#include <Windows.h>
#include <tchar.h>
#include <stdio.h>

#define HASH_KEY						13
#pragma intrinsic( _rotr )
__forceinline DWORD ror(DWORD d) { return _rotr(d, HASH_KEY); }
__forceinline DWORD hash(char * c, BOOL bWide)
{
	register DWORD h = 0;
	do {
		h = ror(h);
		h += *c++;
		if (bWide) {
			h = ror(h);
			h += *c;
		}
	} while (*++c);
	return h;
}

int _tmain(int argc, _TCHAR *argv[])
{
	if (argc != 2 && argc != 3) {
		printf("Usage: %s [-u] <function name>\n", argv[0]);
		return 1;
	}
	if (argc == 3 && _tcscmp(argv[1], L"-u") == 0)
		printf("0x%x\n", hash((char*)argv[2], TRUE));
	else
		printf("0x%x\n", hash((char*)argv[(argc == 3) ? 2 : 1], FALSE));
	return 0;
}

