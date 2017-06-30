////////////////////////////////////////////////////////////////////////////////////////////
// MapRemoteModuleW
////////////////////////////////////////////////////////////////////////////////////////////
BOOL
MapRemoteModuleW(
        DWORD dwProcessId,
        LPCWSTR lpModulePath
        )
{
        BOOL bRet = FALSE;
        HANDLE hFile = 0;
        DWORD fileSize = 0;
        BYTE *dllBin = 0;
        PIMAGE_NT_HEADERS nt_header = 0;
        PIMAGE_DOS_HEADER dos_header = 0;
        HANDLE hProcess = 0;
        LPVOID lpModuleBase = 0;
 
        PIMAGE_IMPORT_DESCRIPTOR pImgImpDesc = 0;
        PIMAGE_BASE_RELOCATION pImgBaseReloc = 0;
        PIMAGE_TLS_DIRECTORY pImgTlsDir = 0;
 
        __try
        {
                // Get a handle for the target process.
                hProcess = OpenProcess(
                        PROCESS_QUERY_INFORMATION       |       // Required by Alpha
                        PROCESS_CREATE_THREAD           |       // For CreateRemoteThread
                        PROCESS_VM_OPERATION            |       // For VirtualAllocEx/VirtualFreeEx
                        PROCESS_VM_WRITE                |       // For WriteProcessMemory
                        PROCESS_VM_READ,
                        FALSE,
                        dwProcessId);
                if(!hProcess)
                {
                        PRINT_ERROR_MSGA("Could not get handle to process (PID: 0x%X).", dwProcessId);
                        __leave;
                }
 
                hFile = CreateFileW(
                        lpModulePath,
                        GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL,
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL,
                        NULL);
                if(hFile == INVALID_HANDLE_VALUE)
                {
                        PRINT_ERROR_MSGA("CreateFileW failed.");
                        __leave;
                }
 
                if(GetFileAttributesW(lpModulePath) & FILE_ATTRIBUTE_COMPRESSED)
                {
                        fileSize = GetCompressedFileSizeW(lpModulePath, NULL);
                }
                else
                {
                        fileSize = GetFileSize(hFile, NULL);
                }
 
                if(fileSize == INVALID_FILE_SIZE)
                {
                        PRINT_ERROR_MSGA("Could not get size of file.");
                        __leave;
                }
 
                dllBin = (BYTE*)malloc(fileSize);
 
                {
                        DWORD NumBytesRead = 0;
                        if(!ReadFile(hFile, dllBin, fileSize, &NumBytesRead, FALSE))
                        {
                                PRINT_ERROR_MSGA("ReadFile failed.");
                        }
                }
       
                dos_header = (PIMAGE_DOS_HEADER)dllBin;
               
                // Make sure we got a valid DOS header
                if(dos_header->e_magic != IMAGE_DOS_SIGNATURE)
                {
                        PRINT_ERROR_MSGA("Invalid DOS header.");
                        __leave;
                }
               
                // Get the real PE header from the DOS stub header
                nt_header = (PIMAGE_NT_HEADERS)( (DWORD_PTR)dllBin +
                        dos_header->e_lfanew);
 
                // Verify the PE header
                if(nt_header->Signature != IMAGE_NT_SIGNATURE)
                {
                        PRINT_ERROR_MSGA("Invalid PE header.");
                        __leave;
                }
 
                // Allocate space for the module in the remote process
                lpModuleBase = VirtualAllocEx(
                        hProcess,
                        NULL,
                        nt_header->OptionalHeader.SizeOfImage,
                        MEM_COMMIT | MEM_RESERVE,
                        PAGE_EXECUTE_READWRITE);
                if(!lpModuleBase)
                {
                        PRINT_ERROR_MSGA("Could not allocate memory in remote process.");
                        __leave;
                }
               
                // fix imports
                pImgImpDesc = (PIMAGE_IMPORT_DESCRIPTOR)GetPtrFromRVA(
                        nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,
                        nt_header,
                        (PBYTE)dllBin);
                if(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
                {
                        if(!FixIAT(dwProcessId, hProcess, (PBYTE)dllBin, nt_header, pImgImpDesc))
                        {
                                PRINT_ERROR_MSGA("@Fixing imports.");
                                __leave;
                        }
                }
               
                // fix relocs
                pImgBaseReloc = (PIMAGE_BASE_RELOCATION)GetPtrFromRVA(
                        (DWORD)(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress),
                        nt_header,
                        (PBYTE)dllBin);
                if(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
                {
                        if(!FixRelocations(dllBin, lpModuleBase, nt_header, pImgBaseReloc))
                        {
                                PRINT_ERROR_MSGA("@Fixing relocations.");
                                __leave;
                        }
                }
 
                // Write the PE header into the remote process's memory space
                {
                        SIZE_T NumBytesWritten = 0;
                        SIZE_T nSize = nt_header->FileHeader.SizeOfOptionalHeader +
                                sizeof(nt_header->FileHeader) +
                                sizeof(nt_header->Signature);
                       
                        if(!WriteProcessMemory(hProcess, lpModuleBase, dllBin, nSize, &NumBytesWritten) ||
                                NumBytesWritten != nSize)
                        {
                                PRINT_ERROR_MSGA("Could not write to memory in remote process.");
                                __leave;
                        }
                }
 
                // Map the sections into the remote process(they need to be aligned
                // along their virtual addresses)
                if(!MapSections(hProcess, lpModuleBase, dllBin, nt_header))
                {
                        PRINT_ERROR_MSGA("@Map sections.");
                        __leave;
                }
 
                // call all tls callbacks
                //
                pImgTlsDir = (PIMAGE_TLS_DIRECTORY)GetPtrFromRVA(
                        nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress,
                        nt_header,
                        (PBYTE)dllBin);
                if(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
                {
                        if(!CallTlsInitializers(dllBin, nt_header, hProcess, (HMODULE)lpModuleBase, DLL_PROCESS_ATTACH, pImgTlsDir))
                        {
                                PRINT_ERROR_MSGA("@Call TLS initializers.");
                                __leave;
                        }
                }
 
                // call entry point
                if(!RemoteDllMainCall(
                        hProcess,
                        (LPVOID)( (DWORD_PTR)lpModuleBase + nt_header->OptionalHeader.AddressOfEntryPoint),
                        (HMODULE)lpModuleBase, 1, 0))
                {
                        PRINT_ERROR_MSGA("@Call DllMain.");
                        __leave;
                }
 
                bRet = TRUE;
 
                wprintf(L"Successfully injected (%s | PID: %x):\n\n"
                        L"  AllocationBase:\t0x%p\n"
                        L"  EntryPoint:\t\t0x%p\n"
                        L"  SizeOfImage:\t\t0x%p\n"
                        L"  CheckSum:\t\t0x%p\n",
                        lpModulePath,
                        dwProcessId,
                        lpModuleBase,
                        (DWORD_PTR)lpModuleBase + nt_header->OptionalHeader.AddressOfEntryPoint,
                        nt_header->OptionalHeader.SizeOfImage,
                        nt_header->OptionalHeader.CheckSum);
        }
        __finally
        {
                if(hFile)
                {
                        CloseHandle(hFile);
                }
 
                if(dllBin)
                {
                        free(dllBin);
                }
 
                if(hProcess)
                {
                        CloseHandle(hProcess);
                }
        }
       
        return bRet;
}