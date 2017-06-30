Ncloader
========

#A simple dll injection utility#
The current design implements the well-known DLL injection technique:
  - VirtualAllocEx (allocates memory for string in remote process)
  - WriteProcessMemory (writes the "path/to/dll/file" in remotely allocated memory)
  - CreateRemoteThread (with start address of LoadLibrary[A/W] and address to "path/to/dll/file" as parameter)

##Features##
  - From elevated admin prompt, injects into any (non-protected) process including session 0 processes
  - Standalone (no third-party library, statically compiled)
  - Clean code (compiles with no warnings and /Wall on MSVC)
  - Strict error checking and verbose reporting
  - No undocumented NT api
  - Not creating services
  - Not using driver
  - 32bit and 64bit pre-compiled binaries

###Usage###
```
ncloader.exe [process name | pid] [dll full path] [1]
note: the optional trailing '1' disables elevation attempt
```

###Examples###
By process name from regular prompt (debug privilege not present in restricted token)
```
ncloader.exe some_service.exe c:\path\to\library.dll
Dll c:\path\to\library.dll successfully injected in session 0 process some_service.exe (debug privilege was enabled)
```
By PID from elevated prompt (token has debug privilege present but disabled)
```
ncloader.exe 1234 c:\path\to\library.dll
Dll c:\path\to\library.dll successfully injected in session 1 process 1234
```
