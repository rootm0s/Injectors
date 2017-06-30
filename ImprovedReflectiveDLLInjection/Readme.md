This is an improvement of the [original reflective DLL injection technique by Stephen Fewer of Harmony Security](https://github.com/stephenfewer/ReflectiveDLLInjection). It uses bootstrap shellcode (x86 or x64) to allow calling any export of the DLL from the reflective loader. See [An Improved Reflective DLL Injection Technique](https://disman.tl/2015/01/30/an-improved-reflective-dll-injection-technique.html) for a detailed description.

About
=====

Reflective DLL injection is a library injection technique in which the concept of reflective programming is employed to perform the loading of a library from memory into a host process. As such the library is responsible for loading itself by implementing a minimal Portable Executable (PE) file loader. It can then govern, with minimal interaction with the host system and process, how it will load and interact with the host.

Injection works from Windows NT4 up to and including Windows 8, running on x86 and x64.

Overview
========

The process of remotely injecting a library into a process is two fold. Firstly, the library you wish to inject must be written into the address space of the target process (Herein referred to as the host process). Secondly the library must be loaded into that host process in such a way that the library's run time expectations are met, such as resolving its imports or relocating it to a suitable location in memory.

Assuming we have code execution in the host process and the library we wish to inject has been written into an arbitrary location of memory in the host process, Reflective DLL Injection works as follows.

* Execution is passed via a tiny bootstrap shellcode to the library's ReflectiveLoader function which is an exported function found in the library's export table.
* As the library's image will currently exist in an arbitrary location in memory the ReflectiveLoader will first calculate its own image's current location in memory so as to be able to parse its own headers for use later on.
* The ReflectiveLoader will then parse the host processes kernel32.dll export table in order to calculate the addresses of four functions required by the loader, namely LoadLibraryA, GetProcAddress, VirtualAlloc, and ExitThread.
* The ReflectiveLoader will now allocate a continuous region of memory into which it will proceed to load its own image. The location is not important as the loader will correctly relocate the image later on.
* The library's headers and sections are loaded into their new locations in memory.
* The ReflectiveLoader will then process the newly loaded copy of its image's import table, loading any additional libraries and resolving their respective imported function addresses.
* The ReflectiveLoader will then process the newly loaded copy of its image's relocation table.
* The ReflectiveLoader will then call its newly loaded image's entry point function, DllMain with DLL_PROCESS_ATTACH. The library has now been successfully loaded into memory.
* The ReflectiveLoader will then call a chosen exported function, passing a caller-specified pointer and DWORD as parameters.
* Finally the ReflectiveLoader will terminate the thread by calling ExitThread or, if available, RtlExitUserThread.

Build
=====

Open the 'rdi.sln' file in Visual Studio C++ and build the solution in Release mode to make inject.exe and reflective_dll.dll

Usage
=====

To test, run inject.exe using an arbitrary test string and the PID of a process to inject into, e.g.:

> inject.exe foobar 1234
	
License
=======

Licensed under a 3 clause BSD license, please see LICENSE.txt for details.
