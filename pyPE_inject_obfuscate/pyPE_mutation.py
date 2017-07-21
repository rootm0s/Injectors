#http://breakinsecurity.com/pe-format-manipulation-with-pefile/
#32 and 64bit support
import pefile
import string
import random
import os
import mmap

def cleanterminal():
	'''
	Clean the terminal window and set title
	'''
	os.system("cls" if os.name == "nt" else "clear")
	os.system("title pyPE_mutator")

def banner():
	print ">> Obfuscating PE sections"

def uniqestr(length):
	'''
	Create a random string
	'''
	return ''.join(random.choice(string.lowercase) for i in range(length))

def modify():
	'''
	Path to executables
	'''
	input = "PsExec.exe"
	output = uniqestr(10)+".exe"
	
	'''
	Load executable
	'''
	originalpe = pefile.PE(input)

	'''
	Parse unmodified sections and replace 
	the name with random strings
	'''
	print "\n[!] Original pe section names"
	for section in originalpe.sections:
		print "\t[+] "+section.Name.decode('utf-8')
		section.Name = "."+uniqestr(4).encode()

	'''
	Write the changes in another executable
	'''
	originalpe.write(output)

	'''
	Load new executable
	'''
	modifiedpe = pefile.PE(output)
	print "\n[!] Modifying pe sections names"

	'''
	Parse modified section names
	'''
	for section in modifiedpe.sections:
		print "\t[+] "+section.Name.decode('utf-8')

if __name__ == '__main__':
	'''
	Run all the functions
	'''
	cleanterminal()
	banner()
	modify()