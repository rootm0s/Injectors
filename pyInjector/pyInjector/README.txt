Copy the shellcode.py to your Ubuntu/BT box. Make sure you change the path in the file to where MSFVenom is located at.

Also change the IP addresses and Ports you want for the reverse shell. 

Run shellcode.py, this will generate the proper format for the shellcode. Copy and paste the shellcode into pyinjector.exe:

pyinjector.exe <shellcode>

