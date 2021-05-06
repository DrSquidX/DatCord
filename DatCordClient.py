import socket, threading

class Client:
    def __init__(self, ip, port):
        print(self.logo())
        self.ip = ip
        self.port = port
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((self.ip, self.port))
        self.logged_in = False
        print("[+] Successfully connected to Datcord Servers!\n")
        msg = self.client.recv(10240).decode()
        self.sender = threading.Thread(target=self.send)
        self.sender.start()
    def logo(self):
        logo = """
 _____        _    _____              _         _____  ___  
|  __ \      | |  / ____|            | |       | ____|/ _ \ 
| |  | | __ _| |_| |     ___  _ __ __| | __   _| |__ | | | |
| |  | |/ _` | __| |    / _ \| '__/ _` | \ \ / /___ \| | | |
| |__| | (_| | |_| |___| (_) | | | (_| |  \ V / ___) | |_| |
|_____/ \__,_|\__|\_____\___/|_|  \__,_|   \_/ |____(_)___/                                                                                                               
Advanced Server by DrSquid"""
        return logo
    def send(self):
        print("[+] Sign-in")
        print("[+] Before you are able to communicate.\n[+] You are needed to either sign in or create an account for Datcord.")
        print("\n[+] Don't have an account?\n[+] Not to worry. Enter the credentials you wish to use, and you will be prompted to register for a new account.\n")
        while True:
            if not self.logged_in:
                username = input("[+] Enter your username: ")
                password = input("[+] Enter your password: ")
                self.client.send(f"!login {username} {password}".encode())
                msg = self.client.recv(10240).decode()
                if "Successfully logged in!" in msg or "Commands For This Server" in msg:
                    print("\n[+] Successfully logged into your account.")
                    print("[+] You are able to communicate with users on Datcord now.")
                    self.logged_in = True
                elif "Authentication Failed." in msg:
                    print("[+] Your password is invalid. Please check for spelling errors.")
                elif "Your account is not registered in the database. Please register your account." in msg:
                    print("[+] Your account is not recognized by the database.")
                    register = input("[+] Would you like to register an account with the details provided?: ")
                    if register.lower() == "yes":
                        self.client.send(f"!register {username} {password}".encode())
                        self.logged_in = True
                    else:
                        print("[+] Please re-enter your crentials.")
                elif "Your account has been banned from the server." in msg:
                    print("[+] Your account has been banned from the server! Try to create a new account or wait until you are unbanned.")
                else:
                    print("[+] Unable to login.")
                    print(msg)
                if self.logged_in:
                    self.reciever = threading.Thread(target=self.recv)
                    self.reciever.start()
                print("")
            else:
                msg = input("[+] Enter your msg: ")
                self.client.send(msg.encode())
    def recv(self):
        print("[+] You are free to send commands to the server.\n[+] You can run the commands that are used by the server(if you know them) or use the commands on this script to communicate with it.")
        while True:
            msg = self.client.recv(10240).decode()
            if msg.strip().startswith("[(DM)]"):
                print("\n[+] You have recieved a Direct Message.")
                main_msg = msg.replace("["," ").replace("]", " ").strip("()").split()
                del main_msg[0]
                username = main_msg[0]
                del main_msg[0]
                result = ""
                for i in main_msg:
                    result = result + i + " "
                print(f"[+] From {username.strip()} {result}")
            else:
                print(msg)
client = Client("192.168.0.145",80)
