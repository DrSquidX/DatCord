import socket, threading, sqlite3, os, sys
class Client:
    """Configures the database files if they don't exist, as well as
    also configuring the database tables if they also don't exist.
    This function also starts the connecting function, which helps
    the user with connecting to the server."""
    def __init__(self):
        print(self.logo())
        self.dbfile = "servers.db"
        try:
            file = open(self.dbfile,"rb")
            file.close()
        except FileNotFoundError:
            file = open(self.dbfile, "wb")
            file.close()
        db = sqlite3.connect(self.dbfile)
        cursor = db.cursor()
        try:
            cursor.execute("select * from servers")
        except:
            cursor.execute("create table servers(server)")
        try:
            cursor.execute("select * from userinfo")
        except:
            cursor.execute("create table userinfo(username, password)")
        try:
            cursor.execute("select * from userinfo")
            self.userinfo = cursor.fetchall()[0]
        except:
            self.userinfo = None
        self.userinfo1 = self.userinfo
        db.commit()
        cursor.close()
        db.close()
        self.join_serv()
    def join_serv(self):
        """This is the function that is used to connect to the server. If first prompts the user
        if they want to connect to an existing server in their directory, or if they want to
        connect to a new server that they haven't connected to one yet. If the user says 'yes',
        the database file with all of the servers and IP's will be displayed. If there isn't
        anything in the database, it will tell the user that there isn't any server to connect
        to. If there is stuff in the database file, then the user can select which server that
        they want to connect to. They can then be able to connect to that server. If the user wants
        to join a new server, they will be prompted to enter the IP and Port of the new server.
        If the user can connect to that IP and Port, it will be added to the server database
        files, and you can connect to it with ease when you want to again."""
        self.inserver = False
        print("\n[+] Connect To A Server\n[+] You are required to go connect to a DatCord Server, before you are able to communicate with others.")
        while True:
            connect = input("\n[+] Would you like to connect to an existing server or create a new profile for one?(yes/no): ")
            if connect.lower().strip() == "yes":
                db = sqlite3.connect(self.dbfile)
                cursor = db.cursor()
                cursor.execute("select server from servers")
                fetched = cursor.fetchall()
                success = False
                cursor.close()
                db.close()
                if len(fetched) == 0:
                    print("[+] You have no existing servers in your directory. You can make a new profile to add a server.")
                else:
                    print("\n[+] Here is the list of servers:")
                    item = 0
                    for i in fetched:
                        item += 1
                        print(f"[+] ({item}) {i[0]}")
                    while True:
                        try:
                            ls = input("\n[+] Which Server would you like to connect to?(enter the number of the server): ")
                            ls_item = int(ls) - 1
                            server = str(fetched[ls_item][0])
                            print(f"\n[+] Connecting to: {server}")
                            server = server.split(":")
                            try:
                                self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                self.client.connect((server[0], int(server[1])))
                                success = True
                                self.inserver = True
                                break
                            except:
                                print("[+] Unable to connect to server. Input 'cancel' if you would like to go back.")
                        except:
                            if ls.lower().strip() == "cancel":
                                break
                            else:
                                print("[+] Please enter a valid number.")
                if success:
                    break
            elif connect.lower().strip() == "no":
                new_ip = input("\n[+] Enter the IP of the server: ")
                while True:
                    try:
                        port = int(input("[+] Enter the Port of the Server: "))
                        break
                    except:
                        print("[+] Please use a number.")
                print(f"\n[+] Attempting to connect to {new_ip}:{port}.")
                try:
                    self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self.client.connect((new_ip, port))
                    self.inserver = True
                    db = sqlite3.connect(self.dbfile)
                    cursor = db.cursor()
                    cursor.execute(f"insert into servers values('{new_ip}:{port}')")
                    db.commit()
                    cursor.close()
                    db.close()
                    break
                except:
                    print("[+] Unable to connect to the server.")
            else:
                print("[+] Please answer with either 'yes' or 'no'.")
        if self.inserver:
            self.logged_in = False
            print("[+] Successfully connected to Datcord Servers!\n")
            msg = self.client.recv(10240).decode()
            self.sender = threading.Thread(target=self.send)
            self.sender.start()
    def logo(self):
        """Logo of the script."""
        logo = """
 _____        _    _____              _    _____ _ _            _          ___    ___  
|  __ \      | |  / ____|            | |  / ____| (_)          | |        |__ \  / _ \ 
| |  | | __ _| |_| |     ___  _ __ __| | | |    | |_  ___ _ __ | |_  __   __ ) || | | |
| |  | |/ _` | __| |    / _ \| '__/ _` | | |    | | |/ _ \ '_ \| __| \ \ / // / | | | |
| |__| | (_| | |_| |___| (_) | | | (_| | | |____| | |  __/ | | | |_   \ V // /_ | |_| |
|_____/ \__,_|\__|\_____\___/|_|  \__,_|  \_____|_|_|\___|_| |_|\__|   \_/|____(_)___/                                                                                               
Client Script For DatCord by DrSquid"""
        return logo
    def send(self):
        """This function is what the client uses to send messages to the server.
        All of the logging in code is here as well."""
        print("[+] Sign-in")
        print("[+] Before you are able to communicate.\n[+] You are needed to either sign in or create an account for Datcord.")
        print("\n[+] Don't have an account?\n[+] Not to worry. Enter the credentials you wish to use, and you will be prompted to register for a new account.")
        while True:
            try:
                if not self.logged_in:
                    if self.userinfo is not None:
                        useinfo = input(f"\n[+] Would you like to use the same userinfo from last time you logged in?: ")
                        if useinfo.lower().strip() == "yes":
                            self.client.send(f"!login {self.userinfo[0]} {self.userinfo[1]}".encode())
                            msg = self.client.recv(10240).decode()
                            if "Successfully logged in!" in msg or "Commands For This Server" in msg:
                                print("\n[+] Successfully logged into your account.")
                                print("[+] You are able to communicate with users on Datcord now.")
                                self.reciever = threading.Thread(target=self.recv)
                                self.reciever.start()
                                self.logged_in = True
                            else:
                                print("[+] There was an error with logging you in. Switching to normal logging in.")
                                self.userinfo = None
                        else:
                            print("[+] Choosing not to use the same info.")
                            self.userinfo = None
                    else:
                        username = input("\n[+] Enter your username: ")
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
                            db = sqlite3.connect(self.dbfile)
                            cursor = db.cursor()
                            if self.userinfo1 is None:
                                cursor.execute(f"insert into userinfo values('{username}','{password}')")
                            else:
                                cursor.execute(f"delete from userinfo where username = '{self.userinfo1[0]}'")
                                cursor.execute(f"insert into userinfo values('{username}','{password}')")
                            self.userinfo = (username, password)
                            self.userinfo1 = self.userinfo
                            db.commit()
                            cursor.close()
                            db.close()
                            self.reciever = threading.Thread(target=self.recv)
                            self.reciever.start()
                        print("")
                    if self.logged_in:
                        print(f"\n[+] Logged in as: {self.userinfo1[0]}")
                else:
                    msg = input("[+] Enter your msg: ")
                    self.client.send(msg.encode())
            except Exception as e:
                print("[+] There appears to be some issues with your connection with the server.")
                servjoiner = threading.Thread(target=self.join_serv).start()
                break
    def recv(self):
        """This function is what the client uses to recieve messages from the server."""
        print("\n[+] You are free to send commands to the server.\n[+] You can run the commands that are used by the server(if you know them) or use the commands on this script to communicate with it.")
        while True:
            try:
                msg = self.client.recv(10240).decode()
                if msg.strip().startswith("[(DM)]"):
                    print("\n[+] You have recieved a Direct Message.")
                    main_msg = msg.replace("[", " ").replace("]", " ").strip("()").split()
                    del main_msg[0]
                    username = main_msg[0]
                    del main_msg[0]
                    result = ""
                    for i in main_msg:
                        result = result + i + " "
                    print(f"[+] From {username.strip()} {result}")
                else:
                    if msg.strip() == "":
                        pass
                    else:
                        print(msg)
            except:
                break
if __name__ == '__main__':
    if sys.platform == "win32":
        os.system("cls")
    else:
        os.system("clear")
    client = Client()
