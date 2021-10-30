import socket, threading, sqlite3, hashlib, datetime, time, sys, random, os, json, urllib.request
from optparse import OptionParser
class Server:
    def logo(self=None):
        """Logo of this script."""
        logo = """  
________          __   _________                  .___       _________ __________________ 
\______ \ _____ _/  |_ \_   ___ \  ___________  __| _/ ___  _\______  \\\______  \______  \\
 |    |  \\\__  \\\   __\/    \  \/ /  _ \_  __ \/ __ |  \  \/ /   /    /    /    /   /    /
 |    `   \/ __ \|  |  \     \___(  <_> )  | \/ /_/ |   \   /   /    /    /    /   /    / 
/_______  (____  /__|   \______  /\____/|__|  \____ |    \_/   /____/ /\ /____/   /____/  
        \/     \/              \/                  \/                 \/                                             
Advanced Encrypted Chat Server by DrSquid
[+] Github: https://github.com/DrSquidX"""
        return logo
    """Note: This server was made for a school project.
    This is the main class for the server where all of the important functions and
    variables needed for the server to work are inside of this class. Every server
    error is also within here. Additionally, this is where all of the client handling,
    server listening, and SQL Database connections happen. I have done my best to
    explain every function, so that you can get a better picture of what they
    actually do. This server is multi-threaded, which allows it to do many tasks at once,
    compared to having a single thread script, which would be slower and can only do
    one task at once."""
    class ServerError:
        """Main Class for defining Server errors. Errors that include names that
        are not registered on the main data base, as well as authentication errors
        (when the user inputs a valid username but not a valid password). There is also
        errors that include names already being in the database. If a user is registering
        but the name provided is already registered, it will raise this error. Lastly,
        there is also a Permission Error for room-admins. If a non-admin were to use
        a room-admin command(for ex. !ban), that error will be raised."""
        class NameNotInDatabaseError(Exception):
            """This error is if a name requested is not registered in the database"""
            def __init__(self, msg="Username is not in Database!"):
                """This displays the error(in error format)."""
                self.msg = msg
                super().__init__(self.msg)
        class NameAlreadyRegisteredError(Exception):
            """This error is if a user is trying to register, however the name
            provided is already registered in the database."""
            def __init__(self, msg="Username is already registered in the Database!"):
                """This displays the error(in error format)."""
                self.msg = msg
                super().__init__(self.msg)
        class AuthenticationError(Exception):
            """This error is for if a user has put in an incorrect password, while
            trying to either log in or trying to change a password."""
            def __init__(self, msg="Authentication Failed."):
                """This displays the error(in error format)."""
                self.msg = msg
                super().__init__(self.msg)
        class PermissionError(Exception):
            """This error is for if the user does not have permissions to do something.
            For example if a non-room admin is trying to run an admin command."""
            def __init__(self, msg="You have insufficient permissions!"):
                """This displays the error(in error format)."""
                self.msg = msg
                super().__init__(self.msg)
        class Deletion_Exception(Exception):
            """This is an error that simply is raised for the deletion of an account.
            It was made to end the client loop nice and cleanly."""
            def __init__(self, msg="Account has been deleted."):
                self.msg = msg
                super().__init__(self.msg)
    def __init__(self, ip, port, dbfile, userdbfile, roomdata, logfile, ownername, ownerpassword, connpersec, version):
        """This is the function where all of the important variables are defined. The databases
        is configuyred here, as well as the owner account along with the logging files and room
        data files. Once configured, the user can choose when to start listening for connections
        (however in this script the .listen() function is used right after being configured so
        the server starts listening on startup)."""
        print(self.logo())
        self.ip = ip
        self.port = port
        self.dbfile = dbfile
        self.userdbfile = userdbfile
        self.roomdata = roomdata
        self.logfile = logfile
        self.member_types = ["Owner:","Admins:","Members:"]
        self.ownername = ownername
        self.ownerpassword = ownerpassword
        self.version = version
        self.start = True
        self.check_update()
        try:
            self.maxconnpersec = int(connpersec)
        except:
            self.maxconnpersec = 20
        self.conncount = 0
        self.connpersec = 0
        self.uptime = 0
        self.manualbanall = False
        if self.start:
            file = open(self.userdbfile, "w")
            file.close()
            file2 = open(self.logfile, "w")
            file2.close()
            try:
                db = sqlite3.connect(self.dbfile)
            except:
                file = open(self.dbfile, "w")
                file.close()
                db = sqlite3.connect(self.dbfile)
            try:
                file2 = open(self.roomdata, "r")
            except:
                file2 = open(self.roomdata, "w")
            file2.close()
            cursor = db.cursor()
            userdb = sqlite3.connect(self.userdbfile)
            userdbcursor = userdb.cursor()
            self.listening = True
            self.banningallincomingconn = False
            self.conn_list = []
            self.roomkicked = []
            self.sqltable_list = ["users(username, password)","open_rooms(roomname, roompass)",
                                "banlist(username)","ipbanlist(ip)","ipwhitelist(ip)",
                                "friendslist(user, friends)","friendrequests(user, requests)",
                                "friendrequests(user, requests)","blocklists(user, blockedusers)"]
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.log(self.logo())
            try:
                self.server.bind((self.ip, self.port))
                self.key = Fernet.generate_key()
                self.fernet = Fernet(self.key)
            except Exception as e:
                print(f"\n[({datetime.datetime.today()})][(ERROR)]: There was an error with binding the server due to error: {e}")
                self.log(f"\n\n[({datetime.datetime.today()})][(ERROR)]: There was an error with binding the server due to error: {e}")
                sys.exit()
            for i in self.sqltable_list:
                cursor.execute(f"create table if not exists {i}")
            cursor.execute(f"delete from users where username = '{self.ownername}'")
            cursor.execute(f"insert into users values('{self.ownername}','{hashlib.sha256(self.ownerpassword.encode()).hexdigest()}')")
            userdbcursor.execute("create table if not exists loggedinusers(username, connection)")
            userdb.commit()
            userdbcursor.close()
            userdb.close()
            db.commit()
            cursor.close()
            db.close()
            self.configure_rooms()
            self.log(f"\n\n[({datetime.datetime.today()})][(INFO)]: Began Logging!")
            self.show_info(f"""
[({datetime.datetime.today()})][(INFO)]: Running on DatCord Version {self.version}.
[({datetime.datetime.today()})][(INFO)]: Server is hosted on: {self.ip}:{self.port}                                       
[({datetime.datetime.today()})][(INFO)]: Owner Account Info: Username: {self.ownername} Password: {self.ownerpassword}      
[({datetime.datetime.today()})][(INFO)]: Server is being logged. Logfile: {self.logfile}                                    
[({datetime.datetime.today()})][(INFO)]: Database file for password storage: {self.dbfile}          
[({datetime.datetime.today()})][(INFO)]: Active Sessions Database File: {self.userdbfile}                        
[({datetime.datetime.today()})][(INFO)]: Room-data file: {self.roomdata}""")
    def check_update(self):
        """Automatically checks for any updates in the version. It compares the current
        version with the latest version in the server to determine whether it should be
        updated or not. It makes a request to the .json file in my github repository,
        where the json data is loaded into a dictionary and information can be extracted
        from there. The latest version of the script then identified from the loaded data
        and is compared to the scripts current version(indictated from a variable in the
        '__init__' function). This would help the script decide whether to ask to update
        or not."""
        try:
            req = urllib.request.Request(url="https://raw.githubusercontent.com/DrSquidX/DatCord/main/DatCordVersion.json")
            resp = urllib.request.urlopen(req).read().decode()
            file = open("DatCordVersion.json", "w")
            file.write(resp)
            file.close()
            loaded = json.load(open("DatCordVersion.json","r"))
            latest_version = loaded[0]["DatCordVersion"]
            if float(latest_version) > float(self.version):
                print(f"\n[+] DatCord Update v{latest_version} available. Your current version is DatCord v{self.version}.")
                while True:
                    item = input("[+] Do you wish to download it(yes/no)?: ")
                    if item.lower() == "yes":
                        print("[+] Updating DatCord...........")
                        req = urllib.request.Request(url="https://raw.githubusercontent.com/DrSquidX/DatCord/main/DatCord.py")
                        resp = urllib.request.urlopen(req).read().decode()
                        file = open(sys.argv[0], "w")
                        file.write(resp)
                        file.close()
                        print("\n[+] Successfully Updated.")
                        time.sleep(1)
                        self.start = False
                        break
                    elif item.lower() == "no":
                        print("[+] Choosing not to update.")
                        break
                    else:
                        print("[+] Invalid Input.")
        except:
            pass
    def log(self, text):
        """Logs server output to the server log file."""
        self.update_file(self.logfile, text)
    def configure_rooms(self):
        """Configures the chat rooms for people to be able to connect
        to them. It adds a connection list for every room created.
        (.append() adds an item to a 'list' object)"""
        self.rooms = []
        db = sqlite3.connect(self.dbfile)
        cursor = db.cursor()
        cursor.execute("select roomname from open_rooms")
        for i in cursor.fetchall():
            item = []
            item.append(str(i[0]))
            self.roomkicked.append(item)
            self.rooms.append(item)
    def listen(self):
        """This is the function that listens for connections. When someone connects to the server,
        the script will start a thread to handle that connection(the threading.Thread() part).
        There the client can communicate with the server, log in and do what they can do. The server
        will also be warned about DDoS Attacks, and will close any incoming connections if the
        connections per second gets too high. This is where the whitelist system takes place, where
        connections from the IP's in the whitelist are accepted into the server. The automatic IP
        banning function starts to take place if the DDoS Attacks last longer than 5 seconds. It
        will start to ban all of the IP Addresses that connect to the server. While not perfect, as
        it may ban innocent IP Addresses, it will help stop the DDoS Attack on the server."""
        if self.start:
            self.uptimeadder = threading.Thread(target=self.add_to_connvar)
            self.uptimeadder.start()
            print(f"[({datetime.datetime.today()})][(LISTEN))]: Server is listening......")
            self.log(f"\n[({datetime.datetime.today()})][(LISTEN))]: Server is listening......")
            self.being_attacked = False
            self.auto_ban = False
            self.waitingforautoban = False
            timetoauto_ban = 0
            while True:
                try:
                    if self.listening:
                        self.server.listen()
                        conn, ip = self.server.accept()
                        if not self.listening:
                            conn.close()
                        else:
                            closed = False
                            if ip[0] in self.get_iplist("ipbanlist"):
                                closed = True
                                conn.close()
                            else:
                                self.conncount += 1
                                self.connpersec = self.conncount / self.uptime
                            if self.connpersec >= self.maxconnpersec:
                                self.connpersec = self.maxconnpersec + 5
                            if not closed:
                                if not self.being_attacked:
                                    if self.uptime == 60:
                                        self.uptime = 0
                                        self.conncount = 0
                                if self.connpersec <= self.maxconnpersec:
                                    self.being_attacked = False
                                    self.waitingforautoban = False
                                    if not self.manualbanall and self.banningallincomingconn:
                                        self.banningallincomingconn = False
                                        self.show_info(f"\n[({datetime.datetime.today()})][(ANTI-DDOS)]: Automatically setting banning all incoming IP's to: {self.banningallincomingconn}.")
                                        if not self.listening:
                                            self.listening = True
                                elif self.connpersec >= self.maxconnpersec:
                                    if not self.waitingforautoban:
                                        timetoauto_ban = time.time()
                                        self.waitingforautoban = True
                                    if round(time.time() - timetoauto_ban) >= 5 and not self.banningallincomingconn:
                                        self.banningallincomingconn = True
                                        self.show_info(f"\n[({datetime.datetime.today()})][(ANTI-DDOS)]: Automatically setting banning all incoming IP's to: {self.banningallincomingconn}.")
                                    self.being_attacked = True
                                    if ip[0] in self.get_iplist("ipwhitelist"):
                                        pass
                                    else:
                                        if not closed:
                                            self.show_info(f"\n[({datetime.datetime.today()})][(DDOS-WARN)]: Server may be under attack! Source IP of Attacker: {ip}")
                                            conn.close()
                                if self.banningallincomingconn:
                                    if ip[0] == "127.0.0.1":
                                        self.listening = False
                                        self.show_info(f"\n[({datetime.datetime.today()})][(INFO)]: Server is being hosted on LOCALHOST! Setting Listening for connections to: {self.listening}")
                                    else:
                                        if ip[0] not in self.get_iplist("ipwhitelist"):
                                            if ip[0] not in self.get_iplist("ipbanlist"):
                                                self.ban_ip_fr_server(ip[0])
                                if self.connpersec < self.maxconnpersec or ip[0] in self.get_iplist("ipwhitelist"):
                                    self.show_info(f"\n[({datetime.datetime.today()})][(CONN)]: {ip} has connected.")
                                    isbanned = False
                                    if ip[0] in self.get_iplist("ipbanlist"):
                                        isbanned = True
                                    if not isbanned:
                                        handler = threading.Thread(target=self.handler, args=(conn, ip))
                                        handler.start()
                                    else:
                                        self.show_info(f"\n[({datetime.datetime.today()})][(WARN)]: {ip} is in the IP Banlist! Closing connection....")
                                else:
                                    try:
                                        conn.close()
                                    except:
                                        pass
                    else:
                        pass
                except Exception as e:
                    self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: Error whilst listening for connections: {e}")
        else:
            print("[+] Restart DatCord to apply the update!")
            sys.exit()
    def exec_sqlcmd(self, file, cmd):
        """This function connects to an SQL Database. It connects to the filename
        that is provided, and executes a command that is provided within the
        arguments. This function was made for optimization, and to help to
        avoid making too-repetitive code."""
        db = sqlite3.connect(file)
        cursor = db.cursor()
        cursor.execute(cmd)
        db.commit()
        cursor.close()
        db.close()
    def attempt_login(self, username, password):
        """Authentication Function with logging in. It connects to the SQL Users
        database file, where it hashes the password provided and then sees if it
        matches the one in the database. If the username does not exist, it will
        raise the NameNotInDatabaseError. The hashed password will be compared
        to the one in the database, and if it's correct, they have successfully
        authenitcated."""
        password = hashlib.sha256(password.encode()).hexdigest()
        db = sqlite3.connect(self.dbfile)
        cursor = db.cursor()
        tag = 0
        username = username.strip('"').strip("'")
        cursor.execute(f"select * from users where username = '{username}'")
        for i in cursor.fetchall():
            if username in i[0]:
                tag = 1
                db_password = i[1]
                if password.strip() == db_password.strip():
                    return True
                else:
                    raise self.ServerError.AuthenticationError
        if tag == 0:
            raise self.ServerError.NameNotInDatabaseError
        cursor.close()
        db.close()
    def add_to_connvar(self):
        """Adds 1 to the up time variable after every second.
        This function is used for the Anti-DDoS Function.
        It additionally changes the connections per second var."""
        while True:
            time.sleep(1)
            if self.connpersec <= self.maxconnpersec:
                self.being_attacked = False
                self.waitingforautoban = False
                if not self.manualbanall and self.banningallincomingconn:
                    self.banningallincomingconn = False
                    logmsg = f"[({datetime.datetime.today()})][(ANTI-DDOS)]: Automatically setting banning all incoming IP's to: {self.banningallincomingconn}."
                    print(logmsg)
                    self.log(f"\n" + logmsg)
                    if not self.listening:
                        self.listening = True
            if not self.being_attacked:
                if self.uptime >= 30:
                    self.uptime = 0
                    self.conncount = 0
            self.uptime += 1
            try:
                self.connpersec = self.conncount / self.uptime
            except:
                pass
    def get_iplist(self, ls):
        """Gets all of the IP Addresses in a list in the database(ex. whitelist, banlist)."""
        db = sqlite3.connect(self.dbfile)
        cursor = db.cursor()
        cursor.execute(f"select * from {ls}")
        ip_list = []
        for i in cursor.fetchall():
            ip_list.append(i[0])
        return ip_list
    def register_accounts(self, username, password):
        """Adds an account to the Users database file and registers the user
        onto it. If the username is already registered in the database, it
        will raise the NameAlreadyRegisteredError."""
        password = hashlib.sha256(password.encode()).hexdigest()
        db = sqlite3.connect(self.dbfile)
        cursor = db.cursor()
        cursor.execute("select * from users")
        tag = 0
        for i in cursor.fetchall():
            if username in i:
                tag = 1
        if tag == 1:
            raise self.ServerError.NameAlreadyRegisteredError
        else:
            cursor.execute(f"insert into users values('{username}', '{password}')")
        db.commit()
        cursor.close()
        db.close()
    def change_password(self, username, password):
        """Changes the users password. It first hashes it and then puts it
        back into the database."""
        password = hashlib.sha256(password.encode()).hexdigest()
        self.exec_sqlcmd(self.dbfile, f'update users set password = "{password}" where username = "{username}"')
    def change_room_password(self, roomname, password):
        """Changes the room password. It first hashes it and then puts it
        back into the database."""
        password = hashlib.sha256(password.encode()).hexdigest()
        self.exec_sqlcmd(self.dbfile, f'update open_rooms set roompass = "{password}" where roomname = "{roomname}"')
    def add_name_to_db(self, name, conn):
        """Adds a name and the connection to the active connections
        database file."""
        self.exec_sqlcmd(self.userdbfile, f"insert into loggedinusers values('{name}', '{conn}')")
    def remove_user_from_db(self, name):
        """This Deletes the name from the Active connections database."""
        self.exec_sqlcmd(self.userdbfile,f"delete from loggedinusers where username = '{name}'")
    def create_room(self, roomname, roompass):
        """This adds a room into the rooms table in the Users database."""
        self.exec_sqlcmd(self.dbfile,f"insert into open_rooms values('{roomname.strip()}','{roompass.strip()}')")
    def ban_user_fr_server(self, user):
        """This adds a user to the banlist in the Users database."""
        self.exec_sqlcmd(self.dbfile, f"insert into banlist values('{user}')")
    def unban_user_fr_server(self, user):
        """This unbans a user from the banlist in the users database."""
        self.exec_sqlcmd(self.dbfile, f"delete from banlist where username = '{user}'")
    def ban_ip_fr_server(self, ip):
        """This adds an ip to the banlist in the Users database."""
        self.exec_sqlcmd(self.dbfile, f"insert into ipbanlist values('{ip}')")
    def unban_ip_fr_server(self, ip):
        """This unbans an ip from the banlist in the users database."""
        self.exec_sqlcmd(self.dbfile, f"delete from ipbanlist where ip = '{ip}'")
    def whitelist_ip_to_server(self, ip):
        """This adds an ip to the whitelist in the Users database."""
        self.exec_sqlcmd(self.dbfile, f"insert into ipwhitelist values('{ip}')")
    def unwhitelist_ip_fr_server(self, ip):
        """This unwhitelists an ip from the whitelist in the users database."""
        self.exec_sqlcmd(self.dbfile, f"delete from ipwhitelist where ip = '{ip}'")
    def attempt_join_room(self, name, password):
        """Attempts to join a chat-room from the database. It connects to the name
        provided and then uses the password provided and hashes it, where if the
        password is correct, the user can go into the room. Otherwise the
        AuthenticationError will be raised."""
        db = sqlite3.connect(self.dbfile)
        cursor = db.cursor()
        cursor.execute(f"select * from open_rooms where roomname = '{name}'")
        tag = 0
        info = None
        for i in cursor.fetchall():
            if name in i[0]:
                info = i
                tag = 1
                break
        if tag == 0:
            raise self.ServerError.NameNotInDatabaseError(f"Room '{name}' does not exist.")
        else:
            hashed_pass = hashlib.sha256(password.encode()).hexdigest()
            if hashed_pass.strip() == info[1].strip():
                return True
            else:
                raise self.ServerError.AuthenticationError(f"Incorrect password for Room '{name}'")
    def delete_account(self, username):
        """Deletes the specified account. It first unfriends all of the people the 
        user is friends with, where it removes its name from all of the SQL Tables."""
        friendslist = self.get_friends_list(username)
        for friend in friendslist:
            self.rm_friend(friend, username)
        tablenames = ["friendslist","friendrequests","blocklists"]
        for i in tablenames:
            self.exec_sqlcmd(self.dbfile, f"delete from {i} where user = '{username}'")
        self.exec_sqlcmd(self.dbfile,f"delete from users where username = '{username}'")
        for i in self.get_all_rooms_in(username):
            for ii in self.member_types:
                if username in self.get_role_members(i, "Owner:"):
                    if len(self.get_role_members(i,"Admins:")) != 0:
                        new_owner = random.choice(self.get_role_members(i,"Admins:"))
                    elif len(self.get_role_members(i,"Members:")) != 0:
                        new_owner = random.choice(self.get_role_members(i,"Members:"))
                    else:
                        new_owner = random.choice(self.get_userlist())
                    try:
                        newowner_conn = self.opendm(new_owner)
                        newowner_conn.send(self.fernet(f"[(SERVER)]: You have become the new owner of the chatroom '{i}'".encode()))
                        self.show(f"\n[({datetime.datetime.today()})][(NEWCHATROOMOWNER)]: User '{new_owner}' has become the new owner of chatroom '{i}'")
                    except:
                        pass
                    self.add_to_roomdata(new_owner, i, "Owner:")
                self.del_from_roomdata(username, i, ii)
    def get_all_rooms_in(self, username):
        """A function that gets all of the rooms that the specified user is in currently."""
        file = open(self.roomdata, "r")
        contents = file.readlines()
        file.close()
        room_list = []
        current_room = ""
        for i in contents:
            if i.startswith("RoomName:"):
                current_room = i.split()[1]
            for ii in i.split():
                if username == ii and current_room not in room_list:
                    room_list.append(current_room)
        return room_list
    def check_for_sameitems(self, file, name, cmd):
        """This checks for same items that already in the server. If the name is
        already in the database, then the value the function is assigned to will
        return as False(bool object). It was recently made into one function. There
        was one for checking for the same names in the database as well as one
        for checking if there is a session with the account opened."""
        db = sqlite3.connect(file)
        cursor = db.cursor()
        tag = 0
        try:
            cursor.execute(cmd)
            for i in cursor.fetchall():
                if name in i[0]:
                    tag = 1
                    return True
            if tag == 0:
                return False
        except:
            return False
        cursor.close()
        db.close()
    def update_file(self, file, text):
        """This function adds text to a file. It opens a file, reads its contents
        and then re-writes those contents and adds the text that needs to be added."""
        try:
            files = open(file, "r")
            content = files.read()
            files.close()
            files = open(file, "w")
            files.write(content)
            files.write(text)
            files.close()
        except Exception as e:
            self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with updating file('{file}'): {e}")
    def add_to_roomdata(self, selfname, roomname, stat):
        """This function adds names to room-data. It adds the name to the
        provided room stat(admin, member, etc)."""
        file = open(self.roomdata, "r")
        contents = file.readlines()
        file.close()
        in_data = False
        new_ls = []
        needed_items = []
        for i in contents:
            if roomname in i:
                in_data = True
            if in_data:
                needed_items.append(i)
                if i.strip() == "EndData":
                    in_data = False
            else:
                new_ls.append(i)
        item = 0
        needed_line = f"{stat} "
        can_do = True
        for i in needed_items:
            if i.startswith("Owner: "):
                owner = i.split()[1]
                if selfname.strip() == owner.strip():
                    if stat != "Members: ":
                        can_do = False
                        raise self.ServerError.PermissionError
        if can_do:
            del needed_items[len(needed_items)-1]
            for i in needed_items:
                if i.strip().startswith(stat):
                    needed_line = i.strip()
                    needed_items.remove(needed_items[item])
                    needed_line += f" {selfname}"
                    needed_line = needed_line.strip()+"\nEndData\n"
                    needed_items.append(needed_line)
                    file = open(self.roomdata, "w")
                    file.writelines(new_ls)
                    file.writelines(needed_items)
                    file.close()
                    break
                item += 1
    def del_from_roomdata(self, user, roomname, stat):
        """This function removes names from room-data. Removes from a provided stat.
        It is very similar to the 'add_to_roomdata' function."""
        file = open(self.roomdata, "r")
        contents = file.readlines()
        file.close()
        in_data = False
        new_ls = []
        needed_items = []
        for i in contents:
            if roomname in i:
                in_data = True
            if in_data:
                needed_items.append(i)
                if i.strip() == "EndData":
                    in_data = False
            else:
                new_ls.append(i)
        item = 0
        needed_line = ""
        can_do = True
        for i in needed_items:
            if i.startswith(stat):
                needed_line = i
                needed_items.remove(needed_items[item])
                main_line = ""
                for i in needed_items:
                    if i.startswith("Owner: "):
                        owner = i.split()[1]
                        if user.strip() == owner.strip():
                            if stat != "Members: ":
                                can_do = False
                                raise self.ServerError.PermissionError
                if can_do:
                    del needed_items[len(needed_items)-1]
                    for items in needed_line.split():
                        if user.strip() == items.strip():
                            pass
                        else:
                            main_line += items + " "
                    main_line = main_line.strip()
                    needed_items.append(main_line)
                    needed_items.extend("\nEndData\n")
                    file = open(self.roomdata, "w")
                    file.writelines(new_ls)
                    file.writelines(needed_items)
                    file.close()
                    break
                break
            item += 1
        pass
    def get_role_members(self, room, stat):
        """Gets all of the members inside of a specific role, in a
        specific chatroom."""
        file = open(self.roomdata,"r")
        contents = file.readlines()
        indata = True
        member_list = []
        for i in contents:
            if i.startswith("RoomName"):
                if i.split()[1] == room:
                    indata = True
            if indata:
                if i != "EndData":
                    if i.startswith(stat):
                        member_list = i.split()
                        del member_list[0]
                        return member_list
                else:
                    indata = False
                    break
    def get_all_room_roles(self, room):
        """Gets all of the roles of a specified room."""
        file = open(self.roomdata,"r")
        contents = file.readlines()
        indata = True
        info = ""
        for i in contents:
            if i.startswith("RoomName"):
                if i.split()[1] == room:
                    indata = True
            if indata:
                if i != "EndData":
                    for i in self.member_types:
                        info += f"({i}) {self.get_role_members(room,i)} "
                    break
                else:
                    indata = False
                    break
        return info
    def show_info(self, msg):
        """This displays and logs errors that happen in the server."""
        self.log(msg)
        print(msg.strip())
    def show_server_com_with_client(self, conn, clientname, msg):
        """This displays and logs server communication with the
        clients."""
        main_msg = self.fernet.encrypt("\n[(SERVER)]: ".encode()+msg.encode())
        conn.send(main_msg)
        new_msg = f"[({datetime.datetime.today()})][(SERVER)--->({clientname})]: {msg}"
        self.show_info("\n"+new_msg.strip("\n"))
    def opendm(self, username):
        """This opens a direct message room with another user."""
        db = sqlite3.connect(self.userdbfile)
        tag = 0
        cursor = db.cursor()
        cursor.execute(f"select * from loggedinusers where username = '{username}'")
        try:
            for i in cursor.fetchall():
                if username in i[0]:
                    ipandsrcport = str(i[1]).split()
                    tag = 1
            if tag == 1:
                for i in self.conn_list:
                    if ipandsrcport[0] in str(i) and ipandsrcport[1] in str(i):
                        return i
            else:
                raise self.ServerError.NameNotInDatabaseError
        except:
            raise self.ServerError.NameNotInDatabaseError
    def sendall(self,msg,ls=None):
        """This sends a message to everyone in the connection list."""
        if ls is None:
            ls = self.conn_list
        for conn in ls:
            try:
                conn.send(self.fernet.encrypt(msg.encode()))
            except:
                pass
    def get_online_friends(self, selfname):
        """Gets a list of all the users online friends."""
        db = sqlite3.connect(self.userdbfile)
        cursor = db.cursor()
        cursor.execute(f"select username from loggedinusers")
        items = cursor.fetchall()
        online_friends = []
        friends = self.get_friends_list(selfname)
        for i in items:
            if i[0] in friends:
                online_friends.append(i[0])
        return online_friends
    def kick_user_fr_room(self, user, chatroomname, banned=False):
        """This function deletes the user from the connections list
        in the room."""
        db = sqlite3.connect(self.userdbfile)
        cursor = db.cursor()
        cursor.execute("select * from loggedinusers")
        for i in cursor.fetchall():
            if user in i[0]:
                conninfo = str(i[1]).split()
                for ii in self.rooms:
                    if chatroomname in ii[0]:
                        for iii in ii:
                            if conninfo[0] in str(iii) and conninfo[1] in str(iii):
                                if banned:
                                    item = "banned"
                                else:
                                    item = "kicked"
                                logmsg = f"[({datetime.datetime.today()})][(SERVER)--->({chatroomname})]: {user} has left the chat!"
                                print(logmsg)
                                self.log("\n" + logmsg)
                                self.sendall(f"\n[(SERVER)]: {user} has left the chat!", ii)
                                try:
                                    self.show_server_com_with_client(iii, user, f"You have been {item} from the chatroom.")
                                except:
                                    pass
                                for items in self.roomkicked:
                                    if chatroomname in items[0]:
                                        if user not in items:
                                            items.append(user)
                                            break
                                ii.remove(iii)
                        break
    def get_friends_list(self, name):
        """Gets the friendlist of the username provided."""
        db = sqlite3.connect(self.dbfile)
        cursor = db.cursor()
        cursor.execute(f"select * from friendslist where user = '{name}'")
        ls = cursor.fetchall()[0][1]
        return str(ls).split()
    def add_friend(self, selfname, friend):
        """Adds a friend to the selfname's friendlist."""
        old_ls = self.get_friends_list(selfname)
        new_ls = ""
        for i in old_ls:
            new_ls = new_ls + " " + i
        items = new_ls + " " + friend
        self.exec_sqlcmd(self.dbfile, f'update friendslist set friends = "{items}" where user = "{selfname}"')
    def rm_friend(self, selfuser, user):
        """Removes a friend from the selfusers friendlist."""
        old_ls = self.get_friends_list(selfuser)
        try:
            old_ls.remove(user)
        except:
            pass
        new_ls = ""
        for i in old_ls:
            new_ls = new_ls + " " + i
        self.exec_sqlcmd(self.dbfile, f"update friendslist set friends = '{new_ls}' where user = '{user}'")
    def block_user(self, selfname, user):
        """Blocks a user and add their name to the original Usernames blocklist."""
        db = sqlite3.connect(self.dbfile)
        cursor = db.cursor()
        cursor.execute(f"select * from blocklists where user = '{selfname}'")
        item = cursor.fetchall()
        items = str(item[0][1]) + " " + user
        self.exec_sqlcmd(self.dbfile, f"update blocklists set blockedusers = '{items}' where user = '{selfname}'")
    def unblock_user(self, selfname, user):
        """Unblocks a user from the original users blocklist."""
        old_ls = self.get_block_list(selfname)
        old_ls.remove(user)
        new_ls = ""
        for i in old_ls:
            new_ls = new_ls + " " + i
        self.exec_sqlcmd(self.dbfile, f"update blocklists set blockedusers = '{new_ls}' where user = '{selfname}'")
    def get_block_list(self, user):
        """Gets a list of all of the blocked users a username has blocked."""
        db = sqlite3.connect(self.dbfile)
        cursor = db.cursor()
        cursor.execute(f"select * from blocklists where user = '{user}'")
        item = cursor.fetchall()
        try:
            ls = item[0][1]
        except:
            ls = ""
        return str(ls).split()
    def get_userlist(self):
        """Gets a list of all the registered users in the database."""
        db = sqlite3.connect(self.dbfile)
        cursor = db.cursor()
        cursor.execute("select username from users")
        users = []
        for i in cursor.fetchall():
            users.append(i[0])
        return users
    def login_help_message(self):
        """Generates the help message with all of the login commands."""
        msg = """
[(SERVER)]:
[+] Log-In Commands For This server:
[+] !login [username] [password]           - Logs into your account.
[+] !register [username] [password]        - Registers your account to the server."""
        return msg
    def regular_client_help_message(self):
        """Generates the help message for regular clients(after logging in)."""
        msg = """
[(SERVER)]:
[+] Regular Commands For This Server:
[+] !help                                  - Displays this message.
[+] !dm [user]                             - Opens a DM With the specified User.
[+] !closedm                               - Closes the DM that you are currently in.
[+] !reregister [old_pass] [new_pass]      - Changes your current password if you enter the correct one.
[+] !createroom [room_name] [room_pass]    - Creates a chat room(the password is optional).
[+] !joinroom [room_name] [room_pass]      - Joins a chat room(the password is optional)
[+] !leaveroom                             - Leaves the current room you are in.
[+] !getroomlist                           - Gets the list of all the rooms you are a part of.
[+] !block [user]                          - Blocks a user(they cannot dm or friend request you).
[+] !unblock [user]                        - Unblocks a user.
[+] !friendreq [user]                      - Sends a friend request to the user.
[+] !friendaccept [user]                   - Accepts a friend request from a user.
[+] !friendremove [user]                   - Removes a user from your friends list.
[+] !getrequests                           - Gets a list of all the people who have sent friend requests to you.
[+] !showonlinefriends                     - Gets a list of all your online friends.
[+] !showfriendslist                       - Gets your friends list.
[+] !roomban [user]                        - Bans a user from the chat-room(you need to be room admin).
[+] !roomunban [user]                      - Unbans a user from the chat-room(you need to be room admin).
[+] !roomkick [user]                       - Kicks a user from the chat room(they can re-enter with the same password).
[+] !changeroompass [new_pass]             - Changes the room password for a room(need to be room owner).
[+] !promoteuser [user]                    - Promotes a user to room-admin(you need to be room admin).
[+] !demoteuser [user]                     - Demotes a user down to regular room client(you need to be room admin).
[+] !deleteacc                             - Removes your account from the database(everything except for banlists will be removed from the database)."""
        return msg
    def admin_help_message(self):
        """Generates the admin help message for admins."""
        msg = """
[(SERVER)]:
[+] Admin Commands For This Server:
[+] !unnick                                - Reverts yourname back to the owner account.
[+] !allipban                              - Toggles whether to ban all incoming IP addresses or not. 
[+] !togglelisten                          - Toggles whether to listen for connections or not.
[+] !nick [username]                       - Changes your name.
[+] !ipban [ip_addr]                       - Bans the IP Address specified.
[+] !ipunban [ip_addr]                     - Unbans the IP Address specified.
[+] !whitelistip [ip_addr]                 - Whitelists an IP Address(connections from it will be accepted even in DDoS Attack).
[+] !unwhitelistip [ip_addr]               - Removes an IP from the IP whitelist.
[+] !broadcast [msg]                       - Broadcasts a message to everyone in the server.
[+] !ban [user]                            - Bans a user from the server.
[+] !unban [user]                          - Unbans a user from the server.
[+] !kick [user]                           - Kicks a user from the server."""
        return msg
    def handler(self, conn, ip):
        """This is the main handler for connections. Every message from the client
        will be used into this function(used as a thread), to do the programmed
        commands from the server. There are variables to recognize whether the user
        is the Owner or not, if the user is in a room, or dm, or not."""
        selfname = str(ip).strip('()')
        logged_in = False
        inroom = False
        roomadmin = False
        indm = False
        dmconn = None
        dmusername = None
        serverowner = False
        roomowner = False
        kicked_from_room = False
        selfroomname = ""
        timer = time.time()
        login_attempts = 0
        max_login_attempts = 5
        msgspersec = 0
        max_spam_warns = 3
        spam_warnings = 0
        del_confirmation = False
        if self.ip == "localhost":
            max_msg_persec = 3
        else:
            max_msg_persec = 4
        valid_conn = False
        try:
            conn.send(f"DatCord Server v{self.version}".encode())
            time.sleep(0.1)
            conn.send(self.key)
            time.sleep(0.1)
            conn.send(self.fernet.encrypt(self.login_help_message().encode()))
            othermsg = f"[({datetime.datetime.today()})][(SERVER)--->({selfname})]: Sent the Login Help Message."
            print(othermsg)
            self.log("\n" + othermsg)
            valid_conn = True
        except:
            conn.close()
        if valid_conn:
            while True:
                try:
                    msg = conn.recv(10240)
                    try:
                        msg = self.fernet.decrypt(msg)
                    except:
                        pass
                    msgspersec += 1
                    try:
                        msg = str(msg.decode())
                    except:
                        msg = str(msg)
                    this_main_msg = f"\n[({selfname})]: {msg}"
                    if not logged_in:
                        if msg.startswith("!register"):
                            try:
                                username = msg.split()[1].strip("'").strip('"')
                                this_main_msg = f"\n[({selfname})]: Attempting to register as {username}."
                            except:
                                pass
                        elif msg.startswith("!login"):
                            try:
                                username = msg.split()[1].strip("'").strip('"')
                                this_main_msg = f"\n[({selfname})]: Attempting to Log into {username}."
                            except:
                                pass
                    else:
                        if msg.startswith("!reregister"):
                            this_main_msg = f"\n[({selfname})]: Attempting to change password."
                        elif msg.startswith("!createroom"):
                            try:
                                roomname = msg.split()[1]
                            except:
                                roomname = len(self.rooms)
                            this_main_msg = f"\n[({selfname})]: Creating Room with name: {roomname}."
                        elif msg.startswith("!changeroompass"):
                            if roomowner:
                                this_main_msg = f"\n[({selfname})]: Attempting to change room password of {selfroomname}."
                    if msg.strip() == "":
                        pass
                    else:
                        if not indm and not inroom:
                            self.show_info(f"\n[({datetime.datetime.today()})]" + this_main_msg.strip())
                    if indm:
                        try:
                            if serverowner:
                                self.show_info(f"\n[({datetime.datetime.today()})][({selfname})--->({dmusername})]: {msg.strip()}")
                                dmconn.send(self.fernet.encrypt("\n[(DM)]".encode() + this_main_msg.strip().encode()))
                            elif selfname in self.get_block_list(dmusername):
                                if not serverowner:
                                    self.show_server_com_with_client(conn, selfname, "You have been blocked by the user you were trying to DM. Closing your DM.")
                                    indm = False
                            elif dmusername in self.get_block_list(selfname):
                                if not serverowner:
                                    self.show_server_com_with_client(conn, selfname, "You have recently blocked the user you were direct messaging. Closing your DM.")
                                    indm = False
                            else:
                                dmconn.send(self.fernet.encrypt("\n[(DM)]".encode() + this_main_msg.strip().encode()))
                                self.show_info(f"\n[({datetime.datetime.today()})][({selfname})--->({dmusername})]: {msg.strip()}")
                        except:
                            self.show_server_com_with_client(conn, selfname, f"There was an error with sending your DM Message! The person may have gone offline. Closing your DM.")
                            indm = False
                    current_timer = time.time()
                    if round(current_timer-timer) >= 1:
                        if not serverowner:
                            if msgspersec >= max_msg_persec:
                                spam_warnings += 1
                                if max_spam_warns - spam_warnings == 1:
                                    self.show_server_com_with_client(conn, selfname, f"Spam warning number {spam_warnings}. Please do not spam in the server. You have {max_spam_warns - spam_warnings} warning left until you are kicked.")
                                else:
                                    self.show_server_com_with_client(conn, selfname, f"Spam warning number {spam_warnings}. Please do not spam in the server. You have {max_spam_warns - spam_warnings} warnings left until you are kicked.")
                            if spam_warnings >= max_spam_warns:
                                self.show_server_com_with_client(conn, selfname, f"You have been kicked for spamming.")
                                conn.close()
                            timer = time.time()
                            msgspersec = 0
                    if not logged_in:
                        if msg.startswith("!login"):
                            try:
                                username = msg.split()[1].strip("'").strip('"')
                                password = msg.split()[2].strip("'").strip('"')
                                authentication = self.attempt_login(username, password)
                                if authentication:
                                    namealreadylogged = self.check_for_sameitems(self.userdbfile, username, f"select * from loggedinusers where username = '{username}'")
                                    if namealreadylogged:
                                        self.show_server_com_with_client(conn, selfname, "Your account is already being used in another location!")
                                        self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: {ip} is unable to log into {username} due to it currently being used in another location!")
                                    else:
                                        selfname = username
                                        isbanned = False
                                        db = sqlite3.connect(self.dbfile)
                                        cursor = db.cursor()
                                        cursor.execute("select * from banlist")
                                        for i in cursor.fetchall():
                                            if selfname in i[0]:
                                                isbanned = True
                                                break
                                        if not isbanned:
                                            logged_in = True
                                            self.conn_list.append(conn)
                                            self.add_name_to_db(selfname, str(ip[0]) + " " + str(ip).strip('()').split()[1])
                                            self.show_server_com_with_client(conn, selfname, "Successfully logged in!")
                                            self.show_info(f"\n[({datetime.datetime.today()})][(SUCCESSAUTH)]: {ip} has logged into the account {selfname}.")
                                            if self.ip == "localhost":
                                                time.sleep(0.5)
                                            conn.send(self.fernet.encrypt(self.regular_client_help_message().encode()))
                                            othermsg = f"[({datetime.datetime.today()})][(SERVER)--->({selfname})]: Sent the Regular Help Message."
                                            print(othermsg)
                                            self.log("\n" + othermsg)
                                            display_msg = f"[({datetime.datetime.today()})][(INFO)]: {ip} is {selfname}."
                                            self.log("\n"+display_msg)
                                            print(display_msg)
                                            if selfname == self.ownername:
                                                serverowner = True
                                                conn.send(self.fernet.encrypt(self.admin_help_message().encode()))
                                                infomsg = f"[({datetime.datetime.today()})][(INFO)]: {selfname} is an Admin!"
                                                print(infomsg)
                                                self.log("\n"+infomsg)
                                                othermsg = f"[({datetime.datetime.today()})][(SERVER)--->({selfname})]: Sent the Admin Help Message."
                                                print(othermsg)
                                                self.log("\n"+othermsg)
                                        else:
                                            self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: ({selfname}) tried to log into {username} but it banned from the server!")
                                            self.show_server_com_with_client(conn, selfname, "Your account has been banned from the server.")
                            except self.ServerError.AuthenticationError:
                                self.show_info(f"\n[({datetime.datetime.today()})][(AUTHENTICATIONERROR)]: ({selfname}) tried to log into {username} but the credentials provided were incorrect!")
                                self.show_server_com_with_client(conn, selfname, "Authentication Failed.")
                                login_attempts += 1
                                if login_attempts >= max_login_attempts:
                                    self.show_server_com_with_client(conn, selfname, "You have exceeded the amount of login attempts. You have been kicked from the server.")
                                    conn.close()
                            except self.ServerError.NameNotInDatabaseError:
                                self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: ({selfname}) tried to log into {username} but it is not registered in the database!")
                                self.show_server_com_with_client(conn, selfname, "Your account is not registered in the database. Please register your account.")
                            except Exception as e:
                                self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing arguments: {e}")
                                self.show_server_com_with_client(conn, selfname, "Invalid arguments! Proper Usage: !login <username> <password>")
                        elif msg.startswith("!register"):
                            try:
                                username = msg.split()[1].strip("'").strip('"')
                                password = msg.split()[2].strip("'").strip('"')
                                self.register_accounts(username, password)
                                logged_in = True
                                selfname = username
                                self.conn_list.append(conn)
                                self.add_name_to_db(selfname, str(ip[0])+" "+str(ip).strip('()').split()[1])
                                self.show_server_com_with_client(conn, selfname, "Successfully Registered. You have been logged in with this account!")
                                self.show_info(f"\n[({datetime.datetime.today()})][(NEWACC)]: {ip} has registered the account {selfname} to the database.")
                                conn.send(self.fernet.encrypt(self.regular_client_help_message().encode()))
                                self.show_info(f"\n[({datetime.datetime.today()})][(SERVER)--->({selfname})]: Sent the Regular Help Message.")
                                self.show_info(f"\n[({datetime.datetime.today()})][(INFO)]: {ip} is {selfname}.")
                                self.exec_sqlcmd(self.dbfile, f"insert into friendslist values('{selfname}', '')")
                                self.exec_sqlcmd(self.dbfile, f"insert into friendrequests values('{selfname}', '')")
                                self.exec_sqlcmd(self.dbfile, f"insert into blocklists values('{selfname}', '')")
                            except self.ServerError.NameAlreadyRegisteredError:
                                self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: ({selfname}) tried to register as {username} but it was already registered in the database!")
                                self.show_server_com_with_client(conn, selfname, "The account name is already registered in the database. Please use another name for your account.")
                            except Exception as e:
                                self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing arguments: {e}")
                                self.show_server_com_with_client(conn, selfname, "Invalid arguments! Proper Usage: !register <username> <password>")
                    if logged_in:
                        if serverowner:
                            if msg.startswith("!nick"):
                                try:
                                    self.show_info(f"\n[({datetime.datetime.today()})][(NICKCHANGE)]: {selfname} has changed their nick to {msg.split()[1]}.")
                                    selfname = msg.split()[1]
                                    self.show_server_com_with_client(conn, selfname, f"Changed your name to: {selfname}")
                                except:
                                    self.show_server_com_with_client(conn, selfname, "Invalid arguments! Proper Usage: !nick <username>")
                            elif msg.startswith("!unnick"):
                                selfname = self.ownername
                                self.show_info(f"\n[({datetime.datetime.today()})][(NICKCHANGE)]: {selfname} has changed their nick back to normal.")
                                self.show_server_com_with_client(conn, selfname, f"Changed your name back to: {selfname}")
                            elif msg.startswith("!togglelisten"):
                                if self.listening:
                                    logmsg = f"[({datetime.datetime.today()})][(INFO)]: Stopped Listening For Connections....."
                                    self.listening = False
                                else:
                                    logmsg = f"[({datetime.datetime.today()})][(INFO)]: Began Listening For Connections....."
                                    self.listening = True
                                self.show_server_com_with_client(conn, selfname, f"Set Listening for connections to {self.listening}.")
                                self.show_info(f"\n{logmsg}")
                            elif msg.startswith("!allipban"):
                                if self.banningallincomingconn:
                                    self.banningallincomingconn = False
                                    self.manualbanall = False
                                    logmsg = f"[({datetime.datetime.today()})][(INFO)]: Stopped banning all incoming IP's."
                                else:
                                    self.banningallincomingconn = True
                                    self.manualbanall = True
                                    logmsg = f"[({datetime.datetime.today()})][(INFO)]: Began banning all incoming IP's."
                                self.show_server_com_with_client(conn, selfname, f"Set Banning all incoming connections to: {self.banningallincomingconn}.")
                                self.show_info(f"\n{logmsg}")
                            elif msg.startswith("!ipban"):
                                try:
                                    ip_addr = msg.split()[1]
                                    actual_ip = socket.gethostbyname(ip_addr)
                                    if ip_addr in self.get_iplist("ipbanlist"):
                                        self.show_server_com_with_client(conn, selfname, f"The IP is already in the banlist!")
                                        self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: {selfname} tried to ban {ip_addr} but it was already in the banlist!")
                                    elif ip_addr == "127.0.0.1":
                                        self.show_server_com_with_client(conn, selfname, f"You can't ban localhost!")
                                        self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: {selfname} tried to ban localhost but failed!")
                                    else:
                                        self.ban_ip_fr_server(ip_addr)
                                        self.show_server_com_with_client(conn, selfname, f"Successfully banned {ip_addr}. They won't be able to join the server the next time they try to.")
                                        self.show_info(f"\n[({datetime.datetime.today()})][(IPBAN)]: {selfname} has banned {ip_addr}.")
                                except socket.error:
                                    self.show_server_com_with_client(conn, selfname, f"You Have provided an invalid IP Address!")
                                except Exception as e:
                                    self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing arguments: {e}")
                                    self.show_server_com_with_client(conn, selfname, f"Invalid arguments! Proper Usage: !ipban <ip>")
                            elif msg.startswith("!ipunban"):
                                try:
                                    ip_addr = msg.split()[1]
                                    actual_ip = socket.gethostbyname(ip_addr)
                                    if ip_addr not in self.get_iplist("ipbanlist"):
                                        self.show_server_com_with_client(conn, selfname, f"The IP Is not in the banlist!")
                                        self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: {selfname} tried to unban {ip_addr} but it wasn't in the banlist!")
                                    else:
                                        self.unban_ip_fr_server(ip_addr)
                                        self.show_server_com_with_client(conn, selfname, f"Successfully unbanned {ip_addr}.")
                                        self.show_info(f"\n[({datetime.datetime.today()})][(IPUNBAN)]: {selfname} has unbanned {ip_addr}.")
                                except socket.error:
                                    self.show_server_com_with_client(conn, selfname, f"You Have provided an invalid IP Address!")
                                except Exception as e:
                                    self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing arguments: {e}")
                                    self.show_server_com_with_client(conn, selfname, f"Invalid arguments! Proper Usage: !ipunban <ip>")
                            elif msg.startswith("!whitelistip"):
                                try:
                                    ip_addr = msg.split()[1]
                                    actual_ip = socket.gethostbyname(ip_addr)
                                    if ip_addr in self.get_iplist("ipbanlist"):
                                        self.show_server_com_with_client(conn, selfname, f"The IP Is in the banlist! Unban them first.")
                                        self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: {selfname} tried to whitelist {ip_addr} but it was in the banlist!")
                                    else:
                                        self.whitelist_ip_to_server(ip_addr)
                                        self.show_server_com_with_client(conn, selfname, f"Successfully whitelisted {ip_addr}.")
                                        self.show_info(f"\n[({datetime.datetime.today()})][(IPWHITELIST)]: {selfname} has whitelisted {ip_addr}.")
                                except socket.error:
                                    self.show_server_com_with_client(conn, selfname, f"You Have provided an invalid IP Address!")
                                except Exception as e:
                                    self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing arguments: {e}")
                                    self.show_server_com_with_client(conn, selfname, f"Invalid arguments! Proper Usage: !whitelistip <ip>")
                            elif msg.startswith("!unwhitelistip"):
                                try:
                                    ip_addr = msg.split()[1]
                                    actual_ip = socket.gethostbyname(ip_addr)
                                    if ip_addr not in self.get_iplist("ipwhitelist"):
                                        self.show_server_com_with_client(conn, selfname, f"The IP Is not in the whitelist!")
                                        self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: {selfname} tried to unban {ip_addr} but it wasn't in the whitelist!")
                                    else:
                                        self.unwhitelist_ip_fr_server(ip_addr)
                                        self.show_server_com_with_client(conn, selfname, f"Successfully unwhitelisted {ip_addr}.")
                                        self.show_info(f"\n[({datetime.datetime.today()})][(IPUNWHITELIST)]: {selfname} has unwhitelisted {ip_addr}.")
                                except socket.error:
                                    self.show_server_com_with_client(conn, selfname, f"You Have provided an invalid IP Address!")
                                except Exception as e:
                                    self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing arguments: {e}")
                                    self.show_server_com_with_client(conn, selfname, f"Invalid arguments! Proper Usage: !unwhitelistip <ip>")
                            elif msg.startswith("!broadcast"):
                                try:
                                    msg_to_all = msg.split()
                                    del msg_to_all[0]
                                    _main_msg = ""
                                    for i in msg_to_all:
                                        _main_msg = _main_msg + i + " "
                                    _main_msg = _main_msg.strip()
                                    main_msg2 = f"\n[(BROADCAST)]: {_main_msg}"
                                    self.sendall(main_msg2)
                                    self.show_info(f"\n[({datetime.datetime.today()})][(BROADCAST)]: {_main_msg}")
                                except Exception as e:
                                    self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing arguments: {e}")
                                    self.show_server_com_with_client(conn, selfname, f"Invalid arguments! Proper Usage: !broadcast <msg>")
                            elif msg.startswith("!ban"):
                                try:
                                    banned_user = msg.split()[1]
                                    if banned_user == self.ownername:
                                        self.show_server_com_with_client(conn, selfname, f"You can't ban yourself!")
                                        self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: {selfname} tried to ban themself!")
                                    else:
                                        if banned_user in self.get_userlist():
                                            self.ban_user_fr_server(banned_user)
                                            self.show_server_com_with_client(conn, selfname, f"The Ban Hammer has spoken! {banned_user} has been banned from the server!")
                                            self.show_info(f"\n[({datetime.datetime.today()})][(USERBAN)]: {selfname} has banned {banned_user}!")
                                            db = sqlite3.connect(self.userdbfile)
                                            cursor = db.cursor()
                                            cursor.execute(f"select * from loggedinusers where username = '{banned_user}'")
                                            for i in cursor.fetchall():
                                                if banned_user.strip() == i[0].strip():
                                                    connectionnum = i[1]
                                                    for i in self.conn_list:
                                                        if connectionnum.split()[0] in str(i) and connectionnum.split()[
                                                            1] in str(i):
                                                            self.show_server_com_with_client(i, banned_user, "You have been banned from the server!")
                                                            i.close()
                                            cursor.close()
                                            db.close()
                                        else:
                                            self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: {selfname} tried to ban {banned_user} but the name wasn't registered!")
                                            self.show_server_com_with_client(conn, selfname, f"The name is not in the database!")
                                except Exception as e:
                                    self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing arguments: {e}")
                                    self.show_server_com_with_client(conn, selfname, f"Invalid arguments! Proper Usage: !ban <username>")
                            elif msg.startswith("!kick"):
                                try:
                                    kick_user = msg.split()[1]
                                    if kick_user == self.ownername:
                                        self.show_server_com_with_client(conn, selfname, f"You can't kick yourself!")
                                        self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: {selfname} tried to kick themself!")
                                    else:
                                        if banned_user in self.get_userlist():
                                            self.show_server_com_with_client(conn, selfname, f"{kick_user} has been kicked from the server!")
                                            db = sqlite3.connect(self.userdbfile)
                                            cursor = db.cursor()
                                            cursor.execute(f"select * from loggedinusers where username = '{kick_user}'")
                                            self.show_info(f"\n[({datetime.datetime.today()})][(USERKICK)]: {selfname} has kicked {kick_user}!")
                                            for i in cursor.fetchall():
                                                if kick_user.strip() == i[0].strip():
                                                    connectionnum = i[1]
                                                    for i in self.conn_list:
                                                        if connectionnum.split()[0] in str(i) and connectionnum.split()[1] in str(i):
                                                            self.show_server_com_with_client(i, kick_user, "You have been kicked from the server!")
                                                            i.close()
                                            cursor.close()
                                            db.close()
                                        else:
                                            self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: {selfname} tried to kick {kick_user} but the name wasn't registered!")
                                            self.show_server_com_with_client(conn, selfname, f"The name is not in the database!")
                                except Exception as e:
                                    self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing arguments: {e}")
                                    self.show_server_com_with_client(conn, selfname, f"Invalid arguments! Proper Usage: !kick <username>")
                            elif msg.startswith("!unban"):
                                try:
                                    unbanned_user = msg.split()[1]
                                    self.unban_user_fr_server(unbanned_user)
                                    self.show_server_com_with_client(conn, selfname, f"Successfully unbanned {unbanned_user} from the banlist.")
                                    self.show_info(f"\n[({datetime.datetime.today()})][(USERUNBAN)]: {selfname} has unbanned {unbanned_user}!")
                                except Exception as e:
                                    self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing arguments: {e}")
                                    self.show_server_com_with_client(conn, selfname, f"There was an error.")
                        if msg.startswith("!reregister"):
                            try:
                                old_pass = msg.split()[1].strip("'").strip('"')
                                newpass = msg.split()[2].strip("'").strip('"')
                                authentication = self.attempt_login(selfname, old_pass)
                                if authentication:
                                    self.show_server_com_with_client(conn, selfname, f"Changing your password to: {newpass}")
                                    self.change_password(selfname, newpass)
                            except self.ServerError.AuthenticationError:
                                self.show_server_com_with_client(conn, selfname, "Authentication Failed.")
                            except Exception as e:
                                self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing arguments: {e}")
                                self.show_server_com_with_client(conn, selfname, "Invalid arguments! Proper Usage: !reregister <old_pass> <new_pass>")
                        elif msg.startswith("!deleteacc"):
                            if del_confirmation:
                                self.show_server_com_with_client(conn, selfname, f"Deleting your account. Sorry for any inconvienence caused while using DatCord.")
                                self.delete_account(selfname)
                                self.show_info(f"\n[({datetime.datetime.today()})][(ACCOUNTDELETION)]: Account '{selfname}' has been removed from the server.")
                                raise self.ServerError.Deletion_Exception
                            else:
                                if selfname == self.ownername:
                                    self.show_server_com_with_client(conn, selfname, "The owner account cannot be deleted!")
                                else:
                                    del_confirmation = True
                                    self.show_server_com_with_client(conn, selfname, "Are you sure you want to delete your account? Please send '!deleteacc' again to confirm.")
                        elif msg.startswith("!getroomroles"):
                            if inroom:
                                roomroles = self.get_all_room_roles(selfroomname)
                                self.show_server_com_with_client(conn, selfname, f"All of the members in the chatroom: {roomroles}")
                            else:
                                self.show_server_com_with_client(conn, selfname, f"You are currently not in a room at the moment!")
                        elif msg.startswith("!getroomlist"):
                            room_lists = self.get_all_rooms_in(username)
                            if len(room_lists) == 0:
                                self.show_server_com_with_client(conn, selfname, f"You are not in any chatrooms at the moment.")
                            else:
                                self.show_server_com_with_client(conn, selfname, f"All of the rooms that you are currently in: {room_lists}")
                        elif msg.startswith("!help"):
                            conn.send(self.fernet.encrypt(self.regular_client_help_message().strip().encode()))
                            self.show_info(f"\n[({datetime.datetime.today()})][(SERVER)--->({selfname})]: Sent the Regular Help Message.")
                            if serverowner:
                                conn.send(self.fernet.encrypt(self.admin_help_message().strip().encode()))
                                self.show_info(f"\n[({datetime.datetime.today()})][(SERVER)--->({selfname})]: Sent the Admin Help Message.")
                        elif msg.startswith("!dm"):
                            try:
                                username = msg.split()[1]
                                valid = False
                                blocked = True
                                try:
                                    if selfname in self.get_block_list(username):
                                        self.show_server_com_with_client(conn, selfname, "You have been blocked by this user.")
                                    elif username in self.get_block_list(selfname):
                                        self.show_server_com_with_client(conn, selfname, "You cannot direct message peope whom you've blocked!")
                                    else:
                                        valid = True
                                        blocked = False
                                except Exception as e:
                                    if username == self.ownername:
                                        valid = True
                                        blocked = False
                                    if selfname not in self.get_block_list(username) and username not in self.get_block_list(selfname):
                                        blocked = False
                                if serverowner:
                                    valid = True
                                    blocked = False
                                if username == selfname:
                                    self.show_server_com_with_client(conn, selfname, f"You can't dm yourself!")
                                elif inroom:
                                    self.show_server_com_with_client(conn, selfname, f"You are currently in a chatroom! Do !leaveroom to leave your room!")
                                else:
                                    if valid:
                                        if indm:
                                            self.show_server_com_with_client(conn, selfname, "You are already in a DM! Do '!closedm' to close it.")
                                        else:
                                            dmconn = self.opendm(username)
                                            indm = True
                                            dmusername = username
                                            self.show_server_com_with_client(conn, selfname, f"Opened a DM with {username}. You can directly speak to them privately!")
                                    else:
                                        if not blocked:
                                            self.show_server_com_with_client(conn, selfname, "The Username specified is not online or is not registered in the database.")
                            except self.ServerError.NameNotInDatabaseError:
                                self.show_server_com_with_client(conn, selfname, "The Username specified is not online or is not registered in the database.")
                            except Exception as e:
                                self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing arguments: {e}")
                                self.show_server_com_with_client(conn, selfname, "Invalid arguments! Proper Usage: !dm <username>")
                        elif msg.startswith("!closedm"):
                            if not indm:
                                self.show_server_com_with_client(conn, selfname, "You are not currently in a DM.")
                            else:
                                self.show_server_com_with_client(conn, selfname, "Closing your dm.")
                                dmusername = None
                                indm = False
                                dmconn = None
                        elif msg.startswith("!createroom"):
                            try:
                                roomname = msg.split()[1]
                            except:
                                roomname = len(self.rooms)
                            try:
                                room_password = msg.split()[2]
                            except:
                                room_password = "None"
                            conflicting_rooms = self.check_for_sameitems(self.dbfile, roomname, f"select * from open_rooms where roomname = '{roomname}'")
                            if not conflicting_rooms:
                                conn.send(self.fernet.encrypt(f"\n[(SERVER)]: Creating a room.\n[+] Room Name: {roomname}\n[+] Room Password: {room_password.strip()}".encode()))
                                self.show_info(f"\n[({datetime.datetime.today()})][(SERVER)--->({selfname})]: Sent room creation message(Name: {roomname}).")
                                room_password = hashlib.sha256(room_password.encode()).hexdigest()
                                self.create_room(roomname, room_password)
                                self.rooms.append([roomname])
                                self.update_file(self.roomdata, f"\nRoomName: {roomname}\nOwner: {selfname}\nAdmins: {selfname}\nMembers: {selfname}\nBanlist: \nEndData\n")
                                self.show_info(f"\n[({datetime.datetime.today()})][(ROOMCREATE)]: Room {roomname} has been created by {selfname}.")
                                self.show_server_com_with_client(conn, selfname, "You are free to join your room.")
                            else:
                                self.show_server_com_with_client(conn, selfname, "There is already a room with the name you provided. Try to use another name.")
                        elif msg.startswith("!joinroom"):
                            try:
                                if inroom:
                                    self.show_server_com_with_client(conn, selfname, "You are currently in a room! Do !leaveroom to leave your room!")
                                elif indm:
                                    self.show_server_com_with_client(conn, selfname, "You are currently in a DM! Do !leaveroom to leave your room!")
                                else:
                                    roomname = msg.split()[1]
                                    try:
                                        roompass = msg.split()[2]
                                    except:
                                        roompass = "None"
                                    roommember = False
                                    file = open(self.roomdata, "r")
                                    contents = file.readlines()
                                    file.close()
                                    in_room = False
                                    roomadmin = False
                                    banned = False
                                    for i in contents:
                                        if roomname.strip() in i.strip():
                                            in_room = True
                                        if in_room:
                                            if i.startswith("Owner: "):
                                                if selfname in i:
                                                    roomowner = True
                                                    roommember = True
                                                    roomadmin = True
                                            if i.startswith("Admins: "):
                                                if selfname in i:
                                                    roommember = True
                                                    roomadmin = True
                                            elif i.startswith("Members: "):
                                                if selfname in i:
                                                    roommember = True
                                            elif i.startswith("Banlist"):
                                                if selfname in i:
                                                    banned = True
                                            elif i.startswith("EndData"):
                                                in_room = False
                                                break
                                            if serverowner:
                                                roomowner = True
                                                roommember = True
                                                roomadmin = True
                                                banned = False
                                    if not banned:
                                        if roomadmin:
                                            inroom = True
                                            selfroomname = roomname
                                        if roommember:
                                            inroom = True
                                            selfroomname = roomname
                                        else:
                                            authentication = self.attempt_join_room(roomname, roompass)
                                            if authentication:
                                                self.add_to_roomdata(selfname, roomname, "Members: ")
                                                in_room = True
                                                inroom = True
                                        if inroom:
                                            self.show_info(f"\n[({datetime.datetime.today()})][({selfname})]: Joined room {roomname}.")
                                            correct_ls = False
                                            ls = []
                                            self.show_server_com_with_client(conn, selfname, "You have joined the room. Say hi!")
                                            for room in self.rooms:
                                                if roomname in room[0]:
                                                    room.append(conn)
                                                    correct_ls = True
                                                    inroom = True
                                                    ls = room
                                                    break
                                            if correct_ls:
                                                for person in room:
                                                    try:
                                                        person.send(self.fernet.encrypt(f"\n[(SERVER)]: {selfname} has joined the chat.".encode()))
                                                    except:
                                                        pass
                                    else:
                                        self.show_server_com_with_client(conn, selfname, "It seems your account has been banned from this chatroom.")
                            except self.ServerError.NameNotInDatabaseError:
                                self.show_server_com_with_client(conn, selfname, "The room provided is not in the database.")
                            except self.ServerError.AuthenticationError:
                                self.show_info(f"\n[({datetime.datetime.today()})][(AUTHENTICATION-ERROR)]: {selfname} has provided incorrect credentials to join {roomname}!")
                                self.show_server_com_with_client(conn, selfname, "Password provided for the room is incorrect.")
                            except Exception as e:
                                self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing arguments: {e}")
                                self.show_server_com_with_client(conn, selfname, "Invalid arguments! Proper Usage: !joinroom <roomname> <password>")
                        elif msg.startswith("!leaveroom"):
                            if inroom:
                                self.show_server_com_with_client(conn, selfname, "Leaving your current room.")
                                for room in self.rooms:
                                    if selfroomname in room:
                                        item = 0
                                        room.remove(conn)
                                        inroom = False
                                        self.show_info(f"\n[({datetime.datetime.today()})][(SERVER)--->({selfroomname})]: {selfname} has left the chat!")
                                        self.show_info(f"\n[({datetime.datetime.today()})][({selfname})]: Left room {selfroomname}.")
                                        self.sendall(f"\n[(SERVER)]: {selfname} has left the chat!", room)
                                        roomowner = False
                                        roomadmin = False
                                        selfroomname = ""
                                        break
                            else:
                                self.show_server_com_with_client(conn, selfname, "You are not currently in a room.")
                        elif msg.startswith("!roomban"):
                            if inroom:
                                if roomadmin:
                                    try:
                                        name = msg.split()[1]
                                        self.add_to_roomdata(name, selfroomname, "Banlist:")
                                        self.show_server_com_with_client(conn, selfname, f"{name} has been banned from the room.")
                                        self.kick_user_fr_room(name,selfroomname,True)
                                        self.show_info(f"\n[({datetime.datetime.today()})][(ROOMBAN)]: {name} has been banned from {selfroomname} by {selfname}.")
                                    except self.ServerError.PermissionError:
                                        self.show_server_com_with_client(conn, selfname, "Your permissions are invalid for this command.")
                                        self.show_info(f"\n[({datetime.datetime.today()})][(PERMISSION-ERROR)]: {selfname} ran command '{msg.strip()}' that was forbidden!")
                                    except Exception as e:
                                        self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing arguments: {e}")
                                        self.show_server_com_with_client(conn, selfname, "Invalid arguments! Proper Usage: !roomban <username>")
                                else:
                                    self.show_server_com_with_client(conn, selfname, "Your permissions are invalid for this command.")
                                    self.show_info(f"\n[({datetime.datetime.today()})][(PERMISSION-ERROR)]: {selfname} ran command '{msg.strip()}' that was forbidden!")
                        elif msg.startswith("!roomunban"):
                            if inroom:
                                if roomadmin:
                                    try:
                                        name = msg.split()[1]
                                        self.del_from_roomdata(name, selfroomname, "Banlist:")
                                        self.show_server_com_with_client(conn, selfname, f"{name} has been unbanned from the room.")
                                        self.show_info(f"\n[({datetime.datetime.today()})][(ROOMUNBAN)]: {name} has been unbanned from {selfroomname} by {selfname}.")
                                    except self.ServerError.PermissionError:
                                        self.show_server_com_with_client(conn, selfname, "Your permissions are invalid for this command.")
                                        self.show_info(f"\n[({datetime.datetime.today()})][(PERMISSION-ERROR)]: {selfname} ran command '{msg.strip()}' that was forbidden!")
                                    except Exception as e:
                                        self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing arguments: {e}")
                                        self.show_server_com_with_client(conn, selfname, "Invalid arguments! Proper Usage: !roomunban <username>")
                                else:
                                    self.show_server_com_with_client(conn, selfname, "Your permissions are invalid for this command.")
                                    self.show_info(f"\n[({datetime.datetime.today()})][(PERMISSION-ERROR)]: {selfname} ran command '{msg.strip()}' that was forbidden!")
                        elif msg.startswith("!roomkick"):
                            if inroom:
                                if roomadmin:
                                    try:
                                        name = msg.split()[1]
                                        if name in self.get_userlist():
                                            self.del_from_roomdata(name, selfroomname, "Members:")
                                            self.show_server_com_with_client(conn, selfname, f"{name} has been kicked from the room.")
                                            self.show_info(f"\n[({datetime.datetime.today()})][(ROOMKICK)]: {name} has been kicked from {selfroomname} by {selfname}.")
                                            self.kick_user_fr_room(name, selfroomname)
                                        else:
                                            self.show_server_com_with_client(conn, selfname, f"The name is not in the database!")
                                            self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: {selfname} tried to kick {name} but their name is not registered!")
                                    except self.ServerError.PermissionError:
                                        self.show_server_com_with_client(conn, selfname, "Your permissions are invalid for this command.")
                                        self.show_info(f"\n[({datetime.datetime.today()})][(PERMISSION-ERROR)]: {selfname} ran command '{msg.strip()}' that was forbidden!")
                                    except Exception as e:
                                        self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing arguments: {e}")
                                        self.show_server_com_with_client(conn, selfname, "Invalid arguments! Proper Usage: !roomkick <username>")
                                else:
                                    self.show_server_com_with_client(conn, selfname, "Your permissions are invalid for this command.")
                                    self.show_info(f"\n[({datetime.datetime.today()})][(PERMISSION-ERROR)]: {selfname} ran command '{msg.strip()}' that was forbidden!")
                        elif msg.startswith("!changeroompass"):
                            if inroom:
                                if roomowner:
                                    try:
                                        newpass = msg.split()[1]
                                        self.change_room_password(selfroomname, newpass)
                                        conn.send(f"Changed the room's password to: {newpass}.".encode())
                                        self.show_info(f"\n[({datetime.datetime.today()})][({selfname})]: The room password for {selfroomname} has been changed by {selfname}.")
                                    except Exception as e:
                                        self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing arguments: {e}")
                                        self.show_server_com_with_client(conn, selfname, "Invalid arguments! Proper Usage: !roomkick <username>")
                                else:
                                    self.show_server_com_with_client(conn, selfname, "Your permissions are invalid for this command.")
                                    self.show_info(f"\n[({datetime.datetime.today()})][(PERMISSION-ERROR)]: {selfname} ran command '{msg.strip()}' that was forbidden!")
                        elif msg.startswith("!promoteuser"):
                            if inroom:
                                try:
                                    if roomadmin:
                                        usertopromote = msg.split()[1]
                                        if usertopromote in self.get_userlist():
                                            self.add_to_roomdata(usertopromote, selfroomname, "Admins: ")
                                            self.show_info(f"\n[({datetime.datetime.today()})][(ROOMPROMOTE)]: {name} has been promoted to a admin in {selfroomname} by {selfname}.")
                                        else:
                                            self.show_server_com_with_client(conn, selfname, f"The name is not in the database!")
                                            self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: {selfname} tried to promote {name} but their name is not registered!")
                                    else:
                                        self.show_server_com_with_client(conn, selfname, "Your permissions are invalid for this command.")
                                        self.show_info(f"\n[({datetime.datetime.today()})][(PERMISSION-ERROR)]: {selfname} ran command '{msg.strip()}' that was forbidden!")
                                except:
                                    self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing arguments: {e}")
                                    self.show_server_com_with_client(conn, selfname, "Invalid arguments! Proper Usage: !promoteuser <user>")
                        elif msg.startswith("!demoteuser"):
                            if inroom:
                                try:
                                    if roomadmin:
                                        usertodemote = msg.split()[1]
                                        self.del_from_roomdata(usertodemote, selfroomname, "Admins: ")
                                        self.show_info(f"\n[({datetime.datetime.today()})][(ROOMDEMOTE)]: {name} has been demoted to a member in {selfroomname} by {selfname}.")
                                    else:
                                        self.show_info(f"\n[({datetime.datetime.today()})][(PERMISSION-ERROR)]: {selfname} ran command '{msg.strip()}' that was forbidden!")
                                        self.show_server_com_with_client(conn, selfname, "Your permissions are invalid for this command.")
                                except self.ServerError.PermissionError:
                                    self.show_info(f"\n[({datetime.datetime.today()})][(PERMISSION-ERROR)]: {selfname} ran command '{msg.strip()}' that was forbidden!")
                                    self.show_server_com_with_client(conn, selfname, "Invalid Permissions to demote the user.")
                                except Exception as e:
                                    self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing arguments: {e}")
                                    self.show_server_com_with_client(conn, selfname, "Invalid arguments! Proper Usage: !demoteuser <username>")
                        elif msg.startswith("!showonlinefriends"):
                            friends = self.get_online_friends(selfname)
                            if len(friends) == 0:
                                self.show_server_com_with_client(conn, selfname, f"You don't have any online friends :( .")
                            else:
                                self.show_server_com_with_client(conn, selfname, f"Online Friends: {friends}")
                        elif msg.startswith("!showfriendslist"):
                            friends = self.get_friends_list(selfname)
                            if len(friends) == 0:
                                self.show_server_com_with_client(conn, selfname, f"You don't have any friends :( .")
                            else:
                                self.show_server_com_with_client(conn, selfname, f"Current Friends List: {friends}")
                        elif msg.startswith("!block"):
                            try:
                                user = msg.split()[1]
                                in_list = False
                                try:
                                    if user in self.get_friends_list(selfname) or user in self.get_block_list(user):
                                        self.show_server_com_with_client(conn, selfname, "This user is in your friends list! Unfriend them to block them!")
                                        in_list = True
                                except:
                                    in_list = False
                                if not in_list:
                                    if user in self.get_userlist():
                                        if user == selfname:
                                            self.show_server_com_with_client(conn, selfname, "Dont block yourself!")
                                        else:
                                            self.show_server_com_with_client(conn, selfname, f"Blocking {user}.")
                                            self.block_user(selfname, user)
                                    else:
                                        self.show_server_com_with_client(conn, selfname, f"The name is not in the database!")
                            except Exception as e:
                                self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing arguments: {e}")
                                self.show_server_com_with_client(conn, selfname, "Invalid arguments! Proper Usage: !block <user>")
                        elif msg.startswith("!unblock"):
                            try:
                                user = msg.split()[1]
                                if user not in self.get_block_list(selfname):
                                    self.show_server_com_with_client(conn, selfname, "The user is not blocked.")
                                else:
                                    self.show_server_com_with_client(conn, selfname, f"Unblocking {user}.")
                                    self.unblock_user(selfname, user)
                            except Exception as e:
                                self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing arguments: {e}")
                                self.show_server_com_with_client(conn, selfname, "Invalid arguments! Proper Usage: !block <user>")
                        elif msg.startswith("!friendremove"):
                            try:
                                user = msg.split()[1]
                                if user in self.get_friends_list(selfname):
                                    self.show_server_com_with_client(conn, selfname, f"Removing {user} from your friends list.")
                                    self.rm_friend(selfname, user)
                                    self.rm_friend(user, selfname)
                                else:
                                    self.show_server_com_with_client(conn, selfname, f"The user is not in your friends list!")
                            except Exception as e:
                                self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing arguments: {e}")
                                self.show_server_com_with_client(conn, selfname, "Invalid arguments! Proper Usage: !friendremove <user>")
                        elif msg.startswith("!getrequests"):
                            db = sqlite3.connect(self.dbfile)
                            cursor = db.cursor()
                            cursor.execute(f"select * from friendrequests where user = '{selfname}'")
                            item = str(cursor.fetchall()[0][1]).split()
                            if len(item) == 0:
                                self.show_server_com_with_client(conn, selfname, f"Nobody wants to be friends with you :( .")
                            else:
                                self.show_server_com_with_client(conn, selfname, f"Here is a list of the people who want to friends with you: {item}")
                            cursor.close()
                            db.close()
                        elif msg.startswith("!friendreq"):
                            try:
                                user = msg.split()[1]
                                friends_list = self.get_friends_list(user)
                                if selfname in self.get_block_list(user):
                                    self.show_server_com_with_client(conn, selfname, "You have been blocked by this user.")
                                else:
                                    if selfname in friends_list:
                                        self.show_server_com_with_client(conn, selfname, "You are already friends with that user.")
                                    else:
                                        if user in self.get_userlist():
                                            if user == selfname:
                                                self.show_server_com_with_client(conn, selfname, "You can't friend yourself!")
                                            else:
                                                db = sqlite3.connect(self.dbfile)
                                                cursor = db.cursor()
                                                cursor.execute(f"select * from friendrequests where user = '{user}'")
                                                info = cursor.fetchall()
                                                i = str(info[0][1]).split()
                                                if selfname in i:
                                                    self.show_server_com_with_client(conn, selfname, "You have already sent a request to that user.")
                                                else:
                                                    self.show_server_com_with_client(conn, selfname, f"Sending a friend request to {user}.")
                                                    try:
                                                        self.show_server_com_with_client(self.opendm(user), user, f"Friend Request from: {selfname}. Do '!friendaccept {selfname}' to accept it.")
                                                    except:
                                                        pass
                                                    item = str(info[0][1]) + " " + selfname
                                                    cursor.execute(f'update friendrequests set requests = "{item}" where user = "{user}"')
                                                    cursor.execute(f"select * from friendrequests where user = '{user}'")
                                                db.commit()
                                                cursor.close()
                                                db.close()
                                        else:
                                            self.show_server_com_with_client(conn, selfname, f"The name is not in the database!")
                            except Exception as e:
                                self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing arguments: {e}")
                                self.show_server_com_with_client(conn, selfname, "Invalid arguments! Proper Usage: !friendreq <user>")
                        elif msg.startswith("!friendaccept"):
                            try:
                                user = msg.split()[1]
                                db = sqlite3.connect(self.dbfile)
                                cursor = db.cursor()
                                cursor.execute(f"select * from friendrequests where user = '{selfname}'")
                                ls = str(cursor.fetchall()[0][1]).split()
                                if user in ls:
                                    self.show_server_com_with_client(conn, selfname, f"Accepting friend request from {user}.")
                                    self.add_friend(selfname, user)
                                    self.add_friend(user, selfname)
                                    ls.remove(user)
                                    new_ls = ""
                                    for i in ls:
                                        new_ls = new_ls + " " + i
                                    cursor.execute(f'update friendrequests set requests = "{new_ls}" where user = "{selfname}"')
                                    try:
                                        userconn = self.opendm(user)
                                        self.show_server_com_with_client(userconn, user, f"{selfname} has accepted your friend request.")
                                    except:
                                        pass
                                else:
                                    self.show_server_com_with_client(conn, selfname, f"You have not been sent a request from {user}.")
                                db.commit()
                                cursor.close()
                                db.close()
                            except Exception as e:
                                self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing arguments: {e}")
                                self.show_server_com_with_client(conn, selfname, "Invalid arguments! Proper Usage: !friendaccept <user>")
                        elif msg.strip() == "":
                            pass
                        else:
                            if inroom:
                                kicked_from_room = False
                                for kicked in self.roomkicked:
                                    if selfroomname in kicked[0]:
                                        for person in kicked:
                                            if person == selfname:
                                                inroom = False
                                                in_room = False
                                                kicked_from_room = True
                                                roomowner = False
                                                roomadmin = False
                                                selfroomname = ""
                                                try:
                                                    self.roomkicked.remove(selfname)
                                                except:
                                                    pass
                                                break
                                if not kicked_from_room:
                                    servermsg = ""
                                    alt_main_msg = this_main_msg.strip().split()
                                    del alt_main_msg[0]
                                    for i in alt_main_msg:
                                        servermsg += f" {i}"
                                    servermsg = servermsg.strip("\n").strip()
                                    self.show_info(f"\n[({datetime.datetime.today()})][({selfname})--->({selfroomname})]: {servermsg}")
                                    for room in self.rooms:
                                        if selfroomname in room[0]:
                                            for person in room:
                                                try:
                                                    person.send(self.fernet.encrypt(this_main_msg.encode()))
                                                except:
                                                    pass
                except Exception as e:
                    self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: Client Error with {ip}(known as {selfname}): {e}")
                    if inroom:
                        self.kick_user_fr_room(selfname, selfroomname)
                    if logged_in:
                        try:
                            self.remove_user_from_db(selfname)
                        except Exception as e:
                            self.show_info(f"\n[({datetime.datetime.today()})][(ERROR)]: Error whilst removing name from database: {e}")
                    conn.close()
                    break
class OptionParse:
    """Option-Parsing Class for parsing arguments."""
    def __init__(self):
        """Starts to parse the arguments."""
        self.version = "7.77"
        self.parse_args()
    def whatsnew(self):
        """Displays all of the new features added to DatCord in the current version."""
        print(Server.logo())
        print(f"""
[+] Whats New in DatCord Version v{self.version}:
[+] - Bug Fixes.
[+] - Added account self deletion command.
[+] - Added 'self.get_all_rooms_in' function for users to see what room they are currently in.
[+] - Added Banner(Allows clients or port scanners to see current version of server).
[+] - Added more logging commands.
[+] - Renamed function 'show_errors()' to 'show_info()' to prevent confusing code readability.
[+] - Passwords are no longer logged(for privacy reasons).
[+] - Optimized and cut off useless lines with useful functions.
[+] - Corrected OS Command to execute to pip install cryptography.
[+] - Fixed Permission Error that turns up when the owner joins their own room.
[+] - Fixed Bug that prevents room messages from displaying.
[+] - Fixed update checking bugs.""")
    def usage(self):
        """Displays the help message for option-parsing(in case you need it)."""
        print(Server.logo())
        print("""
[+] Option-Parsing Help:

[+] Required Arguments:
[+] --ip, --ipaddr     - Specify the IP to host the server on.
[+] --p,  --port       - Specify the Port to host the server on.
[+] These are needed to host the server.

[+] Optional Arguments:
[+] --i,  --info       - Shows this message.
[+] --wn, --whatsnew   - Shows a message of what all of the new features are.
[+] --db, --database   - Specify the Database file to store passwords on(must be a .db).
[+] --au, --activeuser - Specify the database file with all the current active users.
[+] --rd, --roomdata   - Specify the room data file where room data is stored.
[+] --sl, --servlog    - Specify the server log file.
[+] --ou, --owneruser  - Specify the owner username.
[+] --op, --ownerpass  - Specify the owner password.
[+] --mc, --maxconn    - Specify the max amount of connections per second.
[+] Note: These optional arguments have defaults, so you are able to leave them.

[+] Usage:
[+] python3 DatCord.py --ip <ip> --p <port> --db <dbfile> --au <aufile> --rd <roomdata> --sl <servlog> --ou <owneruser> --op <ownerpass> --mc <maxconn>
[+] python3 DatCord.py --wn
[+] python3 DatCord.py --i""")
    def parse_args(self):
        """This function parses the arguments."""
        args = OptionParser()
        args.add_option("--ip", "--ipaddr", dest="ip")
        args.add_option("--p",  "--port", dest="port")
        args.add_option("--db", "--database", dest="db")
        args.add_option("--au", "--activeuser", dest="au")
        args.add_option("--rd", "--roomdata", dest="rd")
        args.add_option("--sl", "--servlog", dest="sl")
        args.add_option("--ou", "--owneruser", dest="ou")
        args.add_option("--op", "--ownerpass", dest="op")
        args.add_option("--mc", "--maxconn", dest="mc")
        args.add_option("--wn", "--whatsnew",dest="wn", action="store_true")
        args.add_option("--i",  "--info",dest="i", action="store_true")
        arg, opt = args.parse_args()
        if arg.i is not None:
            self.usage()
            sys.exit()
        if arg.wn is not None:
            self.whatsnew()
            sys.exit()
        if arg.ip is not None:
            ip = arg.ip
        else:
            self.usage()
            sys.exit()
        if arg.port is not None:
            try:
                port = int(arg.port)
            except:
                if sys.platform == "darwin" or sys.platform == "linux":
                    if os.getlogin() == "root":
                        port = 80
                    else:
                        port = 8081
                else:
                    port = 80
        else:
            port = 80
        if arg.db is not None:
            db = arg.db
            if not db.endswith(".db"):
                db = "users.db"
        else:
            db = "users.db"
        if arg.au is not None:
            au = arg.au
            if not db.endswith(".db"):
                db = "active_users.db"
        else:
            au = "active_users.db"
        if arg.rd is not None:
            rd = arg.rd
        else:
            rd = "roomdata.txt"
        if arg.sl is not None:
            sl = arg.sl
        else:
            sl = "servlog.txt"
        if arg.ou is not None:
            ou = arg.ou
        else:
            ou = "DatCord"
        if arg.op is not None:
            op = arg.op
        else:
            op = str(random.randint(126378123,96457864485678))
        if arg.mc is not None:
            try:
                mc = int(arg.mc)
            except:
                mc = 30
        else:
            mc = 30
        server = Server(ip, port, db, au, rd, sl, ou, op, mc, self.version)
        server.listen()
if __name__ == '__main__':
    """Initiates the script."""
    if sys.platform == "win32":
        os.system("cls")
    else:
        os.system("clear")
    try:
        from cryptography.fernet import Fernet
    except Exception as e:
        print(Server.logo())
        print("[+] You have not installed the module 'cryptography'.")
        print("[+] This is needed for sending Encrypted Messages, and it is missing.")
        item = input("[+] Would you like to try and install it?(yes/no): ")
        if item.lower() == "yes":
            print("\n[+] Attempting to install....")
            os.system("python -m pip install cryptography")
            print("[+] If cryptography was installed, re-run the script.")
            print("[+] If it wasn't, make sure that you have 'pip' installed so you can install the correct packages.")
        else:
            print("[+] If you have 'pip' installed, run 'pip install cryptography'.")
        sys.exit()
    parse = OptionParse()
