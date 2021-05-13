import socket, threading, sqlite3, hashlib, datetime, time, sys, random, os
from optparse import OptionParser
class Server:
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
    def __init__(self, ip, port, dbfile, userdbfile, roomdata, logfile, ownername, ownerpassword, connpersec):
        """This is the function where all of the important variables are defined. The databases
        is configuyred here, as well as the owner account along with the logging files and room
        data files. Once configured, the user can choose when to start listening for connections
        (however in this script the .listen() function is used right after being configured so
        the server starts listening on startup)."""
        self.ip = ip
        self.port = port
        self.dbfile = dbfile
        self.userdbfile = userdbfile
        self.roomdata = roomdata
        self.logfile = logfile
        self.ownername = ownername
        self.ownerpassword = ownerpassword
        try:
            self.maxconnpersec = int(connpersec)
        except:
            self.maxconnpersec = 20
        self.conncount = 0
        self.connpersec = 0
        self.uptime = 0
        self.manualbanall = False
        print(self.logo())
        file = open(self.userdbfile,"w")
        file.close()
        file2 = open(self.logfile,"w")
        file2.close()
        try:
            db = sqlite3.connect(self.dbfile)
        except:
            file = open(self.dbfile,"w")
            file.close()
            db = sqlite3.connect(self.dbfile)
        cursor = db.cursor()
        userdb = sqlite3.connect(self.userdbfile)
        userdbcursor = userdb.cursor()
        self.listening = True
        self.banningallincomingconn = False
        self.conn_list = []
        self.roomkicked = []
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.log(self.logo())
        try:
            self.server.bind((self.ip, self.port))
        except Exception as e:
            print(f"\n[({datetime.datetime.today()})][(ERROR)]: There was an error with binding the server due to error: {e}")
            self.log(f"\n\n[({datetime.datetime.today()})][(ERROR)]: There was an error with binding the server due to error: {e}")
            sys.exit()
        try:
            cursor.execute("select * from users")
        except:
            cursor.execute("create table users(username, password)")
        cursor.execute(f"delete from users where username = '{self.ownername}'")
        cursor.execute(f"insert into users values('{self.ownername}','{hashlib.sha256(self.ownerpassword.encode()).hexdigest()}')")
        try:
            cursor.execute("select * from open_rooms")
        except:
            cursor.execute("create table open_rooms(roomname, roompass)")
        try:
            cursor.execute("select * from banlist")
        except:
            cursor.execute("create table banlist(username)")
        try:
            cursor.execute("select * from ipbanlist")
        except:
            cursor.execute("create table ipbanlist(ip)")
        try:
            cursor.execute("select * from ipwhitelist")
        except:
            cursor.execute("create table ipwhitelist(ip)")
        try:
            cursor.execute("select * from friendslist")
        except:
            cursor.execute("create table friendslist(user, friends)")
        try:
            cursor.execute("select * from friendrequests")
        except:
            cursor.execute("create table friendrequests(user, requests)")
        try:
            cursor.execute("select * from blocklists")
        except:
            cursor.execute("create table blocklists(user, blockedusers)")
        userdbcursor.execute("create table loggedinusers(username, connection)")
        userdb.commit()
        userdbcursor.close()
        userdb.close()
        db.commit()
        cursor.close()
        db.close()
        self.configure_rooms()
        logmsg = f"""
[({datetime.datetime.today()})][(INFO)]: Server is hosted on: {self.ip}:{self.port}                                       
[({datetime.datetime.today()})][(INFO)]: Owner Account Info: Username: {self.ownername} Password: {self.ownerpassword}      
[({datetime.datetime.today()})][(INFO)]: Server is being logged. Logfile: {self.logfile}                                    
[({datetime.datetime.today()})][(INFO)]: Database file for password storage: {self.dbfile}                                  
[({datetime.datetime.today()})][(INFO)]: Room-data file: {self.roomdata}"""
        print(logmsg)
        self.log(f"\n\n[({datetime.datetime.today()})][(INFO)]: Began Logging!")
        self.log(logmsg)
    def logo(self=None):
        """Logo of this script."""
        logo = """
 _____        _    _____              _           __   ___  
|  __ \      | |  / ____|            | |         / /  / _ \ 
| |  | | __ _| |_| |     ___  _ __ __| | __   __/ /_ | | | |
| |  | |/ _` | __| |    / _ \| '__/ _` | \ \ / / '_ \| | | |
| |__| | (_| | |_| |___| (_) | | | (_| |  \ V /| (_) | |_| |
|_____/ \__,_|\__|\_____\___/|_|  \__,_|   \_/  \___(_)___/                                                          
Advanced Server by DrSquid"""
        return logo
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
                                    logmsg = f"[({datetime.datetime.today()})][(ANTI-DDOS)]: Automatically setting banning all incoming IP's to: {self.banningallincomingconn}."
                                    self.log(f"\n" + logmsg)
                                    if not self.listening:
                                        self.listening = True
                            elif self.connpersec >= self.maxconnpersec:
                                if not self.waitingforautoban:
                                    timetoauto_ban = time.time()
                                    self.waitingforautoban = True
                                if round(time.time() - timetoauto_ban) >= 5 and not self.banningallincomingconn:
                                    self.banningallincomingconn = True
                                    logmsg = f"[({datetime.datetime.today()})][(ANTI-DDOS)]: Automatically setting banning all incoming IP's to: {self.banningallincomingconn}."
                                    print(logmsg)
                                    self.log(f"\n" + logmsg)
                                self.being_attacked = True
                                if ip[0] in self.get_iplist("ipwhitelist"):
                                    pass
                                else:
                                    if not closed:
                                        print(f"[({datetime.datetime.today()})][(DDOS-WARN)]: Server may be under attack! Source IP of Attacker: {ip}")
                                        self.log(f"\n[({datetime.datetime.today()})][(DDOS-WARN)]: Server may be under attack! Source IP of Attacker: {ip}")
                                        conn.close()
                            if self.banningallincomingconn:
                                if ip[0] == "127.0.0.1":
                                    self.listening = False
                                    logmsg = f"[({datetime.datetime.today()})][(INFO)]: Server is being hosted on LOCALHOST! Setting Listening for connections to: {self.listening}"
                                    print(logmsg)
                                    self.log("\n"+logmsg)
                                else:
                                    if ip[0] not in self.get_iplist("ipwhitelist"):
                                        if ip[0] not in self.get_iplist("ipbanlist"):
                                            self.ban_ip_fr_server(ip[0])
                            if self.connpersec < self.maxconnpersec or ip[0] in self.get_iplist("ipwhitelist"):
                                msg = f"[({datetime.datetime.today()})][(CONN)]: {ip} has connected."
                                print(msg)
                                self.log("\n" + msg)
                                isbanned = False
                                if ip[0] in self.get_iplist("ipbanlist"):
                                    isbanned = True
                                if not isbanned:
                                    handler = threading.Thread(target=self.handler, args=(conn, ip))
                                    handler.start()
                                else:
                                    msg2 = f"[({datetime.datetime.today()})][(WARN)]: {ip} is in the IP Banlist! Closing connection...."
                                    print(msg2)
                                    self.log("\n" + msg2)
                                    conn.close()
                            else:
                                try:
                                    conn.close()
                                except:
                                    pass
                else:
                    pass
            except Exception as e:
                self.show_errors(f"\n[({datetime.datetime.today()})][(ERROR)]: Error when listening for connections: {e}")
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
        This function is used for the Anti-DDoS Function."""
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
    def check_for_sameitems(self, name, cmd):
        """This checks for same items that already in the server. If the name is
        already in the database, then the value the function is assigned to will
        return as False(bool object). It was recently made into one function. There
        was one for checking for the same names in the database as well as one
        for checking if there is a session with the account opened."""
        db = sqlite3.connect(self.userdbfile)
        cursor = db.cursor()
        tag = 0
        try:
            cursor.execute(cmd)
            for i in cursor.fetchall():
                if username in i[0]:
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
            self.show_errors(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with updating file({file}): {e}")
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
                    in_room = False
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
    def show_errors(self, msg):
        """This displays and logs errors that happen in the server."""
        self.log(msg)
        print(msg.strip())
    def show_server_com_with_client(self, conn, clientname, msg):
        """This displays and logs server communication with the
        clients."""
        conn.send("\n[(SERVER)]: ".encode()+msg.encode())
        new_msg = f"[({datetime.datetime.today()})][(SERVER)--->({clientname})]: {msg}"
        print(new_msg.strip("\n"))
        self.log("\n"+new_msg.strip("\n"))
    def opendm(self, username):
        """This opens a direct message room with another user."""
        db = sqlite3.connect(self.userdbfile)
        tag = 0
        cursor = db.cursor()
        cursor.execute(f"select * from loggedinusers where username = '{username}'")
        for i in cursor.fetchall():
            if username in i[0]:
                ipandsrcport = str(i[1]).split()
                tag = 1
        if tag == 1:
            for i in self.conn_list:
                if ipandsrcport[0] in str(i) and ipandsrcport[1] in str(i):
                    return i
                    break
        else:
            raise self.ServerError.NameNotInDatabaseError
    def sendall(self,msg,ls=None):
        """This sends a message to everyone in the connection list."""
        if ls is None:
            ls = self.conn_list
        for conn in ls:
            try:
                conn.send(msg.encode())
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
        cursor.execute("select * from blocklists")
        ls = cursor.fetchall()[0][1]
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
[+] !block [user]                          - Blocks a user(they cannot dm or friend request you).
[+] !unblock [user]                        - Unblocks a user.
[+] !friendreq [user]                      - Sends a friend request to the user.
[+] !friendaccept [user]                   - Accepts a friend request from a user.
[+] !friendremove [user]                   - Removes a user from your friends list.
[+] !showonlinefriends                     - Gets a list of all your online friends.
[+] !roomban [user]                        - Bans a user from the chat-room(you need to be room admin).
[+] !roomunban [user]                      - Unbans a user from the chat-room(you need to be room admin).
[+] !roomkick [user]                       - Kicks a user from the chat room(they can re-enter with the same password).
[+] !promoteuser [user]                    - Promotes a user to room-admin(you need to be room admin).
[+] !demoteuser [user]                     - Demotes a user down to regular room client(you need to be room admin)."""
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
        room_admin = False
        roomadmin = False
        indm = False
        dmconn = None
        dmusername = None
        serverowner = False
        roomowner = False
        kicked_from_room = False
        selfroomname = ""
        prev_roomname = ""
        timer = time.time()
        login_attempts = 0
        max_login_attempts = 5
        msgspersec = 0
        max_spam_warns = 3
        spam_warnings = 0
        if self.ip == "localhost":
            max_msg_persec = 3
        else:
            max_msg_persec = 4
        valid_conn = False
        try:
            conn.send(self.login_help_message().encode())
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
                    msgspersec += 1
                    try:
                        msg = str(msg.decode())
                    except:
                        msg = str(msg)
                    this_main_msg = f"\n[({selfname})]: {msg}"
                    current_timer = time.time()
                    if round(current_timer-timer) >= 1:
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
                                    namealreadylogged = self.check_for_sameitems(username, f"select * from loggedinusers where username = '{username}'")
                                    if namealreadylogged:
                                        self.show_server_com_with_client(conn, selfname, "Your account is already being used in another location!")
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
                                            if self.ip == "localhost":
                                                time.sleep(0.5)
                                            conn.send(self.regular_client_help_message().encode())
                                            othermsg = f"[({datetime.datetime.today()})][(SERVER)--->({selfname})]: Sent the Regular Help Message."
                                            print(othermsg)
                                            self.log("\n" + othermsg)
                                            display_msg = f"[({datetime.datetime.today()})][(INFO)]: {ip} is {selfname}."
                                            self.log("\n"+display_msg)
                                            print(display_msg)
                                            if selfname == self.ownername:
                                                serverowner = True
                                                conn.send(self.admin_help_message().encode())
                                                infomsg = f"[({datetime.datetime.today()})][(INFO)]: {selfname} is an Admin!"
                                                print(infomsg)
                                                self.log("\n"+infomsg)
                                                othermsg = f"[({datetime.datetime.today()})][(SERVER)--->({selfname})]: Sent the Admin Help Message."
                                                print(othermsg)
                                                self.log("\n"+othermsg)
                                        else:
                                            self.show_server_com_with_client(conn, selfname, "Your account has been banned from the server.")
                            except self.ServerError.AuthenticationError:
                                self.show_server_com_with_client(conn, selfname, "Authentication Failed.")
                                login_attempts += 1
                                if login_attempts >= max_login_attempts:
                                    self.show_server_com_with_client(conn, selfname, "You have exceeded the amount of login attempts. You have been kicked from the server.")
                                    conn.close()
                            except self.ServerError.NameNotInDatabaseError:
                                self.show_server_com_with_client(conn, selfname, "Your account is not registered in the database. Please register your account.")
                            except Exception as e:
                                self.show_errors(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing arguments: {e}")
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
                                conn.send(self.regular_client_help_message().encode())
                                othermsg = f"[({datetime.datetime.today()})][(SERVER)--->({selfname})]: Sent the Regular Help Message."
                                print(othermsg)
                                self.log("\n" + othermsg)
                                display_msg = f"[({datetime.datetime.today()})][(INFO)]: {ip} is {selfname}."
                                self.log("\n" + display_msg)
                                self.exec_sqlcmd(self.dbfile, f"insert into friendslist values('{selfname}', '')")
                                self.exec_sqlcmd(self.dbfile, f"insert into friendrequests values('{selfname}', '')")
                                self.exec_sqlcmd(self.dbfile, f"insert into blocklists values('{selfname}', '')")
                            except self.ServerError.NameAlreadyRegisteredError:
                                self.show_server_com_with_client(conn, selfname, "The account name is already registered in the database. Please use another name for your account.")
                            except Exception as e:
                                self.show_errors(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing arguments: {e}")
                                self.show_server_com_with_client(conn, selfname, "Invalid arguments! Proper Usage: !login <username> <password>")
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
                            print(logmsg)
                            self.log("\n" + logmsg)
                    if logged_in:
                        if serverowner:
                            if msg.startswith("!nick"):
                                try:
                                    selfname = msg.split()[1]
                                    self.show_server_com_with_client(conn, selfname, f"Changed your name to: {selfname}")
                                except:
                                    self.show_server_com_with_client(conn, selfname, "Invalid arguments! Proper Usage: !nick <username>")
                            elif msg.startswith("!unnick"):
                                selfname = self.ownername
                                self.show_server_com_with_client(conn, selfname, f"Changed your name back to: {selfname}")
                            elif msg.startswith("!togglelisten"):
                                if self.listening:
                                    logmsg = f"[({datetime.datetime.today()})][(INFO)]: Stopped Listening For Connections....."
                                    self.listening = False
                                else:
                                    logmsg = f"[({datetime.datetime.today()})][(INFO)]: Began Listening For Connections....."
                                    self.listening = True
                                self.show_server_com_with_client(conn, selfname, f"Set Listening for connections to {self.listening}.")
                                print(logmsg)
                                self.log("\n"+logmsg)
                            elif msg.startswith("!ipban"):
                                try:
                                    ip_addr = msg.split()[1]
                                    actual_ip = socket.gethostbyname(ip_addr)
                                    if ip_addr in self.get_iplist("ipbanlist"):
                                        self.show_server_com_with_client(conn, selfname, f"The IP is already in the banlist!")
                                    elif ip_addr == "127.0.0.1":
                                        self.show_server_com_with_client(conn, selfname, f"You can't ban localhost!")
                                    else:
                                        self.ban_ip_fr_server(ip_addr)
                                        self.show_server_com_with_client(conn, selfname, f"Successfully banned {ip_addr}. They won't be able to join the server the next time they try to.")
                                except socket.error:
                                    self.show_server_com_with_client(conn, selfname, f"You Have provided an invalid IP Address!")
                                except:
                                    self.show_server_com_with_client(conn, selfname, f"Invalid arguments! Proper Usage: !ipban <ip>")
                            elif msg.startswith("!ipunban"):
                                try:
                                    ip_addr = msg.split()[1]
                                    actual_ip = socket.gethostbyname(ip_addr)
                                    if ip_addr not in self.get_iplist("ipbanlist"):
                                        self.show_server_com_with_client(conn, selfname, f"The IP Is not in the banlist!")
                                    else:
                                        self.unban_ip_fr_server(ip_addr)
                                        self.show_server_com_with_client(conn, selfname, f"Successfully unbanned {ip_addr}.")
                                except socket.error:
                                    self.show_server_com_with_client(conn, selfname, f"You Have provided an invalid IP Address!")
                                except:
                                    self.show_server_com_with_client(conn, selfname, f"Invalid arguments! Proper Usage: !ipunban <ip>")
                            elif msg.startswith("!whitelistip"):
                                try:
                                    ip_addr = msg.split()[1]
                                    actual_ip = socket.gethostbyname(ip_addr)
                                    if ip_addr in self.get_iplist("ipbanlist"):
                                        self.show_server_com_with_client(conn, selfname, f"The IP Is in the banlist! Unban them first.")
                                    else:
                                        self.whitelist_ip_to_server(ip_addr)
                                        self.show_server_com_with_client(conn, selfname, f"Successfully whitelisted {ip_addr}.")
                                except socket.error:
                                    self.show_server_com_with_client(conn, selfname, f"You Have provided an invalid IP Address!")
                                except:
                                    self.show_server_com_with_client(conn, selfname, f"Invalid arguments! Proper Usage: !whitelistip <ip>")
                            elif msg.startswith("!unwhitelistip"):
                                try:
                                    ip_addr = msg.split()[1]
                                    actual_ip = socket.gethostbyname(ip_addr)
                                    if ip_addr not in self.get_iplist("ipwhitelist"):
                                        self.show_server_com_with_client(conn, selfname, f"The IP Is not in the whitelist!")
                                    else:
                                        self.unwhitelist_ip_fr_server(ip_addr)
                                        self.show_server_com_with_client(conn, selfname, f"Successfully unwhitelisted {ip_addr}.")
                                except socket.error:
                                    self.show_server_com_with_client(conn, selfname, f"You Have provided an invalid IP Address!")
                                except:
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
                                    logmsg = f"[({datetime.datetime.today()})][(BROADCAST)]: {_main_msg}"
                                    print(logmsg)
                                    self.log("\n"+logmsg)
                                except:
                                    self.show_server_com_with_client(conn, selfname, f"Invalid arguments! Proper Usage: !broadcast <msg>")
                            elif msg.startswith("!ban"):
                                try:
                                    banned_user = msg.split()[1]
                                    if banned_user == self.ownername:
                                        self.show_server_com_with_client(conn, selfname, f"You can't ban yourself!")
                                    else:
                                        if banned_user in self.get_userlist():
                                            self.ban_user_fr_server(banned_user)
                                            self.show_server_com_with_client(conn, selfname, f"The Ban Hammer has spoken! {banned_user} has been banned from the server!")
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
                                            self.show_server_com_with_client(conn, selfname, f"The name is not in the database!")
                                except Exception as e:
                                    self.show_errors(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing arguments: {e}")
                                    self.show_server_com_with_client(conn, selfname, f"Invalid arguments! Proper Usage: !ban <username>")
                            elif msg.startswith("!kick"):
                                try:
                                    kick_user = msg.split()[1]
                                    if kick_user == self.ownername:
                                        self.show_server_com_with_client(conn, selfname, f"You can't kick yourself!")
                                    else:
                                        if banned_user in self.get_userlist():
                                            self.show_server_com_with_client(conn, selfname, f"{kick_user} has been kicked from the server!")
                                            db = sqlite3.connect(self.userdbfile)
                                            cursor = db.cursor()
                                            cursor.execute(f"select * from loggedinusers where username = '{kick_user}'")
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
                                            self.show_server_com_with_client(conn, selfname, f"The name is not in the database!")
                                except Exception as e:
                                    self.show_errors(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing arguments: {e}")
                                    self.show_server_com_with_client(conn, selfname, f"Invalid arguments! Proper Usage: !kick <username>")
                            elif msg.startswith("!unban"):
                                try:
                                    unbanned_user = msg.split()[1]
                                    self.unban_user_fr_server(unbanned_user)
                                    self.show_server_com_with_client(conn, selfname, f"Successfully unbanned {unbanned_user} from the banlist.")
                                except Exception as e:
                                    self.show_errors(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing arguments: {e}")
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
                                self.show_errors(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing arguments: {e}")
                                self.show_server_com_with_client(conn, selfname, "Invalid arguments! Proper Usage: !login <username> <password>")
                        elif msg.startswith("!help"):
                            conn.send(self.regular_client_help_message().strip().encode())
                            othermsg = f"[({datetime.datetime.today()})][(SERVER)--->({selfname})]: Sent the Regular Help Message."
                            print(othermsg)
                            self.log("\n"+othermsg)
                            if serverowner:
                                conn.send(self.admin_help_message().strip().encode())
                                othermsg = f"[({datetime.datetime.today()})][(SERVER)--->({selfname})]: Sent the Admin Help Message."
                                print(othermsg)
                                self.log("\n"+othermsg)
                        elif msg.startswith("!dm"):
                            try:
                                username = msg.split()[1]
                                if selfname in self.get_block_list(username):
                                    self.show_server_com_with_client(conn, selfname, "You have been blocked by this user.")
                                else:
                                    if username == selfname:
                                        self.show_server_com_with_client(conn, selfname, f"You can't dm yourself!")
                                    else:
                                        dmconn = self.opendm(username)
                                        indm = True
                                        dmusername = username
                                        self.show_server_com_with_client(conn, selfname, f"Opened a DM with {username}. You can directly speak to them privately!")
                            except self.ServerError.NameNotInDatabaseError:
                                self.show_server_com_with_client(conn, selfname, "The Username specified is not online or is not registered in the database.")
                            except:
                                self.show_server_com_with_client(conn, selfname, "Invalid arguments! Proper Usage: !login <username> <password>")
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
                            conflicting_rooms = self.check_for_sameitems(roomname, f"select * from open_rooms where roomname = '{roomname}'")
                            if not conflicting_rooms:
                                conn.send(f"\n[(SERVER)]: Creating a room.\n[+] Room Name: {roomname}\n[+] Room Password: {room_password.strip()}".encode())
                                logmsg = f"[({datetime.datetime.today()})][(SERVER)--->({selfname})]: Sent room creation message(Name: {roomname}, Pass: {room_password})."
                                self.log("\n"+logmsg)
                                room_password = hashlib.sha256(room_password.encode()).hexdigest()
                                self.create_room(roomname, room_password)
                                self.rooms.append([roomname])
                                self.update_file(self.roomdata, f"\nRoomName: {roomname}\nOwner: {selfname}\nAdmins: {selfname}\nMembers: {selfname}\nBanlist: \nEndData\n")
                                self.show_server_com_with_client(conn, selfname, "You are free to join your room.")
                            else:
                                self.show_server_com_with_client(conn, selfname, "There is already a room with the name you provided. Try to use another name.")
                        elif msg.startswith("!joinroom"):
                            try:
                                if inroom:
                                    self.show_server_com_with_client(conn, selfname, "You are currently in a room! Do !leaveroom to leave your room!")
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
                                    if not banned:
                                        if roomadmin:
                                            room_admin = True
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
                                            prev_roomname = selfroomname
                                            correct_ls = False
                                            ls = []
                                            self.show_server_com_with_client(conn, selfname, "You have joined the room. Say hi!")
                                            for room in self.rooms:
                                                if roomname in room[0]:
                                                    room.append(conn)
                                                    correct_ls = True
                                                    ls = room
                                                    break
                                            if correct_ls:
                                                for person in room:
                                                    try:
                                                        person.send(f"\n[(SERVER)]: {selfname} has joined the chat.".encode())
                                                    except:
                                                        pass
                                    else:
                                        self.show_server_com_with_client(conn, selfname, "It seems your account has been banned from this chatroom.")
                            except self.ServerError.NameNotInDatabaseError:
                                self.show_server_com_with_client(conn, selfname, "The room provided is not in the database.")
                            except self.ServerError.AuthenticationError:
                                self.show_errors(f"\n[({datetime.datetime.today()})][(AUTENTICATION-ERROR)]: {selfname} has provided incorrect credentials!")
                                self.show_server_com_with_client(conn, selfname, "Password provided for the room is incorrect.")
                            except Exception as e:
                                self.show_errors(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing argumentss: {e}")
                                self.show_server_com_with_client(conn, selfname, "Invalid arguments! Proper Usage: !login <username> <password>")
                        elif msg.startswith("!leaveroom"):
                            if inroom:
                                self.show_server_com_with_client(conn, selfname, "Leaving your current room.")
                                for room in self.rooms:
                                    if selfroomname in room:
                                        item = 0
                                        room.remove(conn)
                                        inroom = False
                                        logmsg = f"[({datetime.datetime.today()})][(SERVER)--->({selfroomname})]: {selfname} has left the chat!"
                                        print(logmsg)
                                        self.log("\n"+logmsg)
                                        self.sendall(f"\n[(SERVER)]: {selfname} has left the chat!", room)
                                        room_admin = False
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
                                    except self.ServerError.PermissionError:
                                        self.show_server_com_with_client(conn, selfname, "Your permissions are invalid for this command.")
                                        self.show_errors(f"\n[({datetime.datetime.today()})][(PERMISSION-ERROR)]: {selfname} ran command '{msg.strip()}' that was forbidden!")
                                    except Exception as e:
                                        self.show_errors(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing arguments: {e}")
                                        self.show_server_com_with_client(conn, selfname, "Invalid arguments! Proper Usage: !roomban <username>")
                                else:
                                    self.show_server_com_with_client(conn, selfname, "Your permissions are invalid for this command.")
                                    self.show_errors(f"\n[({datetime.datetime.today()})][(PERMISSION-ERROR)]: {selfname} ran command '{msg.strip()}' that was forbidden!")
                        elif msg.startswith("!roomunban"):
                            if inroom:
                                if roomadmin:
                                    try:
                                        name = msg.split()[1]
                                        self.del_from_roomdata(name, selfroomname, "Banlist:")
                                        self.show_server_com_with_client(conn, selfname, f"{name} has been unbanned from the room.")
                                    except self.ServerError.PermissionError:
                                        self.show_server_com_with_client(conn, selfname, "Your permissions are invalid for this command.")
                                        self.show_errors(f"\n[({datetime.datetime.today()})][(PERMISSION-ERROR)]: {selfname} ran command '{msg.strip()}' that was forbidden!")
                                    except Exception as e:
                                        self.show_errors(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing arguments: {e}")
                                        self.show_server_com_with_client(conn, selfname, "Invalid arguments! Proper Usage: !roomunban <username>")
                                else:
                                    self.show_server_com_with_client(conn, selfname, "Your permissions are invalid for this command.")
                                    self.show_errors(f"\n[({datetime.datetime.today()})][(PERMISSION-ERROR)]: {selfname} ran command '{msg.strip()}' that was forbidden!")
                        elif msg.startswith("!roomkick"):
                            if inroom:
                                if roomadmin:
                                    try:
                                        name = msg.split()[1]
                                        if name in self.get_userlist():
                                            self.del_from_roomdata(name, selfroomname, "Members:")
                                            self.show_server_com_with_client(conn, selfname, f"{name} has been kicked from the room.")
                                            self.kick_user_fr_room(name, selfroomname)
                                        else:
                                            self.show_server_com_with_client(conn, selfname, f"The name is not in the database!")
                                    except self.ServerError.PermissionError:
                                        self.show_server_com_with_client(conn, selfname, "Your permissions are invalid for this command.")
                                        self.show_errors(f"\n[({datetime.datetime.today()})][(PERMISSION-ERROR)]: {selfname} ran command '{msg.strip()}' that was forbidden!")
                                    except Exception as e:
                                        self.show_errors(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing arguments: {e}")
                                        self.show_server_com_with_client(conn, selfname, "Invalid arguments! Proper Usage: !roomkick <username>")
                                else:
                                    self.show_server_com_with_client(conn, selfname, "Your permissions are invalid for this command.")
                                    self.show_errors(f"\n[({datetime.datetime.today()})][(PERMISSION-ERROR)]: {selfname} ran command '{msg.strip()}' that was forbidden!")
                        elif msg.startswith("!changeroompass"):
                            if inroom:
                                if roomowner:
                                    try:
                                        newpass = msg.split()[1]
                                        self.change_room_password(selfroomname, newpass)
                                        self.show_server_com_with_client(conn, selfname, f"Changed the room's password to: {newpass}.")
                                    except Exception as e:
                                        self.show_errors(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing arguments: {e}")
                                        self.show_server_com_with_client(conn, selfname, "Invalid arguments! Proper Usage: !roomkick <username>")
                                else:
                                    self.show_server_com_with_client(conn, selfname, "Your permissions are invalid for this command.")
                                    self.show_errors(f"\n[({datetime.datetime.today()})][(PERMISSION-ERROR)]: {selfname} ran command '{msg.strip()}' that was forbidden!")
                        elif msg.startswith("!promoteuser"):
                            if inroom:
                                try:
                                    if roomadmin:
                                        usertopromote = msg.split()[1]
                                        if usertopromote in self.get_userlist():
                                            self.add_to_roomdata(usertopromote, selfroomname, "Admins: ")
                                        else:
                                            self.show_server_com_with_client(conn, selfname, f"The name is not in the database!")
                                    else:
                                        self.show_server_com_with_client(conn, selfname, "Your permissions are invalid for this command.")
                                        self.show_errors(f"\n[({datetime.datetime.today()})][(PERMISSION-ERROR)]: {selfname} ran command '{msg.strip()}' that was forbidden!")
                                except:
                                    self.show_errors(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing arguments: {e}")
                                    self.show_server_com_with_client(conn, selfname, "Invalid arguments! Proper Usage: !login <username> <password>")
                        elif msg.startswith("!demoteuser"):
                            if inroom:
                                try:
                                    if roomadmin:
                                        usertodemote = msg.split()[1]
                                        self.del_from_roomdata(usertodemote, selfroomname, "Admins: ")
                                    else:
                                        self.show_errors(f"\n[({datetime.datetime.today()})][(PERMISSION-ERROR)]: {selfname} ran command '{msg.strip()}' that was forbidden!")
                                        self.show_server_com_with_client(conn, selfname, "Your permissions are invalid for this command.")
                                except self.ServerError.PermissionError:
                                    self.show_errors(f"\n[({datetime.datetime.today()})][(PERMISSION-ERROR)]: {selfname} ran command '{msg.strip()}' that was forbidden!")
                                    self.show_server_com_with_client(conn, selfname, "Invalid Permissions to ban the user.")
                                except Exception as e:
                                    self.show_errors(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing arguments: {e}")
                                    self.show_server_com_with_client(conn, selfname, "Invalid arguments! Proper Usage: !login <username> <password>")
                        elif msg.startswith("!showonlinefriends"):
                            friends = self.get_online_friends(selfname)
                            self.show_server_com_with_client(conn, selfname, f"Online Friends: {friends}")
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
                                        self.show_server_com_with_client(conn, selfname, f"Blocking {user}.")
                                        self.block_user(selfname, user)
                                    else:
                                        self.show_server_com_with_client(conn, selfname, f"The name is not in the database!")
                            except Exception as e:
                                self.show_errors(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing arguments: {e}")
                                self.show_server_com_with_client(conn, selfname, "Invalid arguments! Proper Usage: !block <user>")
                        elif msg.startswith("!unblock"):
                            try:
                                user = msg.split()[1]
                                if user not in self.get_block_list(user):
                                    self.show_server_com_with_client(conn, selfname, "The user is not blocked.")
                                else:
                                    self.show_server_com_with_client(conn, selfname, f"Unblocking {user}.")
                                    self.unblock_user(selfname, user)
                            except Exception as e:
                                self.show_errors(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing arguments: {e}")
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
                                self.show_errors(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing arguments: {e}")
                                self.show_server_com_with_client(conn, selfname, "Invalid arguments! Proper Usage: !friendremove <user>")
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
                                            db = sqlite3.connect(self.dbfile)
                                            cursor = db.cursor()
                                            cursor.execute(f"select * from friendrequests where user = '{user}'")
                                            info = cursor.fetchall()
                                            i = str(info[0][1]).split()
                                            if selfname in i:
                                                self.show_server_com_with_client(conn, selfname, "You have already sent a request to that user.")
                                            else:
                                                self.show_server_com_with_client(conn, selfname, f"Sending a friend request to {user}.")
                                                self.show_server_com_with_client(self.opendm(user), user,  f"Friend Request from: {selfname}. Do '!friendaccept {selfname}' to accept it.")
                                                item = str(info[0][1]) + " " + selfname
                                                cursor.execute(f'update friendrequests set requests = "{item}" where user = "{user}"')
                                                cursor.execute(f"select * from friendrequests where user = '{user}'")
                                            db.commit()
                                            cursor.close()
                                            db.close()
                                        else:
                                            self.show_server_com_with_client(conn, selfname, f"The name is not in the database!")
                            except Exception as e:
                                self.show_errors(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing arguments: {e}")
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
                                else:
                                    self.show_server_com_with_client(conn, selfname, f"You have not been sent a request from {user}.")
                                db.commit()
                                cursor.close()
                                db.close()
                            except Exception as e:
                                self.show_errors(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing arguments: {e}")
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
                                                room_admin = False
                                                roomowner = False
                                                roomadmin = False
                                                selfroomname = ""
                                                try:
                                                    self.roomkicked.remove(selfname)
                                                except:
                                                    pass
                                                break
                                if not kicked_from_room:
                                    for room in self.rooms:
                                        if selfroomname in room[0]:
                                            for person in room:
                                                try:
                                                    person.send(this_main_msg.encode())
                                                except:
                                                    pass
                            if indm:
                                try:
                                    dmconn.send("\n[(DM)]".encode() + this_main_msg.strip().encode())
                                    logmsg = f"[({datetime.datetime.today()})][({selfname})--->({dmusername})]: {msg.strip()}"
                                    print(logmsg)
                                    self.log("\n"+logmsg)
                                except:
                                    self.show_server_com_with_client(conn, selfname, f"There was an error with sending your DM Message! The person may have gone offline. Closing your DM.")
                                    indm = False
                    if msg.strip() == "":
                        pass
                    else:
                        if not indm:
                            self.log(f"\n[({datetime.datetime.today()})]" + this_main_msg.strip())
                            print(f"[({datetime.datetime.today()})]" + this_main_msg.strip())
                except Exception as e:
                    self.show_errors(f"\n[({datetime.datetime.today()})][(ERROR)]: Client Error with {ip}(known as {selfname}): {e}")
                    if inroom:
                        self.kick_user_fr_room(selfname, selfroomname)
                    if logged_in:
                        try:
                            self.remove_user_from_db(selfname)
                        except Exception as e:
                            self.show_errors(f"\n[({datetime.datetime.today()})][(ERROR)]: Error whilst removing name from database: {e}")
                    conn.close()
                    break
class OptionParse:
    """Option-Parsing Class for parsing arguments."""
    def __init__(self):
        """Starts to parse the arguments."""
        self.parse_args()
    def whatsnew(self):
        """Displays all of the new features added to DatCord in the current version."""
        print(Server.logo())
        print("""
[+] Whats New in DatCord Version v6.0:
[+] - Added 'Whats New' feature.
[+] - Added Friends system.
[+] - Added User block system.""")
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
[+] python3 Datcord.py --ip <ip> --p <port> --db <dbfile> --au <aufile> --rd <roomdata> --sl <servlog> --ou <owneruser> --op <ownerpass> --mc <maxconn>
[+] python3 Datcord.py --i""")
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
        args.add_option("--wN", "--whatsnew",dest="wn")
        args.add_option("--i",  "--info",dest="i", action="store_true")
        arg, opt = args.parse_args()
        if arg.i is not None:
            self.usage()
            sys.exit()
        if arg.ip is not None:
            ip = arg.ip
        else:
            self.usage()
            sys.exit()
        if arg.wn is not None:
            self.whatsnew()
            sys.exit()
        if arg.port is not None:
            try:
                port = int(arg.port)
            except:
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
        server = Server(ip, port, db, au, rd, sl, ou, op, mc)
        server.listen()
if __name__ == '__main__':
    """Initiates the script."""
    if sys.platform == "win32":
        os.system("cls")
    else:
        os.system("clear")
    parse = OptionParse()
