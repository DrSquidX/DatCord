import socket, threading, sqlite3, hashlib, datetime, time, sys, random, os
from optparse import OptionParser
class Server:
    class ServerError:
        class NameNotInDatabaseError(Exception):
            def __init__(self, msg="Username is not in Database!"):
                self.msg = msg
                super().__init__(self.msg)
        class NameAlreadyRegisteredError(Exception):
            def __init__(self, msg="Username is already registered in the Database!"):
                self.msg = msg
                super().__init__(self.msg)
        class AuthenticationError(Exception):
            def __init__(self, msg="Authentication Failed."):
                self.msg = msg
                super().__init__(self.msg)
        class PermissionError(Exception):
            def __init__(self, msg="You have insufficient permissions!"):
                self.msg = msg
                super().__init__(self.msg)
    def __init__(self, ip, port, dbfile, userdbfile, roomdata, logfile, ownername, ownerpassword, connpersec):
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
        self.connpersec = 0
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
        self.conn_list = []
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.server.bind((self.ip, self.port))
        except Exception as e:
            print(f"[+] There was an error with binding the server due to error: {e}.")
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
        userdbcursor.execute("create table loggedinusers(username, connection)")
        userdb.commit()
        userdbcursor.close()
        userdb.close()
        db.commit()
        cursor.close()
        db.close()
        self.configure_rooms()
        print(f"\n[({datetime.datetime.today()})][(INFO)]: Server is hosted on: {self.ip}:{self.port}")
        print(f"[({datetime.datetime.today()})][(INFO)]: Owner Account Info: Username: {self.ownername} Password: {self.ownerpassword}")
        print(f"[({datetime.datetime.today()})][(INFO)]: Server is being logged. Logfile: {self.logfile}")
        print(f"[({datetime.datetime.today()})][(INFO)]: Database file for password storage: {self.dbfile}")
        print(f"[({datetime.datetime.today()})][(INFO)]: Room-data file: {self.roomdata}")
        self.log(self.logo())
        self.log(f"\n[({datetime.datetime.today()})][(INFO)]: Began Logging!")
        self.log(f"\n[({datetime.datetime.today()})][(INFO)]: Server is hosted on: {self.ip}:{self.port}")
        self.log(f"""\n[({datetime.datetime.today()})][(INFO)]: Owner Account Info: Username: {self.ownername} Password: {self.ownerpassword}
[({datetime.datetime.today()})][(INFO)]: Server is being logged. Logfile: {self.logfile}
[({datetime.datetime.today()})][(INFO)]: Database file for password storage: {self.dbfile}
[({datetime.datetime.today()})][(INFO)]: Room-data file: {self.roomdata}""")
    def logo(self):
        logo = """
 _____        _    _____              _        ___    ___  
|  __ \      | |  / ____|            | |      |__ \  / _ \ 
| |  | | __ _| |_| |     ___  _ __ __| | __   __ ) || | | |
| |  | |/ _` | __| |    / _ \| '__/ _` | \ \ / // / | | | |
| |__| | (_| | |_| |___| (_) | | | (_| |  \ V // /_ | |_| |
|_____/ \__,_|\__|\_____\___/|_|  \__,_|   \_/|____(_)___/                                                         
Advanced Server by DrSquid"""
        return logo
    def log(self, text):
        self.update_file(self.logfile, text)
    def configure_rooms(self):
        self.rooms = []
        db = sqlite3.connect(self.dbfile)
        cursor = db.cursor()
        cursor.execute("select roomname from open_rooms")
        for i in cursor.fetchall():
            item = []
            item.append(str(i[0]))
            self.rooms.append(item)
    def listen(self):
        print(f"[({datetime.datetime.today()})][(LISTEN))]: Server is listening......")
        self.log(f"\n[({datetime.datetime.today()})][(LISTEN))]: Server is listening......")
        while True:
            self.server.listen()
            conn, ip = self.server.accept()
            self.connpersec += 1
            if self.connpersec >= self.maxconnpersec:
                print(f"[({datetime.datetime.today()})][(DDOS_WARNING)]: Server may be under attack!")
                self.log(f"\n[({datetime.datetime.today()})][(DDOS_WARNING)]: Server may be under attack!")
                conn.close()
            else:
                msg = f"[({datetime.datetime.today()})][(CONNECTION)]: {ip} has connected."
                print(msg)
                self.log("\n"+msg)
                handler = threading.Thread(target=self.handler,args=(conn,ip))
                handler.start()
    def exec_sqlcmd(self, file, cmd):
        db = sqlite3.connect(file)
        cursor = db.cursor()
        cursor.execute(cmd)
        db.commit()
        cursor.close()
        db.close()
    def attempt_login(self, username, password):
        password = hashlib.sha256(password.encode()).hexdigest()
        db = sqlite3.connect(self.dbfile)
        cursor = db.cursor()
        tag = 0
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
    def reset_connvar(self):
        while True:
            time.sleep(1)
            self.connpersec = 0
    def register_accounts(self, username, password):
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
        password = hashlib.sha256(password.encode()).hexdigest()
        self.exec_sqlcmd(self.dbfile, f'update users set password = "{password}" where username = "{username}"')
    def add_name_to_db(self, name, conn):
        self.exec_sqlcmd(self.userdbfile, f"insert into loggedinusers values('{name}', '{conn}')")
    def remove_user_from_db(self, name):
        self.exec_sqlcmd(self.userdbfile,f"delete from loggedinusers where username = '{name}'")
    def create_room(self, roomname, roompass):
        self.exec_sqlcmd(self.dbfile,f"insert into open_rooms values('{roomname.strip()}','{roompass.strip()}')")
    def ban_user_fr_server(self, user):
        self.exec_sqlcmd(self.dbfile, f"insert into banlist values('{user}')")
    def unban_user_fr_server(self, user):
        self.exec_sqlcmd(self.dbfile, f"delete from banlist where username = '{user}'")
    def attempt_join_room(self, name, password):
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
    def check_for_sameusers(self, username):
        db = sqlite3.connect(self.userdbfile)
        cursor = db.cursor()
        tag = 0
        try:
            cursor.execute(f"select * from loggedinusers where username = '{username}'")
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
    def check_for_samerooms(self, roomname):
        db = sqlite3.connect(self.dbfile)
        cursor = db.cursor()
        tag = 0
        try:
            cursor.execute(f"select * from open_rooms where roomname = '{roomname}'")
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
        files = open(file,"r")
        content = files.read()
        files.close()
        files = open(file,"w")
        files.write(content)
        files.write(text)
        files.close()
    def add_to_roomdata(self, selfname, roomname, stat):
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
        self.log(msg)
        print(msg.strip())
    def show_server_com_with_client(self, conn, clientname, msg):
        conn.send("\n[(SERVER)]: ".encode()+msg.encode())
        new_msg = f"[({datetime.datetime.today()})][(SERVER)--->({clientname})]: {msg}"
        print(new_msg)
        self.log("\n"+new_msg)
    def opendm(self, username):
        db = sqlite3.connect(self.userdbfile)
        tag = 0
        cursor = db.cursor()
        cursor.execute(f"select * from loggedinusers where username = '{username}'")
        for i in cursor.fetchall():
            if username in i[0]:
                ipandsrcport = str(i[1]).split()
                tag = 1
        if tag == 1:
            conn = None
            for i in self.conn_list:
                if ipandsrcport[0] in str(i) and ipandsrcport[1] in str(i):
                    return i
                    break
        else:
            raise self.ServerError.NameNotInDatabaseError
    def sendall(self,msg):
        for conn in self.conn_list:
            try:
                self.show_server_com_with_client(conn, selfname, msg)
            except:
                pass
    def handler(self, conn, ip):
        selfname = str(ip).strip('()')
        logged_in = False
        inroom = False
        room_admin = False
        indm = False
        dmconn = None
        dmusername = None
        serverowner = False
        selfroomname = ""
        while True:
            try:
                msg = conn.recv(1024)
                try:
                    msg = str(msg.decode())
                except:
                    msg = str(msg)
                main_msg = f"\n[({selfname})]: {msg}"
                if not logged_in:
                    if msg.startswith("!login"):
                        try:
                            username = msg.split()[1]
                            password = msg.split()[2]
                            authentication = self.attempt_login(username, password)
                            if authentication == True:
                                namealreadylogged = self.check_for_sameusers(username)
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
                                        if selfname == self.ownername:
                                            serverowner = True
                                    else:
                                        self.show_server_com_with_client(conn, selfname, "Your account has been banned from the server.")
                        except self.ServerError.AuthenticationError:
                            self.show_server_com_with_client(conn, selfname, "Authentication Failed.")
                        except self.ServerError.NameNotInDatabaseError:
                            self.show_server_com_with_client(conn, selfname, "Your account is not registered in the database. Please register your account.")
                        except Exception as e:
                            self.show_errors(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing agruments: {e}")
                            self.show_server_com_with_client(conn, selfname, "Invalid arguements! Proper Usage: !login <username> <password>")
                    elif msg.startswith("!register"):
                        try:
                            username = msg.split()[1]
                            password = msg.split()[2]
                            self.register_accounts(username, password)
                            logged_in = True
                            selfname = username
                            self.conn_list.append(conn)
                            self.add_name_to_db(selfname, str(ip[0])+" "+str(ip).strip('()').split()[1])
                            self.show_server_com_with_client(conn, selfname, "Successfully Registered. You have been logged in with this account!")
                        except self.ServerError.NameAlreadyRegisteredError:
                            self.show_server_com_with_client(conn, selfname, "The account name is already registered in the database. Please use another name for your account.")
                        except Exception as e:
                            self.show_errors(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing agruments: {e}")
                            self.show_server_com_with_client(conn, selfname, "Invalid arguements! Proper Usage: !login <username> <password>")
                if logged_in:
                    if serverowner:
                        if msg.startswith("!nick"):
                            try:
                                selfname = msg.split()[1]
                                self.show_server_com_with_client(conn, selfname, f"Changed your name to: {selfname}")
                            except:
                                self.show_server_com_with_client(conn, selfname, "Invalid arguements! Proper Usage: !nick <username>")
                        elif msg.startswith("!unnick"):
                            selfname = self.ownername
                            self.show_server_com_with_client(conn, selfname, f"Changed your name back to: {selfname}")
                        elif msg.startswith("!banuser"):
                            try:
                                banned_user = msg.split()[1]
                                if banned_user == self.ownername:
                                    self.show_server_com_with_client(conn, selfname, f"You can't ban yourself!")
                                else:
                                    self.ban_user_fr_server(banned_user)
                                    self.show_server_com_with_client(conn, selfname, f"The Ban Hammer has spoken! {banned_user} has been banned from the server!")
                                    db = sqlite3.connect(self.userdbfile)
                                    cursor = db.cursor()
                                    cursor.execute(f"select * from loggedinusers where username = '{banned_user}'")
                                    for i in cursor.fetchall():
                                        if banned_user.strip() == i[0].strip():
                                            connectionnum = i[1]
                                            for i in self.conn_list:
                                                if connectionnum.split()[0] in str(i) and connectionnum.split()[1] in str(i):
                                                    self.show_server_com_with_client(i, banned_user, "You have been banned from the server!")
                                                    i.close()
                                    cursor.close()
                                    db.close()
                            except Exception as e:
                                self.show_errors(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing agruments: {e}")
                                self.show_server_com_with_client(conn, selfname, f"Invalid arguements! Proper Usage: !banuser <username>")
                        elif msg.startswith("!kickuser"):
                            try:
                                kick_user = msg.split()[1]
                                if kick_user == self.ownername:
                                    self.show_server_com_with_client(conn, selfname, f"You can't kick yourself!")
                                else:
                                    self.show_server_com_with_client(conn, selfname, f"{kick_user} has been kicked from the server!")
                                    db = sqlite3.connect(self.userdbfile)
                                    cursor = db.cursor()
                                    cursor.execute(f"select * from loggedinusers where username = '{kick_user}'")
                                    for i in cursor.fetchall():
                                        if kick_user.strip() == i[0].strip():
                                            connectionnum = i[1]
                                            for i in self.conn_list:
                                                if connectionnum.split()[0] in str(i) and connectionnum.split()[1] in str(i):
                                                    self.show_server_com_with_client(i, kick_user, "You have been banned from the server!")
                                                    i.close()
                                    cursor.close()
                                    db.close()
                            except Exception as e:
                                self.show_errors(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing agruments: {e}")
                                self.show_server_com_with_client(conn, selfname, f"Invalid arguements! Proper Usage: !kickuser <username>")
                        elif msg.startswith("!unban"):
                            try:
                                unbanned_user = msg.split()[1]
                                self.unban_user_fr_server(unbanned_user)
                            except:
                                self.show_errors(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing agruments: {e}")
                                self.show_server_com_with_client(conn, selfname, f"There was an error.")
                    if msg.startswith("!reregister"):
                        try:
                            old_pass = msg.split()[1]
                            newpass = msg.split()[2]
                            authentication = self.attempt_login(selfname, old_pass)
                            if authentication == True:
                                self.show_server_com_with_client(conn, selfname, f"Changing your password to: {newpass}")
                                self.change_password(selfname, newpass)
                        except self.ServerError.AuthenticationError:
                            self.show_server_com_with_client(conn, selfname, "Authentication Failed.")
                        except Exception as e:
                            self.show_errors(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing agruments: {e}")
                            self.show_server_com_with_client(conn, selfname, "Invalid arguements! Proper Usage: !login <username> <password>")
                    elif msg.startswith("!dm"):
                        try:
                            username = msg.split()[1]
                            dmconn = self.opendm(username)
                            indm = True
                            dmusername = username
                            self.show_server_com_with_client(conn, selfname, f"Opened a DM with {username}. You can directly speak to them privately!")
                        except self.ServerError.NameNotInDatabaseError:
                            self.show_server_com_with_client(conn, selfname, "The Username specified is not online or is not registered in the database.")
                        except:
                            self.show_server_com_with_client(conn, selfname, "Invalid arguements! Proper Usage: !login <username> <password>")
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
                        conflicting_rooms = self.check_for_samerooms(roomname)
                        if not conflicting_rooms:
                            self.show_server_com_with_client(conn, selfname, f"Creating a room.\n[+] Room Name: {roomname}\n[+] Room Password: {room_password.strip()}")
                            room_password = hashlib.sha256(room_password.encode()).hexdigest()
                            self.create_room(roomname, room_password)
                            self.rooms.append([roomname])
                            self.update_file(self.roomdata, f"RoomName: {roomname}\nOwner: {selfname}\nAdmins: {selfname}\nMembers: {selfname}\nBanlist: \nEndData\n")
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
                                        if authentication == True:
                                            self.add_to_roomdata(selfname, roomname, "Members: ")
                                            in_room = True
                                            inroom = True
                                    if inroom:
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
                            self.show_errors(f"\n[({datetime.datetime.today()})][(AUTENTICATION_ERROR)]: {selfname} has provided incorrect credentials!")
                            self.show_server_com_with_client(conn, selfname, "Password provided for the room is incorrect.")
                        except Exception as e:
                            self.show_errors(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing agruments: {e}")
                            self.show_server_com_with_client(conn, selfname, "Invalid arguements! Proper Usage: !login <username> <password>")
                    elif msg.startswith("!leaveroom"):
                        self.show_server_com_with_client(conn, selfname, "Leaving your current room.")
                        for room in self.rooms:
                            if selfroomname in room:
                                item = 0
                                for i in room:
                                    if str(conn) == str(i):
                                        del room[item]
                                    item += 1
                                inroom = False
                                room_admin = False
                                selfroomname = ""
                                break
                    elif msg.startswith("!ban"):
                        if inroom:
                            if roomadmin:
                                try:
                                    name = msg.split()[1]
                                    self.add_to_roomdata(name, selfroomname, "Banlist: ")
                                except self.ServerError.PermissionError:
                                    self.show_server_com_with_client(conn, selfname, "Your permissions are invalid for this command.")
                                    self.show_errors(
                                        f"\n[({datetime.datetime.today()})][(PERMISSION_ERROR)]: {selfname} ran command '{msg.strip()}' that was forbidden!")
                                except Exception as e:
                                    self.show_errors(
                                        f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing agruments: {e}")
                                    self.show_server_com_with_client(conn, selfname, "Invalid arguements! Proper Usage: !login <username> <password>")
                            else:
                                self.show_server_com_with_client(conn, selfname, "Your permissions are invalid for this command.")
                                self.show_errors(
                                    f"\n[({datetime.datetime.today()})][(PERMISSION_ERROR)]: {selfname} ran command '{msg.strip()}' that was forbidden!")
                    elif msg.startswith("!unban"):
                        if roomadmin:
                            try:
                                name = msg.split()[1]
                                self.del_from_roomdata(name, selfroomname, "Banlist: ")
                            except self.ServerError.PermissionError:
                                self.show_server_com_with_client(conn, selfname, "Your permissions are invalid for this command.")
                                self.show_errors(
                                    f"\n[({datetime.datetime.today()})][(PERMISSION_ERROR)]: {selfname} ran command '{msg.strip()}' that was forbidden!")
                            except Exception as e:
                                self.show_errors(
                                    f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing agruments: {e}")
                                self.show_server_com_with_client(conn, selfname, "Invalid arguements! Proper Usage: !login <username> <password>")
                        else:
                            self.show_server_com_with_client(conn, selfname,
                                                             "Your permissions are invalid for this command.")
                            self.show_errors(f"\n[({datetime.datetime.today()})][(PERMISSION_ERROR)]: {selfname} ran command '{msg.strip()}' that was forbidden!")
                    elif msg.startswith("!promoteuser"):
                        if inroom:
                            try:
                                if roomadmin:
                                    usertopromote = msg.split()[1]
                                    self.add_to_roomdata(usertopromote, selfroomname, "Admins: ")
                                else:
                                    self.show_server_com_with_client(conn, selfname, "Your permissions are invalid for this command.")
                                    self.show_errors(f"\n[({datetime.datetime.today()})][(PERMISSION_ERROR)]: {selfname} ran command '{msg.strip()}' that was forbidden!")
                            except:
                                self.show_errors(
                                    f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing agruments: {e}")
                                self.show_server_com_with_client(conn, selfname, "Invalid arguements! Proper Usage: !login <username> <password>")
                    elif msg.startswith("!demoteuser"):
                        if inroom:
                            try:
                                if roomadmin:
                                    usertodemote = msg.split()[1]
                                    self.del_from_roomdata(usertodemote, selfroomname, "Admins: ")
                                else:
                                    self.show_errors(
                                        f"\n[({datetime.datetime.today()})][(PERMISSION_ERROR)]: {selfname} ran command '{msg.strip()}' that was forbidden!")
                                    self.show_server_com_with_client(conn, selfname, "Your permissions are invalid for this command.")
                            except self.ServerError.PermissionError:
                                self.show_errors(f"\n[({datetime.datetime.today()})][(PERMISSION_ERROR)]: {selfname} ran command '{msg.strip()}' that was forbidden!")
                                self.show_server_com_with_client(conn, selfname, "Invalid Permissions to ban the user.")
                            except Exception as e:
                                self.show_errors(f"\n[({datetime.datetime.today()})][(ERROR)]: Error with parsing agruments: {e}")
                                self.show_server_com_with_client(conn, selfname, "Invalid arguements! Proper Usage: !login <username> <password>")
                    elif msg.strip() == "":
                        pass
                    else:
                        if inroom:
                            for room in self.rooms:
                                if selfroomname in room[0]:
                                    for person in room:
                                        try:
                                            person.send(main_msg.encode())
                                        except:
                                            pass
                        if indm:
                            dmconn.send("\n[(DM)]".encode()+main_msg.strip().encode())
                if msg.strip() == "":
                    pass
                else:
                    self.log(f"\n[({datetime.datetime.today()})]"+main_msg.strip())
                    print(f"[({datetime.datetime.today()})]"+main_msg.strip())
            except Exception as e:
                self.show_errors(f"\n[({datetime.datetime.today()})][(ERROR)]: Client Error with {ip}(known as {selfname}): {e}")
                try:
                    self.remove_user_from_db(selfname)
                except Exception as e:
                    self.show_errors(f"\n[({datetime.datetime.today()})][(ERROR)]: Error whilst removing name from database: {e}")
                conn.close()
                break
class OptionParse:
    def __init__(self):
        self.parse_args()
    def usage(self):
        print(Server.logo(None))
        print("""
[+] Option-Parsing Help:

[+] Required Arguements:
[+] --ip, --ipaddr     - Specify the IP to host the server on.
[+] --p,  --port       - Specify the Port to host the server on.
[+] These are needed to host the server.

[+] Optional Arguements:
[+] --i,  --info       - Shows this message.
[+] --db, --database   - Specify the Database file to store passwords on(must be a .db).
[+] --au, --activeuser - Specify the database file with all the current active users.
[+] --rd, --roomdata   - Specify the room data file where room data is stored.
[+] --sl, --servlog    - Specify the server log file.
[+] --ou, --owneruser  - Specify the owner username.
[+] --op, --ownerpass  - Specify the owner password.
[+] --mc, --maxconn    - Specify the max amount of connections per second.
[+] Note: These optional arguements have defaults, so you are able to leave them.

[+] Usage:
[+] python3 Datcord.py --ip <ip> --p <port> --db <dbfile> --au <aufile> --rd <roomdata> --sl <servlog> --ou <owneruser> --op <ownerpass> --mc <maxconn>
[+] python3 Datcord.py --i""")
    def parse_args(self):
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
                mc = 20
        else:
            mc = 20
        server = Server(ip, port, db, au, rd, sl, ou, op, mc)
        server.listen()
if __name__ == '__main__':
    if sys.platform == "win32":
        os.system("cls")
    else:
        os.system("clear")
    parse = OptionParse()