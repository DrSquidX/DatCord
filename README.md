# DatCord
This is a school project for one of my Design classes. This server is a sophisticated secure server using an SQL database to store passwords, along with sha256 password hashing which made passwords more secure. There is logging system that allows errors and communication between client and server to be displayed, and allows for easier debugging and more. There is also a room system, where people can communicate with each other, as well as a direct messaging system that allows for private messaging.

# Every Feature Included(In a more straightforward way):
* Secure Password Storage - Every password is stored inside of an SQL Database

* Password Hashing        - Passwords are hashed, meaning that they will return what appears to be gibberish if an SQL Injection is to happen.

* Chat Rooms              - Chat rooms made for you to be able to talk and communicate with friends. These can have a password, however it is optional.

* Direct Messaging        - Privately chat with friends on the server.

* Multi-Threaded          - The server can handle multiple clients at oncel, since it is multi-threaded(meaning that it could to many tasks at once, AKA Multi-Tasking).

* Owner Account           - An account made for the server owner. It has the highest authority out of any of the clients.

* Logging                 - Everything in the server is logged. These can include logging errors for easier debugging, as well as being able to see if anything suspicious is going on.

* Developer Friendly      - It is very easy to make a client script to connect to this server!

# Secure Password Storage
Due to some recent learning of SQL, I have changed my old way of password storage of a plain text file, to a more advanced alternative - SQL Databases. This way I can store passwords in a more secure way, where the server would have to run a certain SQL Command to extract a username and password from the Database(this command is similar to "select * from users). This password storage system is more quick than the old text file system, as I can run a certain SQL Command to extract, remove or insert something in the Database, whereas I would have to read a whole text file to extract information from it(this would be worse if the server had a lot of clients, as the reading of the file would take very long). This system is more secure than any system I have made so far. 

# Password Hashing
Every password in this server is hashed. This helps with security, as the hashed password is a hash of an original password, however it looks nothing like it. This would mean if some sort of SQL Injection were to happen, the attacker would get a dictionary of what would look like gibberish. It is unusable, as if the hashed password were to be put into the server, this hash would again be hashed, which would not actually match the password hash in the database. The hashing algorithim is sha256, which is considered a more secure hashing algorithim compared to md5, which is what I used to use.

# Chat Rooms
Every user has the ability to create their own chat room. These chat rooms are private rooms for them and their friends to be able to chat on. These chatrooms are able to have passwords, however these are optional. If you want to have a chat room that is private, it is suggested that you make the chat room created have a password. Once you are have logged into a chatroom once, you won't need to be using a password when you want to join it. If you want a public chat room, you do not need to provide the password. Every chat room also has moderation. This means that you can ban users from the chat room(if you are room admin). The creator of the chat rooms are automatically an admin, and they also have the ability to promote other users to admin, where they can do similar things.

# Direct Messaging
If you want to chat one-to-one with another person, it is very simple. There is a direct messaging system in the server, where you are allowed to chat privately with another user. These are private, so nobody else(maybe the server), will be able to see what is being sent between each person. The only reason that the server is able to see these messages is in case there is any bullying going around, where evidence can be put around to whoever was doing the bad things. Let me know if I should remove that, and I will make it so that the message will not be displayed in the server(I figure that will be rather easy).

# Multi-Threaded
The server is multi-threaded, meaning that It can handle multiple clients at once. This is better than having single-threaded servers, where they do not have the abilities to listen for connections, send and recieve messages at the same time, where multi-threaded servers(like this one) are able to be used.
