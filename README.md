# DatCord
This is a school project for one of my Design classes. This server is a sophisticated secure server using an SQL database to store passwords, along with sha256 password hashing which made passwords more secure. There is logging system that allows errors and communication between client and server to be displayed, and allows for easier debugging and more. There is also a room system, where people can communicate with each other, as well as a direct messaging system that allows for private messaging.

# Every Feature Included(In a more straightforward way):
* Secure Password Storage - Every password is stored inside of an SQL Database

* Password Hashing        - Passwords are hashed, meaning that they will return what appears to be gibberish if an SQL Injection is to happen.

* Chat Rooms              - Chat rooms made for you to be able to talk and communicate with friends. These can have a password, however it is optional.

* Chat Room Moderation    - Chat room admins have the abilities to ban users from the chat-rooms, as well as being able to promote others.

* Direct Messaging        - Privately chat with friends on the server.

* Multi-Threaded          - The server can handle multiple clients at oncel, since it is multi-threaded(meaning that it could to many tasks at once, AKA Multi-Tasking).

* Owner Account           - An account made for the server owner. It has the highest authority out of any of the clients.

* Logging                 - Everything in the server is logged. These can include logging errors for easier debugging, as well as being able to see if anything suspicious is going on.

# Secure Password Storage
Due to some recent learning of SQL, I have changed my old way of password storage of a plain text file, to a more advanced alternative - SQL Databases. This way I can store passwords in a more secure way, where the server would have to run a certain SQL Command to extract a username and password from the Database(this command is similar to "select * from users). This password storage system is more quick than the old text file system, as I can run a certain SQL Command to extract, remove or insert something in the Database, whereas I would have to read a whole text file to extract information from it(this would be worse if the server had a lot of clients, as the reading of the file would take very long). This system is more secure than any system I have made so far. 
