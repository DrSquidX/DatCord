# DatCord
This is a school project for one of my Design classes. This server is a sophisticated secure server using an SQL database to store passwords, along with sha256 password hashing which made passwords more secure. There is a logging system that allows errors and communication between client and server to be displayed, and allows for easier debugging and more. There is also a room system, where people can communicate with each other, as well as a direct messaging system that allows for private messaging.

# Every Feature Included(In a more straightforward way):
* Secure Password Storage - Every password is stored inside of an SQL Database

* Password Hashing        - Passwords are hashed, meaning that they will return what appears to be gibberish if an SQL Injection is to happen.

* Chat Rooms              - Chat rooms made for you to be able to talk and communicate with friends. These can have a password, however it is optional.

* Direct Messaging        - Privately chat with friends on the server.

* Multi-Threaded          - The server can handle multiple clients at once, since it is multi-threaded(meaning that it could do many tasks at once, AKA Multi-Tasking).

* Owner Account           - An account made for the server owner. It has the highest authority out of any of the clients.

* Logging                 - Everything in the server is logged. These can include logging errors for easier debugging, as well as being able to see if anything suspicious is going on.

* Developer Friendly      - It is very easy to make a client script to connect to this server!

* Option Parsing          - Parse arguments when running this script in terminal, where it could help with changing different settings and help with the usability of the server.

* DDoS Protection         - A work in progress(The server can identify when the attack is happening, and will close these connections).

* Anti Spam               - Spammers will get kicked!

* Special Client Script   - Official Client script used for connecting to the server.

* Friends System          - A system to help you know when youre friends are online and available to chat with.

* Blocking System         - Block annoying people with the blocking system.

* Encrypted               - Every message is encrypted so that messages cannot be intercepted by hackers.

* Dependecies             - Figure out what things you may need to download to run the scripts correctly.

# Secure Password Storage
Due to some recent learning of SQL, I have changed my old way of password storage of a plain text file, to a more advanced alternative - SQL Databases. This way I can store passwords in a more secure way, where the server would have to run a certain SQL Command to extract a username and password from the Database(this command is similar to "select * from users). This password storage system is more quick than the old text file system, as I can run a certain SQL Command to extract, remove or insert something in the Database, whereas I would have to read a whole text file to extract information from it(this would be worse if the server had a lot of clients, as the reading of the file would take very long). This system is more secure than any system I have made so far. 

User info SQL Database file:
![sqlfile](/sqlfile.png)

# Password Hashing
Every password in this server is hashed. This helps with security, as the hashed password is a hash of an original password, however it looks nothing like it. This would mean if some sort of SQL Injection were to happen, the attacker would get a dictionary of what would look like gibberish. It is unusable, as if the hashed password were to be put into the server, this hash would again be hashed, which would not actually match the password hash in the database. The hashing algorithm is sha256, which is considered a more secure hashing algorithm compared to md5, which is what I used to use.

User info from executing an SQL Command(clients won't be able to do this):
![hashes](/sql.png)

# Chat Rooms
Every user has the ability to create their own chat room. These chat rooms are private rooms for them and their friends to be able to chat on. These chatrooms are able to have passwords, however these are optional. If you want to have a chat room that is private, it is suggested that you make the chat room created have a password. Once you have logged into a chatroom once, you won't need to be using a password when you want to join it. If you want a public chat room, you do not need to provide the password. Every chat room also has moderation. This means that you can ban users from the chat room(if you are room admin). The creator of the chat rooms are automatically an admin, and they also have the ability to promote other users to admin, where they can do similar things.

2 Test Accounts in a chat room together:

![inroom](/inchatroom.png)

# Direct Messaging
If you want to chat one-to-one with another person, it is very simple. There is a direct messaging system in the server, where you are allowed to chat privately with another user. These are private, so nobody else(maybe the server), will be able to see what is being sent between each person. The only reason that the server is able to see these messages is in case there is any bullying going around, where evidence can be put around to whoever was doing the bad things. Let me know if I should remove that, and I will make it so that the message will not be displayed in the server(I figure that will be rather easy).

2 Test Accounts in a DM Together:

![indm](/dm.png)

# Multi-Threaded
The server is multi-threaded, meaning that It can handle multiple clients at once. This is better than having single-threaded servers, where they do not have the abilities to listen for connections, send and receive messages at the same time, where multi-threaded servers(like this one) are able to be used.

Server handling multiple clients at once:

![multithreaded](/multi-threaded.png)

# Owner Account
In the server, there is one owner account, made for the server owner to be able to use and chat with other people. This account is unlike any normal account, as it has the abilities to broadcast messages to everyone on the server, ban and kick people, as well as being able to change their name to someone else's. This owner account has the highest authority on the server, and it has a lot of power.

Admin Account specified in the server after starting:
![adminacc](/admin1.png)

Admin Help Message after logging into Owner account:
![adminmsg](/admin2.png)

Compared to regular client help messages:
![regularmsg](/default.png)

# Logging
Everything in the server is logged. This is good for being able to report and debug errors on the server, so that these could be easily fixed. Every error, message, and connection is logged, so that the server can know who is connecting, what they might be saying, as well as any errors that pop up when the server is running.

Logging in the Server:
![log](/log.png)

# Developer Friendly
Making scripts to connect to this server is very easy. The possibilities are endless, since there is barely any code(17 lines at most) needed to connect to the main server. This means other people can add more code, such as for GUI's, or making it overall more user friendly. The possibilities are endless, and people can add anything to the client side to make it better.

Simple 17 Line client script needed for a minimally good experience on the server:
![clientpic](/simpleclient.png)

# Option Parsing
This server uses option-parsing. This would mean that it would first need to be ran in terminal, where the command that runs the script will check the arguments of the command. For this script, the arguments are parsed and identified into variables needed to run the server the best way possible. You need to specify the ip to host the server on, as well as the port. Many of the arguments are optional, and are merely for if you have other items for them. There is also a help message for the option-parsing, where if you don't provide an IP address to host the server on, that message will show up and give you more info on how to do it.

Help message for Option Parsing:
![optionparse](/optparse.png)

Example of Option Parsing:

![optionparse2](/optparse2.png)

# DDoS Protected(Depends on Hardware)
This server has somewhat DDoS Protection. I think it's safe to say it's DoS protected, as I have tested my TCP Flood DDoS Script(the server uses TCP, AKA Transmission Control Protocol) on my server, where my server seemed fine and untouched. The attackers IP can also be banned, where they won't be able to connect to the server. For DDoS Attacks, I am not fully sure it is resistant to that, however the server does have a few countermeasures in attempt to combat that. These would include: Banning any incoming IP addresses that are not whitelisted, and Stopping the listening of connections. I forgot to mention that there is also an IP whitelisting system. Since a DoS attack would trigger the server to put on a firewall that would disconnect any incoming connections(keeping the server up and running, just not as open to connections), the IP whitelisting system would come in and allow the whitelisted IP Addresses past the firewall and into the server. There is also an automatic Anti-DDoS system that begins IP Banning incoming connections, if 30 seconds pass without the server owner not doing anything to stop the attacks. The Anti-DDoS System is still a work in progress, but it somewhat works. I have found that the Anti-DDoS works better on windows machines rather than on mac. I will look into fixing that. The issue is most likely due to the Macbook being to weak to handle the larger amount of connections(my windows computer is much more powerful and can handle the large amount of connections).

Server warning of DDoS Attack:
![ddoswarn](/ddos.png)

Admin IP banning the attacker of a DoS Attack:
![ipban](/ipban.png)

Automatic DDoS System in action:
![autoantiddos](/auto_anti_ddos.png)

# Anti Spam
There is an Anti-Spam system on the server. It works somewhat similarly to the Anti-DDoS System, as it measures whether to do something if the amount of messages sent per second(in the Anti-DDoS System it's connections per second). If the messages per second reach the limit(set to 4), the client will be warned. They have 3 warnings, and if they reach the 3rd warning, they will be kicked. This system prevents spammers from flooding peoples direct messages or chat rooms with junk or gibberish.

Spammer getting kicked by server:
![spamkick](/anti-spam.png)

# Special Client Script
There is a client script that is suggested to be used to connect to the server. The client script has an easy way of connecting to different DatCord servers, so you will have no problems with connecting. Logging in is easier, as you dont have to enter commands like "!login blablabla blablabla" and is more straightforward. Direct Messages that you get are also formatted to look better.

Client Script in Use:
![clientscript](/clientscript.png)

# Friends System
In the server, there is a friends system that allows for easier usage in the server. If you want to see which of your friends are online, you can run a simple command and a list of your online friends will show up. To become friends on the server with someone, you need to first send a friend request to the other user, where the other user needs to accept said request. If they accept, you are friends. You could now see if they are online or not.

Example of Sending a friend request:

![friendreqsent](/reqsent.png)

The friend request being recieved by the other user:
![friendreqrecv](/recvreq.png)

The accepting of said request:

![friendreqaccept](/acceptreq.png)

# Blocking System
Got any annoying people that are spamming you non-stop in DatCord? Not to worry. The new blocking system allows for the easy blocking of users, so that they won't be able to spam you in direct messages, and also so that they can't friend request you. This system is for if you don't want someone to direct message nor be able to friend request you, if you really don't like that user.

Person blocked from Direct messaging and Friend Requesting:

![blockdm](/blockdm.png)
![friendreqblocked](/reqblocked.png)

However the person blocking the other user cannot DM the other user:

![cantdm](/cantdm.png)

# Encryption
In DatCord, every message that is sent is encrypted. This makes it so that most of the messages sent are unrecognizable to any external source, and is only able to be decrypted with a key that is sent to the client after they connect. The encryption makes messages more secured and much less able to be intercepted externally from any attackers that are attempting to do Man-In-The-Middle Attacks. There is no noticable change when they are actually being used properly, however these messages look like gibberish when they are encrypted.

Intercepted Not Encrypted Traffic:

![Decrypted](/notencrypted.png)

Intercepted Encrypted Traffic:

![Encrypt](/encrypted.png)

# Dependecies
There is one module you need to install in order to run the script. You need to download 'cryptography' which is a module that is used for encryption. If you have 'pip' installed, you can run "pip install cryptography" in terminal/cmd.

# Overall
DatCord is a secure chat server that is safe to use, DoS-Free, as well as a lot of capibilites for clients. They can create their own chat rooms for their friends, chat privately one-to-one with them, and more. The Owner account on the server can also manage and moderate the server, to stop attackers and hackers(if they have the knowledge), if the server is to be compromised. This server shows the improvement of my skills in networking, and also a bit in cybersecurity.

# Happy Chatting, DrSquidX
