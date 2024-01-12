import socket, threading, json
from sqlalchemy import create_engine, Column, Integer, Boolean, VARCHAR, JSON, select, ForeignKey, or_
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, joinedload, aliased
from datetime import datetime
import secrets
import re
DEBUG = True
RECVCONST = 32
# Define socket
serverS = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Bind socket to host and port
HOST = 'localhost'
PORT = 1234
serverS.bind((HOST,PORT))
# Contains clients address and port
clients = []
# Listen for connections
serverS.listen()

# Use an SQLite database with SQLAlchemy
engine = create_engine("sqlite:///chatapp.db")

Base = declarative_base()

'''
Database structure setup
'''
class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(VARCHAR, unique=True)
    passhash = Column(VARCHAR, unique=False)
    salt = Column(VARCHAR, unique=False)
    publicKey = Column(VARCHAR, unique=False)

    recipientsRel = relationship("Recipient", back_populates="userRel", foreign_keys="[Recipient.user]")

class Message(Base):
    __tablename__ = 'message'
    id = Column(Integer, primary_key=True)
    sender = Column(Integer, ForeignKey('user.id'))
    text = Column(VARCHAR, unique=False)
    timestamp = Column(VARCHAR, unique=False)
    filename = Column(VARCHAR, unique=False)

    recipientsRel = relationship("Recipient", back_populates="messageRel", foreign_keys="[Recipient.msg]")

class Recipient(Base):
    __tablename__ = 'recipient'
    id = Column(Integer, primary_key=True)
    user = Column(Integer, ForeignKey('user.id'))
    msg = Column(Integer, ForeignKey('message.id'))

    userRel = relationship("User", back_populates="recipientsRel", foreign_keys="[Recipient.user]")
    messageRel = relationship("Message", back_populates="recipientsRel", foreign_keys="[Recipient.msg]")


# SQLAlchemy Setup
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
session = Session()

'''
Function to decode message length
'''
def msgLen(client):
    try:
        # Receive first bytes indicating length
        length = client.recv(RECVCONST)
        if DEBUG: print("Decoded length of", length.decode())
        length = int(length.decode())
        if DEBUG: print(f'The message is {length} bytes long')
        return length
    except ConnectionResetError:
        # For each client connected
        for idx, elem in enumerate(clients):
            # If the first index of (clientS, address) tuple is equal to given client
            if elem[0] == client:
                # Remove client from list
                clients.pop(idx)
                print(f'Unresponsive client {client} removed')

'''
Function to send any given message to specified client
'''
def send(client, id, msg):
    try:
        length = str(len(msg))
        # Pad until it is at desired length
        length += ' '*(RECVCONST-len(length))
        client.send(bytes(length, 'utf-8'))
        client.send(bytes(msg, 'utf-8'))
        # if DEBUG: print("Sending message\n", msg, f"\nto {id}\n")
    except ConnectionResetError:
        print(f'Connection {id} closed')
        for idx, elem in enumerate(clients):
            if elem[1] == id:
                clients.pop(idx)
                print(f'Unresponsive client {client} removed')
'''
Function that retrieves and formats chat history between two users from database
- Returns an encrypted string of messages separated by | to be sent to client
'''
def getChatHistory(selfID, targetID):
    # Retrieve the User objects for the specified users
    selfUser = session.query(User).filter(User.username == selfID).first()
    targetUser = session.query(User).filter(User.username == targetID).first()

    # Retrieve messages sent by selfUser to targetUser
    sent = (
        session.query(Message, User.username)
        .join(User, Message.sender == User.id)
        .join(Recipient, Recipient.msg == Message.id)
        .filter(Message.sender == selfUser.id, Recipient.user == targetUser.id)
        .options(joinedload(Message.recipientsRel))
        .all()
    )
    sent = [(message, username) for message, username in sent]

    # Retrieve messages sent by targetUser to selfUser
    received = (
        session.query(Message, User.username)
        .join(Recipient, Recipient.msg == Message.id)
        .join(User, User.id == Message.sender)
        .filter(Recipient.user == selfUser.id, Message.sender == targetUser.id)
        .options(joinedload(Message.recipientsRel))
        .all()
    )
    received = [(message, username) for message, username in received]

    # Merge and sort messages by timestamp
    allmsg = sent + received
    allmsg.sort(key=lambda x: x[0].timestamp)

    # Get the text from all messages and merge into one string
    chathistory = "|".join(f'<{username}> {message.text}' for message, username in allmsg)

    return chathistory + "\n"

# Simple helper function to get key from a given user
def getKey(target):
    user = session.query(User).filter(User.username == target).first()
    return user.publicKey if user else None

# Simple helper function to get file
def getFile(filename, userID):
    user = session.query(User).filter(User.username == userID).first()
    message = (
        session.query(Message)
        .join(Recipient, Recipient.msg == Message.id, isouter=True)
        .filter(
            Message.filename == filename,
            or_(Message.sender == user.id, Recipient.user == user.id)
        )
    ).first()
    return message.text if message else None

'''
Main relay function which relays given information to clients based on a received message
- Checks for flags and handles them accordingly
'''
def relay(client, id):
    while True:
        length = msgLen(client)
        # If message exists
        if length:
            # Get message
            msg = client.recv(length).decode()
            print(f'<{id}> ' + msg)
            if '[getchatwith:' in msg:
                target = re.sub(r'\[getchatwith:|]', '', msg)
                chatrecord = getChatHistory(id, target)
                send(client, id, f'[getchatwith:return:{chatrecord}]')
            elif '[k:getkey:' in msg:
                target = re.sub(r'\[k:getkey:|]', '', msg)
                pubKey = getKey(target)
                if pubKey: send(client, id, f'[k:getkey:return:{pubKey}]')
            elif '[getfile:' in msg:
                filename = re.sub(r'\[getfile:|]', '', msg)
                file = getFile(filename, id)
                if file: send(client, id, f'[getfile:return:{file}]')
                if DEBUG and file: print(f"Sending file with filename {filename} to client")
            elif '[for:' in msg:
                if DEBUG: print("Received [for:] flag in message")
                offlineMsg = True
                for elem in clients:
                    if f'[for:{elem[1]}]' in msg:
                        msg = msg.replace(f'[for:{elem[1]}] ', '')
                        handleDM(client, id, msg, elem, offline=False)
                        offlineMsg = False
                if offlineMsg == True:
                    target = (None, re.search(r'\[for:(.*?)\]', msg).group(1))
                    msg = msg.replace(f'[for:{target[1]}] ', '')
                    handleDM(client, id, msg, target, offline=True)
            # else:
            #     for elem in clients:
            #         send(elem[0], elem[1], f'<{id}> ' + msg)

'''
Adds a message with a sender and recipient to the database
'''
def addMsgtoDB(senderID, recipientID, msgtxt):
    # Create a new message with the provided sender, text, and timestamp
    recipient = session.query(User).filter(User.username == recipientID).first()
    sender = session.query(User).filter(User.username == senderID).first()

    if sender:
        filename = None
        if "(ISFILE:" in msgtxt:
            filename = re.sub(r'.*\(ISFILE:([^\]]*)\).*', r'\1', msgtxt)
            userAlias = aliased(User)

            fileEntry =( session.query(Message)
            .join(Recipient, Recipient.msg == Message.id)
            .join(userAlias, userAlias.id == sender.id)
            .filter(
                Message.filename == filename,
                userAlias.id == sender.id,
                Recipient.user == recipient.id
            )
            .first())
            if fileEntry:
                session.delete(fileEntry)
                session.commit()
        newMsg = Message(sender=sender.id, text=msgtxt, timestamp=datetime.now(), filename=filename)
        session.add(newMsg)
        session.commit()

    if recipient:
        # Create a new recipient entry for the specified recipient and the newly created message
        newRecipient = Recipient(user=recipient.id, msg=newMsg.id)
        session.add(newRecipient)
        session.commit()

'''
Function that handles direct messages, sending the message to both clients
'''
def handleDM(senderClient, senderID, msg, recipient, offline):
    if DEBUG: print('Sending DM\n', f'<{senderID}>' + msg, f'with recipient {recipient}')
    send(senderClient, senderID, f'<{senderID}> ' + msg)
    if not offline: send(recipient[0], recipient[1], f'<{senderID}> ' + msg)
    addMsgtoDB(senderID, recipient[1], msg)

'''
Function that retrieves previously interacted with users for a given userID
This allows for offline messaging
'''
def getPreviouslyInteracted(userID):
    # Get the user with the given username
    user = session.query(User).filter_by(username=userID).first()

    # Get all users who sent messages to the given user
    senders = (
        session.query(User)
        .join(Message, User.id == Message.sender)
        .join(Recipient, Message.id == Recipient.msg)
        .filter(Recipient.user == user.id)
        .all()
    )

    # Get all users to whom the given user sent messages
    recipients = (
        session.query(User)
        .join(Recipient, User.id == Recipient.user)
        .filter(Recipient.msg.in_(session.query(Message.id).filter_by(sender=user.id)))
        .all()
    )

    # Combine and deduplicate the lists of senders and recipients
    interactedUsers = list(set(senders + recipients))

    # Extract usernames from the User objects
    usernames = [u.username for u in interactedUsers]

    return usernames

'''
Function that confirms new connections to clients, runs after clients are authenticated
- Also returns userlist to client for each new connection
'''
def connect(client, id):
    send(client, id, f'\nConnected. Welcome {id}\n')
    for elem in clients:
        currentlyOnline = [c[1] for c in clients if not c[1] == elem[1]]
        previouslyInteracted = getPreviouslyInteracted(elem[1])
        availables = previouslyInteracted + currentlyOnline
        availables = list(set(availables))
        if DEBUG: print("Calculated Availables", availables)
        jsonavailables = json.dumps(availables)
        send(elem[0], elem[1], f'[userlist:{jsonavailables}:]')
    chatT = threading.Thread(target=relay, args=(client,id))
    chatT.start()

'''
Function that handles registering a new user with all their respective arguments
'''
def register(username, password, salt, publicKey):
    # send(client, name, f'[MAKEKEYS]')
    newchatrecord = User(username = username, passhash = password, salt = salt, publicKey = publicKey)
    session.add(newchatrecord)
    session.commit()

'''
Infinite loop to continue accepting connections
'''
while True:
    # Define tuple of connection
    (client, address) = serverS.accept()
    try: name = client.recv(msgLen(client))
    except ValueError: continue
    name = name.decode()
    userRecord = session.query(User).filter(User.username == name).first()
    salt = userRecord.salt if userRecord else secrets.token_hex(16)
    send(client, name, f'[s:{salt}]')
    hashedpw = client.recv(msgLen(client))
    hashedpw = hashedpw.decode()
    if userRecord: 
        if not userRecord.passhash == hashedpw: 
            # Authentication Failure
            send(client, name, '[AUTHFAIL]')
            client.close()
            continue
        else:
            # Authentication success, retrieve key for comparison
            keyFromDB = userRecord.publicKey 
            send(client, name, f'[k:comparekey:{keyFromDB}]')
            flag = client.recv(msgLen(client))
            flag = flag.decode()
            print("Flag", flag)
            if '[k:comparekey:FALSE]' in flag:
                newPubKey = client.recv(msgLen(client))
                newPubKey = newPubKey.decode()
                userRecord.publicKey = newPubKey
                session.commit()
            send(client, name, '[AUTHSUCCESS]')
    else:
        send(client, name, f'[k:generateclientkeys]')
        publicKey = client.recv(msgLen(client))
        publicKey = publicKey.decode()
        register(name, hashedpw, salt, publicKey)
        send(client, name, '[AUTHSUCCESS]') 
    # print(address)
    clients.append((client, name))
    print(f'Client {name} connected at {address}')
    connect(client, name)