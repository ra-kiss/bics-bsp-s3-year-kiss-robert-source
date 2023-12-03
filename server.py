import socket, threading, json
from sqlalchemy import create_engine, Column, Integer, VARCHAR, JSON, select, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, joinedload
from datetime import datetime
import secrets
import re
DEBUG = False
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

# Decode message length
def msgLen(client):
    try:
        # Receive first 4 bytes indicating length
        length = client.recv(4)
        length = int(length.decode())
        #print(f'The message is {length} bytes long')
        return length
    except ConnectionResetError:
        # For each client connected
        for idx, elem in enumerate(clients):
            # If the first index of (clientS, address) tuple is equal to given client
            if elem[0] == client:
                # Remove client from list
                clients.pop(idx)
                print(f'Unresponsive client {client} removed')

def send(client, id, msg):
    try:
        length = str(len(msg))
        # Pad until it is at desired length
        length += ' '*(4-len(length))
        client.send(bytes(length, 'utf-8'))
        client.send(bytes(msg, 'utf-8'))
        if DEBUG: print("Sending message\n", msg, f"\nto {id}\n")
    except ConnectionResetError:
        print(f'Connection {id} closed')
        for idx, elem in enumerate(clients):
            if elem[1] == id:
                clients.pop(idx)
                print(f'Unresponsive client {client} removed')

def getChatHistory(session, userID):
    # Retrieve the User object for the specified user
    user = session.query(User).filter(User.username == userID).first()

    # Retrieve messages sent by the user
    sent = (
        session.query(Message, User.username)
        .join(User, Message.sender == User.id)
        .filter(Message.sender == user.id)
        .options(joinedload(Message.recipientsRel))
        .all()
    )
    sent = [(message, username) for message, username in sent]

    # Retrieve messages received by the user
    received = (
        session.query(Message, User.username)
        .join(Recipient, Recipient.msg == Message.id)
        .join(User, Message.sender == User.id)  # Adjusted join condition
        .filter(Recipient.user == user.id)
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

def getKey(target):
    user = session.query(User).filter(User.username == target).first()
    return user.publicKey

def relay(client, id):
    while True:
        length = msgLen(client)
        # If message exists
        if length:
            # Get message
            msg = client.recv(length).decode()
            print(f'<{id}> ' + msg)
            if '[getchatwith:' in msg:
                chatrecord = getChatHistory(session, id)
                send(client, id, f'[getchatwith:return:{chatrecord}]')
            elif '[k:getkey:' in msg:
                target = re.sub(r'\[k:getkey:|]', '', msg)
                send(client, id, f'[k:getkey:return:{getKey(target)}]')
            elif '[for:' in msg:
                for elem in clients:
                    if f'[for:{elem[1]}]' in msg:
                        handleDM(client, id, msg, elem)
            else:
                for elem in clients:
                    send(elem[0], elem[1], f'<{id}> ' + msg)

def addMsgtoDB(senderID, recipientID, msgtxt):
    # Create a new message with the provided sender, text, and timestamp
    sender = session.query(User).filter(User.username == senderID).first()
    if sender:
        newMsg = Message(sender=sender.id, text=msgtxt, timestamp=datetime.now())
        session.add(newMsg)
        session.commit()  # Commit to get the new message ID generated by the database

    # Retrieve the User object for recipient
    recipient = session.query(User).filter(User.username == recipientID).first()
    if recipient:
        # Create a new recipient entry for the specified recipient and the newly created message
        newRecipient = Recipient(user=recipient.id, msg=newMsg.id)
        session.add(newRecipient)
        session.commit()

def handleDM(client, id, msg, elem):
    msg = msg.replace(f'[for:{elem[1]}] ', '')
    # print('Sending DM\n', f'<{id}>' + msg)
    send(client, id, f'<{id}> ' + msg)
    send(elem[0], elem[1], f'<{id}> ' + msg)
    addMsgtoDB(id, elem[1], msg)
                    
def connect(client, id):
    send(client, id, f'\nConnected. Welcome {id}\n')
    for elem in clients:
        availables = [c[1] for c in clients if not c[1] == elem[1]]
        send(elem[0], elem[1], json.dumps(availables))
    chatT = threading.Thread(target=relay, args=(client,id))
    chatT.start()

# Generate salt function
def register(username, password, salt, publicKey):
    # send(client, name, f'[MAKEKEYS]')
    newchatrecord = User(username = username, passhash = password, salt = salt, publicKey = publicKey)
    session.add(newchatrecord)
    session.commit()

# Infinite loop to continue accepting connections
while True:
    # Define tuple of connection
    (client, address) = serverS.accept()
    name = client.recv(msgLen(client))
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