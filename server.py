import socket, threading, json
from sqlalchemy import create_engine, Column, Integer, VARCHAR, JSON, select
from sqlalchemy.orm import sessionmaker, declarative_base
import secrets
import re
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

# Declare chat class such that users are stored in list and chat is one string
class Chat(Base):
    __tablename__ = 'chats'
    id = Column(Integer, primary_key=True)
    users = Column(VARCHAR, unique=True)
    contents = Column(VARCHAR, unique=False)

class Login(Base):
    __tablename__ = 'login'
    id = Column(Integer, primary_key=True)
    username = Column(VARCHAR, unique=True)
    passhash = Column(VARCHAR, unique=False)
    salt = Column(VARCHAR, unique=False)

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
    except ConnectionResetError:
        print(f'Connection {id} closed')
        for idx, elem in enumerate(clients):
            if elem[1] == id:
                clients.pop(idx)
                print(f'Unresponsive client {client} removed')

def relay(client, id):
    while True:
        length = msgLen(client)
        # If message exists
        if length:
            # Get message
            msg = client.recv(length).decode()
            print(f'<{id}> ' + msg)
            if '[getchatwith:' in msg:
                target = re.search(r'\[getchatwith:(.*?)\]', msg).group(1)
                usersinchat = "|".join(sorted([id, target]))
                chatrecord = session.query(Chat).filter(Chat.users == usersinchat).first()
                send(client,id,f'[getchatwith:return]{chatrecord.contents if chatrecord else ""}')
            elif '[for:' in msg:
                handleDM(client, id, msg)
            else:
                for elem in clients:
                    send(elem[0], elem[1], f'<{id}> ' + msg)

def handleDM(client, id, msg):
    for elem in clients:
        if f'[for:{elem[1]}]' in msg:
            msg = msg.replace(f'[for:{elem[1]}] ', '')
            send(client, id, f'<{id}> ' + msg)
            send(elem[0], elem[1], f'<{id}> ' + msg)
                        # Check if already existing chat between users, if not create and add first messages as string
                        # Create string containing users in chat as unique id
            usersinchat = "|".join(sorted([id, elem[1]]))
            chatrecord = session.query(Chat).filter(Chat.users == usersinchat).first()
            if chatrecord:
                curcontents = chatrecord.contents
                newcontents = f"{curcontents}<{id}> {msg}\n"
                chatrecord.contents = newcontents
                session.commit()
            else:
                newchatrecord = Chat(users = usersinchat, contents=f"<{id}> {msg}\n")
                session.add(newchatrecord)
                session.commit()
                    
def connect(client, id):
    send(client, id, f'\nConnected. Welcome {id}\n')
    for elem in clients:
        availables = [c[1] for c in clients if not c[1] == elem[1]]
        send(elem[0], elem[1], json.dumps(availables))
    chatT = threading.Thread(target=relay, args=(client,id))
    chatT.start()

# Generate salt function
def register(username, password, salt):
    newchatrecord = Login(username = username, passhash = password, salt = salt)
    session.add(newchatrecord)
    session.commit()

# Infinite loop to continue accepting connections
while True:
    # Define tuple of connection
    (client, address) = serverS.accept()
    name = client.recv(msgLen(client))
    name = name.decode()
    userRecord = session.query(Login).filter(Login.username == name).first()
    salt = userRecord.salt if userRecord else secrets.token_hex(16)
    send(client, name, f'[s:{salt}]')
    hashedpw = client.recv(msgLen(client))
    hashedpw = hashedpw.decode()
    if userRecord: 
        if not userRecord.passhash == hashedpw: 
            send(client, name, '[AUTHFAIL]')
            client.close()
            continue
        else: send(client, name, '[AUTHSUCCESS]')
    else: 
        register(name, hashedpw, salt)
        send(client, name, '[AUTHSUCCESS]') 
    print(address)
    clients.append((client, name))
    print(f'Client {name} connected at {address}')
    connect(client, name)