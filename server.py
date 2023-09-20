import socket, threading
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
        length += ' '*(1024-len(length))
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
            # Add ID to message
            msg = f'<{id}> '
            msg += client.recv(length).decode()
            print(msg)
            for elem in clients:
                send(elem[0], elem[1], msg)
                    
def connect(client, id):
    send(client, id, f'Connected. Welcome {id}')
    chatT = threading.Thread(target=relay, args=(client,id))
    chatT.start()

# Infinite loop to continue accepting connections
while True:
    # Define tuple of connection
    (client, address) = serverS.accept()
    name = client.recv(msgLen(client))
    name = name.decode()
    uid = name + "#" + str(address[1])
    clients.append((client, uid))
    print(f'Client {name} connected at {address}')
    connect(client, uid)
    