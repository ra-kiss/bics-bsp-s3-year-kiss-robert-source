import socket, threading, json
import tkinter as tk
import re
import hashlib
import pathlib
from client_interface import loginUI, mainUI
import client_encryption as e2ee
# Create a socket
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
DEBUG = True
HOST = 'localhost'
PORT = 1234
name = None
plainpassword = None
salt = None
authfail = False
sharedKey = None
sharedKeyUpdated = threading.Event()

def send(client, msg):
    try:
        # Send msg length first, then msg
        length = str(len(msg.encode('utf-8')))
        length = ' '*(4-len(length)) + length
        client.send(bytes(length, 'utf-8'))
        client.send(bytes(msg, 'utf-8'))
    except ConnectionResetError:
        print(f'Something went wrong\n Unable to send message to server')
        return True

# Function to print message to chatbox
def chatprint(msg, chatbox):
    chatbox.config(state= tk.NORMAL)
    chatbox.insert(tk.END, f'{msg}\n')
    chatbox.config(state= tk.DISABLED)

def hash(password, salt):
    salted = password + salt
    salted = salted.encode('utf-8')
    hashed = hashlib.sha256(salted).hexdigest()
    return hashed

# Fucntion to handle salt included in [s:] flag
def handleSalt(client, msg):
    global salt
    salt = re.sub(r'\[s:|\]', '', msg)
    hashed = hash(plainpassword, salt)
    if DEBUG: print('Salted Hash Sent')
    send(client, hashed)

# Function to hanlde both fail and success authentication flags
def handleAuthflag(msg):
    global authfail, s
    if '[AUTHFAIL]' in msg:
        print("Authentication Failure") 
        s.close()
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        authfail = True
    elif '[AUTHSUCCESS]' in msg:
        print('Authentication Success')
    return

def handleKeys(client, msg):
    global s, salt, sharedKey, sharedKeyUpdated
    PATH = ""
    privKeyPath = pathlib.Path(f'{PATH}{name}-priv.key')
    if '[k:generateclientkeys' in msg:
        privKey = e2ee.genPrivKey()
        fernetKey = e2ee.passToFernetKey(plainpassword, salt)
        e2ee.storeKeyToFile(privKey, fernetKey, privKeyPath)
        pubKey = e2ee.getPubKey(privKey)
        send(client, e2ee.pointToJSON(pubKey))
    if '[k:comparekey' in msg:
        if DEBUG: print("Comparing key")
        pubKeyJSON = re.sub(r'\[k:comparekey:|]', '', msg)
        compareKeys(privKeyPath, pubKeyJSON)
    if '[k:getkey:return:' in msg:
        if DEBUG: print('Receiving Key')
        targetPubKey = re.sub(r'\[k:getkey:return:|]', '', msg)
        targetPubKey = e2ee.JSONtoPoint(targetPubKey)
        if DEBUG: print("Public Key Received\n", targetPubKey)
        fernetKey = e2ee.passToFernetKey(plainpassword, salt)
        selfPrivKey = e2ee.getKeyFromFile(fernetKey, privKeyPath)
        if DEBUG: print("Private Key Received\n", selfPrivKey)
        sharedKey = targetPubKey * selfPrivKey
        sharedKey = e2ee.deriveKey(sharedKey)
        if DEBUG: print("Shared Key Derived\n", sharedKey)
        sharedKeyUpdated.set()

def compareKeys(privKeyPath, pubKeyJSON):
    keyFromDB = e2ee.JSONtoPoint(pubKeyJSON)
        # print('DBKey', keyFromDB)
        # print('Salt', salt)
    fernetKey = e2ee.passToFernetKey(plainpassword, salt)
    if privKeyPath.exists():
        privKey = e2ee.getKeyFromFile(fernetKey, privKeyPath)
    else:
        privKey = e2ee.genPrivKey()
        e2ee.storeKeyToFile(privKey, fernetKey, privKeyPath)
        # print('PrivKey', privKey)
    pubKey = e2ee.getPubKey(privKey)
        # print('PubKey', pubKey)
    if keyFromDB != pubKey:
        send(s, '[k:comparekey:FALSE]')
        send(s, e2ee.pointToJSON(pubKey))
    else:
        send(s, '[k:comparekey:TRUE]')

def authReceive(client):
    global connected, name, s
    while True:
        try:
            length = client.recv(4)
            if length:
                length = int(length.decode())
                msg = client.recv(length)
                msg = msg.decode()
                # This is the actual output message
                # print(msg)
                if DEBUG: print(f"Recieved Message {msg} from Server while Authenticating")
                if '[s:' in msg:
                    handleSalt(client, msg)
                if '[AUTH' in msg:
                    return handleAuthflag(msg)
                if '[k:' in msg:
                    handleKeys(client, msg)
        except ConnectionResetError or ValueError:
            print(f'Something went wrong\n Error while receiving message')
            break

def getChatTo(chatbox, msg):
    contents = re.sub(r'\[getchatwith:return:|]', '', msg)
    # Decrypt Contents
    '''
    - Split contents by string | -> yields Array
    - For each item in array, decrypt index 1 and store [index[0], decryptedIndex[1]] in new array
    - Concat new array with \n and store as contents
    '''
    encArr = contents.split("|")
    decArr = []
    print("Encrypted Messages", encArr)
    for i in encArr:
        split = i.split(" ")
        split[1] = e2ee.decrypt(e2ee.b64toBytes(split[1]), sharedKey)
        joined = " ".join(split)
        decArr.append(joined)
    print("Formatted Messages", decArr)
    contents = "\n".join(decArr)
    chatbox.config(state= tk.NORMAL)
    chatbox.delete('1.0', tk.END)
    chatbox.insert(tk.END, f'\nConnected. Welcome {name}\n\n{contents}')
    chatbox.config(state= tk.DISABLED)

def handleNewMsg(chatbox, userbox, msg):
    global sharedKey
    sender = re.search(r'<(.*?)>', msg)
    if sender:
        sender = sender.group(1)
        target = userbox.get(userbox.curselection())
        if (sender == target or sender == name): 
            msg = re.sub(r'<[^>]+> ', '', msg)
            msg = e2ee.b64toBytes(msg)
            decMsg = e2ee.decrypt(msg, sharedKey)
            decMsg = f'<{sender}> ' + decMsg
            chatprint(decMsg, chatbox)
    else:
        chatprint(msg, chatbox)

# Message Handler
def handleMsg(msg, userbox, inputfield):
    global sharedKey, sharedKeyUpdated
    inputfield.delete(0, tk.END)
    if len(msg) > 0:
        target = userbox.get(userbox.curselection())
        if target == "Global":
            send(s,msg)
        # Prepend [for:] tag to message
        else:
            encMsg = e2ee.encrypt(msg, sharedKey)
            encMsg = e2ee.bytesToB64(encMsg)
            send(s,f'[for:{target}] ' + encMsg)

# Update chat history everytime selected target user is changed
def getChatHistory(event):
    selection = event.widget.curselection()
    if selection:
        index = selection[0]
        data = event.widget.get(index)
        send(s,f'[k:getkey:{data}]')
        send(s, f"[getchatwith:{data}]")

def setupUserlist(userbox, msg):
    # Load users into sidebar when given
    users = json.loads(msg)
    userbox.delete(0, tk.END)
    userbox.insert(tk.END, "Global")
    userbox.selection_set(0)
    for user in users:
        userbox.insert(tk.END, user)
    # chatprint("Users " + str(users), chatbox)

def receive(client, chatbox, userbox):
    while True:
        try:
            length = client.recv(4)
            if length:
                length = int(length.decode())
                msg = client.recv(length)
                msg = msg.decode()
                # This is the actual output message
                if DEBUG: print(f"Recieved Message {msg} from Server")
                try:
                    setupUserlist(userbox, msg)
                except:
                    # Handle case of getting chat history
                    if '[k:' in msg:
                        if DEBUG: print("Received Key Instruction")
                        handleKeys(client, msg)
                    elif '[getchatwith:return:' in msg:
                        getChatTo(chatbox, msg)
                    else:
                        handleNewMsg(chatbox, userbox, msg)
        except ConnectionResetError or ValueError:
            print(f'Something went wrong\n Error while receiving message')
            break

# Authenticate function to be triggered when login button pressed
def authenticate(loginwindow, userfield, passfield):
    global name, plainpassword, authfail, s

    if authfail: 
        s.connect((HOST, PORT))
        authfail = None

    name = user.get()
    plainpassword = password.get()
    send(s, name)

    authThread = threading.Thread(target=authReceive, args=(s,))
    authThread.start()
    authThread.join()

    if authfail:
        print("Not Authenticated")
        return
    
    loginWindow.destroy()

    main()

# Login screen (choose name and connect)
login = loginUI(authenticate)
loginWindow = login['window']
user = login['userField']
password = login['passwordField']


def main():

    ## Main chatbox interface
    main = mainUI(handleMsg, getChatHistory)
    mainWindow = main['window']
        
    chatbox = main['chatbox']

    # Userlist (userbox) and send button
    userbox = main['userbox']

    # Start thread and loop interface
    threading.Thread(target=receive, args=(s,chatbox,userbox)).start()
    mainWindow.mainloop()


# Confirm button
connect = login['connectButton']
s.connect((HOST, PORT))
loginWindow.mainloop()