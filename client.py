import socket, threading, json
import tkinter as tk
import re
import hashlib
import pathlib
from client_interface import loginUI, mainUI
import client_encryption as e2ee
import sys
# Debug flag, prints all interactions with server to console if enabled
DEBUG = True
# Socket setup
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
HOST = 'localhost'
PORT = 1234
# Variable containing current client's data
name = None
plainpassword = None
salt = None
PATH = ""
privKeyPath = None
# Authentication fail flag, if True will cause authenticate() function to restart
authfail = False
# sharedKey between this client and currently selected client from list
sharedKey = None
# Threading event that decides whether the current sharedKey is up to date
sharedKeyUpdated = threading.Event()

'''
Function to send things to server
'''
def send(client, msg):
    try:
        # Send msg length first, then msg
        length = str(len(msg.encode('utf-8')))
        length = ' '*(4-len(length)) + length
        client.send(bytes(length, 'utf-8'))
        client.send(bytes(msg, 'utf-8'))
        if DEBUG: print("Sent message", msg, "to server")
    except ConnectionResetError:
        print(f'Something went wrong\n Unable to send message to server')
        return True

'''
Helper function to print things to chatbox
'''
def chatprint(msg, chatbox):
    chatbox.config(state= tk.NORMAL)
    chatbox.insert(tk.END, f'{msg}')
    chatbox.config(state= tk.DISABLED)

'''
Helper function to hash a given password with a given salt
'''
def hash(password, salt):
    salted = password + salt
    salted = salted.encode('utf-8')
    hashed = hashlib.sha256(salted).hexdigest()
    return hashed

'''
Function to handle salt included in [s:] flag
- Retrieve salt from flag
- Hash plainpassword with salt
- Send salted hash with server s.t. server does not see plainpassword
'''
def hashWithSalt(client, saltflag):
    global salt
    salt = re.sub(r'\[s:|\]', '', saltflag)
    hashed = hash(plainpassword, salt)
    if DEBUG: print('Salted Hash Sent')
    send(client, hashed)

'''
Function to handle authentication flag 
- If failure, restart socket and set authfail = True, causing authenticate() function to return
- If success, do nothing (print success)
'''
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

'''
Function which generates shared key between a given target's public key and client's private key
- Sets sharedKeyUpdated flag upon succesful completion
'''
def generateSharedKey(targetPubKey):
    global sharedKey
    targetPubKey = e2ee.JSONtoPoint(targetPubKey)
    if DEBUG: print("Public Key Received\n", targetPubKey)
    fernetKey = e2ee.passToFernetKey(plainpassword, salt)
    selfPrivKey = e2ee.getKeyFromFile(fernetKey, privKeyPath)
    if DEBUG: print("Private Key Received\n", selfPrivKey)
    sharedKey = targetPubKey * selfPrivKey
    if DEBUG: print("Shared Key Calculated\n", sharedKey)
    sharedKey = e2ee.deriveKey(sharedKey)
    if DEBUG: print("Shared Key Derived\n", sharedKey)
    sharedKeyUpdated.set()

'''
Function which generates client key pair and stores it to file
'''
def generateClientKeys(client):
    privKey = e2ee.genPrivKey()
    fernetKey = e2ee.passToFernetKey(plainpassword, salt)
    e2ee.storeKeyToFile(privKey, fernetKey, privKeyPath)
    pubKey = e2ee.getPubKey(privKey)
    send(client, e2ee.pointToJSON(pubKey))

'''
Function that validates whether user's private key and public key are a pair
- Converts public key JSON to a Point object for calculations
- If user has private key, retrieve it from file
- If user does not have private key, generate one
- Generate public key from private key
- If they match as a pair, send [k:comparekey:TRUE] to server
- If they do not match as pair, send [k:comparekey:FALSE] alongside the new public key JSON to server
'''
def validateKeys(privKeyPath, pubKeyJSON):
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

'''
Special receive function for the purpose of having its own thread,
runs only while authenticating. Handles salts, as well as AUTH flags and keys
'''
def authReceive(client):
    global connected, name, s, privKeyPath
    while True:
        try:
            length = client.recv(4)
            if length:
                length = int(length.decode())
                msg = client.recv(length)
                msg = msg.decode()
                # This is the actual output message
                # print(msg)
                if DEBUG: print(f"Received Message {msg} from Server while Authenticating")
                if '[s:' in msg:
                    hashWithSalt(client, msg)
                if '[AUTH' in msg:
                    return handleAuthflag(msg)
                if '[k:' in msg:
                    privKeyPath = pathlib.Path(f'{PATH}{name}-priv.key')
                    if '[k:generateclientkeys' in msg:
                        generateClientKeys(client)
                    elif '[k:comparekey' in msg:
                        if DEBUG: print("Comparing key")
                        pubKeyJSON = re.sub(r'\[k:comparekey:|]', '', msg)
                        validateKeys(privKeyPath, pubKeyJSON)
                    elif '[k:getkey:return:' in msg:
                        if DEBUG: print('Receiving Key')
                        targetPubKey = re.sub(r'\[k:getkey:return:|]', '', msg)
                        generateSharedKey(targetPubKey)
        except ConnectionResetError or ValueError:
            print(f'Something went wrong\n Error while receiving message')
            break

'''
Function used to decrypt given chat history between users
'''
def decryptChatlog(chatbox, chatlog):
    contents = re.sub(r'\[getchatwith:return:|]', '', chatlog)
    # Decrypt Contents
    encArr = contents.split("|")
    decArr = []
    if DEBUG: print("Encrypted Messages", encArr)
    for i in encArr:
        split = i.split(" ")
        if len(split) >= 2:
            split[1] = e2ee.decrypt(e2ee.b64toBytes(split[1]), sharedKey)
        joined = " ".join(split) if split else " "
        decArr.append(joined)
    if DEBUG: print("Formatted Messages", decArr)
    contents = "\n".join(decArr)
    chatbox.config(state= tk.NORMAL)
    chatbox.delete('1.0', tk.END)
    chatbox.insert(tk.END, f'\nConnected. Welcome {name}\n\n{contents}')
    chatbox.config(state= tk.DISABLED)

'''
Function that handles decrypting and receiving (chatprinting) a message
'''
def handleReceivingMsg(chatbox, userbox, msg):
    global sharedKey
    sender = re.search(r'<(.*?)>', msg)
    if sender:
        sender = sender.group(1)
        curidx = userbox.curselection()
        target =  userbox.get(curidx) if curidx else None
        if DEBUG: print(f'All variables loaded: sender {sender}, target {target} at {curidx}\nMessage: {msg}')
        if (sender == target or sender == name): 
            msg = re.sub(r'<[^>]+> ', '', msg)
            msg = e2ee.b64toBytes(msg)
            decMsg = e2ee.decrypt(msg, sharedKey)
            decMsg = f'\n<{sender}> ' + decMsg
            if DEBUG: print(f'Message Decrypted:', decMsg)
            chatprint(decMsg, chatbox)
    else:
        chatprint(msg, chatbox)

'''
Function that handles encrypting and sending a message
'''
def handleSendingMsg(msg, userbox, inputfield):
    global sharedKey, sharedKeyUpdated
    inputfield.delete(0, tk.END)
    if len(msg) > 0:
        curidx = userbox.curselection()
        target = userbox.get(curidx) if curidx else None
        # if target == "Global":
        #     send(s,msg)
        # # Prepend [for:] tag to message
        # else:
        if target:
            encMsg = e2ee.encrypt(msg, sharedKey)
            encMsg = e2ee.bytesToB64(encMsg)
            send(s,f'[for:{target}] ' + encMsg)

'''
Function that requests chat history from server
'''
def requestChatHistory(event):
    selection = event.widget.curselection()
    if selection:
        index = selection[0]
        data = event.widget.get(index)
        send(s,f'[k:getkey:{data}]')
        send(s, f"[getchatwith:{data}]")

'''
Function that updates the userbox based on message received from server
'''
def updateUserbox(userbox, userlist):
    # Load users into sidebar when given
    users = json.loads(userlist)
    userbox.delete(0, tk.END)
    # userbox.insert(tk.END, "Global")
    userbox.selection_set(0)
    for user in users:
        userbox.insert(tk.END, user)
    # chatprint("Users " + str(users), chatbox)

'''
Main receive function, infinite loop to get messages from server
'''
def receive(client, chatbox, userbox):
    global privKeyPath
    while True:
        try:
            length = client.recv(4)
            if length:
                length = int(length.decode())
                msg = client.recv(length)
                msg = msg.decode()
                # This is the actual output message
                if DEBUG: print(f"Received Message {msg} from Server")
                if '[k:' in msg:
                    if DEBUG: print("Received Key Instruction")
                    privKeyPath = pathlib.Path(f'{PATH}{name}-priv.key')
                    if '[k:generateclientkeys' in msg:
                        generateClientKeys(client)
                    elif '[k:comparekey' in msg:
                        if DEBUG: print("Comparing key")
                        pubKeyJSON = re.sub(r'\[k:comparekey:|]', '', msg)
                        validateKeys(privKeyPath, pubKeyJSON)
                    elif '[k:getkey:return:' in msg:
                        if DEBUG: print('Receiving Key')
                        targetPubKey = re.sub(r'\[k:getkey:return:|]', '', msg)
                        generateSharedKey(targetPubKey)
                elif '[getchatwith:return:' in msg:
                    decryptChatlog(chatbox, msg)
                elif '[userlist:' in msg:
                    newUserlist = re.sub(r'\[userlist:|:]', '', msg)
                    if DEBUG: print('Userlist Received', newUserlist)
                    updateUserbox(userbox, newUserlist)
                elif '[for:' in msg or re.search(r'<(.*?)>', msg):
                    if DEBUG: print('Handling Receiving Message')
                    handleReceivingMsg(chatbox, userbox, msg)
                else:
                    chatprint(msg, chatbox)
        except ConnectionResetError or ValueError:
            print(f'Something went wrong\n Error while receiving message')
            break

'''
Authenticating function, proceeds to main only if salted hash matches DBs salted hash
- Restarts socket connection in case of authentication failure
- Send username to server, starting authentication process and start authReceive thread
- Wait for authReceive thread to complete, which happens after handleAuthFlag() is triggered
'''
def authenticate(loginwindow, userfield, passfield):
    global name, plainpassword, authfail, s

    if authfail: 
        s.connect((HOST, PORT))
        authfail = None

    name = user.get()
    plainpassword = password.get()
    send(s, name)

    authThread = threading.Thread(target=authReceive, args=(s,), daemon=True)
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

'''
Function that initializes main interface and starts receive thread
'''
def main():

    ## Main chatbox interface
    main = mainUI(handleSendingMsg, requestChatHistory)
    mainWindow = main['window']
        
    chatbox = main['chatbox']

    # Userlist (userbox) and send button
    userbox = main['userbox']

    # Start thread and loop interface
    threading.Thread(target=receive, args=(s,chatbox,userbox), daemon=True).start()
    mainWindow.mainloop()
    sys.exit()


# Start socket connection and initialize login screen
connect = login['connectButton']
s.connect((HOST, PORT))
loginWindow.mainloop()