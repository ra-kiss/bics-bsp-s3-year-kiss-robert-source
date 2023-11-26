import socket, threading, json
import tkinter as tk
from tkinter import scrolledtext
import re
import hashlib
from client_interface import loginUI, mainUI
# Create a socket
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
HOST = 'localhost'
PORT = 1234
name = None
plainpassword = None
authfail = False

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
    contents = re.sub(r'\[s:|\]', '', msg)
    hashed = hash(plainpassword, contents)
    print('Salted Hash Sent')
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
                if '[s:' in msg:
                    handleSalt(client, msg)
                if '[AUTH' in msg:
                    return handleAuthflag(msg)
        except ConnectionResetError or ValueError:
            print(f'Something went wrong\n Error while receiving message')
            break

def getChatTo(chatbox, msg):
    contents = msg.replace('[getchatwith:return]','')
    # print(contents)
    chatbox.config(state= tk.NORMAL)
    chatbox.delete('1.0', tk.END)
    chatbox.insert(tk.END, f'\nConnected. Welcome {name}\n\n{contents}')
    chatbox.config(state= tk.DISABLED)

def handleNewMsg(chatbox, userbox, msg):
    sender = re.search(r'<(.*?)>', msg)
    if sender:
        sendcond = (sender.group(1) == userbox.get(userbox.curselection()) 
                                        or sender.group(1) == name)
        if sendcond: chatprint(msg, chatbox)
    else:
        chatprint(msg, chatbox)

# Message Handler
def handleMsg(msg, userbox, inputfield):
    inputfield.delete(0, tk.END)
    if len(msg) > 0:
        # Prepend [for:] tag to message
        target = userbox.get(userbox.curselection())
        if target == "Global":
            send(s,msg)
        else:
            send(s,f'[for:{target}] ' + msg)

# Update chat history everytime selected target user is changed
def getChatHistory(event):
    selection = event.widget.curselection()
    index = selection[0] if selection else None
    data = event.widget.get(index) if selection else None
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
    global connected, name
    while True:
        try:
            length = client.recv(4)
            if length:
                length = int(length.decode())
                msg = client.recv(length)
                msg = msg.decode()
                # This is the actual output message
                # print(msg)
                try:
                    setupUserlist(userbox, msg)
                except:
                    # Handle case of getting chat history
                    if '[getchatwith:return]' in msg:
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

    # Text input for messages
    typehere = main['inputField']
        
    # Chatbox defined as global s.t. it is able to be updated from other function
    chatbox = main['chatbox']

    # Userlist (userbox) and send button
    userbox = main['userbox']
    '''Move to client_interface.py'''
    # sendbtn = main['sendButton']
    # '''Move to client_interface.py'''
    # sendbtn.config(command=lambda:handleMsg(typehere.get(), userbox))

    # Start thread and loop interface
    threading.Thread(target=receive, args=(s,chatbox,userbox)).start()
    mainWindow.mainloop()


# Confirm button
connect = login['connectButton']
# '''Move to client_interface.py'''
# connect.config(command=lambda:authenticate())
s.connect((HOST, PORT))
loginWindow.mainloop()