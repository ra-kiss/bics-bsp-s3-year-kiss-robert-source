import socket, threading, json
import tkinter as tk
from tkinter import scrolledtext
import re
import hashlib
# Create a socket
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
HOST = 'localhost'
PORT = 1234
name = None
plainpassword = None
auth = None
sopen = False

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
    global sopen, auth
    if '[AUTHFAIL]' in msg: 
        s.close()
        sopen = False
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    elif '[AUTHSUCCESS]' in msg:
        print('Authentication Success')
        auth = True
    return

def authReceive(client):
    global connected, name, auth, sopen, s
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
    global connected
    global name
    global auth
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

# Login screen (choose name and connect)
login = tk.Tk()
login.geometry("200x120")
login.resizable(False, False)
# Username entry field
user = tk.Entry(login, width=30)
user.insert(0, "Username")
user.place(x=8,y=15)
# Password entry field
password = tk.Entry(login, width=30)
password.place(x=8,y=45)

# Connect function
def init():
    global name
    global plainpassword
    global auth
    global sopen

    # Connect to server
    if not sopen:
        s.connect((HOST, PORT))
        print('Socket Connected')
    name = user.get()
    plainpassword = password.get()
    send(s, name)

    if not sopen:
        authThread = threading.Thread(target=authReceive, args=(s,))
        authThread.start()
        sopen = True

    authThread.join()

    if not auth:
        print("Not Authenticated")
        return
    
    login.destroy()
    auth = True

    ## Main chatbox interface
    main = tk.Tk()
    main.geometry('550x500')
    main.resizable(False, False)

    # Text input for messages
    typehere = tk.Entry(main, width=50)
    typehere.place(x=158,y=470)

    # Message Handler
    def handleMsg(msg, userbox):
        typehere.delete(0, tk.END)
        if len(msg) > 0:
            # Prepend [for:] tag to message
            target = userbox.get(userbox.curselection())
            if target == "Global":
                send(s,msg)
            else:
                send(s,f'[for:{target}] ' + msg)
        
    # Chatbox defined as global s.t. it is able to be updated from other function
    chatbox = scrolledtext.ScrolledText(main, wrap=tk.WORD, width=45, height=28)
    chatbox.config(state= tk.DISABLED)
    chatbox.place(x=158,y=10)

    # Update chat history everytime selected target user is changed
    def getChatHistory(event):
        selection = event.widget.curselection()
        index = selection[0] if selection else None
        data = event.widget.get(index) if selection else None
        send(s, f"[getchatwith:{data}]")

    # Userlist (userbox) and send button
    userbox = tk.Listbox(main, selectmode=tk.SINGLE, width=23, height=30)
    userbox.place(x=8,y=9)
    userbox.bind("<<ListboxSelect>>", getChatHistory)
    sendbtn = tk.Button(text="Send", width=9, command=lambda:handleMsg(typehere.get(), userbox))
    sendbtn.place(x=470,y=467)



    # Start thread and loop interface
    threading.Thread(target=receive, args=(s,chatbox,userbox)).start()
    main.mainloop()


# Confirm button
connect = tk.Button(text="Login/Register", width=13, command=lambda:init())
connect.place(x=50,y=80)
login.mainloop()