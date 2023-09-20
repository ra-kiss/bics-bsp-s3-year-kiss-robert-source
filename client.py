import socket, threading
import tkinter as tk
from tkinter import scrolledtext
# Create a socket
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
HOST = 'localhost'
PORT = 1234
connected = False

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

def receive(client, chatbox):
    global connected
    while True:
        try:
            length = client.recv(1024)
            if length:
                length = int(length.decode())
                msg = client.recv(length)
                msg = msg.decode()
                # This is the actual output message
                print(msg)
                chatbox.config(state= tk.NORMAL)
                chatbox.insert(tk.INSERT, f'{msg}\n')
                chatbox.config(state= tk.DISABLED)
                if (msg[:9] == "Connected"):
                    connected = True
        except ConnectionResetError or ValueError:
            print(f'Something went wrong\n Error while receiving message')
            break

# Login screen (choose name and connect)
login = tk.Tk()
login.geometry("200x100")
login.resizable(False, False)
# Username entry field
user = tk.Entry(login, width=30)
user.insert(0, "Username")
user.place(x=8,y=15)

# Connect function
def init():
    # Connect to server
    s.connect((HOST, PORT))
    name = user.get()
    send(s, name)
    login.destroy()

    # Main chatbox interface
    main = tk.Tk()
    main.geometry("400x500")
    main.resizable(False, False)
    typehere = tk.Entry(main, width=50)
    typehere.place(x=8,y=470)

    # Message Handler
    def handleMsg(msg):
        typehere.delete(0, tk.END)
        if len(msg) > 0:
            send(s,msg)

    sendbtn = tk.Button(text="Send", width=9, command=lambda:handleMsg(typehere.get()))
    sendbtn.place(x=320,y=467)
    # Chatbox defined as global s.t. it is able to be updated from other function
    chatbox = scrolledtext.ScrolledText(main, wrap=tk.WORD, width=45, height=27)
    chatbox.config(state= tk.DISABLED)
    chatbox.place(x=8,y=10)
    threading.Thread(target=receive, args=(s,chatbox)).start()
    main.mainloop()


# Confirm button
connect = tk.Button(text="Connect", width=10, command=lambda:init())
connect.place(x=60,y=50)
login.mainloop()

# while True:
#     if connected:
#         msg = input(f'\nType your message > ')
#         send(s, msg)