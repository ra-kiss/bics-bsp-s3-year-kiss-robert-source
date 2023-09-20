import socket, threading
import tkinter as tk
# Create a socket
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
HOST = 'localhost'
PORT = 1234
connected = False

def send(client, msg):
    try:
        # Send msg length first, then msg
        length = str(len(msg.encode('utf-8')))
        length += ' '*(1024-int(length))
        client.send(bytes(length, 'utf-8'))
        client.send(bytes(msg, 'utf-8'))
    except ConnectionResetError:
        print(f'Something went wrong\n Unable to send message to server')
        return True

def receive(client):
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
                if (msg[:9] == "Connected"):
                    connected = True
        except ConnectionResetError or ValueError:
            print(f'Something went wrong\n Error while connecting to server')
            break

# Login screen (choose name and connect)
login = tk.Tk()
login.geometry("200x100")
# Username entry field
user = tk.Entry(login, width=30)
user.insert(0, "Username")
user.place(x=8,y=15)

# Message Handler
def handleMsg(msg):
    if len(msg) > 0:
        send(s,msg)

# Connect function
def init():
    # Connect to server
    s.connect((HOST, PORT))
    name = user.get()
    send(s, name)
    login.destroy()
    threading.Thread(target=receive, args=(s,)).start()

    # Main chatbox interface
    main = tk.Tk()
    main.geometry("200x500")
    typehere = tk.Entry(main, width=30)
    typehere.place(x=8,y=15)
    sendbtn = tk.Button(text="Send", width=10, command=lambda:handleMsg(typehere.get()))
    sendbtn.place(x=60,y=50)
    main.mainloop()


# Confirm button
connect = tk.Button(text="Connect", width=10, command=lambda:init())
connect.place(x=60,y=50)
login.mainloop()

# while True:
#     if connected:
#         msg = input(f'\nType your message > ')
#         send(s, msg)