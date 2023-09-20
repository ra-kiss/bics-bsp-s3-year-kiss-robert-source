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
                print(f'\n{msg}')
                if (msg[:9] == "Connected"):
                    connected = True
        except ConnectionResetError or ValueError:
            print(f'Something went wrong\n Error while connecting to server')
            break

# Login screen (choose name and connect)
login = tk.Tk()
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

# Confirm button
connect = tk.Button(text="Connect", width=10, command=lambda:init())
connect.place(x=60,y=50)
login.geometry("200x100")
login.mainloop()

threading.Thread(target=receive, args=(s,)).start()

while True:
    if connected:
        msg = input(f'\nType your message > ')
        send(s, msg)