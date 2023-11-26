import tkinter as tk
from tkinter import scrolledtext

def loginUI(authenticate):
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
    connect = tk.Button(text="Login/Register", width=13, command=lambda:authenticate(login, user, password))
    connect.place(x=50,y=80)
    return {'window': login, 
            'userField': user, 
            'passwordField': password,
            'connectButton': connect}

def mainUI(handleMsg, getChatHistory):
    ## Main chatbox interface
    main = tk.Tk()
    main.geometry('550x500')
    main.resizable(False, False)

    # Text input for messages
    typehere = tk.Entry(main, width=50)
    typehere.place(x=158,y=470)

    # Chatbox defined as global s.t. it is able to be updated from other function
    chatbox = tk.scrolledtext.ScrolledText(main, wrap=tk.WORD, width=45, height=28)
    chatbox.config(state= tk.DISABLED)
    chatbox.place(x=158,y=10)

    # Userlist (userbox) and send button
    userbox = tk.Listbox(main, selectmode=tk.SINGLE, width=23, height=30)
    userbox.place(x=8,y=9)
    userbox.bind("<<ListboxSelect>>", getChatHistory)
    sendbtn = tk.Button(text="Send", width=9, command=lambda:handleMsg(typehere.get(), userbox, typehere))
    sendbtn.place(x=470,y=467)
    return {'window': main,
            'inputField': typehere,
            'chatbox': chatbox,
            'userbox': userbox,
            'sendButton': sendbtn}

