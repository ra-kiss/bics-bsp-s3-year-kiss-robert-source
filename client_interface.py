import tkinter as tk
from tkinter import scrolledtext

'''
Login interface requiring authenticate function
'''
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

'''
Main chat interface requiring functions for handling sending messages and for retrieving and 
decrypting chatlog
'''
def mainUI(handleSendingText, requestChatHistory, handleSendingFile, requestFileDownload):
    ## Main chatbox interface
    main = tk.Tk()
    main.geometry('710x500')
    main.resizable(False, False)

    # Text input for messages
    typehere = tk.Entry(main, width=50)
    typehere.place(x=158,y=470)

    # Chatbox defined as global s.t. it is able to be updated from other function
    chatbox = tk.scrolledtext.ScrolledText(main, wrap=tk.WORD, width=47, height=28)
    chatbox.config(state= tk.DISABLED)
    chatbox.place(x=158,y=10)

    # Userlist (userbox) and send button
    userbox = tk.Listbox(main, selectmode=tk.SINGLE, width=23, height=30)
    userbox.place(x=8,y=9)
    userbox.bind("<<ListboxSelect>>", lambda event, userbox=userbox: requestChatHistory(userbox, event))

    sendbtn = tk.Button(text="Send", width=9, command=lambda:handleSendingText(typehere.get(), userbox, typehere))
    sendbtn.place(x=470,y=467)

    # Filebox
    filebox = tk.Listbox(main, selectmode=tk.SINGLE, width=24   , height=26)
    filebox.place(x=550,y=10)
    filebox.insert(tk.END, "Files")
    filebox.insert(tk.END, "───────────────")

    # Upload/Download Button
    ulbtn = tk.Button(text="Upload File", width=20, command=lambda:handleSendingFile(userbox))
    ulbtn.place(x=550,y=467)

    dlbtn = tk.Button(text="Download File", width=20, command=lambda:requestFileDownload(filebox))
    dlbtn.place(x=550,y=437)

    return {'window': main,
            'inputField': typehere,
            'chatbox': chatbox,
            'userbox': userbox,
            'filebox': filebox,
            'uploadButton': ulbtn,
            'downloadButton': dlbtn,
            'sendButton': sendbtn}

