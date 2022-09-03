import socket

def connect():
    s = socket.socket()
    s.connect(('127.0.0.1', 9000))
    return s

