from socket import socket, AF_INET, SOCK_STREAM
from enum import IntEnum

BUF_SIZE = 4096

class PacketType(IntEnum):
    InvalidUser = 1
    ValidUser   = 2

with socket(AF_INET, SOCK_STREAM) as s:
    s.connect(("localhost", 8096))
    cmessage = input("Username: ").strip().encode()
    s.sendall(cmessage)
    cmessage = input("Password: ").strip().encode()
    s.sendall(cmessage)

    response = s.recv(BUF_SIZE).decode()
    print(response[1:])

    if response[0] == "1":
        while True:
            cmessage = input("Message: ").strip().encode()
            s.sendall(cmessage)
            print(s.recv(BUF_SIZE).decode())
            if cmessage == b"q":
                break
