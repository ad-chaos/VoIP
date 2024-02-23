from __future__ import annotations

from socket import socket, AF_INET, SOCK_STREAM
from packet_parser import Packet, PacketType, VOIP_PORT, NAddr


class Client:
    def __init__(self, username: str, password: str, addr: NAddr) -> None:
        self.socket = socket(AF_INET, SOCK_STREAM)
        self.socket.connect(addr)
        self.username: str = username
        self.password: str = password

    def chat(self) -> None:
        pkt = self.read_packet()

        if pkt.ty == PacketType.InvalidUser:
            print(pkt.msg.extra)
            return
        try:
            while True:
                print(self.read_packet().msg.extra)
        except KeyboardInterrupt:
            self.send_packet(Packet.quit())
            while self.read_packet().ty != PacketType.ShutDown:
                pass
            print("\nSuccessfully Exited call!")

    def send_packet(self, pkt: Packet) -> None:
        self.socket.sendall(pkt.to_bytes())

    def read_packet(self) -> Packet:
        size = int.from_bytes(self.socket.recv(4), "big")
        bts = b""
        while size > 0:
            rbts = self.socket.recv(size)
            size -= len(rbts)
            bts += rbts

        return Packet.parse(bts)

    def login(self) -> None:
        self.send_packet(Packet.login(self.username, self.password))

    def signin(self) -> None:
        self.send_packet(Packet.signin(self.username, self.password))

    def __enter__(self) -> Client:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.socket.close()


# ip = input("Server IP: ").strip()
username = input("Username: ").strip()
password = input("Password: ").strip()
auth_ty = input("[L]ogin/[S]ignup? ")

with Client(username, password, ("localhost", VOIP_PORT)) as c:
    match auth_ty.lower():
        case 'l':
            c.login()
        case 's':
            c.signin()

    c.chat()
