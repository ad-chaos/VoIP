from __future__ import annotations

from socket import socket, AF_INET, SOCK_STREAM
from packet_parser import Packet, PacketType, VOIP_PORT, NAddr, MsgData
from selectors import DefaultSelector, EVENT_READ, EVENT_WRITE


class Client:
    def __init__(
        self, username: str, password: str, reciever: str, addr: NAddr
    ) -> None:
        self.socket = socket(AF_INET, SOCK_STREAM)
        self.socket.connect(addr)
        self.username = username
        self.password = password
        self.reciever = reciever
        self.selector = DefaultSelector()
        self.selector.register(self, EVENT_WRITE | EVENT_READ)

    def fileno(self) -> int:
        return self.socket.fileno()

    def chat(self) -> None:
        pkt = self.read_packet()

        if pkt.ty == PacketType.InvalidUser:
            print(pkt.msg.extra)
            return
        alive = True
        while alive:
            for ready, events in self.selector.select():
                if events & EVENT_READ:
                    print(self.read_packet().msg.extra)
                elif events & EVENT_WRITE:
                    msg = input("Message: ")
                    if msg == "q":
                        self.quit()
                        alive = False
                        break
                    self.send_packet(Packet(PacketType.Msg, MsgData(extra=msg)))

    def quit(self):
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
        self.send_packet(Packet.login(self.username, self.password, self.reciever))

    def signin(self) -> None:
        self.send_packet(Packet.signin(self.username, self.password, self.reciever))

    def __enter__(self) -> Client:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.socket.close()
        self.selector.close()


# ip = input("Server IP: ").strip()
username = input("Username: ").strip()
password = input("Password: ").strip()
reciever = input("Reciever: ").strip()
auth_ty = input("[L]ogin/[S]ignup? ")

with Client(username, password, reciever, ("localhost", VOIP_PORT)) as c:
    match auth_ty.lower():
        case "l":
            c.login()
        case "s":
            c.signin()

    c.chat()
