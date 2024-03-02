from __future__ import annotations

from socket import socket, AF_INET, SOCK_STREAM
from packet_parser import Packet, PacketType, VOIP_PORT, NAddr
from selectors import DefaultSelector, EVENT_READ, EVENT_WRITE
import sys
from itertools import count
from time import sleep
from typing import Iterator


class Client:
    def __init__(
        self, username: str, password: str, reciever: str, auth_ty: str, addr: NAddr
    ) -> None:
        self.socket = socket(AF_INET, SOCK_STREAM)
        self.socket.connect(addr)
        self.username = username
        self.password = password
        self.reciever = reciever
        self.auth_ty = auth_ty
        self.conversing = True
        self.selector = DefaultSelector()
        self.selector.register(self, EVENT_WRITE | EVENT_READ)

    def fileno(self) -> int:
        return self.socket.fileno()

    def chat(self) -> None:
        match auth_ty.lower():
            case "l":
                c.login()
            case "s":
                c.signin()

        pkt = self.read_packet()
        print(pkt.msg.extra)

        if pkt.ty == PacketType.InvalidUser:
            return

        self.wait_for_reciever()

        print(f"\nPairing successful! with {self.reciever}")

        to_send: Iterator[Packet] = map(
            Packet.message,
            [
                "First Message",
                "Second Message",
                "Third Message",
                "Fourth Message",
                "Fifth Message",
            ],
        )

        try:
            self.conversing = True
            while self.conversing:
                sleep(0.2)
                for ready, event in self.selector.select():
                    if event & EVENT_READ:
                        pkt = self.read_packet()
                        if pkt.ty == PacketType.Quit:
                            self.conversing = False
                            self.quit()
                            break
                        print(pkt.msg.extra)

                    if event & EVENT_WRITE:
                        self.send_packet(next(to_send))
        except StopIteration:
            self.quit()

    def wait_for_reciever(self):
        self.socket.setblocking(False)
        for i in count():
            sleep(0.5)
            try:
                # We wait for a packet that let's us know we've been paired
                pkt = self.read_packet()
                if pkt.ty != PacketType.Paired:
                    print("Expected a Paired Packet")
                    return
                else:
                    break
            except BlockingIOError:
                print("\r\033[KWaiting to Pair" + "." * (i % 4 + 1), end="")  # ]
        self.socket.setblocking(True)

    def quit(self):
        print("Quitting!")
        self.send_packet(Packet.quit())
        while self.conversing and self.read_packet().ty != PacketType.Quit:
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
# username = input("Username: ").strip()
# password = input("Password: ").strip()
# reciever = input("Reciever: ").strip()
# auth_ty = input("[L]ogin/[S]ignup? ")

if sys.argv[1] == "a":
    print("I'm ad")
    username = "ad"
    password = "a"
    reciever = "sad"
    auth_ty = "L"
else:
    print("I'm sad")
    username = "sad"
    password = "s"
    reciever = "ad"
    auth_ty = "L"

with Client(username, password, reciever, auth_ty, ("localhost", VOIP_PORT)) as c:
    c.chat()
