from __future__ import annotations

from socket import socket, AF_INET, SOCK_STREAM
from packet_parser import Packet, PacketType, NAddr
from selectors import DefaultSelector, EVENT_READ, EVENT_WRITE
from itertools import count
from time import sleep
from typing import Iterator


class QuitException(KeyboardInterrupt, StopIteration):
    pass


class Client:
    def __init__(
        self, username: str, password: str, reciever: str, addr: NAddr
    ) -> None:
        self.socket = socket(AF_INET, SOCK_STREAM)
        self.socket.connect(addr)
        self.username = username
        self.password = password
        self.reciever = reciever
        self.conversing = True
        self.selector = DefaultSelector()
        self.selector.register(self, EVENT_WRITE | EVENT_READ)

    def fileno(self) -> int:
        return self.socket.fileno()

    def chat(self, consumer: Iterator[Packet]) -> None:
        try:
            self.conversing = True
            while self.conversing:
                for ready, event in self.selector.select():
                    if event & EVENT_READ:
                        pkt = self.read_packet()
                        if pkt is None or pkt.ty == PacketType.Quit:
                            self.conversing = False
                            self.quit()
                            break
                        self.handle_packet(pkt)

                    if event & EVENT_WRITE:
                        self.send_packet(next(consumer))
        except (KeyboardInterrupt, StopIteration):
            self.quit()

    def handle_packet(self, pkt: Packet | None) -> None:
        raise NotImplementedError

    def wait_for_reciever(self) -> None:
        self.socket.setblocking(False)
        for i in count():
            sleep(0.5)
            try:
                # We wait for a packet that let's us know we've been paired
                pkt = self.read_packet()
                if pkt is None or pkt.ty != PacketType.Paired:
                    print("Expected a Paired Packet")
                    return
                else:
                    break
            except BlockingIOError:
                print("\r\033[KWaiting to Pair" + "." * (i % 4 + 1), end="")  # ]
        self.socket.setblocking(True)

    def drain_recieve_buffer(self) -> None:
        self.socket.setblocking(False)
        try:
            while True:
                self.handle_packet(self.read_packet())
        except BlockingIOError:
            self.socket.setblocking(True)

    def quit(self) -> None:
        self.drain_recieve_buffer()
        print("Quitting!")
        self.send_packet(Packet.quit())
        while self.conversing:
            pkt = self.read_packet()
            if pkt is None or pkt.ty == PacketType.Quit:
                break
        print("\nSuccessfully Exited call!")

    def send_packet(self, pkt: Packet) -> None:
        self.socket.sendall(pkt.to_bytes())

    def read_packet(self) -> Packet | None:
        size = int.from_bytes(self.socket.recv(4), "big")
        if size == 0:
            return None
        bts = b""
        while size > 0:
            rbts = self.socket.recv(size)
            size -= len(rbts)
            bts += rbts

        return Packet.parse(bts)

    def login(self) -> Packet | None:
        self.send_packet(Packet.login(self.username, self.password, self.reciever))
        return self.read_packet()

    def signin(self) -> Packet | None:
        self.send_packet(Packet.signin(self.username, self.password, self.reciever))
        return self.read_packet()

    def __enter__(self) -> Client:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.socket.close()
        self.selector.close()
