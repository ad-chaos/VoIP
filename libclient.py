from __future__ import annotations

from socket import socket, AF_INET, SOCK_STREAM
from packet_parser import Packet, PacketType, NAddr
from itertools import count
from typing import Iterator


class Client:
    def __init__(
        self,
        username: str,
        password: str,
        reciever: str,
        producer: Iterator[Packet],
        addr: NAddr,
    ) -> None:
        self.socket = socket(AF_INET, SOCK_STREAM)
        self.socket.connect(addr)
        self.socket.settimeout(0.5)
        self.username = username
        self.password = password
        self.reciever = reciever
        self.voice_producer = producer

    def fileno(self) -> int:
        return self.socket.fileno()

    def chat(self) -> None:
        try:
            has_recv = True
            while True:
                if has_recv:
                    self.try_send(next(self.voice_producer))
                maybe_pkt = self.try_read()
                if maybe_pkt is None or maybe_pkt.ty == PacketType.Quit:
                    self.quit(True)
                    break
                has_recv = maybe_pkt.ty != PacketType.NoPacket
                self.handle_packet(maybe_pkt)
        except (KeyboardInterrupt, StopIteration):
            self.quit(False)

    def try_read(self) -> Packet | None:
        try:
            return self.read_packet()
        except TimeoutError:
            return Packet.none()

    def try_send(self, pkt) -> None:
        try:
            self.send_packet(pkt)
        except TimeoutError:
            pass

    def handle_packet(self, pkt: Packet | None) -> None:
        raise NotImplementedError

    def wait_for_reciever(self) -> None:
        for i in count():
            try:
                # We wait for a packet that let's us know we've been paired
                pkt = self.read_packet()
                if pkt is None or pkt.ty != PacketType.Paired:
                    print("Expected a Paired Packet")
                    return
                else:
                    break
            except TimeoutError:
                print("\r\033[KWaiting to Pair" + "." * (i % 4 + 1), end="")  # ]

    def quit(self, await_confirm: bool) -> None:
        print("Quitting!")
        self.send_packet(Packet.quit())
        while await_confirm:
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
