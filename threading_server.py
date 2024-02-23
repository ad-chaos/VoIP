from __future__ import annotations

from socket import socket, AF_INET, SOCK_STREAM
from threading import Thread
from typing import Callable, Literal
from enum import IntEnum, auto
from packet_parser import Packet, PacketType, MsgData, VOIP_PORT, NAddr
from selectors import DefaultSelector, EVENT_READ, EVENT_WRITE
from time import sleep

BUF_SIZE = 8192
DATABASE: dict[str, str] = {
    "ad": "a",
    "sad": "s",
}
SERVER_NAME = "[Khazad-dûm]"


class ClientState(IntEnum):
    Authenticated = auto()
    UnAuthenticated = auto()


class ClientThread(Thread):
    def __init__(
        self, conn: socket, addr: NAddr, id: int, on_close: Callable[[int], None]
    ) -> None:
        super().__init__()

        self.request = conn
        self.req_addr = addr
        self.id = id
        self.on_close = on_close
        self.username = ""
        self.selector = DefaultSelector()
        self.selector.register(self, EVENT_READ | EVENT_WRITE)

    def fileno(self) -> int:
        return self.request.fileno()

    def read_packet(self) -> Packet:
        size = int.from_bytes(self.request.recv(4), "big")
        bts = b""
        while size > 0:
            rbts = self.request.recv(size)
            size -= len(rbts)
            bts += rbts

        return Packet.parse(bts)

    def send_packet(self, pkt: Packet) -> None:
        self.request.sendall(pkt.to_bytes())

    def run(self) -> None:
        match self.authenticate():
            case ClientState.Authenticated:
                self.chat()
            case ClientState.UnAuthenticated:
                self.on_close(self.id)

    def chat(self) -> None:
        alive = True
        while alive:
            for ready, events in self.selector.select():
                if events & EVENT_READ and self.read_packet().ty == PacketType.Quit:
                    self.send_packet(Packet.shutdown())
                    self.on_close(self.id)
                    alive = False
                    break
                elif events & EVENT_WRITE:
                    sleep(0.5)
                    self.send_packet(
                        Packet(
                            PacketType.Msg,
                            msg=MsgData(
                                extra=f"You are {self.username} and here's a greet"
                            ),
                        )
                    )

    def authenticate(self) -> ClientState:
        pkt = self.read_packet()

        if pkt.msg.username is None:
            return self.invalid()

        self.username = pkt.msg.username

        match pkt.ty:
            case PacketType.Login:
                return self.login(pkt)
            case PacketType.Signin:
                return self.signin(pkt)
            case _:
                assert False

    def login(self, pkt: Packet) -> ClientState:
        if DATABASE.get(self.username) == pkt.msg.password:
            return self.valid()
        else:
            return self.invalid()

    def signin(self, pkt: Packet) -> ClientState:
        if pkt.msg.username and pkt.msg.password:
            DATABASE[pkt.msg.username] = pkt.msg.password
        else:
            return self.invalid()
        return self.valid()

    def valid(self) -> Literal[ClientState.Authenticated]:
        self.send_packet(
            Packet.valid_user(SERVER_NAME + " Welcome to the World of Voicing!")
        )
        return ClientState.Authenticated

    def invalid(self) -> Literal[ClientState.UnAuthenticated]:
        self.send_packet(
            Packet.invalid_user(SERVER_NAME + " Invalid username or password")
        )
        return ClientState.UnAuthenticated

    def cleanup(self) -> None:
        self.request.close()
        self.selector.close()


class Server:
    def __init__(self, addr: NAddr) -> None:
        server_sock = socket(AF_INET, SOCK_STREAM)
        server_sock.bind(addr)
        server_sock.listen()
        self.socket = server_sock

        self.clients: list[ClientThread] = []
        self.addr = addr
        self.cid = 1

    def handle_request(self) -> None:
        csock, addr = self.socket.accept()
        self.cid += 1
        client = ClientThread(csock, addr, self.cid, self.on_auth_fail)
        client.start()
        self.clients.append(client)

    def on_auth_fail(self, cid: int) -> None:
        client = next((client for client in self.clients if client.id == cid), None)
        if client is not None:
            client.cleanup()
            self.clients.remove(client)

    def serve_forever(self) -> None:
        try:
            while True:
                self.handle_request()
        except KeyboardInterrupt:
            print("Server shutting down")

    def __enter__(self) -> Server:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.socket.close()
        for client in self.clients:
            client.cleanup()
            client.join()


if __name__ == "__main__":
    with Server(("localhost", VOIP_PORT)) as server:
        print(f"Server ready on port: {VOIP_PORT}")
        server.serve_forever()
