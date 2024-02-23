from __future__ import annotations

from socket import socket, AF_INET, SOCK_STREAM
from threading import Thread
from typing import Callable
from enum import IntEnum, auto
from packet_parser import Packet, PacketType, MsgData

NAddr = tuple[str, int]
BUF_SIZE = 8192
DATABASE: dict[str, str] = {
    "ad": "a",
    "sad": "s",
}
SERVER_NAME = "[Khazad-dûm]"


class ClientState(IntEnum):
    Authenticated = auto()
    UnAuthenticated = auto()


class Client(Thread):
    def __init__(
        self, conn: socket, addr: NAddr, id: int, on_close: Callable[[int], None]
    ) -> None:
        super().__init__()

        self.request = conn
        self.req_addr = addr
        self.id = id
        self.on_close = on_close
        self.username = ""

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

    def send_packet(self, pkt: Packet):
        pass

    def run(self) -> None:
        match self.authenticate():
            case ClientState.Authenticated:
                self.chat()
            case ClientState.UnAuthenticated:
                self.on_close(self.id)

    def chat(self):
        while True:
            recv_pkt = self.read_packet()
            if recv_pkt.ty == PacketType.Quit:
                self.on_close(self.id)
                break
            self.send_packet(
                Packet(
                    PacketType.Msg,
                    msg=MsgData(
                        extra=f"You are {self.username} and sent: {recv_pkt.msg.extra}"
                    ),
                )
            )

    def authenticate(self) -> ClientState:
        pkt = self.read_packet()

        self.username = pkt.msg.username

        if DATABASE.get(self.username) == pkt.msg.password:
            self.send_packet(
                Packet.valid_user(SERVER_NAME + " Welcome to the World of Voicing!")
            )
            return ClientState.Authenticated
        else:
            self.send_packet(
                Packet.invalid_user(SERVER_NAME + " Invalid username of password")
            )
            return ClientState.UnAuthenticated

    def cleanup(self) -> None:
        self.request.close()


class Server:
    def __init__(self, addr: NAddr) -> None:
        server_sock = socket(AF_INET, SOCK_STREAM)
        server_sock.bind(addr)
        server_sock.listen()
        self.socket = server_sock

        self.clients: list[Client] = []
        self.addr = addr
        self.cid = 1

    def handle_request(self) -> None:
        csock, addr = self.socket.accept()
        self.cid += 1
        client = Client(csock, addr, self.cid, self.on_auth_fail)
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
    with Server(("localhost", 8096)) as server:
        server.serve_forever()
