from __future__ import annotations

from socket import socket, AF_INET, SOCK_STREAM
from threading import Thread
from typing import Callable
from enum import IntEnum, auto

NAddr = tuple[str, int]
BUF_SIZE = 8192
DATABASE: dict[str, str] = {
    "ad": "a",
    "sad": "s",
}


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
        self.password = ""

    def fileno(self) -> int:
        return self.request.fileno()

    def run(self) -> None:
        match self.authenticate():
            case ClientState.Authenticated:
                self.chat()
            case ClientState.UnAuthenticated:
                self.on_close(self.id)

    def chat(self):
        while True:
            recvd = self.request.recv(BUF_SIZE).decode()
            if recvd == "q":
                self.request.sendall("Alright Bye!".encode())
                self.on_close(self.id)
                break
            recvd = f"You are {self.username} and sent: " + recvd
            self.request.sendall(recvd.encode())

    def authenticate(self) -> ClientState:
        self.username = self.request.recv(BUF_SIZE).decode()
        self.password = self.request.recv(BUF_SIZE).decode()

        if DATABASE.get(self.username) == self.password:
            self.request.sendall("1[Khazad-dûm]: Welcome to VoIP".encode())
            return ClientState.Authenticated
        else:
            self.request.sendall(
                "0[Khazad-dûm]: Incorrect Username or Password!".encode()
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
