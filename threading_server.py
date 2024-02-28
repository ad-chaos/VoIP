from __future__ import annotations

from socket import socket, AF_INET, SOCK_STREAM
from threading import Thread
from typing import Callable, Literal
from enum import IntEnum
from packet_parser import Packet, PacketType, VOIP_PORT, NAddr
from selectors import DefaultSelector, EVENT_READ, EVENT_WRITE
from time import sleep

DATABASE: dict[str, str] = {
    "ad": "a",
    "sad": "s",
}

SERVER_NAME = "[Khazad-dûm]"


class ClientState(IntEnum):
    Conversing = 0
    Quitting = 1


class Client:
    def __init__(self, conn: socket, addr: NAddr) -> None:
        self.request = conn
        self.req_addr = addr
        self.sender = ""
        self.reciever = ""
        self.state = ClientState.Conversing

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

    def read_packets(self) -> list[Packet]:
        pkts = []
        self.request.setblocking(False)
        try:
            while True:
                pkts.append(self.read_packet())
        except BlockingIOError:
            self.request.setblocking(True)
            return pkts

    def send_packet(self, pkt: Packet) -> None:
        self.request.sendall(pkt.to_bytes())

    def authenticate(self) -> bool:
        pkt = self.read_packet()

        if not (pkt.msg.sender and pkt.msg.reciever):
            return self.invalid()

        self.sender = pkt.msg.sender
        self.reciever = pkt.msg.reciever

        match pkt.ty:
            case PacketType.Login:
                return self.login(pkt)
            case PacketType.Signin:
                return self.signin(pkt)
            case _:
                assert False, "Unexpected PacketType"

    def login(self, pkt: Packet) -> bool:
        if DATABASE.get(self.sender) == pkt.msg.password:
            return self.valid()
        else:
            return self.invalid()

    def signin(self, pkt: Packet) -> bool:
        if pkt.msg.sender and pkt.msg.password:
            DATABASE[pkt.msg.sender] = pkt.msg.password
            return self.valid()
        else:
            return self.invalid()

    def paired(self) -> None:
        self.send_packet(Packet.paired())

    def valid(self) -> Literal[True]:
        self.send_packet(
            Packet.valid_user(SERVER_NAME + " Welcome to the World of Voicing!")
        )
        return True

    def invalid(self) -> Literal[False]:
        self.send_packet(
            Packet.invalid_user(
                SERVER_NAME + " Invalid username or password or reciever"
            )
        )
        return False

    def cleanup(self) -> None:
        self.request.close()


class PairedClientThread(Thread):
    def __init__(
        self, a: Client, b: Client, id: int, on_close: Callable[[int], None]
    ) -> None:
        super().__init__()
        self.a = a
        self.b = b
        self.id = id
        self.on_close = on_close

        self.a_sent: list[Packet] = []
        self.b_sent: list[Packet] = []

        self.selector = DefaultSelector()
        self.selector.register(
            self.a, EVENT_READ | EVENT_WRITE, (self.a_sent, self.b_sent)
        )
        self.selector.register(
            self.b, EVENT_READ | EVENT_WRITE, (self.b_sent, self.a_sent)
        )

    def run(self) -> None:
        self.a.paired()
        self.b.paired()

        alive = 2
        while alive:
            for key, event in self.selector.select():
                (tx, rx) = key.data
                client: Client = key.fileobj  # type: ignore

                if event & EVENT_READ and client.state == ClientState.Conversing:
                    pkt = client.read_packet()
                    if pkt.ty == PacketType.Quit:
                        client.state = ClientState.Quitting
                    rx.append(pkt)
                    rx.extend(client.read_packets())

                if event & EVENT_WRITE:
                    # FIXME: What the fuck?
                    sleep(0.1)
                    if client.state == ClientState.Quitting:
                        client.send_packet(Packet.shutdown())
                        self.selector.unregister(client)
                        alive -= 1
                        continue

                    for pkt in tx:
                        client.send_packet(pkt)
                    tx.clear()

    def cleanup(self) -> None:
        self.a.cleanup()
        self.b.cleanup()


class Server:
    def __init__(self, addr: NAddr) -> None:
        server_sock = socket(AF_INET, SOCK_STREAM)
        server_sock.bind(addr)
        server_sock.listen()
        self.socket = server_sock

        self.paired_clients: list[PairedClientThread] = []
        self.waiting_clients: list[Client] = []
        self.addr = addr
        self.cid = 1

    def handle_request(self) -> None:
        csock, addr = self.socket.accept()
        sender = Client(csock, addr)

        if not sender.authenticate():
            sender.invalid()
            sender.cleanup()
            return

        if (reciever := self.get_potential_reciever(sender)) is not None:
            self.cid += 1
            paired_client = PairedClientThread(
                sender, reciever, self.cid, self.on_auth_fail
            )
            paired_client.start()
            self.paired_clients.append(paired_client)
            self.waiting_clients.remove(reciever)
            return

        self.waiting_clients.append(sender)

    def get_potential_reciever(self, sender: Client) -> Client | None:
        return next(
            (
                reciever
                for reciever in self.waiting_clients
                if reciever.sender == sender.reciever
            ),
            None,
        )

    def on_auth_fail(self, cid: int) -> None:
        client = next(
            (client for client in self.paired_clients if client.id == cid), None
        )
        if client is not None:
            client.cleanup()
            self.paired_clients.remove(client)

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
        for client in self.paired_clients:
            client.cleanup()
            client.join()


if __name__ == "__main__":
    with Server(("localhost", VOIP_PORT)) as server:
        print(f"Server ready on port: {VOIP_PORT}")
        server.serve_forever()
