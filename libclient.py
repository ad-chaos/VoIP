from __future__ import annotations

from socket import socket, AF_INET, SOCK_STREAM
from packet_parser import Packet, PacketType, NAddr
from itertools import count
from voice_channel import Producer
from ssl import create_default_context, Purpose


class Client:
    def __init__(
        self,
        username: str,
        password: str,
        reciever: str,
        producer: Producer,
        addr: NAddr,
    ) -> None:
        s = socket(AF_INET, SOCK_STREAM)
        ssl_ctx = create_default_context(Purpose.SERVER_AUTH)
        ssl_ctx.load_verify_locations(cafile="./ca.pem")
        self.socket = ssl_ctx.wrap_socket(s, server_hostname="voip.com")
        self.socket.connect(addr)
        self.username = username
        self.password = password
        self.reciever = reciever
        self.voice_producer = producer

    def fileno(self) -> int:
        return self.socket.fileno()

    def chat(self) -> None:
        try:
            while True:
                self.send_packet(next(self.voice_producer))
                maybe_pkt = self.read_packet()
                if maybe_pkt.ty == PacketType.NoPacket or maybe_pkt.ty == PacketType.Quit:
                    self.quit(True)
                    break
                self.handle_packet(maybe_pkt)
        except (KeyboardInterrupt, StopIteration):
            self.quit(False)

    def handle_packet(self, pkt: Packet | None) -> None:
        raise NotImplementedError

    def wait_for_reciever(self) -> None:
        self.socket.settimeout(0.5)
        for i in count():
            try:
                # We wait for a packet that let's us know we've been paired
                pkt = self.read_packet()
                if pkt.ty != PacketType.Paired:
                    print("Expected a Paired Packet")
                    return
                else:
                    break
            except TimeoutError:
                print("\r\033[KWaiting to Pair" + "." * (i % 4 + 1), end="")  # ]
        self.socket.settimeout(None)

    def quit(self, await_confirm: bool) -> None:
        print("Quitting!")
        self.send_packet(Packet.quit())
        while await_confirm:
            pkt = self.read_packet()
            if pkt.ty == PacketType.NoPacket or pkt.ty == PacketType.Quit:
                break
        print("\nSuccessfully Exited call!")

    def send_packet(self, pkt: Packet) -> None:
        self.socket.sendall(pkt.to_bytes())

    def read_packet(self) -> Packet:
        size = int.from_bytes(self.socket.recv(4), "big")
        if size == 0:
            return Packet.none()
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
        self.voice_producer.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.socket.close()
        self.voice_producer.stop()
        self.voice_producer.close()
