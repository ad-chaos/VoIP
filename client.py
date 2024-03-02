import sys
from packet_parser import VOIP_PORT, PacketType, Packet
from libclient import Client
from typing import Iterator


class VoIPClient(Client):
    def handle_packet(self, pkt: Packet | None) -> None:
        if pkt:
            print(pkt.msg.extra)


def main(
    username: str, password: str, reciever: str, producer: Iterator[Packet]
) -> None:
    with VoIPClient(username, password, reciever, ("localhost", VOIP_PORT)) as c:
        status = c.login()
        if status is None or status.ty == PacketType.InvalidUser:
            return
        c.wait_for_reciever()
        print(f"\nPairing successful with {c.reciever}!")
        c.chat(producer)


if __name__ == "__main__":
    if sys.argv[1] == "a":
        print("I'm ad")
        username = "ad"
        password = "a"
        reciever = "sad"
    else:
        print("I'm sad")
        username = "sad"
        password = "s"
        reciever = "ad"

    producer: Iterator[Packet] = map(
        Packet.message,
        [
            "First Message",
            "Second Message",
            "Third Message",
            "Fourth Message",
            "Fifth Message",
        ]
        * 5,
    )

    main(username, password, reciever, producer)
