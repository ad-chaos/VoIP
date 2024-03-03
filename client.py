from packet_parser import VOIP_PORT, PacketType, Packet
from libclient import Client
from typing import Iterator
import argparse


class VoIPClient(Client):
    def handle_packet(self, pkt: Packet | None) -> None:
        if pkt and pkt.ty != PacketType.NoPacket:
            print(pkt.msg.extra)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="VoIP",
        description="A client for talking to a VoIP server",
        epilog="Made with ❤ from Kiran & Karthik",
    )
    parser.add_argument(
        "-u", "--username", required=True, help="Username you want to login as"
    )
    parser.add_argument(
        "-p", "--password", required=True, help="Password for the given username"
    )
    parser.add_argument(
        "-r",
        "--reciever",
        required=True,
        help="The name of reciever you want to talk to",
    )
    parser.add_argument(
        "-i", "--ip", default="localhost", help="The ip address of the server"
    )
    grp = parser.add_mutually_exclusive_group(required=True)
    grp.add_argument(
        "-l",
        "--login",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Use the credentials for login",
    )
    grp.add_argument(
        "-s",
        "--sigin",
        type=bool,
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Use the credentials for sigining in as a first time user",
    )
    args = parser.parse_args()

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

    with VoIPClient(
        args.username, args.password, args.reciever, (args.ip, VOIP_PORT)
    ) as c:
        print("Login: ", args.login)
        print("Sigin: ", args.sigin)
        status = c.login() if args.login else c.signin()
        if status is None or status.ty == PacketType.InvalidUser:
            print(status)
            return
        c.wait_for_reciever()
        print(f"\nPairing successful with {c.reciever}!")
        c.chat(producer)


if __name__ == "__main__":
    main()
