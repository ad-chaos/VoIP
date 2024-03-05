from packet_parser import VOIP_PORT, PacketType, Packet
from libclient import Client
from voice_channel import Producer
import argparse
from pickle import loads


class VoIPClient(Client):
    def handle_packet(self, pkt: Packet | None) -> None:
        if pkt is None or pkt.ty == PacketType.NoPacket:
            return

        match pkt.ty:
            case PacketType.Msg:
                print(pkt.msg.extra, pkt.audio)
            case PacketType.Voice:
                self.voice_producer.stream.write(loads(pkt.audio))


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
        "--signin",
        type=bool,
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Use the credentials for sigining in as a first time user",
    )
    args = parser.parse_args()

    with VoIPClient(
        args.username, args.password, args.reciever, Producer(), (args.ip, VOIP_PORT)
    ) as c:
        status = c.login() if args.login else c.signin()
        if status is None:
            return
        print(status.msg.extra)
        if status.ty == PacketType.InvalidUser:
            return
        c.wait_for_reciever()
        print(f"\nPairing successful with {c.reciever}!")
        c.chat()


if __name__ == "__main__":
    main()
