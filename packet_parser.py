from __future__ import annotations
from enum import IntEnum
import json

# The Packet Format:
#
# 1 byte packet id
# msg(optional): key:value pairs separated by comma terminated by a NUL character
# audio(optional): the rest of it is audio

VOIP_PORT = 8096
NAddr = tuple[str, int]


class PacketType(IntEnum):
    Msg = 1
    Login = 2
    Signin = 3
    Voice = 4
    Quit = 5
    ShutDown = 6
    ValidUser = 7
    InvalidUser = 8


class MsgData:
    def __init__(
        self,
        sender: str | None = None,
        password: str | None = None,
        reciever: str | None = None,
        extra: str | None = None,
        fs: str | None = None,
    ):
        self.sender = sender
        self.password = password
        self.reciever = reciever
        self.extra = extra
        self.fs = fs

    @staticmethod
    def from_bytes(bts: bytes) -> MsgData:
        msg = bts.decode()
        msgdata = MsgData()
        for key, value in json.loads(msg).items():
            if key in msgdata.__dict__:
                setattr(msgdata, key, value)

        return msgdata

    def to_bytes(self) -> bytes:
        return (
            json.dumps(
                dict(
                    (attr, getattr(self, attr))
                    for attr in self.__dict__
                    if getattr(self, attr) is not None
                ),
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode()
            + b"\x00"
        )

    def __repr__(self) -> str:
        return f"MsgData({', '.join(f'{attr}={getattr(self, attr)!r}' for attr in self.__dict__)})"

    def __eq__(self, other) -> bool:
        return all(
            getattr(self, attr) == getattr(other, attr) for attr in self.__dict__
        )


class Packet:
    def __init__(self, ty: PacketType, msg: MsgData = MsgData(), audio: bytes = b""):
        self.ty = ty
        self.msg = msg
        self.audio = audio

    @staticmethod
    def parse(bts: bytes) -> Packet:
        ty = int.from_bytes(bts[0:1], "big")
        delim = bts.find(b"\x00")
        msg = MsgData.from_bytes(bts[1:delim])
        audio = bts[delim + 1 :]

        return Packet(PacketType(ty), msg, audio)

    @staticmethod
    def shutdown() -> Packet:
        return Packet(PacketType.ShutDown)

    @staticmethod
    def quit() -> Packet:
        return Packet(PacketType.Quit)

    @staticmethod
    def valid_user(msg: str = "Welcome to VoIP!") -> Packet:
        return Packet(PacketType.ValidUser, MsgData(extra=msg))

    @staticmethod
    def invalid_user(msg: str = "Invalid Username or Password") -> Packet:
        return Packet(PacketType.InvalidUser, MsgData(extra=msg))

    @staticmethod
    def login(sender: str, password: str, reciever: str) -> Packet:
        return Packet(PacketType.Login, MsgData(sender=sender, password=password, reciever=reciever))

    @staticmethod
    def signin(sender: str, password: str, reciever: str) -> Packet:
        return Packet(PacketType.Signin, MsgData(sender=sender, password=password, reciever=reciever))

    def to_bytes(self) -> bytes:
        pkt = b""
        pkt += self.ty.to_bytes(1, "big")
        pkt += self.msg.to_bytes()
        pkt += self.audio
        return len(pkt).to_bytes(4, "big") + pkt

    def __eq__(self, other: Packet) -> bool:  # type: ignore[override]
        return (
            (self.ty == other.ty)
            and (self.msg == other.msg)
            and (self.audio == other.audio)
        )

    def __repr__(self) -> str:
        return f"Packet(ty={self.ty!r}, msg={self.msg!r}, audio={self.audio!r})"


def test():
    from random import randbytes

    voice = randbytes(32)
    cases = [
        (
            "Message Packet",
            b'\x01{"extra":"some-message"}\x00',
            Packet(PacketType.Msg, MsgData(extra="some-message")),
        ),
        ("Quit Packet", b"\x05{}\x00", Packet(PacketType.Quit)),
        ("Quit Packet (cls method)", b"\x05{}\x00", Packet.quit()),
        (
            "Login Packet",
            b'\x02{"sender":"ad","password":"a"}\x00',
            Packet(PacketType.Login, MsgData(sender="ad", password="a")),
        ),
        (
            "Signin Packet",
            b'\x03{"sender":"ad","password":"a"}\x00',
            Packet(PacketType.Signin, MsgData(sender="ad", password="a")),
        ),
        (
            "Login Packet (Unicode)",
            b'\x02{"sender":"goofy-\xf0\x9f\x98\x9c","password":"fancy"}\x00',
            Packet(
                PacketType.Login,
                MsgData(sender=b"goofy-\xf0\x9f\x98\x9c".decode(), password="fancy"),
            ),
        ),
        (
            "Login Packet (with reciever)",
            b'\x02{"sender":"ad","password":"tik","reciever":"vdh"}\x00',
            Packet(
                PacketType.Login,
                MsgData(
                    sender="ad",
                    password="tik",
                    reciever="vdh",
                ),
            ),
        ),
        ("Valid User packet", b"\x07{}\x00", Packet(PacketType.ValidUser)),
        (
            "Valid User packet (cls method)",
            b'\x07{"extra":"Welcome to VoIP!"}\x00',
            Packet.valid_user(),
        ),
        (
            "Valid User packet (greet)",
            b'\x07{"extra":"Hello <user>! Welcome to VoIP ;)"}\x00',
            Packet.valid_user("Hello <user>! Welcome to VoIP ;)"),
        ),
        ("Invalid User packet", b"\x08{}\x00", Packet(PacketType.InvalidUser)),
        (
            "Invalid User packet",
            b'\x08{"extra":"Invalid Username or Password"}\x00',
            Packet.invalid_user(),
        ),
        (
            "Voice Packet",
            b'\x04{"fs":44100}\x00' + voice,
            Packet(PacketType.Voice, MsgData(fs=44100), voice),
        ),
    ]

    for kind, test, expect in cases:
        parsed = Packet.parse(test)
        print(kind)
        print(end="[Parse]:")
        if parsed == expect:
            print(end="✅ ")
        else:
            print("❌", "\nExpected:", expect, "\nGot:", parsed, end="\n\n")

        print(end="[Bytes]:")
        bts = parsed.to_bytes()
        length, rest = int.from_bytes(bts[:4], "big"), bts[4:]
        if rest == test and length == len(rest):
            print("✅")
        else:
            print(f"""\
❌
Expected: {test} (length: {len(test)})
Got: {rest}      (length: {len(rest)})
""")

        print()


if __name__ == "__main__":
    test()
