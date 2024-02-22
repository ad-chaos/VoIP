from __future__ import annotations
from enum import IntEnum
from typing import Iterable

# The Server PacketFormat
#
# 1 byte packet id
# msg(optional): key:value pairs separated by comma terminated by a |
# audio(optional): the rest of it is audio


class PacketType(IntEnum):
    Welcome = 1
    Login = 2
    Signin = 3
    Voice = 4
    Quit = 5
    ShutDown = 6


class MsgData:
    attrs = ("username", "password", "group", "greet")

    def __init__(self, **kwargs):
        for attr in self.attrs:
            if attr in kwargs:
                setattr(self, attr, kwargs[attr])
            else:
                setattr(self, attr, None)

    @staticmethod
    def from_bytes(bts: bytes) -> MsgData:
        import json
        msg = bts.decode()
        msgdata = MsgData()
        for key, value in json.loads(msg).items():
            if key in msgdata.attrs:
                setattr(msgdata, key, value)

        return msgdata

    def to_bytes(self) -> bytes:
        return (
            b",".join(
                f"{attr}:{getattr(self, attr)}".encode()
                for attr in self.attrs
                if getattr(self, attr) is not None
            )
            + b"|"
        )

    def __repr__(self) -> str:
        return f"MsgData({', '.join(f'{attr}={getattr(self, attr)}' for attr in self.attrs)})"

    def __eq__(self, other) -> bool:
        return all(getattr(self, attr) == getattr(other, attr) for attr in self.attrs)


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
        return Packet(PacketType.ShutDown)

    @staticmethod
    def welcome(msg: bytes = b"Welcome to VoIP") -> Packet:
        return Packet(PacketType.Welcome, MsgData(greet=msg))

    def to_bytes(self) -> bytes:
        pkt = b""
        pkt += self.ty.to_bytes(1, "big")
        pkt += self.msg.to_bytes()
        pkt += self.audio
        return pkt

    def __eq__(self, other: Packet) -> bool:  # type: ignore[override]
        return (
            (self.ty == other.ty)
            and (self.msg == other.msg)
            and (self.audio == other.audio)
        )

    def __repr__(self) -> str:
        return f"Packet(ty={self.ty}, msg={self.msg}, audio={self.audio!r})"


def test():
    from random import randbytes

    music = randbytes(32)
    cases = [
        ("Welcome Packet", b"\x01|", Packet.welcome()),
        ("Welcome Packet (with greet)", b"\x01|", Packet.welcome()),
        ("Quit Packet", b"\x05|", Packet(PacketType.Quit)),
        (
            "Login Packet",
            b"\x02username:ad,password:a|",
            Packet(PacketType.Login, MsgData(username="ad", password="a")),
        ),
        (
            "Signin Packet",
            b"\x03username:ad,password:a|",
            Packet(PacketType.Signin, MsgData(username="ad", password="a")),
        ),
        (
            "Login Packet (Unicode)",
            b"\x02username:goofy-\xf0\x9f\x98\x9c,password:fancy|" + music,
            Packet(
                PacketType.Login,
                MsgData(username=b"goofy-\xf0\x9f\x98\x9c".decode(), password="fancy"),
                music,
            ),
        ),
        (
            "Login Packet (with Group)",
            b"\x02username:goofy-\xf0\x9f\x98\x9c,password:fancy,group:singers|"
            + music,
            Packet(
                PacketType.Login,
                MsgData(
                    username=b"goofy-\xf0\x9f\x98\x9c".decode(),
                    password="fancy",
                    group="singers",
                ),
                music,
            ),
        ),
    ]

    for kind, test, expect in cases:
        parsed = Packet.parse(test)
        if parsed == expect:
            print("✅", kind)
        else:
            print("❌", kind, "\nExpected:", expect, "\nGot:", parsed, end="\n\n")

        if parsed.to_bytes() == test:
            print(
                "✅ (to_bytes)",
                kind,
            )
        else:
            print(
                "❌", kind, "\nExpected:", test, "\nGot:", parsed.to_bytes(), end="\n\n"
            )

        print()


if __name__ == "__main__":
    test()
