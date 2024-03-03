from __future__ import annotations
from packet_parser import Packet

class Producer:
    def __init__(self) -> None:
        self.iter = iter([
            "First Message",
            "Second Message",
            "Third Message",
            "Fourth Message",
            "Fifth Message",
        ] * 5)

    def __iter__(self) -> Producer:
        return self

    def __next__(self) -> Packet:
        return Packet.message(next(self.iter))
