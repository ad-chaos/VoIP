from __future__ import annotations
from packet_parser import Packet
from sounddevice import Stream  # type: ignore
from typing import TYPE_CHECKING
from queue import SimpleQueue
from pickle import dumps
import numpy as np

if TYPE_CHECKING:
    from sounddevice import CData, CallbackFlags


class Producer:
    def __init__(self) -> None:
        def callback(
            indata: np.ndarray,
            outdata: np.ndarray,
            frames: int,
            time: CData,
            status: CallbackFlags,
        ) -> None:
            self.packet_queue.put(Packet.voice(dumps(indata)))

        self.stream = Stream(
            samplerate=44100,
            blocksize=1 << 15,
            channels=(1, 1),
            callback=callback,
            dtype=np.int32,
        )
        self.packet_queue: SimpleQueue[Packet] = SimpleQueue()

    def stop(self):
        self.stream.stop()

    def close(self):
        self.stream.close()

    def start(self):
        self.stream.start()

    def __iter__(self) -> Producer:
        return self

    def __next__(self) -> Packet:
        return self.packet_queue.get()
