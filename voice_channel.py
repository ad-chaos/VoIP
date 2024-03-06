from __future__ import annotations
from packet_parser import Packet
from sounddevice import Stream  # type: ignore
from typing import TYPE_CHECKING
from queue import SimpleQueue
from pickle import dumps
import numpy as np
from collections import deque

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
            if self.audio_queue:
                outdata[:] = self.audio_queue.popleft()
            else:
                outdata.fill(0)

        self.stream = Stream(
            samplerate=44100,
            blocksize=1 << 15,
            channels=(1, 1),
            callback=callback,
            dtype=np.int32,
        )
        self.packet_queue: SimpleQueue[Packet] = SimpleQueue()
        self.audio_queue: deque[np.ndarray] = deque()

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
