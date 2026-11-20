from __future__ import annotations

import argparse
import time
from pathlib import Path

import imageio.v2 as imageio
import numpy as np
from PIL import ImageGrab


def capture_frame(width: int, height: int) -> np.ndarray:
    frame = np.asarray(ImageGrab.grab()).astype(np.uint8)
    return frame[:height, :width, :3]


def main() -> None:
    parser = argparse.ArgumentParser(description="Record the primary Windows display to MP4.")
    parser.add_argument("output", type=Path)
    parser.add_argument("--seconds", type=float, default=90)
    parser.add_argument("--fps", type=int, default=10)
    args = parser.parse_args()

    first_frame = np.asarray(ImageGrab.grab())
    height = first_frame.shape[0] - first_frame.shape[0] % 2
    width = first_frame.shape[1] - first_frame.shape[1] % 2
    args.output.parent.mkdir(parents=True, exist_ok=True)

    with imageio.get_writer(
        args.output,
        fps=args.fps,
        codec="libx264",
        quality=8,
        macro_block_size=None,
        pixelformat="yuv420p",
    ) as writer:
        deadline = time.monotonic() + args.seconds
        frame_delay = 1 / args.fps
        while time.monotonic() < deadline:
            started = time.monotonic()
            writer.append_data(capture_frame(width, height))
            time.sleep(max(0, frame_delay - (time.monotonic() - started)))


if __name__ == "__main__":
    main()
