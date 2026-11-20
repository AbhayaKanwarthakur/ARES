from __future__ import annotations

import argparse
from pathlib import Path

import imageio.v2 as imageio
import numpy as np
from PIL import Image, ImageDraw, ImageFont


def font(size: int, bold: bool = False):
    name = "segoeuib.ttf" if bold else "segoeui.ttf"
    path = Path("C:/Windows/Fonts") / name
    return ImageFont.truetype(path, size) if path.exists() else ImageFont.load_default()


def title_frame(size: tuple[int, int], title: str, lines: list[str], accent: str) -> np.ndarray:
    width, height = size
    image = Image.new("RGB", size, "#071711")
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0, 18, height), fill=accent)
    draw.text((80, 100), title, fill="#ecfdf5", font=font(max(36, width // 32), True))
    y = 220
    for line in lines:
        draw.text((86, y), line, fill="#b8d9c5", font=font(max(22, width // 60)))
        y += max(48, width // 55)
    draw.text((86, height - 90), "Safe local simulation • no real traffic • no real blocking", fill="#86a995", font=font(20))
    return np.asarray(image)


def annotate_frame(frame: np.ndarray, step: int, title: str, message: str, accent: str) -> np.ndarray:
    image = Image.fromarray(frame).convert("RGBA")
    width, height = image.size
    overlay = Image.new("RGBA", image.size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)
    left = 42
    right = width - 42
    bottom = height - 34
    top = height - 184
    draw.rounded_rectangle((left, top, right, bottom), radius=18, fill=(7, 23, 17, 236), outline=accent, width=3)
    draw.rectangle((left, top, left + 14, bottom), fill=accent)
    draw.text((left + 38, top + 20), f"STEP {step} / 5  |  {title}", fill="#ecfdf5", font=font(28, True))
    draw.text((left + 38, top + 76), message, fill="#b8d9c5", font=font(24))
    draw.text((right - 360, top + 22), "SYNTHETIC LOCAL DEMO", fill="#86a995", font=font(18, True))
    return np.asarray(Image.alpha_composite(image, overlay).convert("RGB"))


def annotation_for_frame(frame_number: int, total_frames: int) -> tuple[int, str, str, str]:
    progress = frame_number / max(total_frames - 1, 1)
    if progress < 0.18:
        return (1, "OBSERVE", "The SOC dashboard shows the current threat and learning state.", "#22c55e")
    if progress < 0.38:
        return (2, "SIMULATE ATTACK", "A synthetic brute-force event is generated locally for a safe demo.", "#f59e0b")
    if progress < 0.58:
        return (3, "DETECT + RESPOND", "The model classifies HIGH risk and selects BLOCK_IP for simulated containment.", "#ef4444")
    if progress < 0.78:
        return (4, "REMEMBER", "The attack fingerprint and response outcome reinforce adaptive memory and rules.", "#38bdf8")
    return (5, "RETRAIN + VERIFY", "Retraining completes; analytics verify learned patterns and simulated response success.", "#a78bfa")


def main() -> None:
    parser = argparse.ArgumentParser(description="Add informative title cards to a screen recording.")
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    reader = imageio.get_reader(args.input)
    metadata = reader.get_meta_data()
    fps = int(round(metadata.get("fps", 10)))
    first = reader.get_data(0)
    size = (first.shape[1], first.shape[0])
    intro = title_frame(
        size,
        "ADAPTIVE SECURITY AGENT",
        [
            "A safe SOC demonstration",
            "Detect synthetic attack → choose response → remember → retrain",
        ],
        "#22c55e",
    )
    outro = title_frame(
        size,
        "DEMO RESULT",
        [
            "Brute Force detected as HIGH risk",
            "BLOCK_IP selected and simulated containment recorded",
            "Pattern memory reinforced; model retraining available",
        ],
        "#ef4444",
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    total_frames = int(round(metadata.get("duration", 0) * fps)) if metadata.get("duration") else None
    if not total_frames:
        total_frames = reader.count_frames()

    with imageio.get_writer(
        args.output,
        fps=fps,
        codec="libx264",
        quality=8,
        macro_block_size=None,
        pixelformat="yuv420p",
    ) as writer:
        for _ in range(fps * 5):
            writer.append_data(intro)
        for frame_number, frame in enumerate(reader):
            step, title, message, accent = annotation_for_frame(frame_number, total_frames)
            writer.append_data(annotate_frame(frame, step, title, message, accent))
        for _ in range(fps * 6):
            writer.append_data(outro)


if __name__ == "__main__":
    main()
