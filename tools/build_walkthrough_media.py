"""Assemble the product-walkthrough media from captured frames.

Takes the raw 2x PNG frames produced by ``tools/capture_walkthrough.py`` and produces
every asset the README and the showcase site consume:

    site/assets/tour/*.webp          the scroll-driven tour frames (1440x900)
    site/assets/governed-chat*.webp  hero / approval / verified stills
    site/assets/product-walkthrough.gif   README + site animated walkthrough
    site/assets/product-walkthrough.mp4   the same, as broadly-compatible H.264
    site/assets/product-walkthrough-poster.webp   video poster
    docs/assets/product-walkthrough.gif   README copy (docs/assets is the README root)

Requires: Pillow (webp encode) and ffmpeg on PATH. Neither is a project dependency —
run from a throwaway environment, same as the capture rig:

    /tmp/capvenv/bin/python tools/build_walkthrough_media.py \
        --frames /tmp/tour-frames --repo .

Deterministic: given the same input frames the outputs are byte-stable apart from
container timestamps.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

from PIL import Image

# The tour's display size (matches the <img width/height> in site/index.html).
TOUR_W, TOUR_H = 1440, 900
# The animation's width — matches the README's other media at GitHub content width.
ANIM_W = 1000
SECONDS_PER_FRAME = 2.6

# Captured frame stem -> published tour frame name. The published names describe the
# product beat, so the site's captions and the files stay legible together.
TOUR_NAMES = {
    "01-chat-shell": "01-chat-goal",
    "02-plan-and-frozen-proposal": "02-governed-plan-and-proposal",
    "03-self-approval-refused": "03-self-approval-refused",
    "04-owner-approves-sandbox-applies": "04-owner-approves",
    "05-verified-with-evidence-lineage": "05-verified-evidence-lineage",
    "06-authority-withheld-refused": "06-authority-withheld",
    "07-boundary-probe": "07-boundary-probe",
    "08-console-overview": "08-console-overview",
    "09-live-audit": "09-console-live-audit",
    "10-probe-lab-denial": "10-console-probe-denied",
    "11-tools-floors": "11-console-tool-floors",
    "12-capability-not-authority": "12-capability-not-authority",
}

# Standalone stills the README / site / social cards use.
STILLS = {
    "01-chat-shell": "governed-chat.webp",
    "02-plan-and-frozen-proposal": "governed-chat-approval.webp",
    "05-verified-with-evidence-lineage": "governed-chat-verified.webp",
}


def _webp(src: Path, dest: Path, size: tuple[int, int], quality: int = 82) -> None:
    with Image.open(src) as im:
        im = im.convert("RGB").resize(size, Image.LANCZOS)
        dest.parent.mkdir(parents=True, exist_ok=True)
        im.save(dest, "WEBP", quality=quality, method=6)
    print(f"  {dest.relative_to(dest.parents[2])}  {dest.stat().st_size // 1024} KB")


def _run(cmd: list[str]) -> None:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr[-2000:])
        raise SystemExit(f"command failed: {' '.join(cmd[:4])} …")


def build(frames: Path, repo: Path) -> int:
    if shutil.which("ffmpeg") is None:
        raise SystemExit("ffmpeg is required on PATH")
    ordered = sorted(frames.glob("*.png"))
    missing = set(TOUR_NAMES) - {f.stem for f in ordered}
    if missing:
        raise SystemExit(f"missing captured frames: {sorted(missing)}")

    site_assets = repo / "site" / "assets"
    tour_dir = site_assets / "tour"

    print("tour frames:")
    for src in ordered:
        name = TOUR_NAMES.get(src.stem)
        if name:
            _webp(src, tour_dir / f"{name}.webp", (TOUR_W, TOUR_H))

    print("stills:")
    for stem, out_name in STILLS.items():
        _webp(frames / f"{stem}.png", site_assets / out_name, (TOUR_W, TOUR_H), quality=86)

    # --- animation: one numbered sequence, then GIF + MP4 from the same source --------
    work = frames / "_seq"
    work.mkdir(exist_ok=True)
    anim_h = round(ANIM_W * TOUR_H / TOUR_W / 2) * 2      # even height for H.264
    for i, src in enumerate(ordered, start=1):
        with Image.open(src) as im:
            im.convert("RGB").resize((ANIM_W, anim_h), Image.LANCZOS).save(
                work / f"{i:02d}.png"
            )

    fps = f"1/{SECONDS_PER_FRAME}"
    gif = site_assets / "product-walkthrough.gif"
    palette = work / "palette.png"
    _run(["ffmpeg", "-y", "-loglevel", "error", "-framerate", fps,
          "-i", str(work / "%02d.png"), "-vf", "palettegen=max_colors=128",
          str(palette)])
    _run(["ffmpeg", "-y", "-loglevel", "error", "-framerate", fps,
          "-i", str(work / "%02d.png"), "-i", str(palette),
          "-lavfi", "paletteuse=dither=bayer:bayer_scale=3", str(gif)])
    print(f"gif:  {gif.name}  {gif.stat().st_size // 1024} KB")

    mp4 = site_assets / "product-walkthrough.mp4"
    _run(["ffmpeg", "-y", "-loglevel", "error", "-framerate", fps,
          "-i", str(work / "%02d.png"), "-c:v", "libx264", "-profile:v", "baseline",
          "-level", "3.1", "-pix_fmt", "yuv420p", "-r", "25",
          "-movflags", "+faststart", str(mp4)])
    print(f"mp4:  {mp4.name}  {mp4.stat().st_size // 1024} KB")

    _webp(ordered[0], site_assets / "product-walkthrough-poster.webp", (ANIM_W, anim_h))

    # The README renders from the repo root, and docs/assets is where its media lives.
    docs_gif = repo / "docs" / "assets" / "product-walkthrough.gif"
    docs_gif.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(gif, docs_gif)
    print(f"docs: {docs_gif.name}  {docs_gif.stat().st_size // 1024} KB")

    shutil.rmtree(work)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--frames", required=True, type=Path)
    ap.add_argument("--repo", default=Path("."), type=Path)
    args = ap.parse_args()
    return build(args.frames.resolve(), args.repo.resolve())


if __name__ == "__main__":
    sys.exit(main())
