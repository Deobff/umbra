"""Objective before/after check for the JavaFX console redesign.

The model cannot look at the screenshots, so this script measures the properties
the redesign is supposed to change, and prints them as numbers:

  * mean RGB and luminance of the whole frame (palette shift)
  * share of pixels that are the new graphite surfaces (#171b1e, #1b2024, #24292e)
  * share of pixels that are the accent (#4d6ebe / #5d81d4 / #7fa4ff)
  * share of pixels that are the OLD palette (#0e1118, #4f8cff)
  * distinct-colour count (design systems tend to reduce accidental colours)
  * per-region means for header / rail / footer strips

Usage: python check_redesign.py before.png after.png
"""

import sys

from PIL import Image


TOKENS = {
    "canvas": (0x17, 0x1b, 0x1E),
    "panel": (0x1B, 0x20, 0x24),
    "raised": (0x24, 0x29, 0x2E),
    "accent": (0x4D, 0x6E, 0xBE),
    "accent_hi": (0x5D, 0x81, 0xD4),
    "old_bg": (0x0E, 0x11, 0x18),
    "old_accent": (0x4F, 0x8C, 0xFF),
}


def near(pixel, target, tolerance=6):
    return all(abs(int(a) - int(b)) <= tolerance for a, b in zip(pixel[:3], target))


def analyse(path):
    image = Image.open(path).convert("RGB")
    width, height = image.size
    pixels = list(image.getdata())
    total = len(pixels)

    mean = tuple(sum(channel) / total for channel in zip(*pixels))
    luminance = sum(0.2126 * r + 0.7152 * g + 0.0722 * b for r, g, b in pixels) / total

    counts = {name: 0 for name in TOKENS}
    for pixel in pixels:
        for name, target in TOKENS.items():
            if near(pixel, target):
                counts[name] += 1
                break

    distinct = len(set(pixels))
    regions = {}
    for name, box in (
        ("header", (0, 0, width, int(height * 0.09))),
        ("rail", (0, int(height * 0.09), int(width * 0.22), height)),
        ("footer", (0, int(height * 0.93), width, height)),
        ("body", (int(width * 0.22), int(height * 0.09), width, int(height * 0.93))),
    ):
        crop = image.crop(box)
        crop_pixels = list(crop.getdata())
        regions[name] = tuple(
            sum(channel) / len(crop_pixels) for channel in zip(*crop_pixels)
        )

    return {
        "size": (width, height),
        "mean": mean,
        "luminance": luminance,
        "distinct": distinct,
        "shares": {name: 100.0 * value / total for name, value in counts.items()},
        "regions": regions,
    }


def main():
    if len(sys.argv) < 3:
        print("usage: check_redesign.py <before.png> <after.png>")
        return 2
    before = analyse(sys.argv[1])
    after = analyse(sys.argv[2])

    print("metric                          before            after")
    print("------------------------------  ----------------  ----------------")
    for key in ("mean", "luminance", "distinct"):
        left = before[key]
        right = after[key]
        if isinstance(left, tuple):
            print(
                "%-30s  (%.1f,%.1f,%.1f)   (%.1f,%.1f,%.1f)"
                % (key, left[0], left[1], left[2], right[0], right[1], right[2])
            )
        elif isinstance(left, float):
            print("%-30s  %-16.2f  %-16.2f" % (key, left, right))
        else:
            print("%-30s  %-16d  %-16d" % (key, left, right))

    for name in TOKENS:
        print(
            "share %-24s  %-15.2f%%  %-15.2f%%"
            % (name, before["shares"][name], after["shares"][name])
        )

    for name, value in before["regions"].items():
        other = after["regions"][name]
        print(
            "region %-23s  (%.0f,%.0f,%.0f)    (%.0f,%.0f,%.0f)"
            % (name, value[0], value[1], value[2], other[0], other[1], other[2])
        )

    changed = sum(
        1 for name in TOKENS if abs(before["shares"][name] - after["shares"][name]) > 0.05
    )
    print("")
    print("token shares that moved by >0.05pp : %d of %d" % (changed, len(TOKENS)))
    print("frame size match                  : %s" % (before["size"] == after["size"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
