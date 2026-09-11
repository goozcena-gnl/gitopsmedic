from __future__ import annotations

import re


def is_image_pinned(image: str) -> bool:
    component = image.rsplit("/", 1)[-1]
    if "@" in component:
        name, digest = component.split("@", 1)
        return bool(name and re.fullmatch(r"sha256:[0-9a-fA-F]{64}", digest))
    name, separator, tag = component.rpartition(":")
    return bool(name and separator and tag != "latest" and re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", tag))