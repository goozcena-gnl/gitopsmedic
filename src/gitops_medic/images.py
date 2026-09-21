from __future__ import annotations

import re


IMAGE_REFERENCE_MUTABLE = "mutable"
IMAGE_REFERENCE_VERSIONED_TAG = "versioned-tag"
IMAGE_REFERENCE_DIGEST_PINNED = "digest-pinned"

_OCI_DIGEST = re.compile(r"sha256:[0-9a-fA-F]{64}")
_OCI_TAG = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")


def image_reference_kind(image: str) -> str:
    reference = image.strip()
    if not reference:
        return IMAGE_REFERENCE_MUTABLE
    name, separator, digest = reference.partition("@")
    if separator:
        return IMAGE_REFERENCE_DIGEST_PINNED if name and _OCI_DIGEST.fullmatch(digest) else IMAGE_REFERENCE_MUTABLE
    component = name.rsplit("/", 1)[-1]
    repository, separator, tag = component.rpartition(":")
    if repository and separator and tag != "latest" and _OCI_TAG.fullmatch(tag):
        return IMAGE_REFERENCE_VERSIONED_TAG
    return IMAGE_REFERENCE_MUTABLE


def is_image_pinned(image: str) -> bool:
    return image_reference_kind(image) == IMAGE_REFERENCE_DIGEST_PINNED