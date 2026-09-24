from __future__ import annotations

import re


IMAGE_REFERENCE_MUTABLE = "mutable"
IMAGE_REFERENCE_VERSIONED_TAG = "versioned-tag"
IMAGE_REFERENCE_DIGEST_PINNED = "digest-pinned"

_OCI_DIGEST = re.compile(r"sha256:[0-9a-fA-F]{64}")
_OCI_TAG = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
_REPOSITORY_COMPONENT = r"[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*"
_REGISTRY_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
_REGISTRY = rf"(?:{_REGISTRY_LABEL}(?:\.{_REGISTRY_LABEL})*|\[[0-9A-Fa-f:.]+\])(?::[0-9]+)?"
_OCI_NAME = re.compile(rf"(?:{_REGISTRY}/)?{_REPOSITORY_COMPONENT}(?:/{_REPOSITORY_COMPONENT})*(?::{_OCI_TAG.pattern})?")


def image_reference_kind(image: str) -> str:
    reference = image
    if not reference:
        return IMAGE_REFERENCE_MUTABLE
    name, separator, digest = reference.partition("@")
    if not _OCI_NAME.fullmatch(name):
        return IMAGE_REFERENCE_MUTABLE
    if separator:
        return IMAGE_REFERENCE_DIGEST_PINNED if _OCI_DIGEST.fullmatch(digest) else IMAGE_REFERENCE_MUTABLE
    component = name.rsplit("/", 1)[-1]
    repository, separator, tag = component.rpartition(":")
    if repository and separator and tag != "latest" and _OCI_TAG.fullmatch(tag):
        return IMAGE_REFERENCE_VERSIONED_TAG
    return IMAGE_REFERENCE_MUTABLE


def is_image_pinned(image: str) -> bool:
    return image_reference_kind(image) == IMAGE_REFERENCE_DIGEST_PINNED
