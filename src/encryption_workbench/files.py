"""Bounded input reads and atomic output creation without overwrites."""

import os
import tempfile
from pathlib import Path

from .container import MAX_ENVELOPE, MAX_PLAINTEXT, FormatError, decrypt_bytes, encrypt_bytes


def read_bounded(path, maximum):
    with Path(path).open("rb") as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise FormatError("Input file exceeds the size limit.")
    return data


def atomic_create(path, data):
    destination = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=destination.parent, prefix=".encryption-", delete=False
        ) as stream:
            temporary = Path(stream.name)
            if os.name == "posix":
                os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        # The temp file is on the same filesystem. link() atomically fails if
        # any destination already exists, including a symlink, without a TOCTOU check.
        os.link(temporary, destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def encrypt_file(source, destination, passphrase):
    data = read_bounded(source, MAX_PLAINTEXT)
    envelope = encrypt_bytes(data, passphrase, filename=Path(source).name)
    atomic_create(destination, envelope)
    return {"plaintext_bytes": len(data), "container_bytes": len(envelope)}


def decrypt_file(source, destination, passphrase):
    result = decrypt_bytes(read_bounded(source, MAX_ENVELOPE), passphrase)
    atomic_create(destination, result.data)
    return {"plaintext_bytes": len(result.data), "authenticated": True}
