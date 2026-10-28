"""Version-one AES-GCM containers. Cryptographic operations use cryptography/OpenSSL."""

import base64
import binascii
import json
import secrets
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAX_PLAINTEXT = 64 * 1024 * 1024
MAX_METADATA = 4096
MAX_CIPHERTEXT = MAX_PLAINTEXT + MAX_METADATA + 4 + 16
MAX_ENVELOPE = ((MAX_CIPHERTEXT + 2) // 3) * 4 + 4096
ITERATIONS = 600_000
AUTHENTICATION_MESSAGE = "Authentication failed: incorrect passphrase or damaged container."


class FormatError(ValueError):
    """A container or plaintext does not satisfy the bounded version-one format."""


class AuthenticationError(ValueError):
    """Authentication failed without returning plaintext or metadata."""


@dataclass(frozen=True)
class Decrypted:
    data: bytes
    filename: str


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def encode(value):
    return base64.b64encode(value).decode("ascii")


def decode(value, *, exact=None, maximum=MAX_CIPHERTEXT):
    if not isinstance(value, str) or len(value) > ((maximum + 2) // 3) * 4:
        raise FormatError("Invalid or oversized base64 field.")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise FormatError("Invalid base64 field.") from None
    if (
        encode(decoded) != value
        or len(decoded) > maximum
        or (exact is not None and len(decoded) != exact)
    ):
        raise FormatError("Noncanonical base64 or incorrect field length.")
    return decoded


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise FormatError("Duplicate JSON keys are not allowed.")
        result[key] = value
    return result


def read_json(data):
    try:
        return json.loads(
            data,
            object_pairs_hook=unique_object,
            parse_constant=lambda _: (_ for _ in ()).throw(FormatError("Nonfinite JSON value.")),
        )
    except (ValueError, UnicodeError, RecursionError):
        raise FormatError("Invalid JSON container or metadata.") from None


def passphrase_bytes(value, *, creating=False):
    if not isinstance(value, str):
        raise FormatError("The passphrase must be text.")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        raise FormatError("The passphrase must be valid UTF-8 text.") from None
    if not encoded or len(encoded) > 4096 or (creating and len(value) < 12):
        raise FormatError(
            "Use a passphrase of at least 12 characters and at most 4096 UTF-8 bytes."
        )
    return encoded


def key_for(passphrase, salt):
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS
    ).derive(passphrase)


def header_for(salt, nonce):
    return {
        "format": "encryption-workbench",
        "version": 1,
        "kdf": {
            "name": "PBKDF2",
            "hash": "SHA-256",
            "iterations": ITERATIONS,
            "salt": encode(salt),
        },
        "cipher": {"name": "AES-GCM", "bits": 256, "iv": encode(nonce), "tagLength": 128},
    }


def parse(envelope):
    if not isinstance(envelope, bytes) or len(envelope) > MAX_ENVELOPE:
        raise FormatError("Container exceeds the size limit.")
    value = read_json(envelope)
    if not isinstance(value, dict) or set(value) != {
        "format",
        "version",
        "kdf",
        "cipher",
        "ciphertext",
    }:
        raise FormatError("Unsupported container fields.")
    if (
        value["format"] != "encryption-workbench"
        or type(value["version"]) is not int
        or value["version"] != 1
    ):
        raise FormatError("Unsupported container format or version.")
    kdf, cipher = value["kdf"], value["cipher"]
    if not isinstance(kdf, dict) or set(kdf) != {"name", "hash", "iterations", "salt"}:
        raise FormatError("Unsupported key-derivation fields.")
    if (
        kdf["name"] != "PBKDF2"
        or kdf["hash"] != "SHA-256"
        or type(kdf["iterations"]) is not int
        or kdf["iterations"] != ITERATIONS
    ):
        raise FormatError("Unsupported key-derivation parameters.")
    if not isinstance(cipher, dict) or set(cipher) != {"name", "bits", "iv", "tagLength"}:
        raise FormatError("Unsupported cipher fields.")
    if (
        cipher["name"] != "AES-GCM"
        or type(cipher["bits"]) is not int
        or cipher["bits"] != 256
        or type(cipher["tagLength"]) is not int
        or cipher["tagLength"] != 128
    ):
        raise FormatError("Unsupported cipher parameters.")
    salt, nonce = (
        decode(kdf["salt"], exact=16, maximum=16),
        decode(cipher["iv"], exact=12, maximum=12),
    )
    ciphertext = decode(value["ciphertext"])
    if len(ciphertext) < 20:
        raise FormatError("Truncated authenticated payload.")
    header = {key: value[key] for key in ["format", "version", "kdf", "cipher"]}
    return header, salt, nonce, ciphertext


def encrypt_bytes(data, passphrase, *, filename="file"):
    if not isinstance(data, bytes) or len(data) > MAX_PLAINTEXT:
        raise FormatError("Plaintext exceeds the 64 MiB limit.")
    phrase = passphrase_bytes(passphrase, creating=True)
    if not isinstance(filename, str) or "\x00" in filename:
        raise FormatError("Invalid filename metadata.")
    filename = filename.replace("\\", "/").rsplit("/", 1)[-1] or "file"
    metadata = canonical({"filename": filename})
    if len(metadata) > MAX_METADATA:
        raise FormatError("Filename metadata is too long.")
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    header = header_for(salt, nonce)
    payload = struct.pack(">I", len(metadata)) + metadata + data
    ciphertext = AESGCM(key_for(phrase, salt)).encrypt(nonce, payload, canonical(header))
    return canonical({**header, "ciphertext": encode(ciphertext)}) + b"\n"


def decrypt_bytes(envelope, passphrase):
    header, salt, nonce, ciphertext = parse(envelope)
    try:
        payload = AESGCM(key_for(passphrase_bytes(passphrase), salt)).decrypt(
            nonce, ciphertext, canonical(header)
        )
    except InvalidTag:
        raise AuthenticationError(AUTHENTICATION_MESSAGE) from None
    length = struct.unpack(">I", payload[:4])[0] if len(payload) >= 4 else MAX_METADATA + 1
    if (
        not 1 <= length <= MAX_METADATA
        or len(payload) < 4 + length
        or len(payload) - 4 - length > MAX_PLAINTEXT
    ):
        raise FormatError("Authenticated payload has invalid metadata bounds.")
    metadata = read_json(payload[4 : 4 + length])
    if (
        not isinstance(metadata, dict)
        or set(metadata) != {"filename"}
        or not isinstance(metadata["filename"], str)
    ):
        raise FormatError("Authenticated payload has invalid metadata.")
    return Decrypted(data=payload[4 + length :], filename=metadata["filename"])


def inspect_bytes(envelope):
    header, _, _, ciphertext = parse(envelope)
    return {
        **header,
        "ciphertext_bytes": len(ciphertext),
        "authenticated": False,
        "note": "Structural inspection only. Authenticate with verify or decrypt.",
    }
