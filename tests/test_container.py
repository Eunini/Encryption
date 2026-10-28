import base64
import json
import os
import struct

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from encryption_workbench import (
    AuthenticationError,
    FormatError,
    container,
    decrypt_bytes,
    encrypt_bytes,
    inspect_bytes,
)
from encryption_workbench.cli import main
from encryption_workbench.files import atomic_create, decrypt_file, encrypt_file, read_bounded

# Public regression data. This string is deliberately nonsecret and never used
# for user files; it exists only to make the tests reproducible.
PUBLIC_PHRASE = "PUBLIC-REGRESSION-EXAMPLE-ONLY"


@pytest.fixture(scope="module")
def envelope():
    return encrypt_bytes(b"public regression payload\x00\xff", PUBLIC_PHRASE, filename="sample.txt")


@pytest.mark.parametrize(
    "data", [b"", b"hello", bytes(range(256)), "Ẹ káàárọ̀ 🌍".encode(), b"x" * 1_000_000]
)
def test_binary_unicode_empty_and_large_round_trips(data):
    encrypted = encrypt_bytes(data, PUBLIC_PHRASE, filename="private-name.txt")
    assert b"private-name" not in encrypted
    result = decrypt_bytes(encrypted, PUBLIC_PHRASE)
    assert result.data == data
    assert result.filename == "private-name.txt"


def test_fresh_salts_and_nonces():
    first = json.loads(encrypt_bytes(b"same", PUBLIC_PHRASE))
    second = json.loads(encrypt_bytes(b"same", PUBLIC_PHRASE))
    assert first["kdf"]["salt"] != second["kdf"]["salt"]
    assert first["cipher"]["iv"] != second["cipher"]["iv"]
    assert first["ciphertext"] != second["ciphertext"]


def test_wrong_phrase_and_tampering_share_one_authentication_error(envelope):
    damaged = json.loads(envelope)
    ciphertext = bytearray(base64.b64decode(damaged["ciphertext"]))
    ciphertext[0] ^= 1
    damaged["ciphertext"] = base64.b64encode(ciphertext).decode()
    for data, phrase in [
        (envelope, "wrong-public-example"),
        (json.dumps(damaged).encode(), PUBLIC_PHRASE),
    ]:
        with pytest.raises(AuthenticationError, match="incorrect passphrase or damaged container"):
            decrypt_bytes(data, phrase)


@pytest.mark.parametrize("field", ["salt", "iv"])
def test_header_bytes_are_authenticated(envelope, field):
    value = json.loads(envelope)
    parent = value["kdf"] if field == "salt" else value["cipher"]
    data = bytearray(base64.b64decode(parent[field]))
    data[0] ^= 1
    parent[field] = base64.b64encode(data).decode()
    with pytest.raises(AuthenticationError):
        decrypt_bytes(json.dumps(value).encode(), PUBLIC_PHRASE)


@pytest.mark.parametrize(
    "change",
    [
        lambda value: value.update(version=True),
        lambda value: value.update(version=2),
        lambda value: value.update(unknown="x"),
        lambda value: value["kdf"].update(iterations=1),
        lambda value: value["kdf"].update(iterations=600000.0),
        lambda value: value["kdf"].update(iterations=10**20),
        lambda value: value["kdf"].update(hash="SHA-1"),
        lambda value: value["kdf"].update(salt="AA=="),
        lambda value: value["cipher"].update(bits=256.0),
        lambda value: value["cipher"].update(name="AES-CBC"),
        lambda value: value["cipher"].update(iv="bad base64"),
        lambda value: value.update(ciphertext="AAAA===="),
    ],
)
def test_untrusted_parameters_fail_before_key_derivation(envelope, change, monkeypatch):
    value = json.loads(envelope)
    change(value)
    monkeypatch.setattr(
        container, "key_for", lambda *_: pytest.fail("Malformed input must not derive a key")
    )
    with pytest.raises(FormatError):
        decrypt_bytes(json.dumps(value).encode(), PUBLIC_PHRASE)


@pytest.mark.parametrize(
    "value",
    [b"[]", b"null", b"{}", b"{", b"\xff", b'{"version":1,"version":1}', b"[NaN]", b"[" * 2000],
)
def test_malformed_json_is_bounded(value):
    with pytest.raises(FormatError):
        inspect_bytes(value)


def test_payload_and_metadata_bounds_are_checked(monkeypatch, envelope):
    monkeypatch.setattr(container, "MAX_PLAINTEXT", 3)
    with pytest.raises(FormatError):
        encrypt_bytes(b"1234", PUBLIC_PHRASE)
    monkeypatch.setattr(container, "MAX_ENVELOPE", 3)
    with pytest.raises(FormatError):
        inspect_bytes(envelope)
    with pytest.raises(FormatError):
        encrypt_bytes(b"", PUBLIC_PHRASE, filename="x" * 5000)


def test_authenticated_malformed_payload_is_rejected(envelope):
    header, salt, nonce, _ = container.parse(envelope)
    nonce = os.urandom(12)
    header["cipher"]["iv"] = container.encode(nonce)
    data = AESGCM(container.key_for(PUBLIC_PHRASE.encode(), salt)).encrypt(
        nonce,
        struct.pack(">I", container.MAX_METADATA + 1) + b"not metadata",
        container.canonical(header),
    )
    malformed = container.canonical({**header, "ciphertext": container.encode(data)})
    with pytest.raises(FormatError):
        decrypt_bytes(malformed, PUBLIC_PHRASE)


def test_inspection_never_claims_authenticated_data(envelope):
    report = inspect_bytes(envelope)
    assert report["authenticated"] is False
    assert "filename" not in report
    assert report["kdf"]["iterations"] == 600000


@pytest.mark.parametrize("phrase", ["", "short", "x" * 4097, "\ud800" * 12])
def test_creation_rejects_invalid_passphrases(phrase):
    with pytest.raises(FormatError):
        encrypt_bytes(b"public", phrase)


def test_filename_is_metadata_only_and_strips_path_components():
    result = decrypt_bytes(
        encrypt_bytes(b"public", PUBLIC_PHRASE, filename=r"..\folder\report.txt"), PUBLIC_PHRASE
    )
    assert result.filename == "report.txt"


def test_file_roundtrip_does_not_overwrite(tmp_path):
    source = tmp_path / "sample.bin"
    source.write_bytes(bytes(range(256)))
    encrypted = tmp_path / "sample.enc"
    output = tmp_path / "recovered.bin"
    encrypt_file(source, encrypted, PUBLIC_PHRASE)
    decrypt_file(encrypted, output, PUBLIC_PHRASE)
    assert output.read_bytes() == source.read_bytes()
    with pytest.raises(FileExistsError):
        decrypt_file(encrypted, output, PUBLIC_PHRASE)
    assert output.read_bytes() == source.read_bytes()
    assert not list(tmp_path.glob(".encryption-*"))
    if os.name == "posix":
        assert output.stat().st_mode & 0o777 == 0o600


def test_failed_authentication_creates_no_plaintext(tmp_path, envelope):
    source = tmp_path / "input.enc"
    source.write_bytes(envelope)
    output = tmp_path / "output.txt"
    with pytest.raises(AuthenticationError):
        decrypt_file(source, output, "wrong-public-example")
    assert not output.exists() and not list(tmp_path.glob(".encryption-*"))


def test_existing_symlink_is_never_followed(tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"original")
    link = tmp_path / "link"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("Symlink creation is unavailable")
    with pytest.raises(FileExistsError):
        atomic_create(link, b"replacement")
    assert target.read_bytes() == b"original"
    assert not list(tmp_path.glob(".encryption-*"))


def test_failed_link_cleans_temporary_plaintext(tmp_path, monkeypatch):
    def denied(*_):
        raise PermissionError("simulated")

    monkeypatch.setattr(os, "link", denied)
    with pytest.raises(PermissionError):
        atomic_create(tmp_path / "new", b"public test data")
    assert list(tmp_path.iterdir()) == []


def test_bounded_file_reads(tmp_path):
    source = tmp_path / "large"
    source.write_bytes(b"1234")
    with pytest.raises(FormatError):
        read_bounded(source, 3)


def test_cli_never_echoes_passphrases_or_creates_plaintext_on_failure(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setenv("ENCRYPTION_PUBLIC_TEST_PHRASE", PUBLIC_PHRASE)
    source = tmp_path / "source"
    source.write_bytes(b"public example")
    encrypted = tmp_path / "source.enc"
    output = tmp_path / "output"
    prefix = ["--passphrase-env", "ENCRYPTION_PUBLIC_TEST_PHRASE"]
    assert main([*prefix, "encrypt", str(source), str(encrypted)]) == 0
    assert main(["inspect", str(encrypted)]) == 0
    assert main([*prefix, "verify", str(encrypted)]) == 0
    monkeypatch.setenv("ENCRYPTION_PUBLIC_TEST_PHRASE", "wrong-public-example")
    assert main([*prefix, "decrypt", str(encrypted), str(output)]) == 2
    assert not output.exists()
    captured = capsys.readouterr()
    assert PUBLIC_PHRASE not in captured.out + captured.err
    assert "wrong-public-example" not in captured.out + captured.err


def test_unset_environment_value_is_an_error(monkeypatch, capsys, tmp_path):
    monkeypatch.delenv("ENCRYPTION_MISSING_TEST", raising=False)
    assert (
        main(["--passphrase-env", "ENCRYPTION_MISSING_TEST", "verify", str(tmp_path / "missing")])
        == 2
    )
    assert "Traceback" not in capsys.readouterr().err
