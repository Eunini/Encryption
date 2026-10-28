import hashlib
import json
from pathlib import Path

from encryption_workbench import decrypt_bytes


def test_frozen_public_archive():
    root = Path(__file__).parent / "archive"
    index = json.loads((root / "index.json").read_text())
    assert index["synthetic"] is True
    assert index["count"] == len(index["files"]) == 335
    for filename, expected_hash in index["files"].items():
        content = (root / filename).read_bytes()
        assert hashlib.sha256(content).hexdigest() == expected_hash
        fixture = json.loads(content)
        assert fixture["synthetic"] is True
        result = decrypt_bytes(
            json.dumps(fixture["envelope"]).encode(), index["public_regression_passphrase"]
        )
        assert result.data == bytes.fromhex(fixture["plaintext_hex"])
        assert result.filename == fixture["expected_filename"]
