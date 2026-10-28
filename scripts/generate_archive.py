"""Create public, synthetic 2023 calendar fixtures using the current implementation."""

import hashlib
import json
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

from encryption_workbench import encrypt_bytes

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_PHRASE = "PUBLIC-REGRESSION-EXAMPLE-ONLY"


def main():
    folder = ROOT / "tests/archive/2023"
    index = ROOT / "tests/archive/index.json"
    if index.exists():
        raise SystemExit("Archive already exists; refusing to change frozen regression fixtures.")
    folder.mkdir(parents=True, exist_ok=True)
    generated_at = datetime.now(UTC).isoformat()
    days = [date(2023, 1, 1) + timedelta(days=index) for index in range(365)]
    # Same calendar in both projects; dates are sampled once, not user activity.
    days = sorted(
        sorted(days, key=lambda day: hashlib.sha256(f"2023-portfolio:{day}".encode()).hexdigest())[
            :335
        ]
    )
    files = {}
    for number, day in enumerate(days, 1):
        plaintext = (
            f"Public compatibility fixture for {day}. Ẹ káàárọ̀.\n".encode()
            + hashlib.sha256(str(day).encode()).digest()
        )
        envelope = encrypt_bytes(plaintext, PUBLIC_PHRASE, filename=f"public-{day}.bin")
        fixture = {
            "schema": 1,
            "scenario_date": str(day),
            "generated_at": generated_at,
            "synthetic": True,
            "plaintext_hex": plaintext.hex(),
            "expected_filename": f"public-{day}.bin",
            "envelope": json.loads(envelope),
        }
        content = (json.dumps(fixture, indent=2, ensure_ascii=False) + "\n").encode()
        path = folder / f"{day}.json"
        path.write_bytes(content)
        files[str(path.relative_to(ROOT / "tests/archive"))] = hashlib.sha256(content).hexdigest()
        if number % 50 == 0:
            print(json.dumps({"generated": number, "total": len(days)}), flush=True)
    index.write_text(
        json.dumps(
            {
                "schema": 1,
                "generated_at": generated_at,
                "synthetic": True,
                "public_regression_passphrase": PUBLIC_PHRASE,
                "count": len(days),
                "files": files,
            },
            indent=2,
        )
        + "\n"
    )
    print(json.dumps({"generated": len(days), "status": "complete"}))


if __name__ == "__main__":
    main()
