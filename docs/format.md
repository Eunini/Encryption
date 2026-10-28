# Container format, version 1

The container is UTF-8 JSON with exactly five top-level fields:

| Field | Value |
|---|---|
| `format` | `encryption-workbench` |
| `version` | Integer `1` |
| `kdf` | `name: PBKDF2`, `hash: SHA-256`, integer `iterations: 600000`, base64 `salt` |
| `cipher` | `name: AES-GCM`, integer `bits: 256`, base64 `iv`, integer `tagLength: 128` |
| `ciphertext` | Canonical standard base64 encoding of ciphertext plus its 16-byte GCM tag |

The salt is exactly 16 bytes and the nonce exactly 12 bytes. JSON whitespace and
key order may vary when reading. Duplicate keys, unknown fields, nonfinite values,
unsupported parameter types and noncanonical base64 are rejected.

To build the authenticated additional data, take the four fields excluding
`ciphertext` and serialize with Python JSON settings `sort_keys=True`,
`separators=(",", ":")`, `ensure_ascii=True`, then encode as ASCII/UTF-8.
Changing any parameter or randomness field invalidates authentication.

The encrypted plaintext payload consists of:

1. Four bytes: unsigned big-endian metadata length.
2. Metadata JSON with exactly one string field, `filename`, at most 4096 bytes.
3. Original file bytes, at most 64 MiB.

Metadata is checked only after authenticated decryption. The filename is descriptive
and never determines a write location. Creation strips directory components and
rejects NUL characters. Decryption returns the original file bytes and metadata to
library callers; the CLI writes only to an explicitly supplied output path.

The complete JSON envelope has a fixed upper bound derived from the plaintext
limit, metadata allowance, tag and base64 overhead. No field can select a new KDF,
increase work, request a network resource or load executable code.
