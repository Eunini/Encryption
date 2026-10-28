# Encryption Workbench

A Python CLI and small library for authenticated file encryption. AES-256-GCM
protects file bytes and filename metadata; PBKDF2-HMAC-SHA256 derives the key from
a passphrase. Parsing is bounded, format parameters are fixed, and output creation
is atomic and never overwrites an existing file or symlink.

This is an independent recreation of `Eunini/Encryption`. The previous repository
was unavailable; its original code and commit history have not been recovered.

## Browser workspace

The browser app under `web/` encrypts text and files, authenticates and decrypts
containers, and inspects public headers. Web Crypto runs in a worker. Inputs and
passphrases are never uploaded or saved by the app; only a theme preference is
stored. Clear workspace stops the worker and releases input/output references.

The browser and Python CLI share the same version-one container. Cross-runtime
tests verify Python-created files in the browser and browser-created files in
Python, including binary bytes and Unicode filename metadata. The browser limit
is 16 MiB; the CLI limit is 64 MiB. Both use fresh salts/nonces for actual encryption.

```bash
npm ci --prefix web --ignore-scripts
npm run dev
```

Open `http://localhost:4341`. `npm run build` produces `web/dist/`. The checked-in
`vercel.json` selects Vite, Node 24 via `package.json`, and the matching install,
build and output paths. No server functions or encryption keys are deployed.

To check the browser implementation:

```bash
npm test --prefix web
cd web
npx playwright install chromium
npm run test:browser
```

The Python environment must be installed for cross-runtime tests. Browser tests
cover text/file downloads, authentication failures, malformed containers, clearing,
cancellation, both themes, mobile layouts, accessibility and absence of data uploads.

## Use

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --frozen
uv run encryption encrypt notes.txt notes.enc
uv run encryption inspect notes.enc
uv run encryption verify notes.enc
uv run encryption decrypt notes.enc recovered-notes.txt
```

Encryption prompts for a passphrase and confirmation, with terminal echo disabled.
Verification/decryption prompt once. Passphrases are used exactly as UTF-8 text,
without Unicode normalization. Creation requires at least 12 characters; choose
a strong, unique passphrase. There is no password recovery mechanism.

For automation, set an environment variable through your secret manager and use
`encryption --passphrase-env VARIABLE_NAME encrypt input output`. Only its name
is passed as an argument; the program never prints the value. Non-interactive use
without a selected environment variable fails rather than reading an exposed
passphrase from command arguments or stdin.

All commands print machine-readable JSON on success. Failures return status 2;
an interrupted operation returns 130. `inspect` validates structure and reports
`authenticated: false`. `verify` authenticates the complete container in memory
without creating a plaintext output file.

## Design

- AES-256-GCM through the `cryptography` library and OpenSSL, with a 128-bit tag.
- PBKDF2-HMAC-SHA256, 600,000 iterations, a 32-byte key and a fresh 16-byte salt.
- A fresh 12-byte GCM nonce for each encryption operation.
- A canonical versioned header is authenticated as additional data.
- Filename metadata is encrypted inside the payload and is never used as an
  automatic output path. The caller always selects the output path explicitly.
- Unknown fields, duplicate keys, noncanonical base64, unsupported versions,
  algorithm changes, oversized inputs and modified work factors fail closed.
- Complete authentication happens before plaintext is written. Wrong passphrases
  and cryptographic corruption produce the same authentication error.
- Output is staged with owner-only permissions on POSIX, flushed and atomically
  linked into place. A pre-existing destination, including a symlink, is preserved.

The format and implementation boundaries are documented in
[docs/format.md](docs/format.md) and [docs/security.md](docs/security.md).
This implementation has regression coverage and has not received an independent
security audit.

## Verify and build

```bash
uv sync --frozen --extra dev
uv run ruff check src tests scripts
uv run ruff format --check src tests scripts
uv run pytest
uv build
```

Tests cover binary/Unicode/empty-file round trips, one-megabyte inputs, salt/nonce
freshness, wrong passphrases, authenticated-header tampering, malformed envelopes,
bounded work factors, invalid metadata, safe output creation, failed-write cleanup,
symlink protection and CLI output hygiene. CI repeats these on Python 3.12 and 3.13.

## Historical fixture archive

The application was created in **October 2026**. The `tests/archive/2023/` records
are public, synthetic compatibility fixtures labelled by scenario date. Their
known input text and public regression passphrase are deliberately nonsecret.
The program always generates fresh randomness for actual encryption.

A separate, explicitly reconstructed Git branch assigns those fixture commits to
2023. Those dates are archival labels and do not represent actual authorship,
training, publication or customer activity in 2023. The current implementation and
publication use their actual dates. GridSense's history is unchanged.

MIT license. Copyright 2026 Inioluwa Atanda.
