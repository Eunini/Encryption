# Security boundaries

The intended setting is a trusted local machine and filesystem. The container
protects file contents and filename metadata against readers who lack the
passphrase, and detects modifications through AES-GCM authentication. File size,
format version, salt, nonce, work factor and ciphertext length remain public.

The implementation delegates encryption and key derivation to
[cryptography's AEAD](https://cryptography.io/en/stable/hazmat/primitives/aead/)
and [key-derivation APIs](https://cryptography.io/en/stable/hazmat/primitives/key-derivation-functions/).
PBKDF2-HMAC-SHA256 at 600,000 iterations is a fixed interoperability choice;
OWASP's [password-storage discussion](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
provides context about work factors, rather than an endorsement of this file format.
PBKDF2 is CPU intensive and does not provide a memory-hard KDF's resistance to
specialized hardware. A strong passphrase remains essential.

AES-GCM nonces are generated independently for each encryption operation, together
with a fresh salt/key. Reusing a nonce with the same key compromises GCM security.
The production library does not accept caller-supplied salts or nonces. Public
archive fixtures use explicitly published, nonsecret test inputs and are never
used to encrypt user data.

The file limit is 64 MiB because encryption and authentication operate on complete
in-memory payloads. Plaintext and passphrases cannot be guaranteed to be erased
from Python's memory, swap or process dumps. The program does not protect an
already-compromised host, an observed terminal, deleted-file recovery, or an
attacker with the same account's access to live process memory.

Output publication uses a temporary file in the destination directory, mode 0600
on POSIX, `fsync` and atomic `link`. Existing destinations are never overwritten.
Filesystems must support hard links; unsupported operations fail and clean up the
temporary file. This is not a promise about every filesystem's crash durability.
Permission semantics on non-POSIX systems depend on that system's ACLs.

An inspection result is unauthenticated. Authentication failure returns no
plaintext or filename. There is no recovery key, remote service, telemetry,
user account or network dependency in the encryption/verification operations.
The implementation has not been independently audited or certified as FIPS compliant.
