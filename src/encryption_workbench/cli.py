import argparse
import getpass
import json
import os
import sys

from .container import MAX_ENVELOPE, AuthenticationError, FormatError, decrypt_bytes, inspect_bytes
from .files import decrypt_file, encrypt_file, read_bounded


def phrase(args, *, creating=False):
    if args.passphrase_env:
        value = os.getenv(args.passphrase_env)
        if value is None:
            raise FormatError("The selected passphrase environment variable is not set.")
        return value
    if not sys.stdin.isatty():
        raise FormatError("Use an interactive terminal or --passphrase-env NAME.")
    value = getpass.getpass("Passphrase: ")
    if creating and getpass.getpass("Confirm passphrase: ") != value:
        raise FormatError("Passphrases do not match.")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Authenticated file encryption; outputs are never overwritten."
    )
    parser.add_argument(
        "--passphrase-env",
        metavar="NAME",
        help="Read a passphrase from an existing environment variable; never pass its value as an argument",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ["encrypt", "decrypt"]:
        child = subparsers.add_parser(command)
        child.add_argument("input")
        child.add_argument("output")
    for command in ["inspect", "verify"]:
        subparsers.add_parser(command).add_argument("input")
    args = parser.parse_args(argv)
    try:
        if args.command == "inspect":
            result = inspect_bytes(read_bounded(args.input, MAX_ENVELOPE))
        elif args.command == "verify":
            plaintext = decrypt_bytes(read_bounded(args.input, MAX_ENVELOPE), phrase(args))
            result = {"authenticated": True, "plaintext_bytes": len(plaintext.data)}
        elif args.command == "encrypt":
            result = encrypt_file(args.input, args.output, phrase(args, creating=True))
        else:
            result = decrypt_file(args.input, args.output, phrase(args))
        print(json.dumps(result, sort_keys=True))
        return 0
    except (AuthenticationError, FormatError, OSError) as error:
        # File paths and exception internals are intentionally excluded from stderr.
        message = (
            str(error)
            if isinstance(error, (AuthenticationError, FormatError))
            else "File operation failed; check paths, permissions and whether the output already exists."
        )
        print(message, file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Operation cancelled.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
