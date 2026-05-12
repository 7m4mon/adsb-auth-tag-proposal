#!/usr/bin/env python3
"""
generate_key.py

Generate an aircraft/transmitter-specific HMAC secret key for the
Simple ADS-B Authenticity Tag Proposal PoC.

This tool does NOT generate a public/private key pair.
For this PoC, authentication is based on a shared secret key used for
HMAC-SHA256. The same key must be available to the frame generator and
the online verification server.

Example:

    python generate_key.py --icao ABC123 --password testpass --out aircraft_key.json

If --password is omitted, the program asks for it without echoing.
"""

import argparse
import base64
import getpass
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


DEFAULT_ITERATIONS = 200_000
KEY_LEN_BYTES = 32


def normalize_icao(icao: str) -> str:
    """
    Normalize and validate a 24-bit ICAO aircraft address.

    Expected format:
        6 hexadecimal characters, e.g. ABC123
    """
    value = icao.strip().upper()

    if len(value) != 6:
        raise ValueError("ICAO address must be exactly 6 hexadecimal characters.")

    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError("ICAO address must contain only hexadecimal characters.") from exc

    return value


def derive_key_from_password(
    password: str,
    salt: bytes,
    iterations: int = DEFAULT_ITERATIONS,
    key_len: int = KEY_LEN_BYTES,
) -> bytes:
    """
    Derive a fixed-length HMAC secret key from a password using PBKDF2-HMAC-SHA256.

    This is suitable for a demonstration PoC, but a real operational system
    should use a formally specified key provisioning and management process.
    """
    if not password:
        raise ValueError("Password must not be empty.")

    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=key_len,
    )


def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def build_key_record(
    icao: str,
    key_id: str,
    password: str,
    iterations: int,
) -> Dict[str, Any]:
    salt = os.urandom(16)
    secret_key = derive_key_from_password(password, salt, iterations)

    created_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    return {
        "version": 1,
        "scheme": "ADS-B-AUTH-TAG-HMAC-SHA256-TRUNC24",
        "icao": icao,
        "key_id": key_id,
        "kdf": {
            "name": "PBKDF2-HMAC-SHA256",
            "iterations": iterations,
            "salt_b64": b64encode(salt),
            "key_len_bytes": KEY_LEN_BYTES,
        },
        "secret_key_b64": b64encode(secret_key),
        "created_at_utc": created_at,
        "notes": [
            "PoC key file for ADS-B authenticity tag experiments.",
            "This is a shared secret key, not a public/private key pair.",
            "Keep this file private. Do not commit real keys to a public repository.",
            "Use only in a shielded, offline, or simulated environment. Do not transmit on 1090 MHz."
        ],
    }


def write_json(path: Path, record: Dict[str, Any], overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise FileExistsError(
            f"{path} already exists. Use --force to overwrite it."
        )

    path.write_text(
        json.dumps(record, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate an HMAC key file for the ADS-B authenticity tag PoC."
    )

    parser.add_argument(
        "--icao",
        required=True,
        help="24-bit ICAO aircraft address as 6 hex characters, e.g. ABC123.",
    )

    parser.add_argument(
        "--key-id",
        default=None,
        help="Optional key identifier. Default: <ICAO>-demo-key-001.",
    )

    parser.add_argument(
        "--password",
        default=None,
        help=(
            "Password/passphrase used to derive the HMAC key. "
            "If omitted, you will be prompted securely."
        ),
    )

    parser.add_argument(
        "--iterations",
        type=int,
        default=DEFAULT_ITERATIONS,
        help=f"PBKDF2 iteration count. Default: {DEFAULT_ITERATIONS}.",
    )

    parser.add_argument(
        "--out",
        default=None,
        help="Output JSON file. Default: key_<ICAO>.json.",
    )

    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite the output file if it already exists.",
    )

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        icao = normalize_icao(args.icao)

        if args.iterations < 100_000:
            raise ValueError("Iterations should be at least 100000 for this PoC.")

        password = args.password
        if password is None:
            password = getpass.getpass("Password/passphrase: ")
            password_confirm = getpass.getpass("Confirm password/passphrase: ")
            if password != password_confirm:
                raise ValueError("Passwords do not match.")

        key_id = args.key_id or f"{icao}-demo-key-001"
        output_path = Path(args.out or f"key_{icao}.json")

        record = build_key_record(
            icao=icao,
            key_id=key_id,
            password=password,
            iterations=args.iterations,
        )

        write_json(output_path, record, overwrite=args.force)

        print(f"Generated key file: {output_path}")
        print(f"ICAO address      : {record['icao']}")
        print(f"Key ID            : {record['key_id']}")
        print(f"Scheme            : {record['scheme']}")
        print("")
        print("Important:")
        print("  This file contains a shared secret key.")
        print("  Keep it private and do not commit real keys to a public repository.")
        print("  Use this PoC only in simulation or shielded test environments.")

        return 0

    except Exception as exc:
        print(f"Error: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
