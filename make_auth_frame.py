#!/usr/bin/env python3
"""
make_auth_frame.py

Create a DF17 ADS-B Extended Squitter authenticity-tag frame for the
Simple ADS-B Authenticity Tag Proposal PoC.

This program generates a 112-bit Mode S / ADS-B frame as a HEX string.

Frame layout:

    DF17 ADS-B Extended Squitter

    | DF | CA | ICAO Address | ME Field | PI |
    | 5  | 3  | 24 bits      | 56 bits  | 24 bits |

ME field layout used by this PoC:

    | Type Code | Timestamp | Truncated HMAC |
    | 5 bits    | 27 bits   | 24 bits        |

The HMAC input is:

    DF
    CA
    ICAO address
    ME Type Code
    Timestamp

The PI field is the normal Mode S 24-bit CRC/parity value.

Example:

    python make_auth_frame.py --key key_ABC123.json --ca 5
    python make_auth_frame.py --key key_ABC123.json --ca 5 --timestamp 12345678 --verbose

Safety note:
    This tool only prints a HEX frame. Do not transmit on 1090 MHz except in
    legally authorized and properly shielded test environments.
"""

import argparse
import base64
import hashlib
import hmac
import json
import time
from pathlib import Path
from typing import Any, Dict, List


DF17 = 17
TYPE_CODE_AUTH_TAG = 24
TIMESTAMP_BITS = 27
HMAC_BITS = 24
TIMESTAMP_MASK = (1 << TIMESTAMP_BITS) - 1
HMAC_MASK = (1 << HMAC_BITS) - 1

# Mode S generator polynomial, excluding the implicit x^24 term.
# Commonly used for ADS-B / Mode S CRC-24 calculation.
MODES_CRC_POLY = 0xFFF409


def normalize_icao(icao: str) -> str:
    value = icao.strip().upper()

    if len(value) != 6:
        raise ValueError("ICAO address must be exactly 6 hexadecimal characters.")

    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError("ICAO address must contain only hexadecimal characters.") from exc

    return value


def load_key_file(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Key file not found: {path}")

    record = json.loads(path.read_text(encoding="utf-8"))

    required = ["scheme", "icao", "key_id", "secret_key_b64"]
    for name in required:
        if name not in record:
            raise ValueError(f"Key file is missing required field: {name}")

    expected_scheme = "ADS-B-AUTH-TAG-HMAC-SHA256-TRUNC24"
    if record["scheme"] != expected_scheme:
        raise ValueError(
            f"Unsupported key scheme: {record['scheme']} "
            f"(expected {expected_scheme})"
        )

    record["icao"] = normalize_icao(record["icao"])

    try:
        secret_key = base64.b64decode(record["secret_key_b64"], validate=True)
    except Exception as exc:
        raise ValueError("Invalid secret_key_b64 in key file.") from exc

    if len(secret_key) < 16:
        raise ValueError("Secret key is unexpectedly short.")

    record["_secret_key_bytes"] = secret_key
    return record


def int_to_bytes(value: int, length: int) -> bytes:
    return value.to_bytes(length, byteorder="big", signed=False)


def make_hmac_message(df: int, ca: int, icao_int: int, type_code: int, timestamp: int) -> bytes:
    """
    Build a compact canonical byte representation for HMAC input.

    This is not the on-air bitstream. It is a stable PoC encoding of:
        DF, CA, ICAO address, ME Type Code, Timestamp
    """
    return b"ADSB-AUTH-TAG-V1" + bytes([
        df & 0x1F,
        ca & 0x07,
        type_code & 0x1F,
    ]) + int_to_bytes(icao_int, 3) + int_to_bytes(timestamp, 4)


def compute_truncated_hmac24(secret_key: bytes, message: bytes) -> int:
    digest = hmac.new(secret_key, message, hashlib.sha256).digest()
    return int.from_bytes(digest[:3], byteorder="big") & HMAC_MASK


def build_me_field(type_code: int, timestamp: int, tag24: int) -> int:
    if not (0 <= type_code < (1 << 5)):
        raise ValueError("Type Code must fit in 5 bits.")

    if not (0 <= timestamp < (1 << 27)):
        raise ValueError("Timestamp must fit in 27 bits.")

    if not (0 <= tag24 < (1 << 24)):
        raise ValueError("HMAC tag must fit in 24 bits.")

    return (type_code << 51) | (timestamp << 24) | tag24


def build_frame_without_pi(df: int, ca: int, icao_int: int, me: int) -> int:
    """
    Build the first 88 bits of a DF17 frame.

    88-bit payload before PI:
        DF:   bits 1..5
        CA:   bits 6..8
        ICAO: bits 9..32
        ME:   bits 33..88
    """
    if not (0 <= df < (1 << 5)):
        raise ValueError("DF must fit in 5 bits.")

    if not (0 <= ca < (1 << 3)):
        raise ValueError("CA must fit in 3 bits.")

    if not (0 <= icao_int < (1 << 24)):
        raise ValueError("ICAO address must fit in 24 bits.")

    if not (0 <= me < (1 << 56)):
        raise ValueError("ME field must fit in 56 bits.")

    return (df << 83) | (ca << 80) | (icao_int << 56) | me


def int_to_bit_list(value: int, bit_len: int) -> List[int]:
    return [(value >> (bit_len - 1 - i)) & 1 for i in range(bit_len)]


def modes_crc24(data: bytes, bit_len: int) -> int:
    """
    Calculate Mode S CRC-24 over the supplied bits.

    For DF17 parity generation, pass the first 88 bits, not including PI.

    Implementation:
        Polynomial long division with the Mode S CRC polynomial 0xFFF409.
    """
    if bit_len <= 0:
        raise ValueError("bit_len must be positive.")

    total_value = int.from_bytes(data, byteorder="big")
    total_bits = len(data) * 8

    if bit_len > total_bits:
        raise ValueError("bit_len exceeds available data bits.")

    # Keep only the first bit_len bits from data.
    value = total_value >> (total_bits - bit_len)

    # Append 24 zero bits.
    work = value << 24

    # Divide by x^24 + MODES_CRC_POLY.
    # When a 1 exists at the current top position, XOR the polynomial aligned there.
    for i in range(bit_len):
        bit_position = bit_len + 24 - 1 - i
        if work & (1 << bit_position):
            work ^= (MODES_CRC_POLY << (bit_position - 24))

    return work & 0xFFFFFF


def make_df17_auth_frame(
    icao: str,
    ca: int,
    secret_key: bytes,
    timestamp: int,
) -> Dict[str, Any]:
    icao = normalize_icao(icao)
    icao_int = int(icao, 16)

    if not (0 <= ca <= 7):
        raise ValueError("CA must be in the range 0..7.")

    timestamp &= TIMESTAMP_MASK

    hmac_message = make_hmac_message(
        df=DF17,
        ca=ca,
        icao_int=icao_int,
        type_code=TYPE_CODE_AUTH_TAG,
        timestamp=timestamp,
    )
    tag24 = compute_truncated_hmac24(secret_key, hmac_message)
    me = build_me_field(TYPE_CODE_AUTH_TAG, timestamp, tag24)

    first88 = build_frame_without_pi(DF17, ca, icao_int, me)
    first88_bytes = first88.to_bytes(11, byteorder="big")
    pi = modes_crc24(first88_bytes, 88)

    frame112 = (first88 << 24) | pi
    frame_hex = f"{frame112:028X}"

    return {
        "frame_hex": frame_hex,
        "df": DF17,
        "ca": ca,
        "icao": icao,
        "type_code": TYPE_CODE_AUTH_TAG,
        "timestamp": timestamp,
        "tag24_hex": f"{tag24:06X}",
        "me_hex": f"{me:014X}",
        "pi_hex": f"{pi:06X}",
        "hmac_input_hex": hmac_message.hex().upper(),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a DF17 ADS-B authenticity-tag frame as a HEX string."
    )

    parser.add_argument(
        "--key",
        required=True,
        help="Key JSON file generated by generate_key.py.",
    )

    parser.add_argument(
        "--ca",
        type=int,
        default=5,
        help="Transponder capability value, 0..7. Default: 5.",
    )

    parser.add_argument(
        "--timestamp",
        type=int,
        default=None,
        help=(
            "Optional 27-bit timestamp. "
            "Default: current Unix time modulo 2^27."
        ),
    )

    parser.add_argument(
        "--icao",
        default=None,
        help=(
            "Optional ICAO address override. "
            "Default: ICAO address stored in the key file."
        ),
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output full result as JSON.",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print decoded fields in addition to the frame HEX.",
    )

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        key_record = load_key_file(Path(args.key))
        secret_key = key_record["_secret_key_bytes"]

        icao = normalize_icao(args.icao) if args.icao else key_record["icao"]

        timestamp = args.timestamp
        if timestamp is None:
            timestamp = int(time.time()) & TIMESTAMP_MASK

        if not (0 <= timestamp <= TIMESTAMP_MASK):
            raise ValueError(f"Timestamp must be in the range 0..{TIMESTAMP_MASK}.")

        result = make_df17_auth_frame(
            icao=icao,
            ca=args.ca,
            secret_key=secret_key,
            timestamp=timestamp,
        )

        result["key_id"] = key_record["key_id"]

        if args.json:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        elif args.verbose:
            print(f"Frame HEX : {result['frame_hex']}")
            print(f"DF        : {result['df']}")
            print(f"CA        : {result['ca']}")
            print(f"ICAO      : {result['icao']}")
            print(f"TC        : {result['type_code']}")
            print(f"Timestamp : {result['timestamp']}")
            print(f"Tag24     : {result['tag24_hex']}")
            print(f"ME        : {result['me_hex']}")
            print(f"PI        : {result['pi_hex']}")
            print(f"Key ID    : {result['key_id']}")
        else:
            print(result["frame_hex"])

        return 0

    except Exception as exc:
        print(f"Error: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
