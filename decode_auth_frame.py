#!/usr/bin/env python3
"""
decode_auth_frame.py

Decode a 112-bit DF17 ADS-B authenticity-tag frame for the
Simple ADS-B Authenticity Tag Proposal PoC.

This tool:
  - Accepts a 28-hex-character Mode S / ADS-B frame
  - Splits it into DF, CA, ICAO Address, ME Field, and PI
  - Recalculates Mode S CRC/parity over the first 88 bits
  - Checks whether the received PI matches the calculated PI
  - If ME Type Code is 24, decodes:
      Type Code
      27-bit timestamp
      24-bit truncated HMAC tag

Example:

    python decode_auth_frame.py 8DABC123C0..............
    python decode_auth_frame.py 8DABC123C0.............. --json

Safety note:
    This tool only decodes HEX strings. It does not receive or transmit RF.
"""

import argparse
import json
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict


DF17 = 17
TYPE_CODE_AUTH_TAG = 24
TIMESTAMP_BITS = 27
TIMESTAMP_MASK = (1 << TIMESTAMP_BITS) - 1

# Mode S generator polynomial, excluding the implicit x^24 term.
# This must match make_auth_frame.py.
MODES_CRC_POLY = 0xFFF409


def clean_frame_hex(frame_hex: str) -> str:
    """
    Normalize a frame HEX string.

    Accepts:
      - plain 28-character HEX
      - strings with spaces, underscores, or colons
      - optional 0x prefix
    """
    value = frame_hex.strip()

    if value.lower().startswith("0x"):
        value = value[2:]

    value = re.sub(r"[\s_:.-]", "", value).upper()

    if len(value) != 28:
        raise ValueError(
            f"Frame must be exactly 28 hex characters for a 112-bit ADS-B frame. "
            f"Got {len(value)} characters."
        )

    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError("Frame contains non-hexadecimal characters.") from exc

    return value


def modes_crc24(data: bytes, bit_len: int) -> int:
    """
    Calculate Mode S CRC-24 over the supplied bits.

    For DF17 parity checking, pass the first 88 bits, not including PI.
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

    # Polynomial long division.
    for i in range(bit_len):
        bit_position = bit_len + 24 - 1 - i
        if work & (1 << bit_position):
            work ^= (MODES_CRC_POLY << (bit_position - 24))

    return work & 0xFFFFFF


def format_timestamp_info(timestamp: int, now_mod: int) -> Dict[str, Any]:
    """
    Provide useful PoC timestamp information.

    The timestamp is modulo 2^27 seconds, so it is not an absolute Unix time.
    We still calculate the shortest modular difference from current time modulo 2^27.
    """
    modulo = 1 << TIMESTAMP_BITS
    forward = (timestamp - now_mod) % modulo
    backward = (now_mod - timestamp) % modulo

    if backward <= forward:
        signed_delta = -backward
    else:
        signed_delta = forward

    return {
        "current_unix_time_mod_2_27": now_mod,
        "delta_from_now_seconds_modular": signed_delta,
        "note": (
            "Timestamp is modulo 2^27 seconds and is not an absolute time "
            "without additional epoch/key-period context."
        ),
    }


def decode_auth_frame(frame_hex: str) -> Dict[str, Any]:
    frame_hex = clean_frame_hex(frame_hex)
    frame = int(frame_hex, 16)

    # Full frame:
    #   DF:   top 5 bits
    #   CA:   next 3 bits
    #   ICAO: next 24 bits
    #   ME:   next 56 bits
    #   PI:   last 24 bits
    df = (frame >> 107) & 0x1F
    ca = (frame >> 104) & 0x07
    icao = (frame >> 80) & 0xFFFFFF
    me = (frame >> 24) & 0x00FFFFFFFFFFFFFF
    received_pi = frame & 0xFFFFFF

    first88 = frame >> 24
    first88_bytes = first88.to_bytes(11, byteorder="big")
    calculated_pi = modes_crc24(first88_bytes, 88)

    crc_ok = received_pi == calculated_pi

    type_code = (me >> 51) & 0x1F

    result: Dict[str, Any] = {
        "frame_hex": frame_hex,
        "df": df,
        "ca": ca,
        "icao": f"{icao:06X}",
        "me_hex": f"{me:014X}",
        "pi_received_hex": f"{received_pi:06X}",
        "pi_calculated_hex": f"{calculated_pi:06X}",
        "crc_ok": crc_ok,
        "type_code": type_code,
        "is_df17": df == DF17,
        "is_auth_tag_frame": df == DF17 and type_code == TYPE_CODE_AUTH_TAG,
    }

    if type_code == TYPE_CODE_AUTH_TAG:
        timestamp = (me >> 24) & TIMESTAMP_MASK
        tag24 = me & 0xFFFFFF
        now_mod = int(time.time()) & TIMESTAMP_MASK

        result.update(
            {
                "timestamp": timestamp,
                "tag24_hex": f"{tag24:06X}",
                "timestamp_info": format_timestamp_info(timestamp, now_mod),
            }
        )

    return result


def print_human(result: Dict[str, Any]) -> None:
    print(f"Frame HEX       : {result['frame_hex']}")
    print(f"DF              : {result['df']}")
    print(f"CA              : {result['ca']}")
    print(f"ICAO            : {result['icao']}")
    print(f"ME              : {result['me_hex']}")
    print(f"PI received     : {result['pi_received_hex']}")
    print(f"PI calculated   : {result['pi_calculated_hex']}")
    print(f"CRC/PI          : {'OK' if result['crc_ok'] else 'NG'}")
    print(f"Type Code       : {result['type_code']}")

    if result["is_auth_tag_frame"]:
        print("")
        print("ADS-B Authenticity Tag Frame")
        print(f"Timestamp       : {result['timestamp']}")
        print(f"Tag24           : {result['tag24_hex']}")
        print(
            "Delta from now  : "
            f"{result['timestamp_info']['delta_from_now_seconds_modular']} sec "
            "(modulo 2^27)"
        )
    else:
        print("")
        if not result["is_df17"]:
            print("Note            : This is not a DF17 frame.")
        else:
            print("Note            : This is DF17, but not a TC24 authenticity-tag frame.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Decode a 112-bit DF17 ADS-B authenticity-tag frame."
    )

    parser.add_argument(
        "frame",
        help="28-hex-character Mode S / ADS-B frame.",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output decoded result as JSON.",
    )

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        result = decode_auth_frame(args.frame)

        if args.json:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print_human(result)

        return 0

    except Exception as exc:
        print(f"Error: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
