#!/usr/bin/env python3
"""
verify_server.py

HTTP verification server for the Simple ADS-B Authenticity Tag Proposal PoC.

This server receives a 112-bit DF17 ADS-B authenticity-tag frame as a HEX string,
decodes it, checks Mode S CRC/parity, recomputes the 24-bit truncated HMAC using
a shared secret key, and returns a JSON verification result.

This is the online verification-server model:

    Receiver
      -> sends raw frame HEX to server over HTTP
    Server
      -> looks up the aircraft/transmitter shared secret key
      -> recomputes HMAC-SHA256 and truncates it to 24 bits
      -> compares it with the Tag24 value in the ADS-B frame

Example:

    # 1. Generate a key
    python generate_key.py --icao ABC123 --password testpass --out keys/key_ABC123.json

    # 2. Generate a frame
    python make_auth_frame.py --key keys/key_ABC123.json --ca 5

    # 3. Start server
    python verify_server.py --key-dir keys --host 127.0.0.1 --port 8000

    # 4. Verify
    curl "http://127.0.0.1:8000/verify?frame=8DABC123C0.............."

Available endpoints:

    GET  /health
    GET  /verify?frame=<28 hex chars>
    POST /verify
         {"frame": "<28 hex chars>"}

Safety note:
    This server only verifies HEX strings. It does not receive or transmit RF.
    Use this PoC only in simulation or shielded test environments.
"""

import argparse
import base64
import hashlib
import hmac
import json
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlparse


DF17 = 17
TYPE_CODE_AUTH_TAG = 24
TIMESTAMP_BITS = 27
TIMESTAMP_MASK = (1 << TIMESTAMP_BITS) - 1
HMAC_MASK = (1 << 24) - 1
MODES_CRC_POLY = 0xFFF409

EXPECTED_SCHEME = "ADS-B-AUTH-TAG-HMAC-SHA256-TRUNC24"


def clean_frame_hex(frame_hex: str) -> str:
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


def normalize_icao(icao: str) -> str:
    value = icao.strip().upper()

    if len(value) != 6:
        raise ValueError("ICAO address must be exactly 6 hexadecimal characters.")

    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError("ICAO address must contain only hexadecimal characters.") from exc

    return value


def modes_crc24(data: bytes, bit_len: int) -> int:
    if bit_len <= 0:
        raise ValueError("bit_len must be positive.")

    total_value = int.from_bytes(data, byteorder="big")
    total_bits = len(data) * 8

    if bit_len > total_bits:
        raise ValueError("bit_len exceeds available data bits.")

    value = total_value >> (total_bits - bit_len)
    work = value << 24

    for i in range(bit_len):
        bit_position = bit_len + 24 - 1 - i
        if work & (1 << bit_position):
            work ^= (MODES_CRC_POLY << (bit_position - 24))

    return work & 0xFFFFFF


def make_hmac_message(df: int, ca: int, icao_int: int, type_code: int, timestamp: int) -> bytes:
    """
    Must match make_auth_frame.py.
    """
    return b"ADSB-AUTH-TAG-V1" + bytes([
        df & 0x1F,
        ca & 0x07,
        type_code & 0x1F,
    ]) + icao_int.to_bytes(3, byteorder="big") + timestamp.to_bytes(4, byteorder="big")


def compute_truncated_hmac24(secret_key: bytes, message: bytes) -> int:
    digest = hmac.new(secret_key, message, hashlib.sha256).digest()
    return int.from_bytes(digest[:3], byteorder="big") & HMAC_MASK


def decode_frame(frame_hex: str) -> Dict[str, Any]:
    frame_hex = clean_frame_hex(frame_hex)
    frame = int(frame_hex, 16)

    df = (frame >> 107) & 0x1F
    ca = (frame >> 104) & 0x07
    icao_int = (frame >> 80) & 0xFFFFFF
    me = (frame >> 24) & 0x00FFFFFFFFFFFFFF
    received_pi = frame & 0xFFFFFF

    first88 = frame >> 24
    first88_bytes = first88.to_bytes(11, byteorder="big")
    calculated_pi = modes_crc24(first88_bytes, 88)

    type_code = (me >> 51) & 0x1F

    result: Dict[str, Any] = {
        "frame_hex": frame_hex,
        "df": df,
        "ca": ca,
        "icao": f"{icao_int:06X}",
        "icao_int": icao_int,
        "me_hex": f"{me:014X}",
        "pi_received_hex": f"{received_pi:06X}",
        "pi_calculated_hex": f"{calculated_pi:06X}",
        "crc_ok": received_pi == calculated_pi,
        "type_code": type_code,
        "is_df17": df == DF17,
        "is_auth_tag_frame": df == DF17 and type_code == TYPE_CODE_AUTH_TAG,
    }

    if type_code == TYPE_CODE_AUTH_TAG:
        timestamp = (me >> 24) & TIMESTAMP_MASK
        tag24 = me & 0xFFFFFF
        result.update(
            {
                "timestamp": timestamp,
                "tag24_hex": f"{tag24:06X}",
                "tag24_int": tag24,
            }
        )

    return result


def load_key_record(path: Path) -> Dict[str, Any]:
    record = json.loads(path.read_text(encoding="utf-8"))

    required = ["scheme", "icao", "key_id", "secret_key_b64"]
    for name in required:
        if name not in record:
            raise ValueError(f"{path} is missing required field: {name}")

    if record["scheme"] != EXPECTED_SCHEME:
        raise ValueError(
            f"{path} has unsupported scheme: {record['scheme']} "
            f"(expected {EXPECTED_SCHEME})"
        )

    icao = normalize_icao(record["icao"])

    try:
        secret_key = base64.b64decode(record["secret_key_b64"], validate=True)
    except Exception as exc:
        raise ValueError(f"{path} has invalid secret_key_b64.") from exc

    if len(secret_key) < 16:
        raise ValueError(f"{path} has unexpectedly short secret key.")

    return {
        "icao": icao,
        "key_id": str(record["key_id"]),
        "secret_key": secret_key,
        "source_file": str(path),
    }


def load_key_database(key_dir: Path) -> Dict[str, Dict[str, Any]]:
    if not key_dir.exists():
        raise FileNotFoundError(f"Key directory not found: {key_dir}")

    if not key_dir.is_dir():
        raise ValueError(f"Key path is not a directory: {key_dir}")

    database: Dict[str, Dict[str, Any]] = {}

    for path in sorted(key_dir.glob("*.json")):
        record = load_key_record(path)
        icao = record["icao"]

        if icao in database:
            raise ValueError(
                f"Duplicate key record for ICAO {icao}: "
                f"{database[icao]['source_file']} and {path}"
            )

        database[icao] = record

    if not database:
        raise ValueError(f"No key JSON files found in {key_dir}")

    return database


def modular_time_delta_seconds(timestamp: int, now_mod: int) -> int:
    modulo = 1 << TIMESTAMP_BITS
    forward = (timestamp - now_mod) % modulo
    backward = (now_mod - timestamp) % modulo
    return -backward if backward <= forward else forward


def verify_frame(
    frame_hex: str,
    key_db: Dict[str, Dict[str, Any]],
    max_abs_age_seconds: Optional[int],
) -> Dict[str, Any]:
    decoded = decode_frame(frame_hex)

    result: Dict[str, Any] = {
        "ok": False,
        "valid_crc": decoded["crc_ok"],
        "valid_auth": False,
        "valid_time": None,
        "reason": "",
        "decoded": {
            key: value
            for key, value in decoded.items()
            if key not in ("icao_int", "tag24_int")
        },
    }

    if not decoded["crc_ok"]:
        result["reason"] = "CRC/PI check failed."
        return result

    if not decoded["is_df17"]:
        result["reason"] = "Frame is not DF17."
        return result

    if not decoded["is_auth_tag_frame"]:
        result["reason"] = "Frame is DF17 but not TC24 authenticity-tag frame."
        return result

    icao = decoded["icao"]
    key_record = key_db.get(icao)

    if key_record is None:
        result["reason"] = f"No key found for ICAO {icao}."
        return result

    hmac_message = make_hmac_message(
        df=decoded["df"],
        ca=decoded["ca"],
        icao_int=decoded["icao_int"],
        type_code=decoded["type_code"],
        timestamp=decoded["timestamp"],
    )

    expected_tag = compute_truncated_hmac24(key_record["secret_key"], hmac_message)
    received_tag = decoded["tag24_int"]

    valid_auth = hmac.compare_digest(
        f"{expected_tag:06X}",
        f"{received_tag:06X}",
    )

    now_mod = int(time.time()) & TIMESTAMP_MASK
    age_delta = modular_time_delta_seconds(decoded["timestamp"], now_mod)

    if max_abs_age_seconds is None:
        valid_time: Optional[bool] = None
    else:
        valid_time = abs(age_delta) <= max_abs_age_seconds

    result.update(
        {
            "valid_auth": valid_auth,
            "valid_time": valid_time,
            "key_id": key_record["key_id"],
            "expected_tag24_hex": f"{expected_tag:06X}",
            "received_tag24_hex": f"{received_tag:06X}",
            "timestamp_delta_from_now_seconds_modular": age_delta,
            "timestamp_policy": {
                "max_abs_age_seconds": max_abs_age_seconds,
                "note": (
                    "Timestamp is modulo 2^27 seconds. "
                    "A real system also needs key-period/epoch context."
                ),
            },
        }
    )

    if not valid_auth:
        result["reason"] = "HMAC tag verification failed."
        return result

    if valid_time is False:
        result["reason"] = "Timestamp is outside the accepted time window."
        return result

    result["ok"] = True
    result["reason"] = "Frame is valid."
    return result


class VerifyRequestHandler(BaseHTTPRequestHandler):
    key_db: Dict[str, Dict[str, Any]] = {}
    max_abs_age_seconds: Optional[int] = 300

    server_version = "ADSBAUTHVerifyPoC/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        # Keep default access logs but make them slightly cleaner.
        print(f"{self.address_string()} - {fmt % args}")

    def send_json(self, status: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def read_json_body(self) -> Dict[str, Any]:
        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length <= 0:
            raise ValueError("Request body is empty.")

        raw = self.rfile.read(content_length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise ValueError("Request body is not valid JSON.") from exc

        if not isinstance(payload, dict):
            raise ValueError("JSON body must be an object.")

        return payload

    def do_GET(self) -> None:
        parsed = urlparse(self.path)

        if parsed.path == "/health":
            self.send_json(
                200,
                {
                    "ok": True,
                    "service": "ADS-B authenticity tag verification server PoC",
                    "loaded_keys": sorted(self.key_db.keys()),
                    "max_abs_age_seconds": self.max_abs_age_seconds,
                },
            )
            return

        if parsed.path != "/verify":
            self.send_json(
                404,
                {
                    "ok": False,
                    "reason": "Not found. Use /health or /verify?frame=<hex>.",
                },
            )
            return

        query = parse_qs(parsed.query)
        frame_values = query.get("frame")

        if not frame_values:
            self.send_json(
                400,
                {
                    "ok": False,
                    "reason": "Missing required query parameter: frame",
                },
            )
            return

        self.handle_verify(frame_values[0])

    def do_POST(self) -> None:
        parsed = urlparse(self.path)

        if parsed.path != "/verify":
            self.send_json(
                404,
                {
                    "ok": False,
                    "reason": "Not found. Use POST /verify with JSON body.",
                },
            )
            return

        try:
            payload = self.read_json_body()
            frame = payload.get("frame")
            if not isinstance(frame, str):
                raise ValueError("JSON field 'frame' must be a string.")

            self.handle_verify(frame)

        except Exception as exc:
            self.send_json(
                400,
                {
                    "ok": False,
                    "reason": str(exc),
                },
            )

    def handle_verify(self, frame: str) -> None:
        try:
            result = verify_frame(
                frame_hex=frame,
                key_db=self.key_db,
                max_abs_age_seconds=self.max_abs_age_seconds,
            )

            status = 200 if result["ok"] else 400
            self.send_json(status, result)

        except Exception as exc:
            self.send_json(
                400,
                {
                    "ok": False,
                    "reason": str(exc),
                },
            )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run an HTTP verification server for ADS-B authenticity-tag frames."
    )

    parser.add_argument(
        "--key-dir",
        required=True,
        help="Directory containing key_*.json files generated by generate_key.py.",
    )

    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind host. Default: 127.0.0.1.",
    )

    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Bind port. Default: 8000.",
    )

    parser.add_argument(
        "--max-age",
        type=int,
        default=300,
        help=(
            "Maximum absolute timestamp delta in seconds, modulo 2^27. "
            "Default: 300. Use -1 to disable timestamp freshness check."
        ),
    )

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        key_dir = Path(args.key_dir)
        key_db = load_key_database(key_dir)

        max_abs_age_seconds: Optional[int]
        if args.max_age < 0:
            max_abs_age_seconds = None
        else:
            max_abs_age_seconds = args.max_age

        VerifyRequestHandler.key_db = key_db
        VerifyRequestHandler.max_abs_age_seconds = max_abs_age_seconds

        httpd = ThreadingHTTPServer((args.host, args.port), VerifyRequestHandler)

        print("ADS-B authenticity tag verification server PoC")
        print(f"Listening on        : http://{args.host}:{args.port}")
        print(f"Loaded key directory: {key_dir}")
        print(f"Loaded ICAO keys    : {', '.join(sorted(key_db.keys()))}")
        print(f"Timestamp max age   : {max_abs_age_seconds}")
        print("")
        print("Endpoints:")
        print(f"  GET  http://{args.host}:{args.port}/health")
        print(f"  GET  http://{args.host}:{args.port}/verify?frame=<28-hex-frame>")
        print(f"  POST http://{args.host}:{args.port}/verify")
        print("")
        print("Press Ctrl+C to stop.")

        httpd.serve_forever()
        return 0

    except KeyboardInterrupt:
        print("\nStopped.")
        return 0

    except Exception as exc:
        print(f"Error: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
