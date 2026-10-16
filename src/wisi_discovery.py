"""Experimenteller TV2S-UDP-Broadcast zur Gerätesuche."""
from __future__ import annotations

import argparse
import json
import logging
import socket
import struct
import sys
import time
from collections.abc import Sequence

from wisi_common import DEFAULT_IP
from protocol import TCP_PORT

MAGIC = 0x54563253
VERSION = 0x0100
DISCOVERY_REQUEST = 0x0001
APP_ID = "com.tivicon.tv2smart"


def build_request(sequence_id: int) -> bytes:
    payload = json.dumps(
        {"cmd": "DISCOVER_DONGLE", "app_id": APP_ID},
        separators=(",", ":"),
    ).encode("ascii")
    header = struct.pack(">IHHII", MAGIC, VERSION, DISCOVERY_REQUEST, sequence_id, len(payload))
    return header + payload


def parse_response(data: bytes) -> dict[str, object] | None:
    if len(data) < 16:
        return None
    magic, _version, _opcode, _sequence_id, payload_length = struct.unpack_from(">IHHII", data)
    if magic != MAGIC or payload_length != len(data) - 16:
        return None
    try:
        result = json.loads(data[16:].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(result, dict):
        return None
    return result


def run(ip: str, timeout: float) -> int:
    sequence_id = int(time.time()) & 0xFFFFFFFF
    request = build_request(sequence_id)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        udp.settimeout(timeout)
        udp.sendto(request, ("255.255.255.255", TCP_PORT))
        udp.sendto(request, (ip, TCP_PORT))
        seen: set[tuple[str, str]] = set()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, address = udp.recvfrom(65535)
            except socket.timeout:
                break
            result = parse_response(data)
            if result is None:
                continue
            key = (address[0], json.dumps(result, sort_keys=True))
            if key in seen:
                continue
            seen.add(key)
            print(json.dumps({"ip": address[0], **result}, ensure_ascii=False, indent=2))
    if not seen:
        logging.warning(
            "Keine TV2S-Discovery-Antwort empfangen. Dieses Format ist in den "
            "Projektmitschnitten nicht bestätigt; nutze bei Bedarf --ip direkt."
        )
        return 1
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ip", default=DEFAULT_IP, help="Zusätzliche Ziel-IP")
    parser.add_argument("--timeout", type=float, default=2.0, help="Wartezeit in Sekunden")
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout muss größer als 0 sein.")
    try:
        return run(args.ip, args.timeout)
    except OSError as exc:
        logging.error("Discovery fehlgeschlagen: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
