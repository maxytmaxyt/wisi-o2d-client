"""Sendet genau einen ausgewählten, unbekannten APIX-Steueropcode."""
from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence

import protocol
from wisi_common import DEFAULT_IP


def run(ip: str, opcode: int) -> int:
    if not 0x04 <= opcode <= 0x1F or opcode in (0x16, 0x17):
        raise ValueError("Probe erlaubt nur einzelne Opcodes 0x04-0x1F außer 0x16/0x17.")
    sock = protocol.connect(ip)
    if sock is None:
        raise ConnectionError(f"Verbindung zu {ip}:8802 fehlgeschlagen.")
    try:
        response = protocol.send_recv(
            sock,
            protocol.cmd_probe(opcode),
            4,
            f"probe 0x{opcode:02X}",
        )
        print(f"Opcode 0x{opcode:02X}: {response.hex(' ') or '(keine Nutzdaten)'}")
    finally:
        protocol.disconnect(sock)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ip", default=DEFAULT_IP, help="IP-Adresse des Dongles")
    parser.add_argument(
        "--probe-opcode",
        required=True,
        type=lambda value: int(value, 0),
        help="Genau ein Opcode, z. B. 0x12 (kein Opcode-Sweep)",
    )
    args = parser.parse_args(argv)
    try:
        return run(args.ip, args.probe_opcode)
    except (ConnectionError, OSError, ValueError) as exc:
        logging.error("%s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
