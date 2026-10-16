"""Analysiert klassische PCAP-Dateien auf APIX-Befehle und 0xF9/0x0A-Blobs."""
from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Sequence
from pathlib import Path

from channels import parse_service_db
from pcap_parser import analyze, packets


def run(path: str, extract_service_db: str | None = None) -> int:
    capture_path = Path(path)
    result = analyze(capture_path)
    if extract_service_db is not None:
        candidates = [
            pkt.payload
            for pkt in packets(capture_path)
            if pkt.protocol == 17 and pkt.payload.startswith(b"\xf9\x0a")
        ]
        if not candidates:
            raise ValueError("In der PCAP-Datei wurde keine 0xF9/0x0A-Antwort gefunden.")
        blob = max(candidates, key=len)
        Path(extract_service_db).write_bytes(blob)
        print(
            f"Größte 0xF9/0x0A-Antwort ({len(blob)} Byte) "
            f"nach {extract_service_db} geschrieben."
        )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def run_service_db(path: str) -> int:
    data = Path(path).read_bytes()
    services = parse_service_db(data)
    if not services:
        raise ValueError(
            "Keine Einträge dekodiert. Erwartet wird eine vollständige 0xF9/0x0A-Antwort "
            "mit den vom Client angenommenen Headern."
        )
    result = [
        {
            "pat_index": svc.pat_index,
            "service_id": svc.service_id,
            "prog_idx": f"0x{svc.prog_idx:08X}",
            "video_pid": f"0x{svc.video_pid:04X}",
            "audio_pid": f"0x{svc.audio_pid:04X}",
            "encrypted": svc.is_encrypted,
            "name": svc.name,
        }
        for svc in services
    ]
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", nargs="?", help="Pfad zur klassischen PCAP-Datei")
    parser.add_argument(
        "--decode-service-db",
        metavar="DATEI",
        help="Gespeicherte 0xF9/0x0A-Antwort dekodieren (UDP-Payload als Binärdatei)",
    )
    parser.add_argument(
        "--extract-service-db",
        help="Größte gefundene UDP-0xF9/0x0A-Antwort unverändert speichern",
    )
    args = parser.parse_args(argv)
    if bool(args.pcap) == bool(args.decode_service_db):
        parser.error("Genau eine PCAP-Datei oder --decode-service-db DATEI angeben.")
    try:
        if args.decode_service_db:
            if args.extract_service_db:
                parser.error("--extract-service-db kann nur mit einer PCAP-Datei verwendet werden.")
            return run_service_db(args.decode_service_db)
        return run(args.pcap, args.extract_service_db)
    except (OSError, ValueError) as exc:
        logging.error("%s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
