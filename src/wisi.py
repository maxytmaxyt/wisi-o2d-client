"""Einfaches Überskript für die WISI-Dongle-Werkzeuge."""
from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence

from wisi_client import DEFAULT_IP


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="WISI OR S2D: Senderliste, EPG, Stream, Discovery und PCAP-Werkzeuge."
    )
    parser.add_argument("--ip", default=DEFAULT_IP, help="IP-Adresse des Dongles")
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--channels", action="store_true", help="Senderliste anzeigen")
    actions.add_argument("--epg", action="store_true", help="EPG aller Sender als JSON laden")
    actions.add_argument("--stream", action="store_true", help="MPEG-TS-Stream starten")
    actions.add_argument("--discover", action="store_true", help="Experimentelle UDP-Gerätesuche")
    actions.add_argument(
        "--probe-opcode",
        type=lambda value: int(value, 0),
        metavar="OPCODE",
        help="Einen einzelnen unbekannten Opcode testen, z. B. 0x12",
    )
    actions.add_argument("--pcap", metavar="DATEI", help="PCAP-Datei analysieren")
    actions.add_argument(
        "--decode-service-db",
        metavar="DATEI",
        help="Gespeicherten 0xF9/0x0A-Rohblob dekodieren",
    )
    parser.add_argument("--output", default="stream.ts", help="Stream-Datei oder - für stdout")
    parser.add_argument("--duration", type=float, default=0.0, help="Streamdauer in Sekunden")
    parser.add_argument("--pat-idx", type=int, default=4, help="PAT-Index für --stream")
    parser.add_argument("--epg-output", default="epg.json", help="EPG-Datei oder - für stdout")
    parser.add_argument("--epg-limit", type=int, help="EPG nur für die ersten N Sender laden")
    parser.add_argument("--pcap-extract", help="0xF9/0x0A-Antwort zusätzlich in diese Datei schreiben")
    parser.add_argument("--debug", action="store_true", help="Debug-Logs aktivieren")
    args = parser.parse_args(argv)

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    if args.duration < 0:
        parser.error("--duration darf nicht negativ sein.")
    if args.pat_idx < 0 or args.pat_idx > 255:
        parser.error("--pat-idx muss zwischen 0 und 255 liegen.")

    try:
        if args.channels:
            from wisi_channels import run

            return run(args.ip)
        if args.epg:
            from wisi_epg import run

            return run(args.ip, args.epg_output, args.epg_limit)
        if args.stream:
            from wisi_client import main as client_main

            forwarded = ["--ip", args.ip, "--stream", "--pat-idx", str(args.pat_idx),
                         "--output", args.output, "--duration", str(args.duration)]
            if args.debug:
                forwarded.append("--debug")
            original_argv = sys.argv
            try:
                sys.argv = [sys.argv[0], *forwarded]
                client_main()
            finally:
                sys.argv = original_argv
            return 0
        if args.discover:
            from wisi_discovery import run

            return run(args.ip, 2.0)
        if args.probe_opcode is not None:
            from wisi_probe import run

            return run(args.ip, args.probe_opcode)
        if args.pcap:
            from wisi_pcap import run

            return run(args.pcap, args.pcap_extract)
        if args.decode_service_db:
            from wisi_pcap import run_service_db

            if args.pcap_extract:
                parser.error("--pcap-extract kann nicht mit --decode-service-db verwendet werden.")
            return run_service_db(args.decode_service_db)
        if args.pcap_extract:
            parser.error("--pcap-extract benötigt --pcap DATEI.")
        parser.print_help()
        return 0
    except (ConnectionError, OSError, ValueError) as exc:
        logging.error("%s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
