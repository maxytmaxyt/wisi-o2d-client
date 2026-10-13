"""Lädt und zeigt die vom Dongle angebotene Service-Datenbank an."""
from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence

from wisi_common import DEFAULT_IP, load_services


def run(ip: str) -> int:
    services = load_services(ip)
    print(f"{'PAT':>4} {'SID':>6} {'prog_idx':>10} {'vPID':>6} {'aPID':>6} {'Status':>8}  Name")
    for service in services:
        state = "verschl." if service.is_encrypted else "FTA"
        print(
            f"{service.pat_index:>4} {service.service_id:>6} "
            f"0x{service.prog_idx:08X} 0x{service.video_pid:04X} "
            f"0x{service.audio_pid:04X} {state:>8}  {service.name}"
        )
    print(f"\n{len(services)} Sender gefunden.")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ip", default=DEFAULT_IP, help="IP-Adresse des Dongles")
    args = parser.parse_args(argv)
    try:
        return run(args.ip)
    except (ConnectionError, OSError) as exc:
        logging.error("%s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
