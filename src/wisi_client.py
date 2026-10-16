"""
wisi_client.py – CLI-Einstieg und Re-Exporte
=============================================
Dünnes Modul: enthält nur main() für `python src/wisi.py --stream`
und Re-Exportiert DEFAULT_IP für Rückwärtskompatibilität.

Implementierung ist aufgeteilt in:
  models.py    – Channel, ServiceEntry, FALLBACK_SERVICE
  channels.py  – Kanalliste laden + parsen
  stream.py    – Keep-Alive, prepare_channel, stream()
  menu.py      – interaktives Konsolenmenü
  protocol.py  – USBC-Builder, Konstanten, TCP-Helfer, connect/disconnect
"""
from __future__ import annotations

import argparse
import logging
import sys

import protocol
from channels import fetch_channel_list, channels_to_services, fetch_service_db
from menu import main_menu
from models import FALLBACK_SERVICE, ServiceEntry, Channel
from stream import prepare_channel, stream

# Re-Export für wisi.py (importiert DEFAULT_IP von hier)
DEFAULT_IP = protocol.DEFAULT_IP

# Private Aliase für Tests und Rückwärtskompatibilität
_cmd_16 = protocol.cmd_16
_send_recv = protocol.send_recv

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("wisi")


def main() -> None:
    p = argparse.ArgumentParser(
        description="WISI OR S2D DVB-over-IP Client v4 (icube APIX)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--ip", default=DEFAULT_IP)
    p.add_argument("--debug", action="store_true")
    p.add_argument("--stream", action="store_true", help="Direkt streamen")
    p.add_argument("--pat-idx", type=int, default=4, help="PAT-Index für --stream")
    p.add_argument("--output", default="stream.ts")
    p.add_argument("--duration", type=float, default=0.0)
    args = p.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    sock = protocol.connect(args.ip)
    if sock is None:
        sys.exit(1)

    import threading
    lock = threading.Lock()

    if args.stream:
        from stream import _keepalive_worker
        keepalive_stop = threading.Event()
        keepalive = threading.Thread(
            target=_keepalive_worker,
            args=(sock, lock, keepalive_stop),
            daemon=True,
        )
        keepalive.start()
        try:
            channels = fetch_channel_list(sock, lock)
            services = channels_to_services(channels) if channels else [FALLBACK_SERVICE]
            svc = next((s for s in services if s.pat_index == args.pat_idx), None)
            if svc is None:
                log.warning("PAT-Index %d nicht gefunden – nutze Fallback.", args.pat_idx)
                svc = ServiceEntry(**{**FALLBACK_SERVICE.__dict__, "pat_index": args.pat_idx})
            prepare_channel(sock, lock, svc)
            stream(sock, lock, svc, args.output, args.duration, keepalive_active=True)
        finally:
            keepalive_stop.set()
            keepalive.join(timeout=4.0)
            protocol.disconnect(sock)
    else:
        main_menu(sock, args.ip)


if __name__ == "__main__":
    main()
