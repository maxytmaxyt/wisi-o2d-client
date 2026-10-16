"""
menu.py – Interaktives Konsolenmenü für den WISI OR S2D Client
===============================================================
main_menu   – Hauptschleife mit Kanalliste, Prepare, Stream, Re-Connect
_pick_service – Auswahldialog für Dienst aus Liste
"""
from __future__ import annotations

import logging
import socket
import threading
import time
from typing import List, Optional

import protocol
from channels import fetch_channel_list, channels_to_services
from keepalive import _keepalive_worker
from models import ServiceEntry, FALLBACK_SERVICE
from stream import prepare_channel, stream

log = logging.getLogger("wisi.menu")

_MENU = """
╔════════════════════════════════════════════════════╗
║      WISI OR S2D  –  DVB-over-IP Client v4       ║
╠════════════════════════════════════════════════════╣
║  [1]  Kanalliste laden (TCP 0xF6/0x20+0x21)      ║
║  [2]  Kanal vorbereiten + Signal prüfen           ║
║  [3]  Stream starten                              ║
║  [4]  PAT-Index testen (0–5)                      ║
║  [5]  Verbindung neu aufbauen                     ║
║  [q]  Beenden                                     ║
╚════════════════════════════════════════════════════╝"""


def _pick_service(services: List[ServiceEntry]) -> Optional[ServiceEntry]:
    active = [s for s in services if s.is_active and not s.is_encrypted]
    active += [s for s in services if s.is_active and s.is_encrypted]
    if not active:
        active = services

    print(f"\n{'Nr':>4}  {'PAT':>4}  {'sid':>6}  Name")
    print("-" * 60)
    for i, s in enumerate(active[:60], 1):
        lock = "🔒" if s.is_encrypted else "   "
        print(f"{i:>4}  {s.pat_index:>4}  {s.service_id:>6}  {lock} {s.name}")
    print()
    try:
        nr = int(input("Nummer (0=Abbruch): "))
        if 1 <= nr <= len(active):
            return active[nr - 1]
    except (ValueError, EOFError):
        pass
    return None


def main_menu(sock: socket.socket, ip: str) -> None:
    lock = threading.Lock()
    services: List[ServiceEntry] = []
    selected: Optional[ServiceEntry] = None

    keepalive_stop = threading.Event()
    keepalive = threading.Thread(
        target=_keepalive_worker,
        args=(sock, lock, keepalive_stop),
        daemon=True,
    )
    keepalive.start()

    # Beim Start sofort Kanalliste laden
    log.info("Lade Kanalliste via TCP 0xF6/0x20+0x21 …")
    channels = fetch_channel_list(sock, lock)
    if channels:
        services = channels_to_services(channels)
    else:
        log.warning("Kanalliste leer – nutze Fallback.")
        services = [FALLBACK_SERVICE]

    print(_MENU)
    while True:
        try:
            choice = input("\nAuswahl > ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if choice == "q":
            break

        elif choice == "1":
            log.info("Lade Kanalliste …")
            channels = fetch_channel_list(sock, lock)
            if channels:
                services = channels_to_services(channels)
                log.info("%d Kanäle geladen.", len(services))
            else:
                log.warning("Leer – nutze Fallback.")
                services = [FALLBACK_SERVICE]
            selected = _pick_service(services)
            if selected:
                log.info("Gewählt: %s", selected)

        elif choice == "2":
            if not selected:
                log.warning("Erst Kanal wählen (Option 1).")
                continue
            prepare_channel(sock, lock, selected)

        elif choice == "3":
            if not selected:
                selected = FALLBACK_SERVICE
                log.info("Nutze Fallback-Kanal sid=4914")
            if selected.is_encrypted:
                log.warning("Kanal verschlüsselt – Stream evtl. leer.")
            outfile = (
                input("Ausgabedatei [stream.ts] (- für stdout): ").strip() or "stream.ts"
            )
            dur_str = input("Dauer in Sekunden [0=unbegrenzt]: ").strip()
            try:
                dur = float(dur_str) if dur_str else 0.0
            except ValueError:
                dur = 0.0
            stream(sock, lock, selected, outfile, dur, keepalive_active=True)

        elif choice == "4":
            log.info("PAT-Index-Test (schickt 0x01 mit Index 0–5) …")
            for idx in range(6):
                with lock:
                    protocol.send_recv(sock, protocol.cmd_tune(idx), 0, f"0x01 idx={idx}")
                log.info("Index %d gesendet – jetzt UDP-Block prüfen", idx)
                input("  Enter für nächsten Index …")

        elif choice == "5":
            keepalive_stop.set()
            keepalive.join(timeout=4.0)
            protocol.disconnect(sock)
            time.sleep(0.5)
            sock = protocol.connect(ip)
            if sock is None:
                log.error("Verbindung fehlgeschlagen.")
                return
            lock = threading.Lock()
            keepalive_stop = threading.Event()
            keepalive = threading.Thread(
                target=_keepalive_worker,
                args=(sock, lock, keepalive_stop),
                daemon=True,
            )
            keepalive.start()
            print(_MENU)

        else:
            print("1–5 oder q.")

    keepalive_stop.set()
    keepalive.join(timeout=4.0)
    protocol.disconnect(sock)
