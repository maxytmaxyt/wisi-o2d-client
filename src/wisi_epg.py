"""EPG-Daten des Dongles abrufen und als JSON speichern."""
from __future__ import annotations

import argparse
import json
import logging
import struct
import sys
import threading
import xml.etree.ElementTree as ET
from collections.abc import Sequence
from pathlib import Path
from typing import Dict, List

import protocol
from keepalive import _keepalive_worker
from models import ServiceEntry
from wisi_common import DEFAULT_IP, load_services


# ---------------------------------------------------------------------------
# EPG laden (0xF6/0x30 + 0xF6/0x31)
# ---------------------------------------------------------------------------
def _fetch_epg_for_service(
    sock,
    lock: threading.Lock,
    svc: ServiceEntry,
) -> List[dict]:
    """Lädt EPG-XML für einen Dienst. Gibt Liste von Event-Dicts zurück."""
    with lock:
        r = protocol.send_recv(sock, protocol.cmd_epg_size(svc.prog_idx), 6, "0x30 epg-size")
    if len(r) < 6:
        return []
    size = struct.unpack(">I", r[2:6])[0]
    if size == 0:
        return []

    with lock:
        r = protocol.send_recv(
            sock, protocol.cmd_epg_data(svc.prog_idx, 0, size), size, "0x31 epg-data"
        )
    xml_bytes = r[:size]
    try:
        root = ET.fromstring(xml_bytes.decode("utf-8", errors="replace"))
    except ET.ParseError:
        return []

    events = []
    for ch_el in root.findall("ch"):
        for evt_el in ch_el.findall("evt"):
            events.append({
                "event_id": int(evt_el.get("id", 0)),
                "title": evt_el.get("des", ""),
                "date": evt_el.get("date", ""),
                "time": evt_el.get("time", ""),
                "duration": evt_el.get("dur", ""),
            })
    return events


def enrich_with_epg(
    sock,
    lock: threading.Lock,
    services: List[ServiceEntry],
    stop_event: threading.Event,
) -> Dict[int, List[dict]]:
    """Lädt EPG für alle Dienste. Gibt {service_id: [events]} zurück."""
    result: Dict[int, List[dict]] = {}
    for i, svc in enumerate(services):
        if stop_event.is_set():
            break
        events = _fetch_epg_for_service(sock, lock, svc)
        if events:
            result[svc.service_id] = events
        if (i + 1) % 10 == 0:
            logging.getLogger("wisi.epg").info(
                "EPG: %d/%d Dienste abgefragt (%d mit Daten)",
                i + 1, len(services), len(result),
            )
    return result


# ---------------------------------------------------------------------------
# run / main
# ---------------------------------------------------------------------------
def run(ip: str, output: str, limit: int | None = None) -> int:
    if limit is not None and limit < 1:
        raise ValueError("--limit muss mindestens 1 sein.")
    services = load_services(ip)
    if limit is not None:
        services = services[:limit]

    sock = protocol.connect(ip)
    if sock is None:
        raise ConnectionError(f"Verbindung zu {ip}:8802 fehlgeschlagen.")

    lock = threading.Lock()
    stop = threading.Event()
    keepalive = threading.Thread(
        target=_keepalive_worker, args=(sock, lock, stop), daemon=True
    )
    keepalive.start()
    try:
        events_by_service = enrich_with_epg(sock, lock, services, threading.Event())
    finally:
        stop.set()
        keepalive.join(timeout=4.0)
        protocol.disconnect(sock)

    payload = {
        "device_ip": ip,
        "service_count": len(services),
        "services_with_epg": len(events_by_service),
        "channels": [
            {
                "pat_index": svc.pat_index,
                "service_id": svc.service_id,
                "prog_idx": svc.prog_idx,
                "name": svc.name,
                "events": events_by_service.get(svc.service_id, []),
            }
            for svc in services
        ],
    }
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    if output == "-":
        print(text)
    else:
        Path(output).write_text(text + "\n", encoding="utf-8")
        print(f"EPG für {len(services)} Sender nach {output} gespeichert.")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ip", default=DEFAULT_IP, help="IP-Adresse des Dongles")
    parser.add_argument("--output", default="epg.json", help="Zieldatei oder - für stdout")
    parser.add_argument("--limit", type=int, help="Nur die ersten N Sender abfragen")
    args = parser.parse_args(argv)
    try:
        return run(args.ip, args.output, args.limit)
    except (ConnectionError, OSError, ValueError) as exc:
        logging.error("%s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
