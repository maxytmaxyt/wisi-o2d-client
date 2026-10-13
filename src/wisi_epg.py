"""EPG-Daten des Dongles abrufen und als JSON speichern."""
from __future__ import annotations

import argparse
import json
import logging
import sys
import threading
from collections.abc import Sequence
from pathlib import Path

from wisi_client import (
    DEFAULT_IP,
    _keepalive_worker,
    connect,
    disconnect,
    enrich_with_epg,
)
from wisi_common import load_services


def run(ip: str, output: str, limit: int | None = None) -> int:
    if limit is not None and limit < 1:
        raise ValueError("--limit muss mindestens 1 sein.")
    services = load_services(ip)
    if limit is not None:
        services = services[:limit]

    sock = connect(ip)
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
        disconnect(sock)

    payload = {
        "device_ip": ip,
        "service_count": len(services),
        "services_with_epg": len(events_by_service),
        "channels": [
            {
                "pat_index": service.pat_index,
                "service_id": service.service_id,
                "prog_idx": service.prog_idx,
                "name": service.name,
                "events": [
                    {
                        "event_id": event.evt_id,
                        "title": event.desc,
                        "date": event.date,
                        "time": event.time_,
                        "duration": event.dur,
                    }
                    for event in events_by_service.get(service.service_id, [])
                ],
            }
            for service in services
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
