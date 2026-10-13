"""Shared command-line helpers for the WISI tools."""
from __future__ import annotations

import socket
import threading

from wisi_client import (
    DEFAULT_IP,
    UDP_PORT,
    ServiceEntry,
    _keepalive_worker,
    connect,
    disconnect,
    fetch_service_db,
)


def load_services(ip: str, timeout: float = 3.0) -> list[ServiceEntry]:
    control = connect(ip)
    if control is None:
        raise ConnectionError(f"TCP-Initialisierung mit {ip}:8802 fehlgeschlagen.")

    lock = threading.Lock()
    stop = threading.Event()
    keepalive = threading.Thread(
        target=_keepalive_worker, args=(control, lock, stop), daemon=True
    )
    keepalive.start()
    try:
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.settimeout(timeout)
        try:
            services = fetch_service_db(udp, ip)
        finally:
            udp.close()
    finally:
        stop.set()
        keepalive.join(timeout=4.0)
        disconnect(control)
    if not services:
        raise ConnectionError(
            f"Keine Senderliste von {ip}:{UDP_PORT} empfangen. "
            "TCP-Handshake war erfolgreich, aber UDP 0xF9/0x0A lieferte keine "
            "dekodierbaren Sender. Dongle-Status/Sendersuchlauf und UDP-Port "
            "8800 prüfen; Ping allein bestätigt den APIX-Dienst nicht."
        )
    return services


__all__ = ["DEFAULT_IP", "load_services"]
