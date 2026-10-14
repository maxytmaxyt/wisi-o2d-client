"""Shared command-line helpers for the WISI OR S2D tools."""
from __future__ import annotations

import threading
from typing import List

from wisi_client import (
    DEFAULT_IP,
    ServiceEntry,
    _keepalive_worker,
    channels_to_services,
    connect,
    disconnect,
    fetch_channel_list,
)


def load_services(ip: str, timeout: float = 15.0) -> List[ServiceEntry]:
    """
    Verbindet mit dem Dongle, lädt Kanalliste via TCP 0xF6/0x20+0x21
    und gibt eine Liste von ServiceEntry zurück.
    Wirft ConnectionError wenn kein Kanal gefunden wird.
    """
    result = connect(ip)
    if result is None:
        raise ConnectionError(f"TCP-Initialisierung mit {ip}:8802 fehlgeschlagen.")
    control, session_token = result

    lock = threading.Lock()
    stop = threading.Event()
    keepalive = threading.Thread(
        target=_keepalive_worker,
        args=(control, lock, stop, session_token),
        daemon=True,
    )
    keepalive.start()
    try:
        channels = fetch_channel_list(control, lock, session_token, timeout=timeout)
        services = channels_to_services(channels) if channels else []
    finally:
        stop.set()
        keepalive.join(timeout=4.0)
        disconnect(control)

    if not services:
        raise ConnectionError(
            f"Keine Senderliste von {ip}:8802 empfangen. "
            "TCP-Handshake war erfolgreich, aber 0xF6/0x20+0x21 lieferte keine Kanäle. "
            "Dongle-Status prüfen (Sendersuchlauf abgeschlossen?)."
        )
    return services


__all__ = ["DEFAULT_IP", "load_services"]
