"""Shared command-line helpers for the WISI OR S2D tools."""
from __future__ import annotations

import threading
from typing import List

import protocol
from channels import fetch_channel_list, channels_to_services
from keepalive import _keepalive_worker
from models import ServiceEntry, FALLBACK_SERVICE

DEFAULT_IP = protocol.DEFAULT_IP

# Modul-Level-Aliase damit Tests sie via patch.object ersetzen können
connect    = protocol.connect
disconnect = protocol.disconnect


def load_services(ip: str, timeout: float = 15.0) -> List[ServiceEntry]:
    """
    Verbindet mit dem Dongle, lädt Kanalliste via TCP 0xF6/0x20+0x21
    und gibt eine Liste von ServiceEntry zurück.

    connect() darf (sock, session_token) oder nur sock zurückgeben –
    beide Varianten werden korrekt behandelt.
    """
    result = connect(ip)
    # Unterstütze beides: reines socket-Objekt und (sock, session_token)-Tupel
    if isinstance(result, tuple):
        sock, session_token = result
    else:
        sock, session_token = result, b""

    if sock is None:
        raise ConnectionError(f"TCP-Initialisierung mit {ip}:8802 fehlgeschlagen.")

    lock = threading.Lock()
    stop = threading.Event()
    keepalive = threading.Thread(
        target=_keepalive_worker,
        args=(sock, lock, stop),
        daemon=True,
    )
    keepalive.start()
    try:
        channels = fetch_channel_list(sock, lock, session_token, timeout=timeout)
        services = channels_to_services(channels) if channels else []
    finally:
        stop.set()
        keepalive.join(timeout=4.0)
        disconnect(sock)

    if not services:
        raise ConnectionError(
            f"Keine Senderliste von {ip}:8802 empfangen. "
            "TCP-Handshake war erfolgreich, aber 0xF6/0x20+0x21 lieferte keine Kanäle. "
            "Dongle-Status prüfen (Sendersuchlauf abgeschlossen?)."
        )
    return services


__all__ = [
    "DEFAULT_IP", "load_services",
    "connect", "disconnect", "fetch_channel_list", "threading",
]
