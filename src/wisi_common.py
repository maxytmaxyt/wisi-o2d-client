"""Shared command-line helpers for the WISI tools."""
from __future__ import annotations

import socket

from wisi_client import DEFAULT_IP, UDP_PORT, ServiceEntry, fetch_service_db


def load_services(ip: str, timeout: float = 3.0) -> list[ServiceEntry]:
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(timeout)
    try:
        services = fetch_service_db(udp, ip)
    finally:
        udp.close()
    if not services:
        raise ConnectionError(
            f"Keine Senderliste von {ip}:{UDP_PORT} empfangen. "
            "IP, Netzwerkverbindung und Dongle-Status prüfen."
        )
    return services


__all__ = ["DEFAULT_IP", "load_services"]
