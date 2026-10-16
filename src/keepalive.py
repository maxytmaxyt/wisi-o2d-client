"""
keepalive.py – Keep-Alive-Thread für WISI OR S2D
=================================================
_keepalive_worker  – Hintergrund-Thread: sendet alle KEEPALIVE_INTVL Sekunden
                     einen 0x16-Ping und signalisiert via on_dead wenn der
                     Socket abbricht (erwartet nach Tune, siehe PROBLEME.md).
"""
from __future__ import annotations

import logging
import socket
import threading
from typing import Optional

import protocol

log = logging.getLogger("wisi.keepalive")


def _keepalive_worker(
    sock: socket.socket,
    lock: threading.Lock,
    stop: threading.Event,
    on_dead: Optional[threading.Event] = None,
) -> None:
    """
    Sendet alle KEEPALIVE_INTVL Sekunden einen 0x16-Ping.

    `on_dead`: optionales Event das gesetzt wird wenn der Socket abbricht –
    erlaubt dem Stream-Thread darauf zu reagieren (Problem 1/3).
    Nach dem Tune schließt der Dongle die erste TCP-Verbindung (WinError 10053).
    Das ist erwartet; wir loggen es nur als DEBUG.
    """
    cmd = protocol.cmd_16()
    while not stop.wait(protocol.KEEPALIVE_INTVL):
        try:
            with lock:
                sock.sendall(cmd)
                protocol.recv_exactly(sock, 12 + protocol.USBS_LEN)
        except OSError as e:
            log.debug("Keep-Alive Socket gestorben (erwartet nach Tune): %s", e)
            if on_dead is not None:
                on_dead.set()
            break
