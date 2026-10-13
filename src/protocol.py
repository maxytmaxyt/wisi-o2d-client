"""
protocol.py – WISI OR S2D / TiViCon APIX-Protokoll: Shared Layer
Alle USBC-Builder, Konstanten und Basis-TCP/UDP-Helfer.
Kein eigener Einstiegspunkt – wird von allen anderen Modulen importiert.
"""
from __future__ import annotations

import socket
import struct
import logging
from typing import Optional

log = logging.getLogger("wisi.proto")

# ── Netzwerk ─────────────────────────────────────────────────────────────────
DEFAULT_IP   = "192.168.178.32"
TCP_PORT     = 8802
UDP_PORT     = 8800
MAGIC_TAG    = b"\xA0\xCB\x03\x37"

# ── Timing ───────────────────────────────────────────────────────────────────
CONNECT_TIMEOUT  = 5.0
RECV_TIMEOUT     = 4.0
KEEPALIVE_INTVL  = 2.0
SIGNAL_INTVL     = 3.0

# ── UDP / TS ─────────────────────────────────────────────────────────────────
UDP_REQUEST_LEN   = 0xBC00       # 48 128 Byte – Anforderungsgröße im USBC-Feld
UDP_RESPONSE_SIZE = 32_740       # Typische Antwortgröße in Byte
TS_PKT_SIZE       = 188
TS_SYNC           = 0x47
USBS_LEN          = 13           # USBS-Status-Trailer Länge


# ─────────────────────────────────────────────────────────────────────────────
# USBC-Builder
# ─────────────────────────────────────────────────────────────────────────────

def build_usbc(data_len: int, flags: int,
               prefix: int, opcode: int,
               payload: bytes = b"") -> bytes:
    """
    31-Byte USBC Command Block (USB Bulk-Only Transport CBW).
    data_len wird im APIX-Protokoll als Big-Endian kodiert.

    Flags: 0x80 = Lesen (Host ← Gerät), 0x00 = Schreiben (Host → Gerät)
    """
    cdb = (bytes([prefix]) + b"APIX" + bytes([opcode]) + payload).ljust(16, b"\x00")
    assert len(cdb) == 16, f"CDB muss 16 Byte sein, hat {len(cdb)}"
    return (b"USBC" + MAGIC_TAG
            + struct.pack(">I", data_len)
            + bytes([flags, 0x00, 0x10])
            + cdb)


# ── TCP-Befehle (prefix = 0xF6) ─────────────────────────────────────────────

def cmd_16()         -> bytes: return build_usbc(12, 0x80, 0xF6, 0x16)
def cmd_17_init()    -> bytes: return build_usbc(4,  0x80, 0xF6, 0x17)
def cmd_17_confirm() -> bytes: return build_usbc(4,  0x80, 0xF6, 0x17, b"\x01\x00\x00\x00")
def cmd_signal()     -> bytes: return build_usbc(17, 0x80, 0xF6, 0x02)
def cmd_stream_release() -> bytes: return build_usbc(4, 0x00, 0xF8, 0x07)

def cmd_epg_size(prog_idx: int) -> bytes:
    return build_usbc(6, 0x80, 0xF6, 0x30, struct.pack(">I", prog_idx))

def cmd_epg_data(prog_idx: int, offset: int, length: int) -> bytes:
    return build_usbc(length, 0x80, 0xF6, 0x31,
                      struct.pack(">I", prog_idx) + struct.pack(">H", offset))

def cmd_evtdesc_size(prog_idx: int) -> bytes:
    return build_usbc(6, 0x80, 0xF6, 0x35, struct.pack(">I", prog_idx))

def cmd_evtdesc_data(prog_idx: int, length: int) -> bytes:
    return build_usbc(length, 0x80, 0xF6, 0x36, struct.pack(">I", prog_idx))

def cmd_prepare(prog_idx: int) -> bytes:
    return build_usbc(4, 0x80, 0xF6, 0x03,
                      b"\x00\x00\x00\x02" + struct.pack(">I", prog_idx))

def cmd_chinfo_size(prog_idx: int) -> bytes:
    return build_usbc(6, 0x80, 0xF6, 0x32, struct.pack(">I", prog_idx))

def cmd_chinfo_data(prog_idx: int, length: int) -> bytes:
    return build_usbc(length, 0x80, 0xF6, 0x33, struct.pack(">I", prog_idx))

def cmd_tune(pat_index: int) -> bytes:
    """0x01 – Kanal aktivieren. Byte[1] = PAT-Array-Index."""
    return build_usbc(2, 0x80, 0xF6, 0x01, bytes([0x00, pat_index & 0xFF]))

def cmd_probe(opcode: int) -> bytes:
    """Sendet einen unbekannten Opcode (0xF6) mit minimalen Daten – für Opcode-Scan."""
    return build_usbc(4, 0x80, 0xF6, opcode)


# ── UDP-Befehle (prefix = 0xF9) ─────────────────────────────────────────────

def cmd_udp_init() -> bytes:
    """0xF9/0x02 – einmalige Stream-Initialisierung."""
    return build_usbc(0, 0x00, 0xF9, 0x02, b"\x01")

def cmd_udp_service_db() -> bytes:
    """0xF9/0x0A – Service-Datenbank / Kanalliste anfordern."""
    return build_usbc(UDP_REQUEST_LEN, 0x80, 0xF9, 0x0A)

def cmd_udp_ts_block(first: bool = False) -> bytes:
    """0xF9/0x01 – MPEG-TS-Block anfordern (Pull-Mechanismus)."""
    byte21 = b"\x00" if first else b"\x01"
    return build_usbc(UDP_REQUEST_LEN, 0x80, 0xF9, 0x01, byte21)


# ─────────────────────────────────────────────────────────────────────────────
# TCP-Helfer
# ─────────────────────────────────────────────────────────────────────────────

def recv_exactly(sock: socket.socket, n: int,
                 timeout: float = RECV_TIMEOUT) -> bytes:
    """Liest exakt n Bytes mit Timeout. Gibt auch Teilergebnisse zurück."""
    sock.settimeout(timeout)
    buf = bytearray()
    try:
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                break
            buf.extend(chunk)
    except socket.timeout:
        pass
    finally:
        sock.settimeout(None)
    return bytes(buf)


def send_recv(sock: socket.socket, cmd: bytes,
              data_len: int, label: str = "") -> bytes:
    """Sendet Befehl, liest Nutzdaten (data_len Byte) + USBS-Trailer."""
    sock.sendall(cmd)
    raw = recv_exactly(sock, data_len + USBS_LEN)
    payload = raw[:data_len]
    if label:
        log.debug("%-25s tx=%dB rx=%dB head=%s",
                  label, len(cmd), len(raw),
                  payload[:min(6, len(payload))].hex())
    return payload


# ─────────────────────────────────────────────────────────────────────────────
# Verbindung herstellen / trennen
# ─────────────────────────────────────────────────────────────────────────────

def connect(ip: str) -> Optional[socket.socket]:
    """
    Baut TCP-Verbindung auf und führt APIX-Init (0x16 + 0x17) durch.
    Gibt Socket zurück oder None bei Fehler.
    """
    import time
    log.info("Verbinde %s:%d …", ip, TCP_PORT)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(CONNECT_TIMEOUT)
    try:
        sock.connect((ip, TCP_PORT))
    except (OSError, socket.timeout) as e:
        log.error("TCP fehlgeschlagen: %s", e)
        sock.close()
        return None
    sock.settimeout(None)

    r = send_recv(sock, cmd_16(), 12, "0x16 init")
    if len(r) < 3:
        log.error("0x16: keine Antwort"); sock.close(); return None
    status = r[2]
    log.info("0x16 status=0x%02X  gerät=%s", status, r[3:8].hex())

    r = send_recv(sock, cmd_17_init(), 4, "0x17 init")
    log.info("0x17 flag=0x%02X", r[2] if len(r) > 2 else 0xFF)

    if status != 0x01:
        log.info("Warte auf Bereitschaft …")
        for _ in range(10):
            time.sleep(0.5)
            r = send_recv(sock, cmd_16(), 12, "0x16 poll")
            if len(r) >= 3 and r[2] == 0x01:
                log.info("Dongle bereit.")
                break
        else:
            log.warning("Dongle meldet nicht 0x01 – weiter trotzdem.")
    return sock


def disconnect(sock: socket.socket) -> None:
    try:
        sock.close()
    except OSError:
        pass
    log.info("Verbindung getrennt.")
