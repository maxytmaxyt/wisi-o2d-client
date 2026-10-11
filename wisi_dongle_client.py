"""
WISI / Tivizen / TiViCon DVB-over-IP Client  –  v3 (PCAP-verified)
====================================================================
Protokoll-Grundlage: Direktanalyse des PCAP-Mitschnitts im Repository.

╔══════════════════════════════════════════════════════════════════╗
║  WICHTIGE ARCHITEKTUR-ERKENNTNIS (aus PCAP-Analyse)             ║
║                                                                  ║
║  TCP 8802  Steuerkanal – NUR Init (0x16/0x17) und EPG (0x30–    ║
║            0x36); CDB-Byte 0 = 0xF6                             ║
║                                                                  ║
║  UDP 8800  BIDIREKTIONAL – sowohl Befehle als auch Daten!        ║
║    • Client → Dongle: USBC-Befehle mit CDB-Byte 0 = 0xF9        ║
║    • Dongle → Client: TS-Daten (roh, kein 0x47-Prefix-Header)   ║
║                        + USBS-Status (13 Byte)                   ║
║                                                                  ║
║  ABLAUF laut PCAP:                                               ║
║    1. TCP-Connect + Init 0x16/0x17 (optional EPG)               ║
║    2. Nach ~5 s: UDP 0x02 (einmalig, Flags=0x00)                ║
║    3. UDP 0x0A in Schleife (~19 s laut PCAP, hier kürzer)       ║
║    4. UDP 0x01 in Dauerschleife → Dongle antwortet mit TS-Daten  ║
║                                                                  ║
║  FEHLER in v1/v2:                                                ║
║    0x0A und 0x01 wurden fälschlicherweise via TCP gesendet.      ║
║    Der Dongle erwartet diese Befehle zwingend via UDP!           ║
╚══════════════════════════════════════════════════════════════════╝

USBC-Container (31 Byte):
  [0..3]   "USBC"            Signatur
  [4..7]   Tag               konstant A0 CB 03 37
  [8..11]  Datenlänge        Big-Endian (0x0000BC00 = 48128 für TS)
  [12]     Flags             0x80 = Daten lesen / 0x00 = Schreiben
  [13]     LUN               0x00
  [14]     CDB-Länge         0x10 (16 Byte)
  [15..30] CDB               F6/F9 + "APIX" + Opcode + Payload

  CDB-Byte[0]: 0xF6  → Befehl über TCP
               0xF9  → Befehl über UDP  ← NEU (aus PCAP)
"""

import argparse
import logging
import socket
import struct
import sys
import threading
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("wisi")

# ---------------------------------------------------------------------------
# Konfiguration
# ---------------------------------------------------------------------------
DONGLE_IP   = "192.168.178.32"
TCP_PORT    = 8802
UDP_PORT    = 8800

MAGIC_TAG   = b"\xA0\xCB\x03\x37"

TS_PACKETS_PER_BLOCK = 256
TS_PACKET_SIZE       = 188
UDP_PAYLOAD_SIZE     = TS_PACKETS_PER_BLOCK * TS_PACKET_SIZE   # 48 128 Byte (0xBC00)
TS_SYNC_BYTE         = 0x47

# Timing laut PCAP
PRE_STREAM_LOOP_SECS = 5.0    # 0x0A-Schleife (PCAP: ~19 s, kürzer = schneller)
STREAM_INTERVAL      = 0.1    # Sekunden zwischen 0x01-Anfragen
KEEPALIVE_INTERVAL   = 2.5    # APIX 0x16 via TCP alle 2.5 s (aus PCAP: alle ~2 s)

# ---------------------------------------------------------------------------
# USBC-Builder  (TCP = 0xF6, UDP = 0xF9)
# ---------------------------------------------------------------------------

def _make_usbc(data_length: int, flags: int, cdb_prefix: int, opcode: int,
               payload: bytes = b"") -> bytes:
    """
    31-Byte USBC Command Block Wrapper.

    cdb_prefix: 0xF6 für TCP-Befehle, 0xF9 für UDP-Befehle (laut PCAP)
    """
    cdb_raw = bytes([cdb_prefix]) + b"APIX" + bytes([opcode]) + payload
    cdb = cdb_raw.ljust(16, b"\x00")
    if len(cdb) != 16:
        raise ValueError(f"CDB muss 16 Byte haben, hat {len(cdb)}")
    return (
        b"USBC"
        + MAGIC_TAG
        + struct.pack(">I", data_length)
        + bytes([flags, 0x00, 0x10])
        + cdb
    )


# TCP-Befehle (CDB-Prefix 0xF6)
def tcp_cmd_init_16() -> bytes:
    return _make_usbc(12, 0x80, 0xF6, 0x16)

def tcp_cmd_init_17() -> bytes:
    return _make_usbc(4, 0x80, 0xF6, 0x17)

def tcp_cmd_epg_size(prog_idx: int) -> bytes:
    return _make_usbc(6, 0x80, 0xF6, 0x30, struct.pack(">I", prog_idx))

def tcp_cmd_epg_data(prog_idx: int, length: int) -> bytes:
    return _make_usbc(length, 0x80, 0xF6, 0x31,
                      struct.pack(">I", prog_idx) + struct.pack(">I", length))

def tcp_cmd_event_size(evt_id: int) -> bytes:
    return _make_usbc(6, 0x80, 0xF6, 0x35, struct.pack(">I", evt_id))

def tcp_cmd_event_data(evt_id: int, length: int) -> bytes:
    return _make_usbc(length, 0x80, 0xF6, 0x36,
                      struct.pack(">I", evt_id) + struct.pack(">I", length))


# UDP-Befehle (CDB-Prefix 0xF9) – aus PCAP
def udp_cmd_pre_02() -> bytes:
    """APIX 0x02 via UDP; einmalig, Flags=0x00, datalen=0 laut PCAP"""
    return _make_usbc(0, 0x00, 0xF9, 0x02, b"\x01\x00")   # Payload aus PCAP

def udp_cmd_poll_0a() -> bytes:
    """APIX 0x0A via UDP; Vorbereitungsschleife vor dem Stream"""
    return _make_usbc(UDP_PAYLOAD_SIZE, 0x80, 0xF9, 0x0A)

def udp_cmd_stream_01() -> bytes:
    """APIX 0x01 via UDP; triggert TS-Datagramme"""
    return _make_usbc(UDP_PAYLOAD_SIZE, 0x80, 0xF9, 0x01)


# ---------------------------------------------------------------------------
# TCP-Helfer
# ---------------------------------------------------------------------------

def _tcp_drain(sock: socket.socket, expected_data: int = 0,
               timeout: float = 1.5) -> bytes:
    """Liest USBS-Status (13 Byte) + optionale Nutzdaten."""
    total = expected_data + 13
    sock.settimeout(timeout)
    buf = bytearray()
    try:
        while len(buf) < total:
            chunk = sock.recv(min(4096, total - len(buf)))
            if not chunk:
                break
            buf.extend(chunk)
    except socket.timeout:
        pass
    finally:
        sock.settimeout(None)
    return bytes(buf)


def tcp_send(sock: socket.socket, lock: threading.Lock, cmd: bytes,
             expected_data: int = 0, label: str = "") -> bytes:
    """Sendet einen TCP-Befehl (thread-safe) und liest die Antwort."""
    with lock:
        sock.sendall(cmd)
        resp = _tcp_drain(sock, expected_data)
    if label:
        log.debug("TCP %-18s → %d Byte", label, len(resp))
    return resp


# ---------------------------------------------------------------------------
# Keep-Alive-Thread: APIX 0x16 alle ~2,5 s via TCP
# (Im PCAP sendet die App 0x16 periodisch während der EPG-Abfrage)
# ---------------------------------------------------------------------------

def _keepalive_worker(sock: socket.socket, lock: threading.Lock,
                      stop_event: threading.Event) -> None:
    cmd = tcp_cmd_init_16()
    while not stop_event.is_set():
        stop_event.wait(KEEPALIVE_INTERVAL)
        if stop_event.is_set():
            break
        try:
            tcp_send(sock, lock, cmd, expected_data=12, label="0x16 (KA)")
        except OSError as exc:
            log.debug("Keep-Alive-Fehler: %s", exc)
            break
    log.debug("Keep-Alive-Thread beendet.")


# ---------------------------------------------------------------------------
# Handshake & EPG via TCP
# ---------------------------------------------------------------------------

def tcp_handshake(sock: socket.socket, lock: threading.Lock) -> None:
    log.info("Init: APIX 0x16 ...")
    tcp_send(sock, lock, tcp_cmd_init_16(), expected_data=12, label="0x16")
    log.info("Init: APIX 0x17 ...")
    tcp_send(sock, lock, tcp_cmd_init_17(), expected_data=4,  label="0x17")
    log.info("Init abgeschlossen.")


def tcp_fetch_epg(sock: socket.socket, lock: threading.Lock,
                  prog_idx: int) -> bytes | None:
    log.info("EPG-Größe für 0x%08X ...", prog_idx)
    resp = tcp_send(sock, lock, tcp_cmd_epg_size(prog_idx),
                    expected_data=6, label="0x30")
    if len(resp) < 6:
        return None
    offset = 2 if resp[:2] == b"\xF6\x30" else 0
    size = struct.unpack(">I", resp[offset:offset + 4])[0]
    log.info("EPG: %d Byte", size)
    resp2 = tcp_send(sock, lock, tcp_cmd_epg_data(prog_idx, size),
                     expected_data=size, label="0x31")
    return resp2[2:] if resp2[:2] == b"\xF6\x31" else resp2


# ---------------------------------------------------------------------------
# UDP-Stream-Controller
# ---------------------------------------------------------------------------

def udp_stream(dongle_ip: str, output: Path,
               pre_secs: float, stop_event: threading.Event) -> None:
    """
    Öffnet einen UDP-Socket auf Port 8800 und:
      1. Sendet APIX 0x02 (einmalig)
      2. Sendet APIX 0x0A in Schleife für pre_secs Sekunden
      3. Sendet APIX 0x01 in Dauerschleife → empfängt TS-Daten
    """
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    udp.bind(("0.0.0.0", UDP_PORT))
    udp.settimeout(1.0)

    dongle_addr = (dongle_ip, UDP_PORT)

    # 1. Pre-Stream 0x02 (einmalig, Flags=0x00)
    log.info("UDP Pre-Stream: APIX 0x02 ...")
    udp.sendto(udp_cmd_pre_02(), dongle_addr)
    try:
        data, _ = udp.recvfrom(65535)
        log.debug("0x02 Antwort: %d Byte", len(data))
    except socket.timeout:
        log.debug("0x02: keine Antwort (OK)")

    # 2. Pre-Stream 0x0A Schleife
    log.info("UDP Pre-Stream: APIX 0x0A Schleife für %.1f s ...", pre_secs)
    poll_cmd = udp_cmd_poll_0a()
    t_end = time.monotonic() + pre_secs
    loop_count = 0
    while time.monotonic() < t_end and not stop_event.is_set():
        udp.sendto(poll_cmd, dongle_addr)
        try:
            data, _ = udp.recvfrom(65535)
            log.debug("0x0A #%d → %d Byte", loop_count, len(data))
        except socket.timeout:
            pass
        loop_count += 1
        time.sleep(0.05)
    log.info("0x0A Schleife abgeschlossen (%d Iterationen).", loop_count)

    # 3. Stream 0x01 Dauerschleife
    log.info("UDP Live-Stream: APIX 0x01. STRG+C zum Beenden.")
    stream_cmd = udp_cmd_stream_01()
    packet_count = 0
    byte_count   = 0

    with output.open("wb") as fh:
        while not stop_event.is_set():
            udp.sendto(stream_cmd, dongle_addr)

            # Empfange Antwort(en) – Dongle kann mehrere Pakete pro Request senden
            deadline = time.monotonic() + STREAM_INTERVAL
            while time.monotonic() < deadline and not stop_event.is_set():
                try:
                    data, _ = udp.recvfrom(65535)
                except socket.timeout:
                    break

                # USBS-Status (13 Byte) ignorieren
                if data[:4] == b"USBS":
                    continue

                # TS-Sync suchen (kein Header bei echten TS-Paketen)
                if data[0] == TS_SYNC_BYTE:
                    ts = data
                elif TS_SYNC_BYTE in data[:200]:
                    ts = data[data.index(TS_SYNC_BYTE):]
                else:
                    log.debug("Kein TS-Sync, Block verworfen (%d Byte)", len(data))
                    continue

                fh.write(ts)
                fh.flush()
                packet_count += 1
                byte_count   += len(ts)
                sys.stdout.write(
                    f"\r  UDP-Blöcke: {packet_count:5d}  |  "
                    f"TS-Daten: {byte_count / 1_048_576:.1f} MiB"
                )
                sys.stdout.flush()

    udp.close()
    print()
    log.info("UDP gestoppt. %d Blöcke, %.1f MiB geschrieben.",
             packet_count, byte_count / 1_048_576)


# ---------------------------------------------------------------------------
# Haupt-Controller
# ---------------------------------------------------------------------------

def run(ip: str, output: Path, epg_prog_idx: int | None,
        pre_stream_secs: float) -> None:
    stop_event = threading.Event()
    lock       = threading.Lock()

    # TCP-Verbindung für Init + EPG
    log.info("Verbinde TCP %s:%d ...", ip, TCP_PORT)
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.settimeout(10.0)
    try:
        tcp.connect((ip, TCP_PORT))
    except OSError as exc:
        log.error("TCP-Verbindung fehlgeschlagen: %s", exc)
        return
    tcp.settimeout(None)
    log.info("TCP-Steuerkanal verbunden.")

    try:
        # 1. Init
        tcp_handshake(tcp, lock)

        # 2. Keep-Alive-Thread starten (0x16 alle 2.5 s via TCP)
        ka = threading.Thread(target=_keepalive_worker,
                              args=(tcp, lock, stop_event),
                              daemon=True, name="tcp-ka")
        ka.start()

        # 3. EPG (optional)
        if epg_prog_idx is not None:
            xml = tcp_fetch_epg(tcp, lock, epg_prog_idx)
            if xml:
                epg_file = output.with_suffix(".epg.xml")
                epg_file.write_bytes(xml)
                log.info("EPG gespeichert: %s", epg_file)

        # 4. UDP-Stream (blockiert bis STRG+C)
        udp_stream(ip, output, pre_stream_secs, stop_event)

    except KeyboardInterrupt:
        log.info("Streaming durch Nutzer beendet.")
    except OSError as exc:
        log.error("Fehler: %s", exc)
    finally:
        stop_event.set()
        try:
            tcp.close()
        except Exception:
            pass
        log.info("Verbindung geschlossen. Stream-Datei: %s", output)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="WISI / Tivizen DVB-over-IP Client (UDP-Protokoll)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--ip",         default=DONGLE_IP,
                   help="IP-Adresse des Dongles")
    p.add_argument("--output",     default="live_tv_stream.ts",
                   help="Ausgabedatei für den MPEG-TS-Stream")
    p.add_argument("--epg-idx",    type=lambda x: int(x, 0), default=None,
                   help="Programm-Index für EPG (hex/dez), z.B. 0x40B7008F")
    p.add_argument("--pre-stream", type=float, default=PRE_STREAM_LOOP_SECS,
                   help="Sekunden für die APIX-0x0A-Vorbereitungsschleife")
    p.add_argument("--debug",      action="store_true",
                   help="Debug-Logging aktivieren")
    return p.parse_args()


def main() -> None:
    args = _args()
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    run(
        ip              = args.ip,
        output          = Path(args.output),
        epg_prog_idx    = args.epg_idx,
        pre_stream_secs = args.pre_stream,
    )


if __name__ == "__main__":
    main()
