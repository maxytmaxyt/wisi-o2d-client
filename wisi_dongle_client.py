"""
WISI / Tivizen / TiViCon DVB-over-IP Client
============================================
Protokoll-Grundlage: Reverse-Engineering-Analysen im selben Repository.

Architektur:
  TCP 8802  – Steuerkanal  (USBC/APIX-Befehle + USBS-Antworten)
  UDP 8800  – Datenpfad    (MPEG-TS-Blöcke, ausgelöst per APIX 0x01)

USBC-Container (31 Byte):
  [0..3]   "USBC"         – Signatur
  [4..7]   Tag            – konstant A0 CB 03 37
  [8..11]  Datenlänge     – Big-Endian
  [12]     Flags          – 0x80 = Lesezugriff
  [13]     LUN            – 0x00
  [14]     CDB-Länge      – 0x10 (16 Byte)
  [15..30] APIX-Befehl    – 16 Byte, beginnt mit 0xF6 <opcode>

Bug-Fixes / Verbesserungen gegenüber v1:
  1. Keep-Alive (APIX 0xFF) in eigenem Thread alle 250 ms –
     ohne ihn trennt der Dongle nach ~20–30 s (WinError 10053).
  2. Nach JEDEM Befehl wird die USBS-Antwort (13 Byte) sofort
     gelesen; sonst läuft der TCP-Buffer voll → WinError 10054.
  3. Lock um den TCP-Socket (Keep-Alive-Thread und Haupt-Thread
     schreiben gleichzeitig).
  4. Konfigurierbare Pre-Stream-Zeit + Heartbeat-Intervall.
  5. --channel-idx für direkten Kanalwechsel per CLI.

Ablauf laut PCAP:
  0,05 s  – TCP-Connect, APIX 0x16 + 0x17 (Init)
  2,13 s  – EPG-Abfragen (0x30/0x31, 0x35/0x36)  [optional]
  4,98 s  – APIX 0x02, dann wiederholte APIX 0x0A (Pre-Stream-Loop)
 30,41 s  – Umschalten auf APIX 0x01 → UDP liefert MPEG-TS
            Keep-Alive 0xFF läuft parallel alle 250 ms
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
# Standard-Konfiguration
# ---------------------------------------------------------------------------
DONGLE_IP   = "192.168.178.32"
TCP_PORT    = 8802
UDP_PORT    = 8800

MAGIC_TAG   = b"\xA0\xCB\x03\x37"

TS_PACKETS_PER_BLOCK = 256
TS_PACKET_SIZE       = 188
UDP_PAYLOAD_EXPECTED = TS_PACKETS_PER_BLOCK * TS_PACKET_SIZE  # 48 128 Byte
TS_SYNC_BYTE         = 0x47

# Wie lange APIX 0x0A geloopt wird, bevor auf 0x01 umgeschaltet wird
PRE_STREAM_LOOP_SECS = 3.0    # Im PCAP ~25 s; hier verkürzt für schnelleres Testen
PRE_STREAM_INTERVAL  = 0.05   # Sekunden zwischen 0x0A-Anfragen

# Keep-Alive: APIX 0xFF alle 250 ms (Dongle trennt sonst nach ~20–30 s)
KEEPALIVE_INTERVAL   = 0.25   # Sekunden

# Wiederholrate für APIX 0x01 Stream-Requests
STREAM_INTERVAL      = 0.05   # Sekunden

# ---------------------------------------------------------------------------
# USBC-Befehlsbauer
# ---------------------------------------------------------------------------

def _make_usbc(data_length: int, flags: int, apix_cmd: bytes) -> bytes:
    """31-Byte USBC Command Block Wrapper."""
    if len(apix_cmd) != 16:
        raise ValueError(f"APIX-Befehl muss 16 Byte lang sein, hat {len(apix_cmd)}")
    cbw = (
        b"USBC"
        + MAGIC_TAG
        + struct.pack(">I", data_length)
        + bytes([flags, 0x00, 0x10])
        + apix_cmd
    )
    assert len(cbw) == 31
    return cbw


def _apix(opcode: int, payload: bytes = b"") -> bytes:
    """APIX-CDB: 0xF6 + opcode + payload, auf 16 Byte aufgefüllt."""
    raw = bytes([0xF6, opcode]) + payload
    if len(raw) > 16:
        raise ValueError("APIX-Payload zu lang")
    return raw.ljust(16, b"\x00")


# ---------------------------------------------------------------------------
# Konkrete Befehle
# ---------------------------------------------------------------------------

def cmd_init_16()        -> bytes: return _make_usbc(12, 0x80, _apix(0x16))
def cmd_init_17()        -> bytes: return _make_usbc(4,  0x80, _apix(0x17))
def cmd_pre_stream_02()  -> bytes: return _make_usbc(0,  0x80, _apix(0x02))
def cmd_pre_stream_0a()  -> bytes: return _make_usbc(UDP_PAYLOAD_EXPECTED, 0x80, _apix(0x0A))
def cmd_stream_01()      -> bytes:
    return _make_usbc(UDP_PAYLOAD_EXPECTED, 0x80, _apix(0x01, b"APIX"))
def cmd_keepalive_ff()   -> bytes: return _make_usbc(0, 0x80, _apix(0xFF))

def cmd_epg_size(prog_idx: int) -> bytes:
    return _make_usbc(6, 0x80, _apix(0x30, struct.pack(">I", prog_idx)))

def cmd_epg_data(prog_idx: int, length: int) -> bytes:
    return _make_usbc(length, 0x80,
                      _apix(0x31, struct.pack(">I", prog_idx) + struct.pack(">I", length)))

def cmd_event_size(evt_id: int) -> bytes:
    return _make_usbc(6, 0x80, _apix(0x35, struct.pack(">I", evt_id)))

def cmd_event_data(evt_id: int, length: int) -> bytes:
    return _make_usbc(length, 0x80,
                      _apix(0x36, struct.pack(">I", evt_id) + struct.pack(">I", length)))


# ---------------------------------------------------------------------------
# TCP-Helfer: Senden + Antwort drainieren
# ---------------------------------------------------------------------------

def _drain(sock: socket.socket, expected_data_bytes: int = 0,
           drain_timeout: float = 1.5) -> bytes:
    """
    Liest den USBS-Status (13 Byte) + optionale Nutzdaten vom TCP-Socket.
    Gibt die empfangenen Bytes zurück (für Debugging / EPG-Parsing).

    Der Dongle sendet nach JEDEM Befehl mindestens 13 Byte USBS zurück.
    Wird das nicht gelesen, läuft der Socket-Buffer voll → Connection reset.
    """
    total = expected_data_bytes + 13  # Nutzdaten + USBS-Status-Frame
    sock.settimeout(drain_timeout)
    buf = bytearray()
    try:
        while len(buf) < total:
            chunk = sock.recv(min(4096, total - len(buf)))
            if not chunk:
                break
            buf.extend(chunk)
            if len(buf) >= total:
                break
    except socket.timeout:
        pass
    finally:
        sock.settimeout(None)
    return bytes(buf)


def send_cmd(sock: socket.socket, lock: threading.Lock, cmd: bytes,
             expected_data: int = 0, label: str = "") -> bytes:
    """Sendet einen Befehl (thread-safe) und liest sofort die Antwort."""
    with lock:
        sock.sendall(cmd)
        resp = _drain(sock, expected_data)
    if label:
        log.debug("%-20s → %d Byte Antwort: %s...", label, len(resp),
                  resp[:16].hex() if resp else "(leer)")
    return resp


# ---------------------------------------------------------------------------
# Keep-Alive-Thread (APIX 0xFF)
# ---------------------------------------------------------------------------

def _keepalive_worker(sock: socket.socket, lock: threading.Lock,
                      stop_event: threading.Event,
                      interval: float = KEEPALIVE_INTERVAL) -> None:
    """
    Sendet alle `interval` Sekunden APIX 0xFF an den Dongle.
    Ohne diesen Heartbeat trennt der Dongle die Verbindung nach ~20–30 s
    (WinError 10053 / Connection aborted by software on host machine).
    """
    ka_cmd = cmd_keepalive_ff()
    while not stop_event.is_set():
        try:
            send_cmd(sock, lock, ka_cmd, expected_data=0, label="APIX 0xFF (KA)")
        except OSError as exc:
            log.debug("Keep-Alive-Fehler (ignoriert): %s", exc)
            break
        stop_event.wait(interval)
    log.debug("Keep-Alive-Thread beendet.")


# ---------------------------------------------------------------------------
# Initialisierungssequenz
# ---------------------------------------------------------------------------

def handshake(sock: socket.socket, lock: threading.Lock) -> None:
    log.info("Init: APIX 0x16 ...")
    send_cmd(sock, lock, cmd_init_16(), expected_data=12, label="APIX 0x16")

    log.info("Init: APIX 0x17 ...")
    send_cmd(sock, lock, cmd_init_17(), expected_data=4,  label="APIX 0x17")

    log.info("Init abgeschlossen.")


# ---------------------------------------------------------------------------
# EPG-Abfrage (optional)
# ---------------------------------------------------------------------------

def fetch_epg(sock: socket.socket, lock: threading.Lock, prog_idx: int) -> bytes | None:
    log.info("EPG-Größe für prog_idx=0x%08X ...", prog_idx)
    resp = send_cmd(sock, lock, cmd_epg_size(prog_idx), expected_data=6, label="APIX 0x30")
    if len(resp) < 6:
        log.error("Zu kurze Größenantwort (%d Byte)", len(resp))
        return None

    offset = 2 if resp[:2] == b"\xF6\x30" else 0
    epg_size = struct.unpack(">I", resp[offset:offset + 4])[0]
    log.info("EPG-Datensatz: %d Byte", epg_size)

    resp2 = send_cmd(sock, lock, cmd_epg_data(prog_idx, epg_size),
                     expected_data=epg_size, label="APIX 0x31")
    xml = resp2[2:] if resp2[:2] == b"\xF6\x31" else resp2
    log.info("EPG-XML: %d Byte empfangen", len(xml))
    return xml


# ---------------------------------------------------------------------------
# UDP-Empfänger-Thread
# ---------------------------------------------------------------------------

def _udp_receiver_worker(output_path: Path, stop_event: threading.Event,
                          udp_port: int = UDP_PORT) -> None:
    log.info("UDP-Empfänger auf Port %d → %s", udp_port, output_path)
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    udp_sock.bind(("0.0.0.0", udp_port))
    udp_sock.settimeout(3.0)

    packet_count = 0
    byte_count   = 0
    sync_byte    = TS_SYNC_BYTE.to_bytes(1, "big")

    with output_path.open("wb") as fh:
        while not stop_event.is_set():
            try:
                data, _addr = udp_sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError as exc:
                log.error("UDP-Fehler: %s", exc)
                break

            # TiViCon-Header überspringen: ersten TS-Sync (0x47) suchen
            start = data.find(sync_byte)
            if start == -1:
                log.debug("Kein TS-Sync, Block verworfen (%d Byte)", len(data))
                continue

            ts_payload = data[start:]
            fh.write(ts_payload)
            fh.flush()

            packet_count += 1
            byte_count   += len(ts_payload)
            sys.stdout.write(
                f"\r  UDP-Blöcke: {packet_count:5d}  |  "
                f"TS-Daten: {byte_count / 1_048_576:.1f} MiB"
            )
            sys.stdout.flush()

    udp_sock.close()
    print()
    log.info("UDP gestoppt. %d Blöcke, %.1f MiB", packet_count, byte_count / 1_048_576)


# ---------------------------------------------------------------------------
# Haupt-Controller
# ---------------------------------------------------------------------------

def run_controller(ip: str, output: Path, epg_prog_idx: int | None,
                   pre_stream_secs: float) -> None:
    """
    Vollständiger Ablauf:
      1. TCP + Handshake (0x16 / 0x17)
      2. Opt. EPG-Abfrage
      3. APIX 0x02 (einmalig)
      4. APIX 0x0A in Schleife für ~pre_stream_secs Sekunden
      5. Keep-Alive-Thread (APIX 0xFF alle 250 ms) starten
      6. UDP-Empfänger starten
      7. APIX 0x01 in Dauerschleife → UDP liefert MPEG-TS
    """
    log.info("Verbinde mit %s:%d ...", ip, TCP_PORT)
    stop_event = threading.Event()
    lock       = threading.Lock()

    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.settimeout(10.0)
    try:
        tcp_sock.connect((ip, TCP_PORT))
    except OSError as exc:
        log.error("TCP-Verbindung fehlgeschlagen: %s", exc)
        return
    tcp_sock.settimeout(None)
    log.info("TCP-Steuerkanal verbunden.")

    try:
        # 1. Initialisierung
        handshake(tcp_sock, lock)

        # 2. Optionale EPG-Abfrage
        if epg_prog_idx is not None:
            xml = fetch_epg(tcp_sock, lock, epg_prog_idx)
            if xml:
                epg_file = output.with_suffix(".epg.xml")
                epg_file.write_bytes(xml)
                log.info("EPG gespeichert: %s", epg_file)

        # 3. APIX 0x02 (einmalig, laut PCAP vor der 0x0A-Schleife)
        log.info("Pre-Stream: APIX 0x02 ...")
        send_cmd(tcp_sock, lock, cmd_pre_stream_02(), expected_data=0, label="APIX 0x02")

        # 4. APIX 0x0A – Schleife
        log.info("Pre-Stream: APIX 0x0A Schleife für %.1f s ...", pre_stream_secs)
        t_end      = time.monotonic() + pre_stream_secs
        loop_count = 0
        while time.monotonic() < t_end:
            send_cmd(tcp_sock, lock, cmd_pre_stream_0a(),
                     expected_data=0, label=f"APIX 0x0A #{loop_count}")
            loop_count += 1
            time.sleep(PRE_STREAM_INTERVAL)
        log.info("0x0A Schleife abgeschlossen (%d Iterationen).", loop_count)

        # 5. Keep-Alive-Thread starten (APIX 0xFF alle 250 ms)
        #    Muss VOR dem UDP-Empfänger laufen, damit der Dongle die Verbindung
        #    nicht abbricht, bevor UDP-Daten ankommen.
        ka_thread = threading.Thread(
            target=_keepalive_worker,
            args=(tcp_sock, lock, stop_event),
            daemon=True,
            name="keepalive",
        )
        ka_thread.start()
        log.info("Keep-Alive-Thread gestartet (APIX 0xFF alle %.0f ms).",
                 KEEPALIVE_INTERVAL * 1000)

        # 6. UDP-Empfänger starten
        udp_thread = threading.Thread(
            target=_udp_receiver_worker,
            args=(output, stop_event),
            daemon=True,
            name="udp-recv",
        )
        udp_thread.start()
        time.sleep(0.2)

        # 7. APIX 0x01 – Dauerschleife, löst UDP-Datagramme aus
        log.info("Live-Stream aktiv (APIX 0x01). STRG+C zum Beenden.")
        stream_cmd = cmd_stream_01()
        while True:
            send_cmd(tcp_sock, lock, stream_cmd, expected_data=0, label="APIX 0x01")
            time.sleep(STREAM_INTERVAL)

    except KeyboardInterrupt:
        log.info("Streaming durch Nutzer beendet.")
    except OSError as exc:
        log.error("Netzwerkfehler: %s", exc)
    finally:
        stop_event.set()
        try:
            tcp_sock.close()
        except Exception:
            pass
        log.info("Verbindung geschlossen. Stream-Datei: %s", output)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="WISI / Tivizen DVB-over-IP Client",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--ip",           default=DONGLE_IP,
                   help="IP-Adresse des Dongles")
    p.add_argument("--output",       default="live_tv_stream.ts",
                   help="Ausgabedatei für den MPEG-TS-Stream")
    p.add_argument("--epg-idx",      type=lambda x: int(x, 0), default=None,
                   help="Programm-Index für EPG-Abfrage (hex/dez), z.B. 0x40B7008F")
    p.add_argument("--pre-stream",   type=float, default=PRE_STREAM_LOOP_SECS,
                   help="Sekunden für die APIX-0x0A-Vorbereitungsschleife")
    p.add_argument("--keepalive",    type=float, default=KEEPALIVE_INTERVAL,
                   help="Intervall in Sekunden für den Keep-Alive (APIX 0xFF)")
    p.add_argument("--debug",        action="store_true",
                   help="Debug-Logging aktivieren")
    return p.parse_args()


def main() -> None:
    args = _parse_args()
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    global KEEPALIVE_INTERVAL
    KEEPALIVE_INTERVAL = args.keepalive

    run_controller(
        ip              = args.ip,
        output          = Path(args.output),
        epg_prog_idx    = args.epg_idx,
        pre_stream_secs = args.pre_stream,
    )


if __name__ == "__main__":
    main()
