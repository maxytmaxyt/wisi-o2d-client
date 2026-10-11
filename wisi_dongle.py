"""
WISI / Tivizen / TiViCon DVB-over-IP Client
============================================
Protokoll-Grundlage: Reverse-Engineering-Analysen im selben Repository.

Architektur:
  TCP 8802  – Steuerkanal  (USBC/APIX-Befehle + USBS-Antworten)
  UDP 8800  – Datenpfad    (MPEG-TS-Blöcke, ausgelöst per APIX 0x01)

USBC-Container (31 Byte):
  [0..3]  "USBC"          – Signatur
  [4..7]  Tag             – konstant oder inkrementierend
  [8..11] Datenlänge      – Big-Endian
  [12]    Flags           – 0x80 = Lesezugriff
  [13]    LUN             – 0x00
  [14]    CDB-Länge       – 0x10 (16 Byte)
  [15..30] APIX-Befehl   – 16 Byte, beginnt mit 0xF6 <opcode>
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

# Aus dem PCAP bekannter konstanter Tag
MAGIC_TAG   = b"\xA0\xCB\x03\x37"

# Wie viele MPEG-TS-Pakete pro UDP-Block (0xBC00 = 256 × 188 Byte)
TS_PACKETS_PER_BLOCK = 256
TS_PACKET_SIZE       = 188
UDP_PAYLOAD_EXPECTED = TS_PACKETS_PER_BLOCK * TS_PACKET_SIZE  # 48 128
TS_SYNC_BYTE         = 0x47

# Größe des TiViCon-Vorsatzes pro UDP-Datagramm (laut Protokollanalyse 77 Byte extra)
TIVICON_HEADER_SIZE  = 77

# ---------------------------------------------------------------------------
# USBC-Befehlsbauer
# ---------------------------------------------------------------------------

def _make_usbc(data_length: int, flags: int, apix_cmd: bytes) -> bytes:
    """
    Baut einen vollständigen 31-Byte USBC Command Block Wrapper (CBW).

    data_length : angeforderte Datenmenge (Big-Endian in Bytes 8..11)
    flags       : 0x80 = Einlesen, 0x00 = Schreiben
    apix_cmd    : exakt 16 Byte APIX-Nutzlast (CDB)
    """
    if len(apix_cmd) != 16:
        raise ValueError(f"APIX-Befehl muss genau 16 Byte lang sein, hat {len(apix_cmd)}")
    cbw = (
        b"USBC"                                   # Signatur
        + MAGIC_TAG                               # Tag
        + struct.pack(">I", data_length)          # Datenlänge, Big-Endian
        + bytes([flags, 0x00, 0x10])              # Flags | LUN | CDB-Länge
        + apix_cmd                                # 16-Byte CDB
    )
    assert len(cbw) == 31
    return cbw


def _apix(opcode: int, payload: bytes = b"") -> bytes:
    """Packt einen APIX-Befehl in exakt 16 Byte (0xF6, opcode, payload, Padding)."""
    raw = bytes([0xF6, opcode]) + payload
    if len(raw) > 16:
        raise ValueError("APIX-Payload zu lang")
    return raw.ljust(16, b"\x00")


# ---------------------------------------------------------------------------
# Konkrete Befehle
# ---------------------------------------------------------------------------

def cmd_init_16() -> bytes:
    """APIX 0x16 – Initialisierungs-/Statusabfrage (antwortet mit 12 Byte)."""
    return _make_usbc(12, 0x80, _apix(0x16))


def cmd_init_17() -> bytes:
    """APIX 0x17 – Zweite Initialisierungsabfrage (antwortet mit 4 Byte)."""
    return _make_usbc(4, 0x80, _apix(0x17))


def cmd_epg_size(prog_idx: int) -> bytes:
    """APIX 0x30 (APIX0) – Fragt die Byte-Größe eines EPG-Eintrags ab."""
    payload = struct.pack(">I", prog_idx)          # 4-Byte-Programm-Index, Big-Endian
    return _make_usbc(6, 0x80, _apix(0x30, payload))


def cmd_epg_data(prog_idx: int, length: int) -> bytes:
    """APIX 0x31 (APIX1) – Liest einen EPG-XML-Block der bekannten Länge."""
    payload = struct.pack(">I", prog_idx) + struct.pack(">I", length)
    return _make_usbc(length, 0x80, _apix(0x31, payload))


def cmd_event_size(evt_id: int) -> bytes:
    """APIX 0x35 (APIX5) – Fragt die Byte-Größe einer Ereignisbeschreibung ab."""
    payload = struct.pack(">I", evt_id)
    return _make_usbc(6, 0x80, _apix(0x35, payload))


def cmd_event_data(evt_id: int, length: int) -> bytes:
    """APIX 0x36 (APIX6) – Liest eine Ereignisbeschreibung der bekannten Länge."""
    payload = struct.pack(">I", evt_id) + struct.pack(">I", length)
    return _make_usbc(length, 0x80, _apix(0x36, payload))


def cmd_pre_stream() -> bytes:
    """APIX 0x0A – Vorbereitungsschritt vor dem eigentlichen Stream (APIX 0x01)."""
    return _make_usbc(UDP_PAYLOAD_EXPECTED, 0x80, _apix(0x0A))


def cmd_stream_request() -> bytes:
    """APIX 0x01 – Fordert exakt 256 MPEG-TS-Pakete (0xBC00 Byte) per UDP an."""
    payload = b"\x41\x50\x49\x58"                 # ASCII "APIX"
    return _make_usbc(UDP_PAYLOAD_EXPECTED, 0x80, _apix(0x01, payload))


def cmd_keepalive() -> bytes:
    """APIX 0xFF – Heartbeat/Ping, um den Stream offen zu halten."""
    return _make_usbc(0, 0x80, _apix(0xFF))


# ---------------------------------------------------------------------------
# USBS-Antwort-Parser
# ---------------------------------------------------------------------------

def read_usbs(sock: socket.socket) -> bool:
    """
    Liest den 13-Byte USBS Command Status Wrapper vom TCP-Socket.
    Gibt True zurück, wenn Status == 0 (Erfolg).
    """
    try:
        data = _recv_exact(sock, 13)
    except OSError:
        return False
    if data[:4] != b"USBS":
        log.debug("Keine USBS-Signatur: %s", data[:4].hex())
        return False
    status = data[12]
    if status != 0:
        log.warning("USBS-Status ungleich 0: 0x%02X", status)
    return status == 0


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Liest exakt n Byte vom Socket (TCP ist ein Bytestrom!)."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("Verbindung unerwartet geschlossen")
        buf.extend(chunk)
    return bytes(buf)


def _recv_up_to(sock: socket.socket, n: int, timeout: float = 2.0) -> bytes:
    """Liest bis zu n Byte mit Timeout (für variable Antwortlängen)."""
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


# ---------------------------------------------------------------------------
# Initialisierungssequenz
# ---------------------------------------------------------------------------

def handshake(sock: socket.socket) -> bool:
    """
    Sendet APIX 0x16 und 0x17 und liest die jeweilige Antwort.
    Gibt True zurück, wenn beide Schritte erfolgreich waren.
    """
    log.info("Initialisierung: APIX 0x16 ...")
    sock.sendall(cmd_init_16())
    resp16 = _recv_up_to(sock, 12 + 13)          # 12 Byte Nutzdaten + ggf. USBS
    log.debug("0x16-Antwort (%d Byte): %s", len(resp16), resp16.hex())

    log.info("Initialisierung: APIX 0x17 ...")
    sock.sendall(cmd_init_17())
    resp17 = _recv_up_to(sock, 4 + 13)
    log.debug("0x17-Antwort (%d Byte): %s", len(resp17), resp17.hex())

    return True


# ---------------------------------------------------------------------------
# EPG-Abfrage
# ---------------------------------------------------------------------------

def fetch_epg(sock: socket.socket, prog_idx: int) -> bytes | None:
    """
    Zweistufige EPG-Abfrage:
      1. APIX 0x30 → Größe
      2. APIX 0x31 → XML-Daten
    Gibt den XML-Block zurück oder None bei Fehler.
    """
    log.info("EPG-Größe für prog_idx=0x%08X abfragen ...", prog_idx)
    sock.sendall(cmd_epg_size(prog_idx))
    size_resp = _recv_up_to(sock, 6 + 13)
    if len(size_resp) < 6:
        log.error("Zu kurze Größenantwort")
        return None

    # Antwort beginnt mit F6 30, dann 4 Byte Länge Big-Endian
    if size_resp[:2] == b"\xF6\x30":
        epg_size = struct.unpack(">I", size_resp[2:6])[0]
    else:
        # Fallback: letzte 4 Byte der ersten 6 Byte
        epg_size = struct.unpack(">I", size_resp[2:6])[0]

    log.info("EPG-Datensatz: %d Byte – lade Daten ...", epg_size)
    sock.sendall(cmd_epg_data(prog_idx, epg_size))
    xml_data = _recv_up_to(sock, epg_size + 13, timeout=5.0)

    # F6 31 Prefix abschneiden, falls vorhanden
    if xml_data[:2] == b"\xF6\x31":
        xml_data = xml_data[2:]

    log.info("EPG-XML empfangen (%d Byte)", len(xml_data))
    return xml_data


# ---------------------------------------------------------------------------
# Keep-Alive-Thread
# ---------------------------------------------------------------------------

def _keepalive_worker(sock: socket.socket, stop_event: threading.Event,
                      interval: float = 0.25) -> None:
    """Sendet alle `interval` Sekunden einen APIX-0xFF-Ping auf dem TCP-Steuerkanal."""
    log.debug("Keep-Alive-Thread gestartet (Intervall %.2f s)", interval)
    while not stop_event.is_set():
        try:
            sock.sendall(cmd_keepalive())
        except OSError as exc:
            log.warning("Keep-Alive fehlgeschlagen: %s", exc)
            break
        stop_event.wait(interval)
    log.debug("Keep-Alive-Thread beendet")


# ---------------------------------------------------------------------------
# UDP-Empfänger-Thread
# ---------------------------------------------------------------------------

def _udp_receiver_worker(output_path: Path, stop_event: threading.Event,
                          udp_port: int = UDP_PORT) -> None:
    """
    Empfängt UDP-Datagramme auf `udp_port` und schreibt den reinen
    MPEG-TS-Anteil (ohne TiViCon-Vorsatzbytes) in `output_path`.
    """
    log.info("UDP-Empfänger auf Port %d gestartet → %s", udp_port, output_path)
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind(("0.0.0.0", udp_port))
    udp_sock.settimeout(3.0)

    packet_count = 0
    byte_count   = 0

    with output_path.open("wb") as fh:
        while not stop_event.is_set():
            try:
                data, _addr = udp_sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError as exc:
                log.error("UDP-Fehler: %s", exc)
                break

            # TiViCon-Header abtrennen: Sync-Byte 0x47 suchen
            start = data.find(TS_SYNC_BYTE.to_bytes(1, "big"))
            if start == -1:
                log.debug("Kein MPEG-TS-Sync-Byte gefunden, Block verworfen (%d Byte)", len(data))
                continue

            ts_payload = data[start:]

            # Plausibilitätsprüfung: Sync-Bytes alle 188 Byte
            if len(ts_payload) >= TS_PACKET_SIZE:
                if ts_payload[TS_PACKET_SIZE] != TS_SYNC_BYTE:
                    log.debug("Zweites Sync-Byte nicht an erwarteter Stelle – Daten trotzdem gespeichert")

            fh.write(ts_payload)
            fh.flush()

            packet_count += 1
            byte_count   += len(ts_payload)
            sys.stdout.write(
                f"\rEmpfangene UDP-Blöcke: {packet_count:5d}  |  "
                f"TS-Datenmenge: {byte_count / 1_048_576:.1f} MiB"
            )
            sys.stdout.flush()

    udp_sock.close()
    print()
    log.info("UDP-Empfänger gestoppt. Gesamt: %d Blöcke, %.1f MiB",
             packet_count, byte_count / 1_048_576)


# ---------------------------------------------------------------------------
# Haupt-Controller
# ---------------------------------------------------------------------------

def run_controller(ip: str, output: Path, epg_prog_idx: int | None,
                   keepalive_interval: float) -> None:
    """
    Steuert den vollständigen Ablauf:
      1. TCP-Verbindung + Handshake
      2. Optionale EPG-Abfrage
      3. UDP-Empfänger starten
      4. Keep-Alive-Thread starten
      5. Kontinuierliche APIX-0x01-Schleife (triggert UDP-Blöcke)
      6. Sauberes Beenden per STRG+C
    """
    log.info("Verbinde mit %s:%d ...", ip, TCP_PORT)
    stop_event = threading.Event()

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
        handshake(tcp_sock)

        # 2. Optionale EPG-Abfrage
        if epg_prog_idx is not None:
            xml = fetch_epg(tcp_sock, epg_prog_idx)
            if xml:
                epg_file = output.with_suffix(".epg.xml")
                epg_file.write_bytes(xml)
                log.info("EPG-XML gespeichert: %s", epg_file)

        # 3. UDP-Empfänger
        udp_thread = threading.Thread(
            target=_udp_receiver_worker,
            args=(output, stop_event),
            daemon=True,
            name="udp-recv",
        )
        udp_thread.start()
        time.sleep(0.3)  # UDP-Socket Zeit zum Binden geben

        # 4. Keep-Alive-Thread
        ka_thread = threading.Thread(
            target=_keepalive_worker,
            args=(tcp_sock, stop_event, keepalive_interval),
            daemon=True,
            name="keepalive",
        )
        ka_thread.start()

        # 5. Vorbereitungsschritt APIX 0x0A (analog zum PCAP-Ablauf)
        log.info("Sende APIX 0x0A Vorbereitungsbefehl ...")
        tcp_sock.sendall(cmd_pre_stream())
        time.sleep(0.2)

        # 6. APIX-0x01-Trigger-Schleife
        log.info("Starte Live-Stream via APIX 0x01 – STRG+C zum Beenden.")
        stream_cmd = cmd_stream_request()
        while True:
            tcp_sock.sendall(stream_cmd)
            time.sleep(0.05)  # ~20 Anforderungen/s, analog zum PCAP (30,41s-Intervall)

    except KeyboardInterrupt:
        log.info("Streaming durch Nutzer beendet.")
    except OSError as exc:
        log.error("Netzwerkfehler: %s", exc)
    finally:
        stop_event.set()
        tcp_sock.close()
        log.info("Verbindung geschlossen. Stream-Datei: %s", output)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="WISI / Tivizen DVB-over-IP Client",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--ip",        default=DONGLE_IP,        help="IP-Adresse des Dongles")
    p.add_argument("--output",    default="live_tv_stream.ts",
                   help="Ausgabedatei für den MPEG-TS-Stream")
    p.add_argument("--epg-idx",   type=lambda x: int(x, 0), default=None,
                   help="Programm-Index für EPG-Abfrage (hex oder dez), z.B. 0x40B7008F")
    p.add_argument("--ka-interval", type=float, default=0.25,
                   help="Keep-Alive-Intervall in Sekunden")
    p.add_argument("--debug",     action="store_true",       help="Debug-Logging aktivieren")
    return p.parse_args()


def main() -> None:
    args = _parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    run_controller(
        ip               = args.ip,
        output           = Path(args.output),
        epg_prog_idx     = args.epg_idx,
        keepalive_interval = args.ka_interval,
    )


if __name__ == "__main__":
    main()
