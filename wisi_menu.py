"""
WISI / Tivizen / TiViCon DVB-over-IP  –  Interaktiver Client
=============================================================

SCHRITT 1: Dongle-Verbindung prüfen + Hauptmenü

Ablauf:
  1. TCP 8802 verbinden
  2. APIX 0x16 + 0x17 (Init-Handshake) → Dongle antwortet = Verbindung OK
  3. Hauptmenü anzeigen (Platzhalter für spätere Schritte)

Protokoll-Grundlage: PCAP-Analyse im Repository (deep_research_with_pcap.md)
"""

import argparse
import logging
import socket
import struct
import sys
import time

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
DEFAULT_IP   = "192.168.178.32"
TCP_PORT     = 8802
MAGIC_TAG    = b"\xA0\xCB\x03\x37"
CONNECT_TIMEOUT = 5.0   # Sekunden bis Timeout beim Verbinden

# ---------------------------------------------------------------------------
# USBC-Builder (31 Byte)
# ---------------------------------------------------------------------------

def _build_usbc(data_len: int, flags: int, prefix: int,
                opcode: int, payload: bytes = b"") -> bytes:
    """
    Baut einen USBC Command Block Wrapper (31 Byte):
      [0..3]   'USBC'
      [4..7]   Magic Tag A0 CB 03 37
      [8..11]  Datenlänge Big-Endian
      [12]     Flags (0x80 = Lesen)
      [13]     LUN (0x00)
      [14]     CDB-Länge (0x10 = 16)
      [15..30] CDB: prefix + 'APIX' + opcode + payload, auf 16 Byte aufgefüllt
    """
    cdb = (bytes([prefix]) + b"APIX" + bytes([opcode]) + payload).ljust(16, b"\x00")
    assert len(cdb) == 16, f"CDB-Länge falsch: {len(cdb)}"
    packet = (
        b"USBC"
        + MAGIC_TAG
        + struct.pack(">I", data_len)
        + bytes([flags, 0x00, 0x10])
        + cdb
    )
    assert len(packet) == 31, f"USBC-Paket-Länge falsch: {len(packet)}"
    return packet


def cmd_init_16() -> bytes:
    """APIX 0x16: Init/Status-Abfrage → Dongle antwortet mit 12 Byte."""
    return _build_usbc(12, 0x80, 0xF6, 0x16)


def cmd_init_17() -> bytes:
    """APIX 0x17: Zweite Init-Abfrage → Dongle antwortet mit 4 Byte."""
    return _build_usbc(4, 0x80, 0xF6, 0x17)


# ---------------------------------------------------------------------------
# TCP-Helfer
# ---------------------------------------------------------------------------

def _recv_n(sock: socket.socket, n: int, timeout: float = 3.0) -> bytes:
    """Liest bis zu n Byte (nicht-blockierend mit Timeout)."""
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


def _send_cmd(sock: socket.socket, cmd: bytes,
              exp_bytes: int, label: str) -> bytes:
    """Sendet einen Befehl und liest sofort die Antwort (Drain)."""
    sock.sendall(cmd)
    # Dongle schickt immer Nutzdaten + 13-Byte USBS-Status zurück
    resp = _recv_n(sock, exp_bytes + 13)
    log.debug("%-12s  gesendet=%d B  empfangen=%d B  hex=%s",
              label, len(cmd), len(resp), resp[:8].hex())
    return resp


# ---------------------------------------------------------------------------
# Verbindung + Handshake
# ---------------------------------------------------------------------------

def connect(ip: str) -> socket.socket | None:
    """
    Verbindet TCP 8802 und führt den Init-Handshake durch.
    Gibt den offenen Socket zurück oder None bei Fehler.
    """
    log.info("Verbinde mit %s:%d ...", ip, TCP_PORT)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(CONNECT_TIMEOUT)
    try:
        sock.connect((ip, TCP_PORT))
    except (OSError, socket.timeout) as exc:
        log.error("TCP-Verbindung fehlgeschlagen: %s", exc)
        sock.close()
        return None
    sock.settimeout(None)
    log.info("TCP-Steuerkanal verbunden.")

    # APIX 0x16 – Dongle muss mit 12 Byte antworten
    log.info("Handshake: APIX 0x16 ...")
    r16 = _send_cmd(sock, cmd_init_16(), exp_bytes=12, label="0x16")
    if len(r16) < 12:
        log.error(
            "0x16: Zu kurze Antwort (%d/12 Byte) – Dongle antwortet nicht korrekt.",
            len(r16),
        )
        sock.close()
        return None
    log.info("0x16 OK  (%d Byte empfangen, Rohdaten: %s)", len(r16), r16[:12].hex())

    # APIX 0x17 – Dongle muss mit 4 Byte antworten
    log.info("Handshake: APIX 0x17 ...")
    r17 = _send_cmd(sock, cmd_init_17(), exp_bytes=4, label="0x17")
    if len(r17) < 4:
        log.error(
            "0x17: Zu kurze Antwort (%d/4 Byte).", len(r17)
        )
        sock.close()
        return None
    log.info("0x17 OK  (%d Byte empfangen, Rohdaten: %s)", len(r17), r17[:4].hex())

    return sock


def disconnect(sock: socket.socket) -> None:
    try:
        sock.close()
    except OSError:
        pass
    log.info("Verbindung getrennt.")


# ---------------------------------------------------------------------------
# Hauptmenü
# ---------------------------------------------------------------------------

MENU = """
╔══════════════════════════════════════════╗
║     WISI O2D  –  DVB-over-IP Client     ║
╠══════════════════════════════════════════╣
║  [1]  Kanalwahl & EPG     (Schritt 2)   ║
║  [2]  Stream starten      (Schritt 3)   ║
║  [3]  Verbindung trennen & neu verbinden║
║  [q]  Beenden                           ║
╚══════════════════════════════════════════╝
"""


def main_menu(sock: socket.socket, ip: str) -> None:
    """Interaktives Hauptmenü – läuft solange der Nutzer nicht beendet."""
    print(MENU)
    while True:
        try:
            choice = input("Auswahl > ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if choice == "q":
            break

        elif choice == "1":
            print("\n[Schritt 2 – Kanalwahl] → noch nicht implementiert.\n")

        elif choice == "2":
            print("\n[Schritt 3 – Stream starten] → noch nicht implementiert.\n")

        elif choice == "3":
            disconnect(sock)
            time.sleep(0.5)
            new_sock = connect(ip)
            if new_sock is None:
                print("Erneute Verbindung fehlgeschlagen. Programm wird beendet.")
                return
            sock = new_sock
            print("Erneut verbunden.\n")
            print(MENU)

        else:
            print("Unbekannte Eingabe. Bitte 1, 2, 3 oder q eingeben.\n")

    disconnect(sock)


# ---------------------------------------------------------------------------
# CLI-Einstieg
# ---------------------------------------------------------------------------

def main() -> None:
    p = argparse.ArgumentParser(
        description="WISI / Tivizen DVB-over-IP  –  Schritt 1: Dongle-Verbindung + Menü",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--ip",    default=DEFAULT_IP, help="IP-Adresse des Dongles")
    p.add_argument("--debug", action="store_true",  help="Debug-Logging aktivieren")
    args = p.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    sock = connect(args.ip)
    if sock is None:
        sys.exit(1)

    print(f"\n✓ Dongle unter {args.ip} erreichbar und bereit.\n")
    main_menu(sock, args.ip)


if __name__ == "__main__":
    main()
