# Kompatibilitätseinstieg – der aktive Client ist src/wisi_client.py.
# Bekannte Bugs: falsches _cmd_prepare-Payload, gemischtes USBS-Lesen,
#                zu spätes UDP-Bind, hartcodierter pat_index
# Die alte Implementierung bleibt als Referenz erhalten.

"""
Legacy-Implementierung des DVB-over-IP-Clients für das hier als WISI OR S2D identifizierte Gerät.
Beim direkten Start wird an src/wisi_client.py weitergeleitet.
"""

import argparse
import logging
import socket
import struct
import sys
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional

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
DEFAULT_IP       = "192.168.178.32"
TCP_PORT         = 8802
UDP_PORT         = 8800
MAGIC_TAG        = b"\xA0\xCB\x03\x37"
CONNECT_TIMEOUT  = 5.0
RECV_TIMEOUT     = 4.0
KEEPALIVE_INTVL  = 2.0     # Sekunden zwischen 0x16 Keep-Alives
SIGNAL_INTVL     = 3.0     # Sekunden zwischen Signal-Polls
UDP_BLOCK_SIZE   = 0xBC00  # 48128 Byte pro Anforderung
TS_PKT_SIZE      = 188
TS_SYNC          = 0x47

# ---------------------------------------------------------------------------
# Datenmodelle
# ---------------------------------------------------------------------------
@dataclass
class Event:
    evt_id:  int
    desc:    str
    date:    str = ""
    time_:   str = ""
    dur:     str = ""
    rating:  int = 0

@dataclass
class Channel:
    s_id:     int
    ts_id:    int
    prog_idx: int
    events:   list[Event] = field(default_factory=list)

    @property
    def is_encrypted(self) -> bool:
        return (self.prog_idx >> 24) == 0x48

    @property
    def pat_index(self) -> int:
        """Schätzung des Index in der PAT-Liste (für 0x01-Payload)."""
        # Aus PCAP: prog_idx=0x40B40089 (Prog 4914) → PAT-Index 4
        # Heuristik: wird beim echten Kanalwechsel noch bestätigt
        return getattr(self, "_pat_index", 0)

# ---------------------------------------------------------------------------
# USBC-Builder
# ---------------------------------------------------------------------------
def _build_usbc(data_len: int, flags: int, prefix: int,
                opcode: int, payload: bytes = b"") -> bytes:
    """
    Baut einen 31-Byte USBC Command Block:
      [0..3]   'USBC'
      [4..7]   Magic A0 CB 03 37
      [8..11]  Datenlänge Big-Endian
      [12]     Flags (0x80=Lesen, 0x00=Schreiben)
      [13]     LUN 0x00
      [14]     CDB-Länge 0x10
      [15..30] CDB: prefix + 'APIX' + opcode + payload (auf 16 B aufgefüllt)
    """
    cdb = (bytes([prefix]) + b"APIX" + bytes([opcode]) + payload).ljust(16, b"\x00")
    assert len(cdb) == 16
    pkt = (b"USBC" + MAGIC_TAG
           + struct.pack(">I", data_len)
           + bytes([flags, 0x00, 0x10])
           + cdb)
    assert len(pkt) == 31
    return pkt

# Fertige Befehlsbausteine
def _cmd_16()  -> bytes: return _build_usbc(12, 0x80, 0xF6, 0x16)
def _cmd_17()  -> bytes: return _build_usbc( 4, 0x80, 0xF6, 0x17)

def _cmd_epg_size(prog_idx: int) -> bytes:
    return _build_usbc(6, 0x80, 0xF6, 0x30, struct.pack(">I", prog_idx))

def _cmd_epg_data(prog_idx: int, offset: int, length: int) -> bytes:
    return _build_usbc(length, 0x80, 0xF6, 0x31,
                       struct.pack(">I", prog_idx) + struct.pack(">H", offset))

def _cmd_signal() -> bytes:
    return _build_usbc(17, 0x80, 0xF6, 0x02)

def _cmd_prepare(prog_idx: int) -> bytes:
    return _build_usbc(4, 0x00, 0xF6, 0x03,
                       struct.pack(">I", 0x00000002)[:1] +
                       struct.pack(">I", prog_idx)[:3])
    # Tatsächlich aus PCAP: payload=00000002, prog_idx separat – vereinfacht:

def _cmd_chinfo_size(prog_idx: int) -> bytes:
    return _build_usbc(6, 0x80, 0xF6, 0x32, struct.pack(">I", prog_idx))

def _cmd_chinfo_data(prog_idx: int, length: int) -> bytes:
    return _build_usbc(length, 0x80, 0xF6, 0x33, struct.pack(">I", prog_idx))

def _cmd_tune(pat_index: int) -> bytes:
    # Aus PCAP: payload=00 04 für Prog 4914 (Index 4 in PAT)
    return _build_usbc(2, 0x00, 0xF6, 0x01,
                       bytes([0x00, pat_index & 0xFF]))

def _cmd_stream_release() -> bytes:
    return _build_usbc(4, 0x00, 0xF8, 0x07)

def _cmd_tune_confirm() -> bytes:
    return _build_usbc(4, 0x80, 0xF6, 0x17, b"\x01\x00\x00\x00")

def _udp_init() -> bytes:
    return _build_usbc(0, 0x00, 0xF9, 0x02, b"\x01")

def _udp_request_block(first: bool = False) -> bytes:
    byte21 = b"\x00" if first else b"\x01"
    return _build_usbc(UDP_BLOCK_SIZE, 0x80, 0xF9, 0x01, byte21)

# ---------------------------------------------------------------------------
# TCP-Helfer
# ---------------------------------------------------------------------------
def _recv_n(sock: socket.socket, n: int, timeout: float = RECV_TIMEOUT) -> bytes:
    """Liest exakt n Byte mit Timeout."""
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
    """Sendet Befehl, liest Nutzdaten + 13-Byte USBS zurück."""
    sock.sendall(cmd)
    resp = _recv_n(sock, exp_bytes + 13)
    log.debug("%-18s  tx=%dB  rx=%dB  head=%s",
              label, len(cmd), len(resp), resp[:6].hex())
    return resp

# ---------------------------------------------------------------------------
# Phase 1: Verbindung + Init
# ---------------------------------------------------------------------------
def connect(ip: str) -> Optional[socket.socket]:
    log.info("Verbinde mit %s:%d ...", ip, TCP_PORT)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(CONNECT_TIMEOUT)
    try:
        sock.connect((ip, TCP_PORT))
    except (OSError, socket.timeout) as e:
        log.error("TCP fehlgeschlagen: %s", e)
        sock.close()
        return None
    sock.settimeout(None)
    log.info("TCP verbunden.")

    # 0x16 – muss Status-Byte liefern
    r = _send_cmd(sock, _cmd_16(), 12, "0x16 init")
    if len(r) < 2:
        log.error("0x16: keine Antwort"); sock.close(); return None
    status = r[1]  # Byte[1] = Status-Flag (0x00=nicht bereit, 0x01=bereit)
    log.info("0x16 OK  status=0x%02X  gerät=%s", status, r[2:7].hex())

    # 0x17 – Init Phase 2
    r = _send_cmd(sock, _cmd_17(), 4, "0x17 init")
    if len(r) < 2:
        log.error("0x17: keine Antwort"); sock.close(); return None
    log.info("0x17 OK  flag=0x%02X", r[1])

    # Warten bis Status=0x01 (bereit)
    if status == 0x00:
        log.info("Warte auf Dongle-Bereitschaft ...")
        for _ in range(5):
            time.sleep(0.4)
            r = _send_cmd(sock, _cmd_16(), 12, "0x16 poll")
            if len(r) >= 2 and r[1] == 0x01:
                log.info("Dongle bereit.")
                break
        else:
            log.warning("Dongle meldet noch nicht bereit – trotzdem weiter.")

    return sock

def disconnect(sock: socket.socket) -> None:
    try:
        sock.close()
    except OSError:
        pass
    log.info("Verbindung getrennt.")

# ---------------------------------------------------------------------------
# Phase 2: EPG laden
# ---------------------------------------------------------------------------
def load_epg(sock: socket.socket, prog_idx_list: list[int],
             stop_event: threading.Event) -> dict[int, Channel]:
    """
    Lädt EPG-XML für eine Liste von prog_idx-Werten.
    Gibt {s_id: Channel} zurück.
    """
    channels: dict[int, Channel] = {}
    total = len(prog_idx_list)
    for i, pidx in enumerate(prog_idx_list):
        if stop_event.is_set():
            break

        # Größe abfragen
        r = _send_cmd(sock, _cmd_epg_size(pidx), 6, f"0x30 [{i+1}/{total}]")
        if len(r) < 6:
            continue
        size = struct.unpack(">I", r[2:6])[0]
        if size == 0:
            continue

        # XML laden (in einem Block, typisch <1 KB)
        r = _send_cmd(sock, _cmd_epg_data(pidx, 0, size), size, f"0x31 [{i+1}/{total}]")
        xml_bytes = r[2:2 + size]
        try:
            root = ET.fromstring(xml_bytes.decode("utf-8", errors="replace"))
        except ET.ParseError:
            continue

        for ch_el in root.findall("ch"):
            s_id = int(ch_el.get("s_id", 0))
            ts_id = int(ch_el.get("ts_id", 0))
            ch = Channel(s_id=s_id, ts_id=ts_id, prog_idx=pidx)
            for evt_el in ch_el.findall("evt"):
                ch.events.append(Event(
                    evt_id=int(evt_el.get("id", 0)),
                    desc=evt_el.get("des", ""),
                    date=evt_el.get("date", ""),
                    time_=evt_el.get("time", ""),
                    dur=evt_el.get("dur", ""),
                    rating=int(evt_el.get("rating", 0)),
                ))
            channels[s_id] = ch

    log.info("EPG geladen: %d Kanäle.", len(channels))
    return channels

# ---------------------------------------------------------------------------
# Keep-Alive Thread
# ---------------------------------------------------------------------------
def _keepalive_thread(sock: socket.socket, stop: threading.Event) -> None:
    """Sendet alle 2 s einen 0x16-Keep-Alive über TCP."""
    while not stop.is_set():
        try:
            sock.sendall(_cmd_16())
            _recv_n(sock, 25)  # 12 Nutzdaten + 13 USBS
        except OSError:
            break
        stop.wait(KEEPALIVE_INTVL)

# ---------------------------------------------------------------------------
# Phase 3: Kanal vorbereiten + Signal prüfen
# ---------------------------------------------------------------------------
def prepare_channel(sock: socket.socket, ch: Channel) -> bool:
    """0x03 → 0x32/0x33 → 0x02 (Signal)."""
    pidx = ch.prog_idx

    # Kanal vorauswählen (0x03)
    r = _send_cmd(sock, _cmd_prepare(pidx), 0, "0x03 prepare")
    log.debug("0x03 Antwort: %s", r[:6].hex())

    # ch_Info Größe + Daten (0x32/0x33)
    r = _send_cmd(sock, _cmd_chinfo_size(pidx), 6, "0x32 chinfo-size")
    if len(r) >= 6:
        ci_size = struct.unpack(">I", r[2:6])[0]
        if ci_size > 0:
            r = _send_cmd(sock, _cmd_chinfo_data(pidx, ci_size), ci_size, "0x33 chinfo")
            log.debug("ch_Info: %s", r[2:2+min(ci_size, 80)].decode("utf-8", errors="replace"))

    # Signal pollen (0x02), 3 Versuche
    for attempt in range(3):
        time.sleep(SIGNAL_INTVL)
        r = _send_cmd(sock, _cmd_signal(), 17, f"0x02 signal [{attempt+1}/3]")
        if len(r) >= 4:
            strength = r[2]  # Byte[1] nach Header
            quality  = r[3]  # Byte[2] nach Header
            log.info("Signal: Stärke=%d%%  Qualität=%d", strength, quality)
            if strength >= 50:
                return True
        time.sleep(0.5)

    log.warning("Signal schwach oder keine Antwort – trotzdem starten.")
    return True

# ---------------------------------------------------------------------------
# Phase 4 + 5: Tune + Stream
# ---------------------------------------------------------------------------
def stream(tcp_sock: socket.socket, ch: Channel,
           output_path: str, duration_s: float = 0.0) -> None:
    """
    Startet den MPEG-TS-Stream für einen Kanal.
    output_path: Dateipfad oder '-' für stdout.
    duration_s:  0 = unbegrenzt (STRG+C zum Stoppen).
    """
    stop = threading.Event()

    # Keep-Alive starten
    ka = threading.Thread(target=_keepalive_thread, args=(tcp_sock, stop), daemon=True)
    ka.start()

    # UDP-Socket öffnen BEVOR Tune-Befehl
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("", UDP_PORT))
    udp.settimeout(5.0)

    try:
        # 0xF9/0x02 – Stream-Init
        udp.sendto(_udp_init(), (tcp_sock.getpeername()[0], UDP_PORT))
        log.debug("0xF9/0x02 gesendet")

        # 0x01 – Kanal aktivieren (Tune-Trigger)
        pat_idx = ch.pat_index  # aus PAT-Analyse; Standard: 4 für Prog 4914
        r = _send_cmd(tcp_sock, _cmd_tune(pat_idx), 0, "0x01 tune")
        log.debug("0x01 Antwort: %s", r[:6].hex())

        # 0xF8/0x07 – Stream-Freigabe
        r = _send_cmd(tcp_sock, _cmd_stream_release(), 0, "0xF8/0x07 release")
        log.debug("0xF8/0x07 Antwort: %s", r[:6].hex())

        # Erster UDP-Block (Byte21=0x00)
        udp.sendto(_udp_request_block(first=True), (tcp_sock.getpeername()[0], UDP_PORT))

        # 0x17 – Kanalwechsel bestätigen
        r = _send_cmd(tcp_sock, _cmd_tune_confirm(), 4, "0x17 confirm")
        log.info("0x17 Bestätigung: 0x%02X", r[1] if len(r) > 1 else 0)

        # Stream-Loop
        out = open(output_path, "wb") if output_path != "-" else sys.stdout.buffer
        log.info("Stream aktiv → %s   (STRG+C zum Beenden)",
                 output_path if output_path != "-" else "stdout")

        t_start = time.monotonic()
        block_num = 0
        ts_count  = 0

        try:
            while not stop.is_set():
                # Nächsten Block anfordern (Byte21=0x01 nach erstem)
                udp.sendto(_udp_request_block(first=False),
                           (tcp_sock.getpeername()[0], UDP_PORT))
                try:
                    data, _ = udp.recvfrom(65535)
                except socket.timeout:
                    log.warning("UDP-Timeout – kein Datenblock erhalten.")
                    break

                # TS-Sync-Check
                if data[0] != TS_SYNC:
                    log.debug("Kein TS-Sync (0x%02X) – übersprungen.", data[0])
                    continue

                out.write(data)
                out.flush()
                block_num += 1
                ts_count  += len(data) // TS_PKT_SIZE

                if block_num % 50 == 0:
                    elapsed = time.monotonic() - t_start
                    rate_kbps = (block_num * len(data) / 1024) / elapsed
                    log.info("Block %d  |  TS-Pakete: %d  |  %.0f KB/s",
                             block_num, ts_count, rate_kbps)

                if duration_s > 0 and (time.monotonic() - t_start) >= duration_s:
                    log.info("Zieldauer erreicht.")
                    break

        except KeyboardInterrupt:
            print()
            log.info("Abgebrochen.")
        finally:
            if output_path != "-":
                out.close()
            log.info("Stream beendet. Blöcke: %d  TS-Pakete: %d", block_num, ts_count)

    finally:
        stop.set()
        ka.join(timeout=3.0)
        udp.close()

# ---------------------------------------------------------------------------
# Bekannte Kanäle aus PCAP (Fallback wenn EPG-Laden übersprungen)
# ---------------------------------------------------------------------------
KNOWN_CHANNELS: dict[int, Channel] = {
    4914: Channel(s_id=4914, ts_id=33079, prog_idx=0x40B40089),
}
KNOWN_CHANNELS[4914]._pat_index = 4  # type: ignore[attr-defined]

# ---------------------------------------------------------------------------
# Interaktives Menü
# ---------------------------------------------------------------------------
MENU = """
╔══════════════════════════════════════════════╗
║      WISI OR S2D  –  DVB-over-IP Client    ║
╠══════════════════════════════════════════════╣
║  [1]  EPG laden + Kanal wählen              ║
║  [2]  Stream starten (bekannte Kanäle)      ║
║  [3]  Verbindung neu aufbauen               ║
║  [q]  Beenden                               ║
╚══════════════════════════════════════════════╝"""

def _pick_channel(channels: dict[int, Channel]) -> Optional[Channel]:
    """Einfache Kanalwahl per Eingabe."""
    chlist = sorted(channels.values(), key=lambda c: c.s_id)
    print(f"\n{'Nr':>4}  {'s_id':>6}  {'prog_idx':>12}  {'🔒':>2}  Aktuelles Programm")
    print("-" * 60)
    for i, ch in enumerate(chlist):
        lock = "🔒" if ch.is_encrypted else "  "
        evt  = ch.events[0].desc[:30] if ch.events else "(kein EPG)"
        print(f"{i+1:>4}  {ch.s_id:>6}  {ch.prog_idx:#010x}  {lock}  {evt}")
    print()
    try:
        nr = int(input("Nummer wählen (0=Abbruch): "))
        if 1 <= nr <= len(chlist):
            return chlist[nr - 1]
    except (ValueError, EOFError):
        pass
    return None

def main_menu(sock: socket.socket, ip: str) -> None:
    channels: dict[int, Channel] = {}
    selected: Optional[Channel]  = None
    stop_epg = threading.Event()

    print(MENU)
    while True:
        try:
            choice = input("\nAuswahl > ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if choice == "q":
            break

        elif choice == "1":
            # Demo-prog_idx-Liste aus PCAP (echte Liste würde Kanal-Discovery brauchen)
            demo_idxs = [0x40B70000 + i for i in range(10)] + \
                        [0x40B40089, 0x40DE0111]
            log.info("Lade EPG für %d Einträge ...", len(demo_idxs))
            stop_epg.clear()
            channels = load_epg(sock, demo_idxs, stop_epg)
            if not channels:
                log.warning("Keine EPG-Daten – nutze bekannte Kanäle.")
                channels = KNOWN_CHANNELS.copy()
            selected = _pick_channel(channels)
            if selected:
                log.info("Ausgewählt: s_id=%d  prog_idx=%#010x  %s",
                         selected.s_id, selected.prog_idx,
                         "🔒 verschlüsselt" if selected.is_encrypted else "FTA")

        elif choice == "2":
            if not selected:
                # Bekannten Kanal 4914 nutzen
                selected = KNOWN_CHANNELS[4914]
                log.info("Nutze Standard-Kanal s_id=4914")
            if selected.is_encrypted:
                log.warning("Kanal ist verschlüsselt – Stream funktioniert evtl. nicht.")
            log.info("Bereite Kanal vor ...")
            prepare_channel(sock, selected)
            outfile = input("Ausgabedatei (Enter = stream.ts): ").strip() or "stream.ts"
            dur_str = input("Dauer in Sekunden (Enter = unbegrenzt): ").strip()
            dur = float(dur_str) if dur_str.isdigit() else 0.0
            stream(sock, selected, outfile, dur)

        elif choice == "3":
            disconnect(sock)
            time.sleep(0.5)
            new = connect(ip)
            if new is None:
                log.error("Erneute Verbindung fehlgeschlagen.")
                return
            sock = new
            log.info("Erneut verbunden.")
            print(MENU)

        else:
            print("Unbekannte Eingabe. Bitte 1, 2, 3 oder q.")

    disconnect(sock)

# ---------------------------------------------------------------------------
# CLI-Direktmodus
# ---------------------------------------------------------------------------
def main() -> None:
    """Leitet alte Aufrufe an den korrigierten Client weiter."""
    from wisi_client import main as current_main

    current_main()

if __name__ == "__main__":
    main()
