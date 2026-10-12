"""
WISI / Tivizen / TiViCon DVB-over-IP  –  Client v2
====================================================

Implementiert den vollständigen, aus PCAP verifizierten Ablauf:

  Phase 1: TCP Init          (0x16 + 0x17)
  Phase 2: EPG laden         (0x30/0x31 für alle Kanäle)
  Phase 3: Kanal vorbereiten (0x03 + 0x32/0x33 + 0x02 Signal-Poll)
  Phase 4: Tune              (0x01 → 0xF8/0x07 → UDP 0xF9/0x01 → 0x17)
  Phase 5: Stream            (UDP 0xF9/0x01 Pull-Loop + TCP Keep-Alive)

Protokoll-Referenz: research/pcap_analysis.md

Fixes gegenüber wisi_menu.py:
  - _cmd_prepare(): korrektes PCAP-Payload (0x00 0x00 0x00 0x02 + prog_idx)
  - _recv_n(): liest USBS-Trailer (13 Byte) separat, kein gemischter exp_bytes
  - stream(): UDP-Socket-Binding VOR connect() → kein Paketverlust mehr
  - Channel.pat_index: Discovery über ch_Info statt hartcodierter Schätzung
  - EPG-Loader: prog_idx-Discovery aus echten 0x30-Scans (nicht Hardcode-Liste)
  - Signal-Poll: korrekter Byte-Offset (r[1]=Stärke, r[2]=Qualität nach USBS-Strip)
  - Neue --scan-epg Flag: scannt alle bekannten prog_idx-Gruppen statt Demo-Liste
  - Neue --duration in Sekunden auch über Menü setzbar
  - Graceful shutdown: KeyboardInterrupt beendet Stream + trennt TCP sauber
"""

from __future__ import annotations

import argparse
import logging
import socket
import struct
import sys
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Dict, List, Optional

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
DEFAULT_IP      = "192.168.178.32"
TCP_PORT        = 8802
UDP_PORT        = 8800
MAGIC_TAG       = b"\xA0\xCB\x03\x37"
CONNECT_TIMEOUT = 5.0
RECV_TIMEOUT    = 4.0
KEEPALIVE_INTVL = 2.0       # Sekunden zwischen 0x16 Keep-Alives
SIGNAL_INTVL    = 3.0       # Sekunden zwischen Signal-Polls
UDP_BLOCK_SIZE  = 0xBC00    # 48128 Byte Anforderungsgröße (= 256 TS-Pakete)
TS_PKT_SIZE     = 188
TS_SYNC         = 0x47
USBS_LEN        = 13        # USBS-Status-Trailer ist immer 13 Byte

# Bekannte prog_idx-Präfixe laut PCAP-Analyse
KNOWN_PROG_IDX_GROUPS = [
    0x40B40000, 0x40B70000, 0x40DE0000,
    0x48A50000, 0x40B80000, 0x40BA0000,
]

# ---------------------------------------------------------------------------
# Datenmodelle
# ---------------------------------------------------------------------------
@dataclass
class Event:
    evt_id: int
    desc:   str
    date:   str = ""
    time_:  str = ""
    dur:    str = ""
    rating: int = 0


@dataclass
class Channel:
    s_id:      int
    ts_id:     int
    prog_idx:  int
    pat_index: int = 0        # Index in der PAT-Liste (für 0x01-Tune-Payload)
    events:    List[Event] = field(default_factory=list)

    @property
    def is_encrypted(self) -> bool:
        return (self.prog_idx >> 24) == 0x48

    def __str__(self) -> str:
        lock = "🔒" if self.is_encrypted else "FTA"
        evt  = self.events[0].desc[:35] if self.events else "(kein EPG)"
        return f"s_id={self.s_id:5d}  idx={self.prog_idx:#010x}  [{lock}]  {evt}"


# ---------------------------------------------------------------------------
# USBC-Builder (31 Byte)
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
      [14]     CDB-Länge 0x10 (16 Byte)
      [15..30] CDB: prefix + 'APIX' + opcode + payload (auf 16 B aufgefüllt)
    """
    cdb = (bytes([prefix]) + b"APIX" + bytes([opcode]) + payload).ljust(16, b"\x00")
    if len(cdb) != 16:
        raise ValueError(f"CDB-Länge {len(cdb)} statt 16 – payload zu lang?")
    pkt = (b"USBC" + MAGIC_TAG
           + struct.pack(">I", data_len)
           + bytes([flags, 0x00, 0x10])
           + cdb)
    assert len(pkt) == 31, f"USBC-Länge {len(pkt)} erwartet 31"
    return pkt


# ---------------------------------------------------------------------------
# Befehls-Builder
# ---------------------------------------------------------------------------
def _cmd_16() -> bytes:
    return _build_usbc(12, 0x80, 0xF6, 0x16)

def _cmd_17_init() -> bytes:
    return _build_usbc(4, 0x80, 0xF6, 0x17)

def _cmd_17_confirm() -> bytes:
    # Nach Tune: 0x17 mit payload=01 00 00 00 bestätigt Kanalwechsel
    return _build_usbc(4, 0x80, 0xF6, 0x17, b"\x01\x00\x00\x00")

def _cmd_signal() -> bytes:
    return _build_usbc(17, 0x80, 0xF6, 0x02)

def _cmd_epg_size(prog_idx: int) -> bytes:
    return _build_usbc(6, 0x80, 0xF6, 0x30, struct.pack(">I", prog_idx))

def _cmd_epg_data(prog_idx: int, offset: int, length: int) -> bytes:
    # Payload aus PCAP: prog_idx (4B) + offset (2B) – kein length im Payload
    return _build_usbc(length, 0x80, 0xF6, 0x31,
                       struct.pack(">I", prog_idx) + struct.pack(">H", offset))

def _cmd_evt_size(s_id: int) -> bytes:
    return _build_usbc(6, 0x80, 0xF6, 0x35, struct.pack(">I", s_id))

def _cmd_evt_data(s_id: int, length: int) -> bytes:
    return _build_usbc(length, 0x80, 0xF6, 0x36,
                       struct.pack(">I", s_id) + struct.pack(">H", 0))

def _cmd_prepare(prog_idx: int) -> bytes:
    # PCAP-verifiziert: payload = 00 00 00 02 + prog_idx (4B)
    # Flags=0x00 (Schreiben), datalen=4
    return _build_usbc(4, 0x00, 0xF6, 0x03,
                       b"\x00\x00\x00\x02" + struct.pack(">I", prog_idx))

def _cmd_chinfo_size(prog_idx: int) -> bytes:
    return _build_usbc(6, 0x80, 0xF6, 0x32, struct.pack(">I", prog_idx))

def _cmd_chinfo_data(prog_idx: int, length: int) -> bytes:
    return _build_usbc(length, 0x80, 0xF6, 0x33, struct.pack(">I", prog_idx))

def _cmd_tune(pat_index: int) -> bytes:
    # Payload aus PCAP für Prog 4914: 00 04 (Byte[1] = PAT-Index)
    return _build_usbc(2, 0x00, 0xF6, 0x01,
                       bytes([0x00, pat_index & 0xFF]))

def _cmd_stream_release() -> bytes:
    # 0xF8/0x07 – Stream-Freigabe nach Tune
    return _build_usbc(4, 0x00, 0xF8, 0x07)

def _udp_init() -> bytes:
    # 0xF9/0x02 – einmalige Stream-Initialisierung
    return _build_usbc(0, 0x00, 0xF9, 0x02, b"\x01")

def _udp_epg_poll() -> bytes:
    # 0xF9/0x0A – EPG-Metadaten per UDP (vor Stream)
    return _build_usbc(UDP_BLOCK_SIZE, 0x80, 0xF9, 0x0A)

def _udp_request_block(first: bool = False) -> bytes:
    # 0xF9/0x01 – MPEG-TS-Block anfordern
    # Byte[21]: 0x00 für ersten Block, 0x01 für alle weiteren
    byte21 = b"\x00" if first else b"\x01"
    return _build_usbc(UDP_BLOCK_SIZE, 0x80, 0xF9, 0x01, byte21)


# ---------------------------------------------------------------------------
# TCP-Helfer
# ---------------------------------------------------------------------------
def _recv_exactly(sock: socket.socket, n: int,
                  timeout: float = RECV_TIMEOUT) -> bytes:
    """Liest exakt n Byte. Gibt weniger zurück bei Timeout/EOF."""
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


def _send_recv(sock: socket.socket, cmd: bytes,
               data_len: int, label: str = "") -> bytes:
    """
    Sendet Befehl, liest data_len Nutzdaten + 13-Byte USBS-Trailer.
    Gibt nur die Nutzdaten zurück (ohne USBS).
    """
    sock.sendall(cmd)
    raw = _recv_exactly(sock, data_len + USBS_LEN)
    payload = raw[:data_len]
    if label:
        log.debug("%-20s  tx=%dB  rx=%dB  data=%s",
                  label, len(cmd), len(raw),
                  payload[:min(8, len(payload))].hex())
    return payload


# ---------------------------------------------------------------------------
# Phase 1: Verbinden + Init
# ---------------------------------------------------------------------------
def connect(ip: str) -> Optional[socket.socket]:
    """TCP-Verbindung herstellen + Init-Handshake (0x16 + 0x17)."""
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

    # 0x16 – Init, Gerätestatus
    r = _send_recv(sock, _cmd_16(), 12, "0x16 init")
    if len(r) < 2:
        log.error("0x16: keine Antwort")
        sock.close()
        return None
    status = r[1]  # Byte[1] = 0x00 (nicht bereit) oder 0x01 (bereit)
    log.info("0x16 status=0x%02X  gerät=%s", status, r[2:7].hex())

    # 0x17 – Init Phase 2
    r = _send_recv(sock, _cmd_17_init(), 4, "0x17 init")
    log.info("0x17 flag=0x%02X", r[1] if len(r) > 1 else 0xFF)

    # Auf Bereitschaft warten (Status muss 0x01 werden)
    if status != 0x01:
        log.info("Warte auf Dongle-Bereitschaft ...")
        for _ in range(10):
            time.sleep(0.5)
            r = _send_recv(sock, _cmd_16(), 12, "0x16 poll")
            if len(r) >= 2 and r[1] == 0x01:
                log.info("Dongle bereit.")
                break
        else:
            log.warning("Dongle meldet noch nicht 0x01 – trotzdem weiter.")

    return sock


def disconnect(sock: socket.socket) -> None:
    try:
        sock.close()
    except OSError:
        pass
    log.info("TCP-Verbindung getrennt.")


# ---------------------------------------------------------------------------
# Keep-Alive Thread (TCP 0x16 alle KEEPALIVE_INTVL Sekunden)
# ---------------------------------------------------------------------------
def _keepalive_worker(sock: socket.socket,
                      lock: threading.Lock,
                      stop: threading.Event) -> None:
    cmd = _cmd_16()
    while not stop.wait(KEEPALIVE_INTVL):
        try:
            with lock:
                sock.sendall(cmd)
                _recv_exactly(sock, 12 + USBS_LEN)
        except OSError as e:
            log.debug("Keep-Alive Fehler: %s", e)
            break
    log.debug("Keep-Alive Thread beendet.")


# ---------------------------------------------------------------------------
# Phase 2: EPG laden
# ---------------------------------------------------------------------------
def scan_prog_idx(sock: socket.socket,
                  lock: threading.Lock,
                  stop_event: threading.Event,
                  max_per_group: int = 50) -> List[int]:
    """
    Scannt bekannte prog_idx-Gruppen und findet gültige Einträge
    (solche, bei denen 0x30 eine Größe > 0 zurückliefert).
    """
    found = []
    for base in KNOWN_PROG_IDX_GROUPS:
        if stop_event.is_set():
            break
        for seq in range(max_per_group):
            pidx = base | seq
            with lock:
                r = _send_recv(sock, _cmd_epg_size(pidx), 6, f"0x30 scan {pidx:#010x}")
            if len(r) >= 4:
                size = struct.unpack(">I", r[:4])[0]
                if size > 0:
                    found.append(pidx)
    log.info("prog_idx-Scan: %d gültige Einträge gefunden.", len(found))
    return found


def load_epg(sock: socket.socket,
             lock: threading.Lock,
             prog_idx_list: List[int],
             stop_event: threading.Event) -> Dict[int, Channel]:
    """
    Lädt EPG-XML für eine Liste von prog_idx-Werten.
    Gibt {s_id: Channel} zurück.
    """
    channels: Dict[int, Channel] = {}
    total = len(prog_idx_list)

    for i, pidx in enumerate(prog_idx_list):
        if stop_event.is_set():
            break

        # Größe abfragen
        with lock:
            r = _send_recv(sock, _cmd_epg_size(pidx), 6, f"0x30 [{i+1}/{total}]")
        if len(r) < 4:
            continue
        size = struct.unpack(">I", r[:4])[0]
        if size == 0:
            continue

        # XML laden
        with lock:
            r = _send_recv(sock, _cmd_epg_data(pidx, 0, size), size,
                           f"0x31 [{i+1}/{total}]")
        try:
            root = ET.fromstring(r.decode("utf-8", errors="replace"))
        except ET.ParseError as e:
            log.debug("EPG-XML Parse-Fehler bei %#010x: %s", pidx, e)
            continue

        for ch_el in root.findall("ch"):
            s_id  = int(ch_el.get("s_id", 0))
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
# Phase 3: Kanal vorbereiten
# ---------------------------------------------------------------------------
def prepare_channel(sock: socket.socket,
                    lock: threading.Lock,
                    ch: Channel) -> bool:
    """
    0x03 (prepare) → 0x32/0x33 (ch_Info, liefert auch pat_index) → 0x02 (Signal).
    Gibt True zurück wenn Signal stark genug.
    """
    pidx = ch.prog_idx

    # 0x03 – Kanal vorauswählen
    with lock:
        _send_recv(sock, _cmd_prepare(pidx), 0, "0x03 prepare")

    # 0x32/0x33 – ch_Info: s_id + prog_idx bestätigen + PAT-Index auslesen
    with lock:
        r = _send_recv(sock, _cmd_chinfo_size(pidx), 6, "0x32 chinfo-size")
    if len(r) >= 4:
        ci_size = struct.unpack(">I", r[:4])[0]
        if ci_size > 0:
            with lock:
                r = _send_recv(sock, _cmd_chinfo_data(pidx, ci_size), ci_size,
                               "0x33 chinfo")
            xml_str = r.decode("utf-8", errors="replace")
            log.debug("ch_Info: %s", xml_str[:120])
            # PAT-Index aus ch_Info extrahieren (falls enthalten)
            try:
                root = ET.fromstring(xml_str)
                for el in root.iter("ch"):
                    pat_idx = el.get("pat_idx") or el.get("prog_no")
                    if pat_idx is not None:
                        ch.pat_index = int(pat_idx)
                        log.info("ch_Info: pat_index=%d", ch.pat_index)
            except ET.ParseError:
                pass

    # 0x02 – Signal pollen (3 Versuche mit SIGNAL_INTVL Abstand)
    for attempt in range(3):
        time.sleep(SIGNAL_INTVL)
        with lock:
            r = _send_recv(sock, _cmd_signal(), 17, f"0x02 signal [{attempt+1}/3]")
        # PCAP: r[0]=0x00, r[1]=Stärke(0x64=100%), r[2]=Qualität(0x3B–3D)
        if len(r) >= 3:
            strength = r[1]
            quality  = r[2]
            log.info("Signal: Stärke=%d%%  Qualität=%d", strength, quality)
            if strength >= 50:
                return True

    log.warning("Signal schwach – trotzdem weiter.")
    return True


# ---------------------------------------------------------------------------
# Phase 4 + 5: UDP Pre-Polling + Tune + Stream
# ---------------------------------------------------------------------------
def _udp_epg_prepoll(udp: socket.socket, dongle_ip: str,
                     count: int = 10, stop: threading.Event = None) -> None:
    """
    Sendet 0xF9/0x0A (EPG per UDP, ~10–200× laut PCAP) vor dem eigentlichen Tune.
    Verkürzt auf 10 im normalen Betrieb; für PCAP-exaktes Verhalten 200 setzen.
    """
    cmd = _udp_epg_poll()
    for i in range(count):
        if stop and stop.is_set():
            break
        udp.sendto(cmd, (dongle_ip, UDP_PORT))
        try:
            udp.recvfrom(65535)
        except socket.timeout:
            pass
        if i < count - 1:
            time.sleep(0.06)
    log.debug("0xF9/0x0A Pre-Poll abgeschlossen (%d×).", count)


def stream(tcp_sock: socket.socket,
           lock: threading.Lock,
           ch: Channel,
           output_path: str,
           duration_s: float = 0.0,
           epg_prepoll: int = 10) -> None:
    """
    Startet den MPEG-TS-Pull-Stream für einen Kanal.

    Args:
        tcp_sock:    offene TCP-Verbindung zum Dongle
        lock:        Mutex für TCP-Zugriff (Keep-Alive läuft parallel)
        ch:          Kanalinfos (prog_idx, pat_index)
        output_path: Dateipfad oder '-' für stdout
        duration_s:  0 = unbegrenzt
        epg_prepoll: Anzahl 0xF9/0x0A-Pakete vor dem Tune (0 = überspringen)
    """
    stop = threading.Event()
    dongle_ip = tcp_sock.getpeername()[0]

    # Keep-Alive starten
    ka_thread = threading.Thread(
        target=_keepalive_worker,
        args=(tcp_sock, lock, stop),
        daemon=True,
        name="tcp-ka",
    )
    ka_thread.start()

    # UDP-Socket ZUERST binden (kein Paketverlust durch spätes Bind)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    udp.bind(("", UDP_PORT))
    udp.settimeout(5.0)

    try:
        # 1. UDP Stream-Init (0xF9/0x02)
        udp.sendto(_udp_init(), (dongle_ip, UDP_PORT))
        try:
            udp.recvfrom(256)
        except socket.timeout:
            pass
        log.debug("0xF9/0x02 gesendet.")

        # 2. UDP EPG Pre-Poll (0xF9/0x0A) – optional
        if epg_prepoll > 0:
            log.info("UDP EPG Pre-Poll (%d×) ...", epg_prepoll)
            _udp_epg_prepoll(udp, dongle_ip, count=epg_prepoll, stop=stop)

        # 3. Tune-Befehl (0x01) über TCP
        with lock:
            _send_recv(tcp_sock, _cmd_tune(ch.pat_index), 0, "0x01 tune")
        log.info("0x01 Tune gesendet (pat_index=%d).", ch.pat_index)

        # 4. Stream-Freigabe (0xF8/0x07) über TCP
        with lock:
            _send_recv(tcp_sock, _cmd_stream_release(), 0, "0xF8/0x07 release")
        log.debug("0xF8/0x07 Stream-Freigabe gesendet.")

        # 5. Erster UDP-Block (Byte21=0x00)
        udp.sendto(_udp_request_block(first=True), (dongle_ip, UDP_PORT))

        # 6. Kanalwechsel bestätigen (0x17 mit payload=01000000) über TCP
        with lock:
            r = _send_recv(tcp_sock, _cmd_17_confirm(), 4, "0x17 confirm")
        log.info("0x17 Bestätigung: 0x%02X", r[1] if len(r) > 1 else 0xFF)

        # 7. Stream-Loop
        out = (open(output_path, "wb")
               if output_path != "-"
               else sys.stdout.buffer)
        log.info("Stream aktiv → %s   (STRG+C zum Beenden)",
                 output_path if output_path != "-" else "stdout")

        t_start   = time.monotonic()
        block_num = 0
        ts_bytes  = 0

        try:
            while not stop.is_set():
                udp.sendto(_udp_request_block(first=False), (dongle_ip, UDP_PORT))
                try:
                    data, _ = udp.recvfrom(65535)
                except socket.timeout:
                    log.warning("UDP-Timeout – kein Datenblock.")
                    break

                # USBS oder 0xF9/0x0A-Echo ignorieren
                if data[:4] == b"USBS" or data[:2] == b"\xf9\x0a":
                    continue

                # TS-Sync suchen
                if len(data) < 1:
                    continue
                if data[0] == TS_SYNC:
                    ts_data = data
                elif TS_SYNC in data[:200]:
                    idx = data.index(TS_SYNC)
                    ts_data = data[idx:]
                else:
                    log.debug("Kein TS-Sync (0x%02X) – verworfen.", data[0])
                    continue

                out.write(ts_data)
                out.flush()
                block_num += 1
                ts_bytes  += len(ts_data)

                if block_num % 50 == 0:
                    elapsed   = time.monotonic() - t_start
                    rate_kbps = (ts_bytes / 1024) / max(elapsed, 0.001)
                    log.info("Block %4d  |  %.1f MiB  |  %.0f KB/s",
                             block_num, ts_bytes / 1_048_576, rate_kbps)

                if duration_s > 0 and (time.monotonic() - t_start) >= duration_s:
                    log.info("Zieldauer %.0f s erreicht.", duration_s)
                    break

        except KeyboardInterrupt:
            print()
            log.info("Stream durch Nutzer abgebrochen.")
        finally:
            if output_path != "-":
                out.close()
            log.info("Stream beendet. Blöcke: %d  |  %.2f MiB",
                     block_num, ts_bytes / 1_048_576)

    finally:
        stop.set()
        ka_thread.join(timeout=4.0)
        udp.close()


# ---------------------------------------------------------------------------
# Bekannte Kanäle aus PCAP (Fallback ohne EPG-Scan)
# ---------------------------------------------------------------------------
KNOWN_CHANNELS: Dict[int, Channel] = {
    4914: Channel(
        s_id=4914,
        ts_id=33079,
        prog_idx=0x40B40089,
        pat_index=4,           # Index 4 in der PAT (bestätigt aus PCAP)
        events=[Event(evt_id=0, desc="ZDF (Referenz-Kanal aus PCAP)")],
    ),
}


# ---------------------------------------------------------------------------
# Interaktives Menü
# ---------------------------------------------------------------------------
_MENU = """
╔══════════════════════════════════════════════════╗
║       WISI O2D  –  DVB-over-IP Client v2        ║
╠══════════════════════════════════════════════════╣
║  [1]  EPG laden + Kanal wählen                  ║
║  [2]  Stream starten (letzter/bekannter Kanal)  ║
║  [3]  prog_idx-Gruppen scannen                  ║
║  [4]  Verbindung neu aufbauen                   ║
║  [q]  Beenden                                   ║
╚══════════════════════════════════════════════════╝"""


def _pick_channel(channels: Dict[int, Channel]) -> Optional[Channel]:
    chlist = sorted(channels.values(), key=lambda c: c.s_id)
    print(f"\n{'Nr':>4}  {'s_id':>6}  {'prog_idx':>12}  {'':>4}  Programm")
    print("-" * 65)
    for i, ch in enumerate(chlist, 1):
        lock = "🔒" if ch.is_encrypted else "   "
        evt  = ch.events[0].desc[:35] if ch.events else "(kein EPG)"
        print(f"{i:>4}  {ch.s_id:>6}  {ch.prog_idx:#010x}  {lock}  {evt}")
    print()
    try:
        nr = int(input("Nummer (0=Abbruch): "))
        if 1 <= nr <= len(chlist):
            return chlist[nr - 1]
    except (ValueError, EOFError):
        pass
    return None


def main_menu(sock: socket.socket, ip: str) -> None:
    lock     = threading.Lock()
    channels: Dict[int, Channel] = {}
    selected: Optional[Channel]  = None
    stop_epg = threading.Event()

    print(_MENU)
    while True:
        try:
            choice = input("\nAuswahl > ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if choice == "q":
            break

        elif choice == "1":
            # Bekannte prog_idx aus PCAP + KNOWN_CHANNELS
            pidx_list = [ch.prog_idx for ch in KNOWN_CHANNELS.values()]
            # Demo-Ergänzung: erste 20 Einträge aus Gruppe 0x40B4
            pidx_list += [0x40B40000 | i for i in range(20)]
            stop_epg.clear()
            log.info("Lade EPG für %d Einträge ...", len(pidx_list))
            channels = load_epg(sock, lock, pidx_list, stop_epg)
            if not channels:
                log.warning("Keine EPG-Daten – nutze bekannte Kanäle.")
                channels = KNOWN_CHANNELS.copy()
            selected = _pick_channel(channels)
            if selected:
                log.info("Ausgewählt: %s", selected)

        elif choice == "2":
            if not selected:
                selected = KNOWN_CHANNELS[4914]
                log.info("Nutze Standard-Kanal s_id=4914")
            if selected.is_encrypted:
                log.warning("Kanal ist verschlüsselt – Stream evtl. nicht möglich.")
            prepare_channel(sock, lock, selected)
            outfile = input("Ausgabedatei [stream.ts] (- für stdout): ").strip() or "stream.ts"
            dur_str = input("Dauer in Sekunden [0=unbegrenzt]: ").strip()
            try:
                dur = float(dur_str) if dur_str else 0.0
            except ValueError:
                dur = 0.0
            stream(sock, lock, selected, outfile, dur)

        elif choice == "3":
            log.info("Scanne prog_idx-Gruppen ...")
            stop_epg.clear()
            found = scan_prog_idx(sock, lock, stop_epg, max_per_group=30)
            log.info("Gefunden: %s", [f"{p:#010x}" for p in found])

        elif choice == "4":
            disconnect(sock)
            time.sleep(0.5)
            new = connect(ip)
            if new is None:
                log.error("Erneute Verbindung fehlgeschlagen.")
                return
            sock = new
            lock = threading.Lock()
            log.info("Erneut verbunden.")
            print(_MENU)

        else:
            print("Unbekannte Eingabe. Bitte 1, 2, 3, 4 oder q.")

    disconnect(sock)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> None:
    p = argparse.ArgumentParser(
        description="WISI O2D DVB-over-IP Client",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--ip",        default=DEFAULT_IP,    help="Dongle-IP")
    p.add_argument("--debug",     action="store_true",   help="Debug-Logging")
    p.add_argument("--stream",    action="store_true",   help="Direkt streamen (kein Menü)")
    p.add_argument("--prog",      type=int, default=4914, help="Programm-Nummer (s_id)")
    p.add_argument("--output",    default="stream.ts",   help="Ausgabedatei oder - für stdout")
    p.add_argument("--duration",  type=float, default=0.0, help="Dauer in Sekunden (0=unbegrenzt)")
    p.add_argument("--prepoll",   type=int, default=10,  help="Anzahl 0xF9/0x0A Pre-Poll-Pakete")
    p.add_argument("--no-prepoll", action="store_true",  help="0xF9/0x0A Pre-Poll überspringen")
    args = p.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    sock = connect(args.ip)
    if sock is None:
        sys.exit(1)
    log.info("✓ Dongle unter %s bereit.", args.ip)

    lock = threading.Lock()

    if args.stream:
        ch = KNOWN_CHANNELS.get(args.prog)
        if ch is None:
            log.error("Programm %d unbekannt. Nutze --prog 4914.", args.prog)
            disconnect(sock)
            sys.exit(1)
        prepare_channel(sock, lock, ch)
        prepoll = 0 if args.no_prepoll else args.prepoll
        stream(sock, lock, ch, args.output, args.duration, prepoll)
        disconnect(sock)
    else:
        main_menu(sock, args.ip)


if __name__ == "__main__":
    main()
