"""
WISI / Tivizen / TiViCon DVB-over-IP  –  Client v3
====================================================

Protokoll-Referenz:
  research/pcap_analysis.md         – Eigene PCAP-Analyse
  research/deep_research_gemini.md  – Gemini Deep Research (icube Corp.)

Änderungen v3 gegenüber v2:
  - 0xF9/0x0A-Block wird jetzt geparst: 28-Byte-Header verworfen,
    Datensätze (128B) extrahieren Kanalliste + PAT-Index direkt
  - 0xF9/0x01-Stream: 28-Byte-Header wird verworfen, nur reiner MPEG-TS geschrieben
  - dCBWDataTransferLength: Big-Endian, verifiziert gegen den neuen App-PCAP
  - Kanalliste wird aus 0xF9/0x0A gebaut (kein EPG-TCP-Scan mehr nötig)
  - Kanalwechsel per verifiziertem PAT-Index aus Service-DB
  - Daemon-Hintergrund: icube Corp. apixd (Seoul, KR)
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
KEEPALIVE_INTVL = 2.0
SIGNAL_INTVL    = 3.0
UDP_PULL_INTVL  = 0.5

# UDP-Block: 32.740 Byte = 28 Byte Header + 174 × 188 Byte TS
UDP_RESPONSE_SIZE = 32_740
UDP_HEADER_SIZE   = 28        # Diese Bytes am Anfang jedes 0xF9-Blocks verwerfen
UDP_TS_SIZE       = 32_712    # 174 × 188 Byte reiner MPEG-TS
UDP_REQUEST_LEN   = 0xBC00    # 48128 – Anforderungsgröße im USBC-datalen-Feld

# APIX serialisiert das Längenfeld Big-Endian, anders als ein natives USB-BOT-CBW.
CBW_LEN_FORMAT = ">I"

TS_PKT_SIZE = 188
TS_SYNC     = 0x47
USBS_LEN    = 13   # USBS-Status-Trailer

# Service-Datensatz-Layout im 0xF9/0x0A-Block (ab Offset 32, je 128 Byte)
SERVICE_ENTRY_SIZE  = 128
SERVICE_DB_HEADER   = 32   # Bytes zu überspringen vor erstem Datensatz


# ---------------------------------------------------------------------------
# Datenmodelle
# ---------------------------------------------------------------------------
@dataclass
class ServiceEntry:
    """Ein Eintrag aus dem 0xF9/0x0A Service-DB-Block."""
    pat_index:   int          # Position im Array = PAT-Index für 0x01-Tune
    prog_idx:    int          # 0x40xxxxxx=FTA, 0x48xxxxxx=Pay-TV
    service_id:  int          # DVB Service ID
    pmt_pid:     int
    pcr_pid:     int
    video_pid:   int
    video_type:  int          # 0x1B=H.264, 0x02=MPEG-2
    audio_pid:   int
    audio_type:  int          # 0x03=MPEG-1 Audio L2, 0x0F=AAC
    flags:       int          # 0x0001=Aktiv, 0x0008=Verschlüsselt
    name:        str

    @property
    def is_encrypted(self) -> bool:
        return bool(self.flags & 0x0008) or (self.prog_idx >> 24) == 0x48

    @property
    def is_active(self) -> bool:
        return bool(self.flags & 0x0001)

    def __str__(self) -> str:
        lock = "🔒" if self.is_encrypted else "FTA"
        return (f"[{self.pat_index:3d}] sid={self.service_id:5d} "
                f"vpid={self.video_pid:#06x} apid={self.audio_pid:#06x} "
                f"[{lock}] {self.name}")


@dataclass
class Event:
    evt_id: int
    desc:   str
    date:   str = ""
    time_:  str = ""
    dur:    str = ""

@dataclass
class Channel:
    service:  ServiceEntry
    events:   List[Event] = field(default_factory=list)

    @property
    def s_id(self) -> int:
        return self.service.service_id

    @property
    def pat_index(self) -> int:
        return self.service.pat_index


# ---------------------------------------------------------------------------
# USBC-Builder
# ---------------------------------------------------------------------------
def _build_usbc(data_len: int, flags: int, prefix: int,
                opcode: int, payload: bytes = b"") -> bytes:
    """
    31-Byte USBC Command Block (USB Bulk-Only Transport CBW).
    data_len wird im APIX-Protokoll als Big-Endian kodiert.
    """
    cdb = (bytes([prefix]) + b"APIX" + bytes([opcode]) + payload).ljust(16, b"\x00")
    assert len(cdb) == 16
    return (b"USBC" + MAGIC_TAG
            + struct.pack(CBW_LEN_FORMAT, data_len)
            + bytes([flags, 0x00, 0x10])
            + cdb)


# Befehls-Builder
def _cmd_16()           -> bytes: return _build_usbc(12, 0x80, 0xF6, 0x16)
def _cmd_17_init()      -> bytes: return _build_usbc(4,  0x80, 0xF6, 0x17)
def _cmd_17_confirm()   -> bytes: return _build_usbc(4,  0x80, 0xF6, 0x17, b"\x01\x00\x00\x00")
def _cmd_signal()       -> bytes: return _build_usbc(17, 0x80, 0xF6, 0x02)
def _cmd_stream_release() -> bytes: return _build_usbc(4, 0x00, 0xF8, 0x07)

def _cmd_epg_size(prog_idx: int) -> bytes:
    return _build_usbc(6, 0x80, 0xF6, 0x30, struct.pack(">I", prog_idx))

def _cmd_epg_data(prog_idx: int, offset: int, length: int) -> bytes:
    return _build_usbc(length, 0x80, 0xF6, 0x31,
                       struct.pack(">I", prog_idx) + struct.pack(">H", offset))

def _cmd_prepare(prog_idx: int) -> bytes:
    return _build_usbc(4, 0x80, 0xF6, 0x03,
                       b"\x00\x00\x00\x02" + struct.pack(">I", prog_idx))

def _cmd_chinfo_size(prog_idx: int) -> bytes:
    return _build_usbc(6, 0x80, 0xF6, 0x32, struct.pack(">I", prog_idx))

def _cmd_chinfo_data(prog_idx: int, length: int) -> bytes:
    return _build_usbc(length, 0x80, 0xF6, 0x33, struct.pack(">I", prog_idx))

def _cmd_tune(pat_index: int) -> bytes:
    # Byte[0]=0x00 Flag, Byte[1]=PAT-Array-Index (0-basiert)
    return _build_usbc(2, 0x80, 0xF6, 0x01,
                       bytes([0x00, pat_index & 0xFF]))

def _udp_init() -> bytes:
    return _build_usbc(0, 0x00, 0xF9, 0x02, b"\x01")

def _udp_service_db() -> bytes:
    """0xF9/0x0A – Vorkompilierte Service-Datenbank anfordern."""
    return _build_usbc(UDP_REQUEST_LEN, 0x80, 0xF9, 0x0A)

def _udp_request_block(first: bool = False) -> bytes:
    """0xF9/0x01 – MPEG-TS-Block anfordern (Pull)."""
    byte21 = b"\x00" if first else b"\x01"
    return _build_usbc(UDP_REQUEST_LEN, 0x80, 0xF9, 0x01, byte21)


# ---------------------------------------------------------------------------
# TCP-Helfer
# ---------------------------------------------------------------------------
def _recv_exactly(sock: socket.socket, n: int,
                  timeout: float = RECV_TIMEOUT) -> bytes:
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
    """Sendet Befehl, liest Nutzdaten (ohne USBS-Trailer)."""
    sock.sendall(cmd)
    raw = _recv_exactly(sock, data_len + USBS_LEN)
    payload = raw[:data_len]
    if label:
        log.debug("%-22s tx=%dB rx=%dB head=%s",
                  label, len(cmd), len(raw),
                  payload[:min(6, len(payload))].hex())
    return payload


# ---------------------------------------------------------------------------
# Phase 1: Verbinden + Init
# ---------------------------------------------------------------------------
def connect(ip: str) -> Optional[socket.socket]:
    log.info("Verbinde %s:%d ...", ip, TCP_PORT)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(CONNECT_TIMEOUT)
    try:
        sock.connect((ip, TCP_PORT))
    except (OSError, socket.timeout) as e:
        log.error("TCP fehlgeschlagen: %s", e)
        sock.close()
        return None
    sock.settimeout(None)

    r = _send_recv(sock, _cmd_16(), 12, "0x16 init")
    if len(r) < 3:
        log.error("0x16: keine Antwort"); sock.close(); return None
    status = r[2]
    log.info("0x16 status=0x%02X  gerät=%s", status, r[3:8].hex())

    r = _send_recv(sock, _cmd_17_init(), 4, "0x17 init")
    log.info("0x17 flag=0x%02X", r[2] if len(r) > 2 else 0xFF)

    if status != 0x01:
        log.info("Warte auf Bereitschaft ...")
        for _ in range(10):
            time.sleep(0.5)
            r = _send_recv(sock, _cmd_16(), 12, "0x16 poll")
            if len(r) >= 3 and r[2] == 0x01:
                log.info("Dongle bereit.")
                break
        else:
            log.warning("Dongle nicht 0x01 – weiter.")
    return sock


def disconnect(sock: socket.socket) -> None:
    try:
        sock.close()
    except OSError:
        pass
    log.info("Verbindung getrennt.")


# ---------------------------------------------------------------------------
# Keep-Alive Thread
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


# ---------------------------------------------------------------------------
# Service-DB aus 0xF9/0x0A parsen (NEU – ersetzt EPG-TCP-Scan)
# ---------------------------------------------------------------------------
def parse_service_db(data: bytes) -> List[ServiceEntry]:
    """
    Parst den 32.740-Byte-Block von 0xF9/0x0A.
    Struktur: 28-Byte UDP-Header + 32-Byte DB-Header + N × 128-Byte-Datensätze.

    Gibt Liste von ServiceEntry zurück, indiziert = PAT-Index für 0x01-Tune.
    """
    if len(data) < UDP_HEADER_SIZE + SERVICE_DB_HEADER:
        log.warning("Service-DB zu kurz: %d Byte", len(data))
        return []

    # 28-Byte UDP-Response-Header verwerfen (F9 0A 00 00 ...)
    body = data[UDP_HEADER_SIZE:]
    # Weiteren 32-Byte DB-Header verwerfen
    entries_raw = body[SERVICE_DB_HEADER:]

    services: List[ServiceEntry] = []
    idx = 0
    offset = 0
    while offset + SERVICE_ENTRY_SIZE <= len(entries_raw):
        rec = entries_raw[offset:offset + SERVICE_ENTRY_SIZE]

        prog_idx   = struct.unpack_from(">I", rec, 0x00)[0]
        service_id = struct.unpack_from(">H", rec, 0x04)[0]
        pmt_pid    = struct.unpack_from(">H", rec, 0x06)[0]
        pcr_pid    = struct.unpack_from(">H", rec, 0x08)[0]
        video_pid  = struct.unpack_from(">H", rec, 0x0A)[0]
        video_type = rec[0x0C]
        audio_pid  = struct.unpack_from(">H", rec, 0x0D)[0]
        audio_type = rec[0x0F]
        flags      = struct.unpack_from(">H", rec, 0x10)[0]
        name_raw   = rec[0x12:0x32]
        name       = name_raw.rstrip(b"\x00").decode("iso-8859-15", errors="replace")

        # Leere / ungültige Einträge überspringen
        if service_id == 0 and prog_idx == 0:
            offset += SERVICE_ENTRY_SIZE
            idx += 1
            continue

        services.append(ServiceEntry(
            pat_index=idx,
            prog_idx=prog_idx,
            service_id=service_id,
            pmt_pid=pmt_pid,
            pcr_pid=pcr_pid,
            video_pid=video_pid,
            video_type=video_type,
            audio_pid=audio_pid,
            audio_type=audio_type,
            flags=flags,
            name=name,
        ))
        offset += SERVICE_ENTRY_SIZE
        idx += 1

    log.info("Service-DB geparst: %d Einträge.", len(services))
    return services


def fetch_service_db(udp: socket.socket, dongle_ip: str,
                     attempts: int = 5) -> List[ServiceEntry]:
    """Holt die Service-DB via 0xF9/0x0A (mehrere Versuche)."""
    cmd = _udp_service_db()
    for attempt in range(attempts):
        udp.sendto(cmd, (dongle_ip, UDP_PORT))
        try:
            data, _ = udp.recvfrom(65535)
            if len(data) >= UDP_HEADER_SIZE + SERVICE_DB_HEADER:
                log.info("Service-DB empfangen: %d Byte (Versuch %d)", len(data), attempt + 1)
                return parse_service_db(data)
        except socket.timeout:
            log.debug("0xF9/0x0A Timeout (Versuch %d/%d)", attempt + 1, attempts)
        time.sleep(0.5)
    log.warning("Service-DB nicht empfangen – nutze leere Liste.")
    return []


# ---------------------------------------------------------------------------
# EPG via TCP laden (optional, ergänzt Service-DB mit Programm-Infos)
# ---------------------------------------------------------------------------
def enrich_with_epg(sock: socket.socket, lock: threading.Lock,
                    services: List[ServiceEntry],
                    stop: threading.Event) -> Dict[int, List[Event]]:
    """Lädt EPG-Ereignisse per TCP 0x30/0x31 für alle Service-Einträge."""
    epg: Dict[int, List[Event]] = {}
    for svc in services:
        if stop.is_set():
            break
        with lock:
            r = _send_recv(sock, _cmd_epg_size(svc.prog_idx), 6,
                           f"0x30 sid={svc.service_id}")
        if len(r) < 6:
            continue
        size = struct.unpack(">I", r[2:6])[0]
        if size == 0:
            continue
        with lock:
            r = _send_recv(sock, _cmd_epg_data(svc.prog_idx, 0, size), size,
                           f"0x31 sid={svc.service_id}")
        try:
            root = ET.fromstring(r[2:2 + size].decode("utf-8", errors="replace"))
            evts = []
            for ch_el in root.findall("ch"):
                for evt_el in ch_el.findall("evt"):
                    evts.append(Event(
                        evt_id=int(evt_el.get("id", 0)),
                        desc=evt_el.get("des", ""),
                        date=evt_el.get("date", ""),
                        time_=evt_el.get("time", ""),
                        dur=evt_el.get("dur", ""),
                    ))
            epg[svc.service_id] = evts
        except ET.ParseError as exc:
            log.warning("EPG-XML für SID %d nicht lesbar: %s", svc.service_id, exc)
    return epg


# ---------------------------------------------------------------------------
# Phase 3: Kanal vorbereiten
# ---------------------------------------------------------------------------
def prepare_channel(sock: socket.socket, lock: threading.Lock,
                    svc: ServiceEntry) -> None:
    with lock:
        _send_recv(sock, _cmd_prepare(svc.prog_idx), 4, "0x03 prepare")
    with lock:
        r = _send_recv(sock, _cmd_chinfo_size(svc.prog_idx), 6, "0x32 chinfo-size")
    if len(r) >= 6:
        ci_size = struct.unpack(">I", r[2:6])[0]
        if ci_size > 0:
            with lock:
                r = _send_recv(sock, _cmd_chinfo_data(svc.prog_idx, ci_size), ci_size,
                               "0x33 chinfo")
            log.debug("ch_Info: %s", r[2:2 + ci_size].decode("utf-8", "replace")[:80])

    for attempt in range(3):
        time.sleep(SIGNAL_INTVL)
        with lock:
            r = _send_recv(sock, _cmd_signal(), 17, f"0x02 signal [{attempt+1}/3]")
        if len(r) >= 5:
            log.info("Signal: Stärke=%d%%  Qualität=%d", r[3], r[4])
            if r[3] >= 50:
                return
    log.warning("Signal schwach – weiter.")


# ---------------------------------------------------------------------------
# Phase 4+5: Tune + MPEG-TS-Stream
# ---------------------------------------------------------------------------
def stream(tcp_sock: socket.socket, lock: threading.Lock,
           svc: ServiceEntry, output_path: str,
           duration_s: float = 0.0,
           keepalive_active: bool = False) -> None:
    """
    Startet MPEG-TS-Pull-Stream.
    Verwirft den 28-Byte-Header jedes 0xF9/0x01-Antwortblocks.
    """
    stop = threading.Event()
    dongle_ip = tcp_sock.getpeername()[0]

    ka: Optional[threading.Thread] = None
    if not keepalive_active:
        ka = threading.Thread(target=_keepalive_worker,
                              args=(tcp_sock, lock, stop), daemon=True)
        ka.start()
    stream_ka_stop: Optional[threading.Event] = None
    stream_ka: Optional[threading.Thread] = None
    stream_ka_sock: Optional[socket.socket] = None

    # UDP-Socket VOR Tune binden
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    udp.bind(("", 0))
    udp.settimeout(0.1)

    try:
        # UDP Init
        udp.sendto(_udp_init(), (dongle_ip, UDP_PORT))
        try:
            udp.recvfrom(256)
        except socket.timeout:
            pass

        # Tune (TCP)
        with lock:
            _send_recv(tcp_sock, _cmd_tune(svc.pat_index), 2, "0x01 tune")
        log.info("Tune: pat_index=%d  sid=%d  (%s)", svc.pat_index, svc.service_id, svc.name)

        # Stream-Freigabe (TCP)
        with lock:
            _send_recv(tcp_sock, _cmd_stream_release(), 0, "0xF8/0x07 release")

        # Erster UDP-Block (Byte21=0x00)
        udp.sendto(_udp_request_block(first=True), (dongle_ip, UDP_PORT))

        # Tune bestätigen (TCP)
        with lock:
            r = _send_recv(tcp_sock, _cmd_17_confirm(), 4, "0x17 confirm")
        log.info("0x17 confirm: 0x%02X", r[2] if len(r) > 2 else 0xFF)

        # The dongle closes the tuning connection after confirmation. Keep the
        # stream alive on a separate control connection, as the app does.
        stream_ka_sock = connect(dongle_ip)
        if stream_ka_sock is None:
            raise ConnectionError("Keep-Alive-Verbindung nach Tune fehlgeschlagen.")
        stream_ka_stop = threading.Event()
        stream_ka = threading.Thread(
            target=_keepalive_worker,
            args=(stream_ka_sock, threading.Lock(), stream_ka_stop),
            daemon=True,
        )
        stream_ka.start()

        out = (open(output_path, "wb")
               if output_path != "-" else sys.stdout.buffer)
        log.info("Stream → %s  (STRG+C zum Beenden)", output_path)

        t_start = time.monotonic()
        block_num = 0
        ts_bytes  = 0
        pull_count = 1
        next_pull = t_start + UDP_PULL_INTVL
        last_packet_at = t_start
        next_timeout_warning = t_start + 5.0

        try:
            while not stop.is_set():
                now = time.monotonic()
                if duration_s > 0 and now - t_start >= duration_s:
                    log.info("Dauer %.0f s erreicht.", duration_s)
                    break
                if now >= next_pull:
                    udp.sendto(_udp_request_block(first=False), (dongle_ip, UDP_PORT))
                    pull_count += 1
                    next_pull = now + UDP_PULL_INTVL
                    log.debug("0xF9/0x01 Pull #%d gesendet", pull_count)

                try:
                    data, _ = udp.recvfrom(65535)
                except socket.timeout:
                    now = time.monotonic()
                    if now >= next_timeout_warning and now - last_packet_at >= 5.0:
                        log.warning("Seit 5 Sekunden keine UDP-Streamdaten; Pulls laufen weiter.")
                        next_timeout_warning = now + 5.0
                    continue

                # USBS oder 0xF9/0x0A-Echo ignorieren
                if data[:4] == b"USBS" or data[:2] == b"\xf9\x0a":
                    continue

                # Locate an aligned MPEG-TS payload without assuming a fixed header.
                sync_offset = data.find(bytes([TS_SYNC]))
                while sync_offset >= 0:
                    if (sync_offset + 3 * TS_PKT_SIZE < len(data)
                            and all(data[sync_offset + i * TS_PKT_SIZE] == TS_SYNC
                                    for i in range(4))):
                        break
                    sync_offset = data.find(bytes([TS_SYNC]), sync_offset + 1)
                if sync_offset < 0:
                    log.debug("Kein MPEG-TS-Sync in UDP-Datagramm (%d Byte) – verworfen",
                              len(data))
                    continue
                ts_data = data[sync_offset:]
                last_packet_at = time.monotonic()
                next_timeout_warning = last_packet_at + 5.0
                if block_num == 0:
                    log.debug("Erstes Stream-Datagramm: %d Byte, TS-Offset %d",
                              len(data), sync_offset)

                complete_len = len(ts_data) - len(ts_data) % TS_PKT_SIZE
                if complete_len == 0:
                    log.debug("UDP-Datagramm enthält keine vollständigen TS-Pakete")
                    continue
                out.write(ts_data[:complete_len])
                out.flush()
                block_num += 1
                ts_bytes  += complete_len

                if block_num % 50 == 0:
                    elapsed = time.monotonic() - t_start
                    kbps = (ts_bytes / 1024) / max(elapsed, 0.001)
                    log.info("Block %4d | %.1f MiB | %.0f KB/s",
                             block_num, ts_bytes / 1_048_576, kbps)

        except KeyboardInterrupt:
            print()
            log.info("Abgebrochen.")
        finally:
            if output_path != "-":
                out.close()
            log.info("Stream beendet. %d Blöcke, %d Pulls, %.2f MiB",
                     block_num, pull_count, ts_bytes / 1_048_576)

    finally:
        stop.set()
        if ka is not None:
            ka.join(timeout=4.0)
        if stream_ka_stop is not None:
            stream_ka_stop.set()
        if stream_ka is not None:
            stream_ka.join(timeout=4.0)
        if stream_ka_sock is not None:
            disconnect(stream_ka_sock)
        udp.close()


# ---------------------------------------------------------------------------
# Fallback: bekannte Kanäle (wenn Service-DB leer)
# ---------------------------------------------------------------------------
_FALLBACK_SERVICE = ServiceEntry(
    pat_index=4, prog_idx=0x40B40089, service_id=4914,
    pmt_pid=0x006E, pcr_pid=0x1338,
    video_pid=0x1338, video_type=0x1B,
    audio_pid=0x1339, audio_type=0x03,
    flags=0x0001, name="ZDF (Fallback aus PCAP)",
)


# ---------------------------------------------------------------------------
# Interaktives Menü
# ---------------------------------------------------------------------------
_MENU = """
╔════════════════════════════════════════════════════╗
║      WISI OR S2D  –  DVB-over-IP Client v3       ║
╠════════════════════════════════════════════════════╣
║  [1]  Service-DB laden (0xF9/0x0A) + Kanal wählen║
║  [2]  EPG nachladen (TCP 0x30/0x31)               ║
║  [3]  Stream starten                              ║
║  [4]  PAT-Index testen (0–5)                      ║
║  [5]  Verbindung neu aufbauen                     ║
║  [q]  Beenden                                     ║
╚════════════════════════════════════════════════════╝"""


def _pick_service(services: List[ServiceEntry]) -> Optional[ServiceEntry]:
    active = [s for s in services if s.is_active and not s.is_encrypted]
    active += [s for s in services if s.is_active and s.is_encrypted]
    if not active:
        active = services

    print(f"\n{'Nr':>4}  {'PAT':>4}  {'sid':>6}  {'vpid':>6}  {'apid':>6}  Name")
    print("-" * 70)
    for i, s in enumerate(active[:50], 1):
        lock = "🔒" if s.is_encrypted else "   "
        print(f"{i:>4}  {s.pat_index:>4}  {s.service_id:>6}  "
              f"{s.video_pid:#06x}  {s.audio_pid:#06x}  {lock} {s.name}")
    print()
    try:
        nr = int(input("Nummer (0=Abbruch): "))
        if 1 <= nr <= len(active):
            return active[nr - 1]
    except (ValueError, EOFError):
        pass
    return None


def main_menu(sock: socket.socket, ip: str) -> None:
    lock      = threading.Lock()
    services: List[ServiceEntry] = []
    selected: Optional[ServiceEntry] = None
    stop_epg  = threading.Event()
    keepalive_stop = threading.Event()
    keepalive = threading.Thread(
        target=_keepalive_worker, args=(sock, lock, keepalive_stop), daemon=True)
    keepalive.start()

    # UDP-Socket für Service-DB-Abfragen (wird wiederverwendet)
    udp_ctrl = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_ctrl.settimeout(3.0)

    # Beim Start sofort Service-DB laden
    log.info("Lade Service-DB via 0xF9/0x0A ...")
    services = fetch_service_db(udp_ctrl, ip)

    print(_MENU)
    while True:
        try:
            choice = input("\nAuswahl > ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print(); break

        if choice == "q":
            break

        elif choice == "1":
            log.info("Lade Service-DB ...")
            services = fetch_service_db(udp_ctrl, ip)
            if not services:
                log.warning("Leer – nutze Fallback.")
                services = [_FALLBACK_SERVICE]
            selected = _pick_service(services)
            if selected:
                log.info("Gewählt: %s", selected)

        elif choice == "2":
            if not services:
                log.warning("Erst [1] ausführen.")
                continue
            log.info("Lade EPG ...")
            stop_epg.clear()
            epg = enrich_with_epg(sock, lock, services, stop_epg)
            log.info("EPG geladen für %d Kanäle.", len(epg))

        elif choice == "3":
            if not selected:
                selected = _FALLBACK_SERVICE
                log.info("Nutze Fallback-Kanal sid=4914")
            if selected.is_encrypted:
                log.warning("Kanal verschlüsselt – Stream evtl. leer.")
            prepare_channel(sock, lock, selected)
            outfile = input("Ausgabedatei [stream.ts] (- für stdout): ").strip() or "stream.ts"
            dur_str = input("Dauer in Sekunden [0=unbegrenzt]: ").strip()
            try:
                dur = float(dur_str) if dur_str else 0.0
            except ValueError:
                dur = 0.0
            stream(sock, lock, selected, outfile, dur, keepalive_active=True)

        elif choice == "4":
            log.info("PAT-Index-Test (schickt 0x01 mit Index 0–5) ...")
            for idx in range(6):
                with lock:
                    _send_recv(sock, _cmd_tune(idx), 0, f"0x01 idx={idx}")
                log.info("Index %d gesendet – jetzt UDP-Block prüfen", idx)
                input("  Enter für nächsten Index ...")

        elif choice == "5":
            keepalive_stop.set()
            keepalive.join(timeout=4.0)
            udp_ctrl.close()
            disconnect(sock)
            time.sleep(0.5)
            new = connect(ip)
            if new is None:
                log.error("Verbindung fehlgeschlagen.")
                return
            sock = new
            lock = threading.Lock()
            keepalive_stop = threading.Event()
            keepalive = threading.Thread(
                target=_keepalive_worker, args=(sock, lock, keepalive_stop), daemon=True)
            keepalive.start()
            udp_ctrl = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_ctrl.settimeout(3.0)
            print(_MENU)
        else:
            print("1–5 oder q.")

    keepalive_stop.set()
    keepalive.join(timeout=4.0)
    udp_ctrl.close()
    disconnect(sock)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> None:
    p = argparse.ArgumentParser(
        description="WISI OR S2D DVB-over-IP Client v3 (icube APIX)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--ip",       default=DEFAULT_IP)
    p.add_argument("--debug",    action="store_true")
    p.add_argument("--stream",   action="store_true",  help="Direkt streamen")
    p.add_argument("--pat-idx",  type=int, default=4,  help="PAT-Index für --stream")
    p.add_argument("--output",   default="stream.ts")
    p.add_argument("--duration", type=float, default=0.0)
    args = p.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    sock = connect(args.ip)
    if sock is None:
        sys.exit(1)
    lock = threading.Lock()

    if args.stream:
        keepalive_stop = threading.Event()
        keepalive = threading.Thread(
            target=_keepalive_worker, args=(sock, lock, keepalive_stop), daemon=True)
        keepalive.start()

        # Service-DB laden um PAT-Index zu verifizieren
        udp_tmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_tmp.settimeout(3.0)
        try:
            services = fetch_service_db(udp_tmp, args.ip)
            svc = next((s for s in services if s.pat_index == args.pat_idx), None)
            if svc is None:
                log.warning("PAT-Index %d nicht in Service-DB – nutze Fallback.", args.pat_idx)
                svc = _FALLBACK_SERVICE
                svc = ServiceEntry(**{**svc.__dict__, "pat_index": args.pat_idx})

            prepare_channel(sock, lock, svc)
            stream(sock, lock, svc, args.output, args.duration, keepalive_active=True)
        finally:
            udp_tmp.close()
            keepalive_stop.set()
            keepalive.join(timeout=4.0)
            disconnect(sock)
    else:
        main_menu(sock, args.ip)


if __name__ == "__main__":
    main()
