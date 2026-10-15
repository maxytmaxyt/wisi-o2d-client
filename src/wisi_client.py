"""
WISI / TiViCon OR S2D DVB-over-IP  –  Client v4
=================================================

Protokoll-Referenz:
  research/pcap_analysis.md             – ursprüngliche PCAP-Analyse (OR S2D / O2D)
  PCAPdroid_12_Okt._16_16_04.pcap      – neues OR S2D PCAP (Kanal-Liste)
  PCAPdroid_12_Okt._16_28_17.pcap      – neues OR S2D PCAP (Stream)

Verifizierter Framing-Stand:
    - APK-SDK und PCAPs erzeugen 31-Byte-USBC-Grundrequests.
    - Die untersuchten APIX-Antworten enden mit einem 13-Byte-USBS-Suffix.
    - Die OR-S2D-Kanalliste läuft im PCAP über TCP 0xF6/0x20 und 0xF6/0x21.
    - Das APK-SDK verwendet UDP 0xF9/0x0A für einen Speedtest, nicht als Senderliste.
"""

from __future__ import annotations

import argparse
import logging
import re
import socket
import struct
import sys
import threading
import time
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
DEFAULT_IP       = "192.168.178.32"
TCP_PORT         = 8802
UDP_PORT         = 8800
MAGIC_TAG        = b"\xA0\xCB\x03\x37"
CONNECT_TIMEOUT  = 5.0
RECV_TIMEOUT     = 8.0
KEEPALIVE_INTVL  = 2.0
SIGNAL_INTVL     = 3.0
UDP_PULL_INTVL   = 0.5

# USBC-Paketformat aus APK-SDK und Mitschnitten
USBC_CBW_LEN     = 31    # Standard USB Bulk-Only CBW
USBC_TOTAL_LEN   = USBC_CBW_LEN

# USBS response suffix observed in APIX TCP/UDP captures
USBS_LEN         = 13

# UDP-Stream
UDP_REQUEST_LEN  = 0xBC00   # 48128
UDP_HEADER_SIZE  = 28       # Zu verwerfende Bytes am Anfang jedes 0xF9-Blocks
UDP_TS_SIZE      = 32712    # 174 × 188 Byte reiner MPEG-TS
TS_PKT_SIZE      = 188
TS_SYNC          = 0x47

CBW_LEN_FORMAT   = ">I"


# ---------------------------------------------------------------------------
# Datenmodelle
# ---------------------------------------------------------------------------
@dataclass
class Channel:
    """Ein Kanal aus der <ch_List> XML-Antwort (0xF6/0x21)."""
    prog_idx:   int          # z. B. 0x40B20009 (FTA) oder 0x48xxxxxx (Pay-TV)
    service_id: int          # DVB Service-ID (s_id)
    ts_id:      int
    freq:       int          # Frequenz in MHz
    pol:        str          # Polarisation: H oder V
    sym:        int          # Symbolrate in kSymbols/s
    lcn:        int          # Logical Channel Number
    name:       str          # Sendername
    fta:        bool         # Free-to-Air
    ch_type:    str          # TV oder RADIO

    @property
    def is_encrypted(self) -> bool:
        return not self.fta or (self.prog_idx >> 24) == 0x48

    def __str__(self) -> str:
        lock = "🔒" if self.is_encrypted else "FTA"
        return (
            f"[lcn={self.lcn:3d}] sid={self.service_id:5d} "
            f"prog={self.prog_idx:#010x} [{lock}] {self.name}"
        )


# Rückwärtskompatibles Alias (wisi_channels.py erwartet ServiceEntry-Felder)
@dataclass
class ServiceEntry:
    """Compat-Wrapper um Channel mit den alten Feldnamen."""
    pat_index:   int
    prog_idx:    int
    service_id:  int
    pmt_pid:     int = 0
    pcr_pid:     int = 0
    video_pid:   int = 0
    video_type:  int = 0x1B
    audio_pid:   int = 0
    audio_type:  int = 0x03
    flags:       int = 0x0001
    name:        str = ""

    @property
    def is_encrypted(self) -> bool:
        return bool(self.flags & 0x0008) or (self.prog_idx >> 24) == 0x48

    @property
    def is_active(self) -> bool:
        return bool(self.flags & 0x0001)

    def __str__(self) -> str:
        lock = "🔒" if self.is_encrypted else "FTA"
        return (
            f"[{self.pat_index:3d}] sid={self.service_id:5d} "
            f"vpid={self.video_pid:#06x} apid={self.audio_pid:#06x} "
            f"[{lock}] {self.name}"
        )


def channel_to_service(ch: Channel, idx: int) -> ServiceEntry:
    """Konvertiert Channel (aus XML) in ServiceEntry (Compat-Schicht)."""
    encrypted = ch.is_encrypted
    return ServiceEntry(
        pat_index=idx,
        prog_idx=ch.prog_idx,
        service_id=ch.service_id,
        flags=0x0001 if not encrypted else 0x0009,
        name=ch.name,
    )


# ---------------------------------------------------------------------------
# USBC-Builder (31-Byte-CBW)
# ---------------------------------------------------------------------------
def _build_usbc(
    data_len: int,
    flags: int,
    prefix: int,
    opcode: int,
    payload: bytes = b"",
    session_token: bytes = b"\x00\x00",
) -> bytes:
    """
    31-Byte-USBC-CBW wie im APK-SDK und in den Mitschnitten.

    `session_token` bleibt aus Kompatibilitätsgründen in der internen Signatur;
    der belegte Request-Builder serialisiert keine Auth-Erweiterung.
    """
    del session_token
    cdb = (
        bytes([prefix]) + b"APIX" + bytes([opcode]) + payload
    ).ljust(16, b"\x00")
    assert len(cdb) == 16

    cbw = (
        b"USBC"
        + MAGIC_TAG
        + struct.pack(CBW_LEN_FORMAT, data_len)
        + bytes([flags, 0x00, 0x10])
        + cdb
    )
    assert len(cbw) == USBC_CBW_LEN

    return cbw


# Befehls-Builder
def _cmd_16(st: bytes = b"\x00\x00") -> bytes:
    return _build_usbc(12, 0x80, 0xF6, 0x16, session_token=st)

def _cmd_17_init(st: bytes = b"\x00\x00") -> bytes:
    return _build_usbc(4, 0x80, 0xF6, 0x17, session_token=st)

def _cmd_17_confirm(st: bytes = b"\x00\x00") -> bytes:
    return _build_usbc(4, 0x80, 0xF6, 0x17, b"\x01\x00\x00\x00", session_token=st)

def _cmd_signal(st: bytes = b"\x00\x00") -> bytes:
    return _build_usbc(17, 0x80, 0xF6, 0x02, session_token=st)

def _cmd_stream_release(st: bytes = b"\x00\x00") -> bytes:
    return _build_usbc(4, 0x00, 0xF8, 0x07, session_token=st)

def _cmd_chlist_size(st: bytes = b"\x00\x00") -> bytes:
    """0xF6/0x20 – Länge der <ch_List> XML abfragen."""
    return _build_usbc(8, 0x80, 0xF6, 0x20, session_token=st)

def _cmd_chlist_data(size: int, st: bytes = b"\x00\x00") -> bytes:
    """0xF6/0x21 – <ch_List> XML-Daten abrufen."""
    return _build_usbc(size, 0x80, 0xF6, 0x21, session_token=st)

def _cmd_chlist_ack(size: int, st: bytes = b"\x00\x00") -> bytes:
    """0xF6/0x22 – Empfang der ch_List quittieren (gleiche data_len wie 0x21)."""
    return _build_usbc(size, 0x80, 0xF6, 0x22, session_token=st)

def _cmd_prepare(prog_idx: int, st: bytes = b"\x00\x00") -> bytes:
    return _build_usbc(
        4, 0x80, 0xF6, 0x03,
        b"\x00\x00\x00\x02" + struct.pack(">I", prog_idx),
        session_token=st,
    )

def _cmd_chinfo_size(prog_idx: int, st: bytes = b"\x00\x00") -> bytes:
    return _build_usbc(6, 0x80, 0xF6, 0x32, struct.pack(">I", prog_idx), session_token=st)

def _cmd_chinfo_data(prog_idx: int, length: int, st: bytes = b"\x00\x00") -> bytes:
    return _build_usbc(length, 0x80, 0xF6, 0x33, struct.pack(">I", prog_idx), session_token=st)

def _cmd_tune(pat_index: int, st: bytes = b"\x00\x00") -> bytes:
    """0xF6/0x01 – Kanal anwählen; Byte[0]=0x00, Byte[1]=PAT-Index."""
    return _build_usbc(
        2, 0x80, 0xF6, 0x01,
        bytes([0x00, pat_index & 0xFF]),
        session_token=st,
    )

def _udp_init(st: bytes = b"\x00\x00") -> bytes:
    return _build_usbc(0, 0x00, 0xF9, 0x02, b"\x01", session_token=st)

def _udp_request_block(first: bool = False, st: bytes = b"\x00\x00") -> bytes:
    byte21 = b"\x00" if first else b"\x01"
    return _build_usbc(UDP_REQUEST_LEN, 0x80, 0xF9, 0x01, byte21, session_token=st)


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
        log.debug(
            "%-22s tx=%dB rx=%dB head=%s",
            label, len(cmd), len(raw),
            payload[:min(6, len(payload))].hex(),
        )
    return payload


# ---------------------------------------------------------------------------
# Phase 1: Verbinden + Init
# ---------------------------------------------------------------------------
def connect(ip: str) -> Optional[tuple[socket.socket, bytes]]:
    """
    Verbindet mit Dongle, führt 0x16/0x17-Handshake durch.
    Gibt (socket, session_token) zurück oder None.
    """
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

    # Erstes 0x16 ohne Session-Token
    r = _send_recv(sock, _cmd_16(b"\x00\x00"), 12, "0x16 init")
    if len(r) < 3:
        log.error("0x16: keine Antwort")
        sock.close()
        return None
    status = r[2]
    log.info("0x16 status=0x%02X  gerät=%s", status, r[3:8].hex())

    # The observed 31-byte request/13-byte response framing has no session-token field.
    st = b"\x00\x00"
    r17 = _send_recv(sock, _cmd_17_init(st), 4, "0x17 init")
    log.info("0x17 flag=0x%02X", r17[2] if len(r17) > 2 else 0xFF)

    if status != 0x01:
        log.info("Warte auf Bereitschaft ...")
        for _ in range(10):
            time.sleep(0.5)
            r = _send_recv(sock, _cmd_16(st), 12, "0x16 poll")
            if len(r) >= 3 and r[2] == 0x01:
                log.info("Dongle bereit.")
                break
        else:
            log.warning("Dongle nicht 0x01 – weiter.")

    return sock, st


def disconnect(sock: socket.socket) -> None:
    try:
        sock.close()
    except OSError:
        pass
    log.info("Verbindung getrennt.")


# ---------------------------------------------------------------------------
# Keep-Alive Thread
# ---------------------------------------------------------------------------
def _keepalive_worker(
    sock: socket.socket,
    lock: threading.Lock,
    stop: threading.Event,
    session_token: bytes = b"\x00\x00",
) -> None:
    cmd = _cmd_16(session_token)
    while not stop.wait(KEEPALIVE_INTVL):
        try:
            with lock:
                sock.sendall(cmd)
                _recv_exactly(sock, 12 + USBS_LEN)
        except OSError as e:
            log.debug("Keep-Alive Fehler: %s", e)
            break


# ---------------------------------------------------------------------------
# Kanalliste via TCP: 0xF6/0x20 + 0xF6/0x21
# ---------------------------------------------------------------------------
def parse_chlist_xml(xml_bytes: bytes) -> List[Channel]:
    """
    Parst <ch_List> XML in eine Liste von Channel-Objekten.
    Jeder Kanal hat: type, pol, sym, s_id, ts_id, freq, prog_idx, lcn, s_name, fta
    """
    text = xml_bytes.decode("utf-8", errors="replace")
    channels: List[Channel] = []
    for m in re.finditer(r"<ch\s+([^/]+)/>", text):
        attrs: dict[str, str] = dict(re.findall(r'(\w+)="([^"]*)"', m.group(1)))
        try:
            channels.append(Channel(
                prog_idx=int(attrs.get("prog_idx", "0")),
                service_id=int(attrs.get("s_id", "0")),
                ts_id=int(attrs.get("ts_id", "0")),
                freq=int(attrs.get("freq", "0")),
                pol=attrs.get("pol", ""),
                sym=int(attrs.get("sym", "0")),
                lcn=int(attrs.get("lcn", "0")),
                name=attrs.get("s_name", ""),
                fta=attrs.get("fta", "1") == "1",
                ch_type=attrs.get("type", "TV"),
            ))
        except (ValueError, KeyError):
            pass
    return channels


def fetch_channel_list(
    sock: socket.socket,
    lock: threading.Lock,
    session_token: bytes = b"\x00\x00",
    timeout: float = 15.0,
) -> List[Channel]:
    """
    Holt die Kanalliste via TCP:
      0xF6/0x20  →  Länge der XML (8 Byte Antwort, [0:4] = uint32 BE)
      0xF6/0x21  →  XML-Daten (<ch_List>...</ch_List>)

    Gibt Liste von Channel-Objekten zurück.
    """
    # Schritt 1: Länge abfragen
    with lock:
        r = _send_recv(sock, _cmd_chlist_size(session_token), 8, "0xF6/0x20 ch_List_Size")

    if len(r) < 6:
        log.warning("0xF6/0x20: Antwort zu kurz (%dB)", len(r))
        return []

    # Die 8-Byte-Antwort hat das Format:
    #   [0:2]  Opcode-Echo  (f6 20)
    #   [2:6]  XML-Größe als BE uint32
    #   [6:8]  Padding
    xml_size = struct.unpack(">I", r[2:6])[0]
    if xml_size == 0:
        log.warning("0xF6/0x20: Kanalliste leer (Größe=0)")
        return []
    if xml_size > 10 * 1024 * 1024:
        log.error(
            "0xF6/0x20: XML-Größe %d Byte unrealistisch groß – "
            "falsches Antwort-Offset? raw=%s",
            xml_size, r[:8].hex(),
        )
        return []

    log.info("ch_List XML-Größe: %d Byte", xml_size)

    # Schritt 2: XML-Daten abrufen (kann mehrere TCP-Segmente umfassen)
    with lock:
        sock.sendall(_cmd_chlist_data(xml_size, session_token))
        xml_raw = _recv_exactly(sock, xml_size + USBS_LEN, timeout=timeout)

    xml_bytes = xml_raw[:xml_size]
    log.debug("ch_List empfangen: %dB", len(xml_bytes))

    if len(xml_bytes) == 0:
        log.warning("ch_List: keine Daten empfangen (0 Byte)")
        return []

    # XML-Grenzen ermitteln
    start = xml_bytes.find(b"<ch_List>")
    end = xml_bytes.rfind(b"</ch_List>")
    if start < 0 or end < 0:
        # Kein vollständiges XML → versuche trotzdem zu parsen
        log.warning("ch_List: kein vollständiges <ch_List>-Element gefunden, versuche Regex-Parse")
        channels = parse_chlist_xml(xml_bytes)
    else:
        channels = parse_chlist_xml(xml_bytes[start : end + len(b"</ch_List>")])

    log.info("ch_List geparst: %d Kanäle", len(channels))

    # Schritt 3: 0xF6/0x22 – Empfang quittieren (optional laut Spec, aber Dongle trennt sonst)
    try:
        with lock:
            _send_recv(sock, _cmd_chlist_ack(xml_size, session_token), 8, "0xF6/0x22 ch_List_Ack")
    except Exception as e:
        log.debug("0xF6/0x22 Ack fehlgeschlagen (ignoriert): %s", e)

    return channels


def channels_to_services(channels: List[Channel]) -> List[ServiceEntry]:
    """Wandelt Channel-Liste in ServiceEntry-Liste (LCN = PAT-Index-Proxy)."""
    # LCN als Sortierkriterium, dann als PAT-Index-Proxy verwenden
    sorted_chs = sorted(channels, key=lambda c: c.lcn)
    return [channel_to_service(ch, idx) for idx, ch in enumerate(sorted_chs)]


# ---------------------------------------------------------------------------
# Fallback Service-DB (0xF9/0x0A) – nur für Rückwärtskompatibilität
# ---------------------------------------------------------------------------
def parse_service_db(data: bytes) -> List[ServiceEntry]:
    """Legacy-Parser für 0xF9/0x0A UDP-Blob (OR S2D gibt anderes Format zurück)."""
    log.debug("parse_service_db: %dB (wird wahrscheinlich 0 Einträge liefern beim OR S2D)", len(data))
    UDP_HEADER_SIZE = 28
    SERVICE_DB_HEADER = 32
    SERVICE_ENTRY_SIZE = 128

    if len(data) < UDP_HEADER_SIZE + SERVICE_DB_HEADER:
        return []

    body = data[UDP_HEADER_SIZE:]
    entries_raw = body[SERVICE_DB_HEADER:]
    services: List[ServiceEntry] = []
    idx = 0
    offset = 0
    while offset + SERVICE_ENTRY_SIZE <= len(entries_raw):
        rec = entries_raw[offset : offset + SERVICE_ENTRY_SIZE]
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


def fetch_service_db(
    udp: socket.socket,
    dongle_ip: str,
    attempts: int = 5,
    session_token: bytes = b"\x00\x00",
) -> List[ServiceEntry]:
    """Veraltet beim OR S2D. Gibt leere Liste zurück (Kanalliste via TCP)."""
    log.warning(
        "fetch_service_db() via 0xF9/0x0A UDP wird vom OR S2D nicht unterstützt. "
        "Bitte fetch_channel_list() via TCP 0xF6/0x20+0x21 verwenden."
    )
    return []


# ---------------------------------------------------------------------------
# Phase 3: Kanal vorbereiten
# ---------------------------------------------------------------------------
def prepare_channel(
    sock: socket.socket,
    lock: threading.Lock,
    svc: ServiceEntry,
    session_token: bytes = b"\x00\x00",
) -> None:
    with lock:
        _send_recv(sock, _cmd_prepare(svc.prog_idx, session_token), 4, "0x03 prepare")
    with lock:
        r = _send_recv(sock, _cmd_chinfo_size(svc.prog_idx, session_token), 6, "0x32 chinfo-size")
    if len(r) >= 6:
        ci_size = struct.unpack(">I", r[2:6])[0]
        if ci_size > 0:
            with lock:
                r2 = _send_recv(sock, _cmd_chinfo_data(svc.prog_idx, ci_size, session_token), ci_size, "0x33 chinfo")
            log.debug("ch_Info: %s", r2[:min(80, ci_size)].decode("utf-8", "replace"))

    for attempt in range(3):
        time.sleep(SIGNAL_INTVL)
        with lock:
            r = _send_recv(sock, _cmd_signal(session_token), 17, f"0x02 signal [{attempt+1}/3]")
        if len(r) >= 5:
            log.info("Signal: Stärke=%d%%  Qualität=%d", r[3], r[4])
            if r[3] >= 50:
                return
    log.warning("Signal schwach – weiter.")


# ---------------------------------------------------------------------------
# Phase 4+5: Tune + MPEG-TS-Stream
# ---------------------------------------------------------------------------
def stream(
    tcp_sock: socket.socket,
    lock: threading.Lock,
    svc: ServiceEntry,
    output_path: str,
    duration_s: float = 0.0,
    keepalive_active: bool = False,
    session_token: bytes = b"\x00\x00",
) -> None:
    stop = threading.Event()
    dongle_ip = tcp_sock.getpeername()[0]

    ka: Optional[threading.Thread] = None
    if not keepalive_active:
        ka = threading.Thread(
            target=_keepalive_worker,
            args=(tcp_sock, lock, stop, session_token),
            daemon=True,
        )
        ka.start()

    stream_ka_stop: Optional[threading.Event] = None
    stream_ka: Optional[threading.Thread] = None
    stream_ka_sock = None

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    udp.bind(("", 0))
    udp.settimeout(0.1)

    try:
        # UDP Init
        udp.sendto(_udp_init(session_token), (dongle_ip, UDP_PORT))
        try:
            udp.recvfrom(256)
        except socket.timeout:
            pass

        # Tune (TCP)
        with lock:
            _send_recv(tcp_sock, _cmd_tune(svc.pat_index, session_token), 2, "0x01 tune")
        log.info("Tune: pat_index=%d  sid=%d  (%s)", svc.pat_index, svc.service_id, svc.name)

        # Stream-Freigabe (TCP)
        with lock:
            _send_recv(tcp_sock, _cmd_stream_release(session_token), 0, "0xF8/0x07 release")

        # Erster UDP-Block
        udp.sendto(_udp_request_block(first=True, st=session_token), (dongle_ip, UDP_PORT))

        # Tune bestätigen (TCP)
        with lock:
            r = _send_recv(tcp_sock, _cmd_17_confirm(session_token), 4, "0x17 confirm")
        log.info("0x17 confirm: 0x%02X", r[2] if len(r) > 2 else 0xFF)

        # Keep-Alive-Verbindung nach Tune
        result = connect(dongle_ip)
        if result is None:
            raise ConnectionError("Keep-Alive-Verbindung nach Tune fehlgeschlagen.")
        stream_ka_sock, _ = result
        stream_ka_stop = threading.Event()
        stream_ka = threading.Thread(
            target=_keepalive_worker,
            args=(stream_ka_sock, threading.Lock(), stream_ka_stop, session_token),
            daemon=True,
        )
        stream_ka.start()

        out = (
            open(output_path, "wb") if output_path != "-" else sys.stdout.buffer
        )
        log.info("Stream → %s  (STRG+C zum Beenden)", output_path)

        t_start = time.monotonic()
        block_num = 0
        ts_bytes = 0
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
                    udp.sendto(
                        _udp_request_block(first=False, st=session_token),
                        (dongle_ip, UDP_PORT),
                    )
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

                if data[:4] == b"USBS" or data[:2] == b"\xf9\x0a":
                    continue

                sync_offset = data.find(bytes([TS_SYNC]))
                while sync_offset >= 0:
                    if (
                        sync_offset + 3 * TS_PKT_SIZE < len(data)
                        and all(
                            data[sync_offset + i * TS_PKT_SIZE] == TS_SYNC
                            for i in range(4)
                        )
                    ):
                        break
                    sync_offset = data.find(bytes([TS_SYNC]), sync_offset + 1)
                if sync_offset < 0:
                    log.debug(
                        "Kein MPEG-TS-Sync in UDP-Datagramm (%dB) – verworfen", len(data)
                    )
                    continue

                ts_data = data[sync_offset:]
                last_packet_at = time.monotonic()
                next_timeout_warning = last_packet_at + 5.0

                if block_num == 0:
                    log.debug(
                        "Erstes Stream-Datagramm: %dB, TS-Offset %d", len(data), sync_offset
                    )

                complete_len = len(ts_data) - len(ts_data) % TS_PKT_SIZE
                if complete_len == 0:
                    continue
                out.write(ts_data[:complete_len])
                out.flush()
                block_num += 1
                ts_bytes += complete_len

                if block_num % 50 == 0:
                    elapsed = time.monotonic() - t_start
                    kbps = (ts_bytes / 1024) / max(elapsed, 0.001)
                    log.info(
                        "Block %4d | %.1f MiB | %.0f KB/s",
                        block_num,
                        ts_bytes / 1_048_576,
                        kbps,
                    )

        except KeyboardInterrupt:
            print()
            log.info("Abgebrochen.")
        finally:
            if output_path != "-":
                out.close()
            log.info(
                "Stream beendet. %d Blöcke, %d Pulls, %.2f MiB",
                block_num,
                pull_count,
                ts_bytes / 1_048_576,
            )

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
# Fallback-Kanal (wenn ch_List leer)
# ---------------------------------------------------------------------------
_FALLBACK_SERVICE = ServiceEntry(
    pat_index=4,
    prog_idx=0x40B40089,
    service_id=4914,
    pmt_pid=0x006E,
    pcr_pid=0x1338,
    video_pid=0x1338,
    video_type=0x1B,
    audio_pid=0x1339,
    audio_type=0x03,
    flags=0x0001,
    name="ZDF (Fallback aus PCAP)",
)


# ---------------------------------------------------------------------------
# Interaktives Menü
# ---------------------------------------------------------------------------
_MENU = """
╔════════════════════════════════════════════════════╗
║      WISI OR S2D  –  DVB-over-IP Client v4       ║
╠════════════════════════════════════════════════════╣
║  [1]  Kanalliste laden (TCP 0xF6/0x20+0x21)      ║
║  [2]  Kanal vorbereiten + Signal prüfen           ║
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

    print(f"\n{'Nr':>4}  {'PAT':>4}  {'sid':>6}  Name")
    print("-" * 60)
    for i, s in enumerate(active[:60], 1):
        lock = "🔒" if s.is_encrypted else "   "
        print(f"{i:>4}  {s.pat_index:>4}  {s.service_id:>6}  {lock} {s.name}")
    print()
    try:
        nr = int(input("Nummer (0=Abbruch): "))
        if 1 <= nr <= len(active):
            return active[nr - 1]
    except (ValueError, EOFError):
        pass
    return None


def main_menu(sock: socket.socket, ip: str, session_token: bytes) -> None:
    lock = threading.Lock()
    services: List[ServiceEntry] = []
    selected: Optional[ServiceEntry] = None
    keepalive_stop = threading.Event()
    keepalive = threading.Thread(
        target=_keepalive_worker,
        args=(sock, lock, keepalive_stop, session_token),
        daemon=True,
    )
    keepalive.start()

    # Beim Start sofort Kanalliste laden
    log.info("Lade Kanalliste via TCP 0xF6/0x20+0x21 ...")
    channels = fetch_channel_list(sock, lock, session_token)
    if channels:
        services = channels_to_services(channels)
    else:
        log.warning("Kanalliste leer – nutze Fallback.")
        services = [_FALLBACK_SERVICE]

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
            log.info("Lade Kanalliste ...")
            channels = fetch_channel_list(sock, lock, session_token)
            if channels:
                services = channels_to_services(channels)
                log.info("%d Kanäle geladen.", len(services))
            else:
                log.warning("Leer – nutze Fallback.")
                services = [_FALLBACK_SERVICE]
            selected = _pick_service(services)
            if selected:
                log.info("Gewählt: %s", selected)

        elif choice == "2":
            if not selected:
                log.warning("Erst Kanal wählen (Option 1).")
                continue
            prepare_channel(sock, lock, selected, session_token)

        elif choice == "3":
            if not selected:
                selected = _FALLBACK_SERVICE
                log.info("Nutze Fallback-Kanal sid=4914")
            if selected.is_encrypted:
                log.warning("Kanal verschlüsselt – Stream evtl. leer.")
            outfile = (
                input("Ausgabedatei [stream.ts] (- für stdout): ").strip() or "stream.ts"
            )
            dur_str = input("Dauer in Sekunden [0=unbegrenzt]: ").strip()
            try:
                dur = float(dur_str) if dur_str else 0.0
            except ValueError:
                dur = 0.0
            stream(sock, lock, selected, outfile, dur, keepalive_active=True, session_token=session_token)

        elif choice == "4":
            log.info("PAT-Index-Test (schickt 0x01 mit Index 0–5) ...")
            for idx in range(6):
                with lock:
                    _send_recv(sock, _cmd_tune(idx, session_token), 0, f"0x01 idx={idx}")
                log.info("Index %d gesendet – jetzt UDP-Block prüfen", idx)
                input("  Enter für nächsten Index ...")

        elif choice == "5":
            keepalive_stop.set()
            keepalive.join(timeout=4.0)
            disconnect(sock)
            time.sleep(0.5)
            result = connect(ip)
            if result is None:
                log.error("Verbindung fehlgeschlagen.")
                return
            sock, session_token = result
            lock = threading.Lock()
            keepalive_stop = threading.Event()
            keepalive = threading.Thread(
                target=_keepalive_worker,
                args=(sock, lock, keepalive_stop, session_token),
                daemon=True,
            )
            keepalive.start()
            print(_MENU)
        else:
            print("1–5 oder q.")

    keepalive_stop.set()
    keepalive.join(timeout=4.0)
    disconnect(sock)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> None:
    p = argparse.ArgumentParser(
        description="WISI OR S2D DVB-over-IP Client v4 (icube APIX)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--ip", default=DEFAULT_IP)
    p.add_argument("--debug", action="store_true")
    p.add_argument("--stream", action="store_true", help="Direkt streamen")
    p.add_argument("--pat-idx", type=int, default=4, help="PAT-Index für --stream")
    p.add_argument("--output", default="stream.ts")
    p.add_argument("--duration", type=float, default=0.0)
    args = p.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    result = connect(args.ip)
    if result is None:
        sys.exit(1)
    sock, session_token = result
    lock = threading.Lock()

    if args.stream:
        keepalive_stop = threading.Event()
        keepalive = threading.Thread(
            target=_keepalive_worker,
            args=(sock, lock, keepalive_stop, session_token),
            daemon=True,
        )
        keepalive.start()
        try:
            channels = fetch_channel_list(sock, lock, session_token)
            services = channels_to_services(channels) if channels else [_FALLBACK_SERVICE]
            svc = next((s for s in services if s.pat_index == args.pat_idx), None)
            if svc is None:
                log.warning("PAT-Index %d nicht gefunden – nutze Fallback.", args.pat_idx)
                svc = ServiceEntry(**{**_FALLBACK_SERVICE.__dict__, "pat_index": args.pat_idx})
            prepare_channel(sock, lock, svc, session_token)
            stream(sock, lock, svc, args.output, args.duration, keepalive_active=True, session_token=session_token)
        finally:
            keepalive_stop.set()
            keepalive.join(timeout=4.0)
            disconnect(sock)
    else:
        main_menu(sock, args.ip, session_token)


if __name__ == "__main__":
    main()
