"""
channels.py – Kanalliste via TCP (0xF6/0x20 + 0xF6/0x21)
==========================================================
fetch_channel_list   – XML-Kanalliste vom Dongle laden
parse_chlist_xml     – <ch_List>-XML in Channel-Objekte parsen
channels_to_services – Channel-Liste → ServiceEntry-Liste (LCN-sortiert)
parse_service_db     – Legacy-Parser für 0xF9/0x0A-Blob (OR S2D: immer leer)
fetch_service_db     – Legacy-Stub (immer leere Liste)
"""
from __future__ import annotations

import logging
import re
import struct
import threading
from typing import List, Optional

import protocol
from models import Channel, ServiceEntry, channel_to_service

log = logging.getLogger("wisi.channels")


# ---------------------------------------------------------------------------
# Befehls-Builder für Kanalliste (nicht in protocol.py, da spezifisch hier)
# ---------------------------------------------------------------------------
def _cmd_chlist_size() -> bytes:
    """0xF6/0x20 – Länge der <ch_List> XML abfragen."""
    return protocol.build_usbc(8, 0x80, 0xF6, 0x20)


def _cmd_chlist_data(size: int) -> bytes:
    """0xF6/0x21 – <ch_List> XML-Daten abrufen."""
    return protocol.build_usbc(size, 0x80, 0xF6, 0x21)


def _cmd_chlist_ack(size: int) -> bytes:
    """0xF6/0x22 – Empfang der ch_List quittieren."""
    return protocol.build_usbc(size, 0x80, 0xF6, 0x22)


# ---------------------------------------------------------------------------
# XML-Parser
# ---------------------------------------------------------------------------
def parse_chlist_xml(xml_bytes: bytes) -> List[Channel]:
    """
    Parst <ch_List> XML in eine Liste von Channel-Objekten.
    Jeder Kanal: type, pol, sym, s_id, ts_id, freq, prog_idx, lcn, s_name, fta
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


# ---------------------------------------------------------------------------
# Kanalliste laden
# ---------------------------------------------------------------------------
def fetch_channel_list(
    sock,
    lock: threading.Lock,
    session_token: bytes = b"",
    timeout: float = 15.0,
) -> List[Channel]:
    """
    Holt die Kanalliste via TCP:
      0xF6/0x20  →  Länge der XML (8 Byte Antwort, [2:6] = uint32 BE)
      0xF6/0x21  →  XML-Daten (<ch_List>…</ch_List>)
      0xF6/0x22  →  Empfangsquittung (optional, aber Dongle trennt sonst)

    session_token: wird aktuell nicht im Protokoll benötigt, aber von
                   wisi_common.load_services weitergereicht (für künftige Nutzung
                   und Testkompatibilität).
    """
    # Schritt 1: Länge
    with lock:
        r = protocol.send_recv(sock, _cmd_chlist_size(), 8, "0xF6/0x20 ch_List_Size")

    if len(r) < 6:
        log.warning("0xF6/0x20: Antwort zu kurz (%dB)", len(r))
        return []

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

    # Schritt 2: XML-Daten
    with lock:
        sock.sendall(_cmd_chlist_data(xml_size))
        xml_raw = protocol.recv_exactly(sock, xml_size + protocol.USBS_LEN, timeout=timeout)

    xml_bytes = xml_raw[:xml_size]
    log.debug("ch_List empfangen: %dB", len(xml_bytes))

    if not xml_bytes:
        log.warning("ch_List: keine Daten empfangen")
        return []

    start = xml_bytes.find(b"<ch_List>")
    end = xml_bytes.rfind(b"</ch_List>")
    if start < 0 or end < 0:
        log.warning("ch_List: kein vollständiges <ch_List>-Element, versuche Regex-Parse")
        channels = parse_chlist_xml(xml_bytes)
    else:
        channels = parse_chlist_xml(xml_bytes[start : end + len(b"</ch_List>")])

    log.info("ch_List geparst: %d Kanäle", len(channels))

    # Schritt 3: Quittung
    try:
        with lock:
            protocol.send_recv(sock, _cmd_chlist_ack(xml_size), 8, "0xF6/0x22 ch_List_Ack")
    except Exception as e:
        log.debug("0xF6/0x22 Ack fehlgeschlagen (ignoriert): %s", e)

    return channels


def channels_to_services(channels: List[Channel]) -> List[ServiceEntry]:
    """Wandelt Channel-Liste in ServiceEntry-Liste (nach LCN sortiert)."""
    sorted_chs = sorted(channels, key=lambda c: c.lcn)
    return [channel_to_service(ch, idx) for idx, ch in enumerate(sorted_chs)]


# ---------------------------------------------------------------------------
# Legacy-Stubs (0xF9/0x0A – OR S2D liefert keinen Service-DB-Blob)
# ---------------------------------------------------------------------------
def parse_service_db(data: bytes) -> List[ServiceEntry]:
    """Legacy-Parser für 0xF9/0x0A UDP-Blob (OR S2D: liefert immer 0 Einträge)."""
    log.debug("parse_service_db: %dB (OR S2D gibt kein Service-DB-Format zurück)", len(data))
    UDP_HEADER_SIZE_LEGACY = 28
    SERVICE_DB_HEADER = 32
    SERVICE_ENTRY_SIZE = 128

    if len(data) < UDP_HEADER_SIZE_LEGACY + SERVICE_DB_HEADER:
        return []

    body = data[UDP_HEADER_SIZE_LEGACY:]
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
        name       = rec[0x12:0x32].rstrip(b"\x00").decode("iso-8859-15", errors="replace")
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


def fetch_service_db(*_args, **_kwargs) -> List[ServiceEntry]:
    """Veraltet beim OR S2D. Bitte fetch_channel_list() via TCP verwenden."""
    log.warning(
        "fetch_service_db() via 0xF9/0x0A UDP wird vom OR S2D nicht unterstützt. "
        "Bitte fetch_channel_list() via TCP 0xF6/0x20+0x21 verwenden."
    )
    return []
