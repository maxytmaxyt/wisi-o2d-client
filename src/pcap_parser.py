"""
pcap_parser.py – PCAP-Parsing und APIX-Analyse
================================================
Packet      – NamedTuple für ein dekodiertes IP-Paket
packets()   – Iterator über alle IP-Pakete einer klassischen PCAP-Datei
analyze()   – Zählt APIX-Befehle und 0xF9/0x0A-Blobs in einer PCAP-Datei

Die CLI (main, run, run_service_db) befindet sich in wisi_pcap.py.
"""
from __future__ import annotations

import collections
import struct
from collections.abc import Iterator
from pathlib import Path
from typing import NamedTuple

from channels import parse_service_db


class Packet(NamedTuple):
    protocol: int
    source: str
    destination: str
    source_port: int
    destination_port: int
    payload: bytes


def _ipv4_payload(frame: bytes, linktype: int) -> bytes | None:
    if linktype == 101:
        packet = frame
    elif linktype == 1:
        if len(frame) < 14:
            return None
        ethertype = struct.unpack_from(">H", frame, 12)[0]
        offset = 14
        while ethertype in (0x8100, 0x88A8, 0x9100):
            if len(frame) < offset + 4:
                return None
            ethertype = struct.unpack_from(">H", frame, offset + 2)[0]
            offset += 4
        if ethertype != 0x0800:
            return None
        packet = frame[offset:]
    else:
        raise ValueError(
            f"Nicht unterstützter PCAP-Linktyp {linktype} "
            "(erwartet Ethernet/Raw IPv4)."
        )

    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    header_length = (packet[0] & 0x0F) * 4
    total_length = struct.unpack_from(">H", packet, 2)[0]
    fragment = struct.unpack_from(">H", packet, 6)[0]
    if (
        header_length < 20
        or total_length < header_length
        or len(packet) < header_length
        or fragment & 0x3FFF
    ):
        return None
    return packet[:min(total_length, len(packet))]


def packets(path: Path) -> Iterator[Packet]:
    """Iteriert über alle TCP- und UDP-Pakete einer klassischen PCAP-Datei."""
    with path.open("rb") as capture:
        header = capture.read(24)
        if len(header) != 24:
            raise ValueError("PCAP-Header fehlt oder ist abgeschnitten.")
        byte_order = {
            b"\xd4\xc3\xb2\xa1": "<",
            b"\xa1\xb2\xc3\xd4": ">",
            b"\x4d\x3c\xb2\xa1": "<",
            b"\xa1\xb2\x3c\x4d": ">",
        }.get(header[:4])
        if byte_order is None:
            raise ValueError("Kein unterstütztes klassisches PCAP-Format.")
        linktype = struct.unpack_from(f"{byte_order}I", header, 20)[0]

        while record_header := capture.read(16):
            if len(record_header) != 16:
                raise ValueError("Abgeschnittener PCAP-Paketeintrag.")
            captured_length = struct.unpack_from(f"{byte_order}I", record_header, 8)[0]
            frame = capture.read(captured_length)
            if len(frame) != captured_length:
                raise ValueError("Abgeschnittener PCAP-Paketinhalt.")
            ip_pkt = _ipv4_payload(frame, linktype)
            if ip_pkt is None:
                continue
            proto = ip_pkt[9]
            source = ".".join(str(b) for b in ip_pkt[12:16])
            destination = ".".join(str(b) for b in ip_pkt[16:20])
            data = ip_pkt[(ip_pkt[0] & 0x0F) * 4:]
            if proto == 17 and len(data) >= 8:
                src_port, dst_port, length = struct.unpack_from(">HHH", data)
                if length >= 8:
                    yield Packet(proto, source, destination, src_port, dst_port,
                                 data[8:min(length, len(data))])
            elif proto == 6 and len(data) >= 20:
                src_port, dst_port = struct.unpack_from(">HH", data)
                tcp_header_length = (data[12] >> 4) * 4
                if tcp_header_length >= 20 and len(data) >= tcp_header_length:
                    yield Packet(proto, source, destination, src_port, dst_port,
                                 data[tcp_header_length:])


def analyze(path: Path) -> dict[str, object]:
    """Analysiert eine PCAP-Datei: zählt APIX-Befehle und Service-DB-Blobs."""
    counts: collections.Counter[str] = collections.Counter()
    commands: collections.Counter[str] = collections.Counter()
    service_db_blobs: list[bytes] = []
    packet_count = 0

    for pkt in packets(path):
        packet_count += 1
        transport = "TCP" if pkt.protocol == 6 else "UDP"
        counts[f"{transport} {pkt.source_port} -> {pkt.destination_port}"] += 1
        payload = pkt.payload
        if transport == "UDP" and payload.startswith(b"\xf9\x0a"):
            service_db_blobs.append(payload)
        start = 0
        while (offset := payload.find(b"USBC", start)) >= 0:
            start = offset + 4
            if len(payload) - offset < 31:
                continue
            prefix = payload[offset + 15]
            if payload[offset + 16:offset + 20] == b"APIX":
                commands[f"0x{prefix:02X}/0x{payload[offset + 20]:02X}"] += 1

    result: dict[str, object] = {
        "capture": str(path),
        "ipv4_packets": packet_count,
        "flows": dict(sorted(counts.items())),
        "apiX_commands": dict(sorted(commands.items())),
        "service_db_responses": len(service_db_blobs),
    }
    if service_db_blobs:
        largest = max(service_db_blobs, key=len)
        services = parse_service_db(largest)
        result["largest_service_db_response_bytes"] = len(largest)
        result["decoded_service_count"] = len(services)
        result["decoded_services"] = [
            {
                "pat_index": svc.pat_index,
                "service_id": svc.service_id,
                "prog_idx": f"0x{svc.prog_idx:08X}",
                "video_pid": f"0x{svc.video_pid:04X}",
                "audio_pid": f"0x{svc.audio_pid:04X}",
                "name": svc.name,
            }
            for svc in services[:100]
        ]
    return result
