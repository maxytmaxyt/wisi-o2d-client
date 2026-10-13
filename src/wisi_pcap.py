"""Analysiert klassische PCAP-Dateien auf APIX-Befehle und 0xF9/0x0A-Blobs."""
from __future__ import annotations

import argparse
import collections
import json
import logging
import struct
import sys
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import NamedTuple

from wisi_client import parse_service_db


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


def _packets(path: Path) -> Iterator[Packet]:
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
            packet = _ipv4_payload(frame, linktype)
            if packet is None:
                continue
            protocol = packet[9]
            source = ".".join(str(byte) for byte in packet[12:16])
            destination = ".".join(str(byte) for byte in packet[16:20])
            data = packet[(packet[0] & 0x0F) * 4:]
            if protocol == 17 and len(data) >= 8:
                source_port, destination_port, length = struct.unpack_from(">HHH", data)
                if length >= 8:
                    yield Packet(protocol, source, destination, source_port, destination_port,
                                 data[8:min(length, len(data))])
            elif protocol == 6 and len(data) >= 20:
                source_port, destination_port = struct.unpack_from(">HH", data)
                tcp_header_length = (data[12] >> 4) * 4
                if tcp_header_length >= 20 and len(data) >= tcp_header_length:
                    yield Packet(protocol, source, destination, source_port, destination_port,
                                 data[tcp_header_length:])


def analyze(path: Path) -> dict[str, object]:
    counts: collections.Counter[str] = collections.Counter()
    commands: collections.Counter[str] = collections.Counter()
    service_db_blobs: list[bytes] = []
    packet_count = 0
    for packet in _packets(path):
        packet_count += 1
        transport = "TCP" if packet.protocol == 6 else "UDP"
        counts[f"{transport} {packet.source_port} -> {packet.destination_port}"] += 1
        payload = packet.payload
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
                "pat_index": service.pat_index,
                "service_id": service.service_id,
                "prog_idx": f"0x{service.prog_idx:08X}",
                "video_pid": f"0x{service.video_pid:04X}",
                "audio_pid": f"0x{service.audio_pid:04X}",
                "name": service.name,
            }
            for service in services[:100]
        ]
    return result


def run(path: str, extract_service_db: str | None = None) -> int:
    capture_path = Path(path)
    result = analyze(capture_path)
    if extract_service_db is not None:
        candidates = [
            packet.payload
            for packet in _packets(capture_path)
            if packet.protocol == 17 and packet.payload.startswith(b"\xf9\x0a")
        ]
        if not candidates:
            raise ValueError("In der PCAP-Datei wurde keine 0xF9/0x0A-Antwort gefunden.")
        blob = max(candidates, key=len)
        Path(extract_service_db).write_bytes(blob)
        print(
            f"Größte 0xF9/0x0A-Antwort ({len(blob)} Byte) "
            f"nach {extract_service_db} geschrieben."
        )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def run_service_db(path: str) -> int:
    data = Path(path).read_bytes()
    services = parse_service_db(data)
    if not services:
        raise ValueError(
            "Keine Einträge dekodiert. Erwartet wird eine vollständige 0xF9/0x0A-Antwort "
            "mit den vom Client angenommenen Headern."
        )
    result = [
        {
            "pat_index": service.pat_index,
            "service_id": service.service_id,
            "prog_idx": f"0x{service.prog_idx:08X}",
            "video_pid": f"0x{service.video_pid:04X}",
            "audio_pid": f"0x{service.audio_pid:04X}",
            "encrypted": service.is_encrypted,
            "name": service.name,
        }
        for service in services
    ]
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", nargs="?", help="Pfad zur klassischen PCAP-Datei")
    parser.add_argument(
        "--decode-service-db",
        metavar="DATEI",
        help="Gespeicherte 0xF9/0x0A-Antwort dekodieren (UDP-Payload als Binärdatei)",
    )
    parser.add_argument(
        "--extract-service-db",
        help="Größte gefundene UDP-0xF9/0x0A-Antwort unverändert speichern",
    )
    args = parser.parse_args(argv)
    if bool(args.pcap) == bool(args.decode_service_db):
        parser.error("Genau eine PCAP-Datei oder --decode-service-db DATEI angeben.")
    try:
        if args.decode_service_db:
            if args.extract_service_db:
                parser.error("--extract-service-db kann nur mit einer PCAP-Datei verwendet werden.")
            return run_service_db(args.decode_service_db)
        return run(args.pcap, args.extract_service_db)
    except (OSError, ValueError) as exc:
        logging.error("%s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
