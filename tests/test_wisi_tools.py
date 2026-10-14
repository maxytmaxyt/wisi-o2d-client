from __future__ import annotations

import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import wisi_common
import wisi_client
from wisi_discovery import DISCOVERY_REQUEST, MAGIC, VERSION, build_request, parse_response
from wisi_pcap import analyze


def _service_db_blob() -> bytes:
    record = bytearray(128)
    struct.pack_into(">IHHHH", record, 0, 0x40B40089, 4914, 0x006E, 0x1338, 0x1338)
    record[12] = 0x1B
    struct.pack_into(">H", record, 13, 0x1339)
    record[15] = 0x03
    struct.pack_into(">H", record, 16, 1)
    record[18:22] = b"ZDF\0"
    return b"\xF9\x0A" + bytes(26 + 32) + record


def _ethernet_ipv4_udp(payload: bytes, source_port: int, destination_port: int) -> bytes:
    udp = struct.pack(">HHHH", source_port, destination_port, len(payload) + 8, 0) + payload
    ip_length = len(udp) + 20
    ip = (
        b"\x45\x00"
        + struct.pack(">H", ip_length)
        + b"\x00\x01\x00\x00\x40\x11\x00\x00"
        + bytes((192, 168, 178, 10, 192, 168, 178, 32))
    )
    ethernet = bytes(12) + b"\x08\x00"
    return ethernet + ip + udp


def _write_pcap(path: Path, frames: list[bytes]) -> None:
    with path.open("wb") as capture:
        capture.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for frame in frames:
            capture.write(struct.pack("<IIII", 0, 0, len(frame), len(frame)))
            capture.write(frame)


class DiscoveryTests(unittest.TestCase):
    def test_request_and_response(self) -> None:
        request = build_request(123)
        magic, version, opcode, sequence, payload_length = struct.unpack_from(">IHHII", request)
        self.assertEqual(
            (magic, version, opcode, sequence),
            (MAGIC, VERSION, DISCOVERY_REQUEST, 123),
        )
        self.assertEqual(payload_length, len(request) - 16)
        self.assertEqual(json.loads(request[16:])["cmd"], "DISCOVER_DONGLE")

        body = b'{"status":"OK"}'
        response = struct.pack(">IHHII", MAGIC, VERSION, DISCOVERY_REQUEST, 123, len(body)) + body
        self.assertEqual(parse_response(response), {"status": "OK"})
        self.assertIsNone(parse_response(response[:-1]))


class PcapTests(unittest.TestCase):
    def test_extracts_apiX_request_and_decodes_service_db_response(self) -> None:
        command = b"USBC" + bytes(4) + struct.pack(">I", 0) + bytes((0x80, 0, 16))
        command += bytes((0xF9,)) + b"APIX" + bytes((0x0A,)) + bytes(10)
        frames = [
            _ethernet_ipv4_udp(command, 40000, 8800),
            _ethernet_ipv4_udp(_service_db_blob(), 8800, 40000),
        ]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "capture.pcap"
            _write_pcap(path, frames)
            result = analyze(path)

        self.assertEqual(result["apiX_commands"].get("0xF9/0x0A"), 1)
        self.assertEqual(result["service_db_responses"], 1)
        self.assertEqual(result["decoded_service_count"], 1)
        services = result["decoded_services"]
        self.assertEqual(services[0]["service_id"], 4914)
        self.assertEqual(services[0]["name"], "ZDF")


class ServiceDatabaseTests(unittest.TestCase):
    def test_load_services_fetches_tcp_channel_list_and_closes_resources(self) -> None:
        events: list[str] = []
        control = object()

        class KeepaliveThread:
            def __init__(self, *args: object, **kwargs: object) -> None:
                pass

            def start(self) -> None:
                events.append("keepalive")

            def join(self, timeout: float) -> None:
                events.append("join")

        def fake_connect(ip: str) -> object:
            events.append("tcp")
            return control, b"\x12\x34"

        def fake_fetch(
            sock: object, lock: object, session_token: bytes, timeout: float
        ) -> list[wisi_client.Channel]:
            events.append("channels")
            return [wisi_client.Channel(
                prog_idx=0x40B40089,
                service_id=4914,
                ts_id=33079,
                freq=10744,
                pol="H",
                sym=22000,
                lcn=1,
                name="Testkanal",
                fta=True,
                ch_type="TV",
            )]

        with (
            patch.object(wisi_common, "connect", side_effect=fake_connect),
            patch.object(
                wisi_common, "disconnect", side_effect=lambda sock: events.append("close-tcp")
            ),
            patch.object(wisi_common, "fetch_channel_list", side_effect=fake_fetch),
            patch.object(wisi_common.threading, "Thread", KeepaliveThread),
        ):
            services = wisi_common.load_services("192.168.178.32")

        self.assertEqual(events, ["tcp", "keepalive", "channels", "join", "close-tcp"])
        self.assertEqual(len(services), 1)
        self.assertEqual(services[0].name, "Testkanal")

    def test_legacy_service_db_fetch_is_disabled(self) -> None:
        udp = MagicMock()

        services = wisi_client.fetch_service_db(udp, "192.168.178.32")

        self.assertEqual(services, [])
        udp.sendto.assert_not_called()


if __name__ == "__main__":
    unittest.main()
