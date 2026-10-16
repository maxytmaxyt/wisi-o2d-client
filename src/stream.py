"""
stream.py – Kanal-Prepare und MPEG-TS-Stream
=============================================
prepare_channel    – 0x03 → 0x32/0x33 → 0x02 (Signal prüfen)
stream             – Tune + UDP-MPEG-TS-Stream

Fixes aus PROBLEME.md:
  Problem 1: on_dead-Event wenn tcp_sock nach Tune abbricht (erwartet)
  Problem 2: Speedtest-Response-Filter (48205 Byte) + Request-Response-Pull
  Problem 3: Re-Tune + Stream-Freigabe auf stream_ka_sock nach Verbindungsaufbau

Keep-Alive-Logik ist in keepalive.py ausgelagert.
"""
from __future__ import annotations

import logging
import socket
import struct
import sys
import threading
import time
from typing import Optional

import protocol
from keepalive import _keepalive_worker
from models import ServiceEntry

log = logging.getLogger("wisi.stream")

# Speedtest-Response: 48128 Nutzdaten + 77 Byte Overhead = 48205 Byte.
# Diese Pakete haben weder USBS- noch \xf9\x0a-Prefix (Problem 2).
SPEEDTEST_RESPONSE_SIZE: int = protocol.UDP_REQUEST_LEN + 77  # 48205

SIGNAL_INTVL: float = protocol.SIGNAL_INTVL
UDP_PULL_INTVL: float = 0.5


# ---------------------------------------------------------------------------
# Phase 3: Kanal vorbereiten + Signal prüfen
# ---------------------------------------------------------------------------
def prepare_channel(
    sock: socket.socket,
    lock: threading.Lock,
    svc: ServiceEntry,
) -> None:
    """0x03 prepare → 0x32/0x33 ch_Info → 0x02 Signal-Poll."""
    with lock:
        protocol.send_recv(sock, protocol.cmd_prepare(svc.prog_idx), 4, "0x03 prepare")

    with lock:
        r = protocol.send_recv(sock, protocol.cmd_chinfo_size(svc.prog_idx), 6, "0x32 chinfo-size")
    if len(r) >= 6:
        ci_size = struct.unpack(">I", r[2:6])[0]
        if ci_size > 0:
            with lock:
                r2 = protocol.send_recv(
                    sock, protocol.cmd_chinfo_data(svc.prog_idx, ci_size),
                    ci_size, "0x33 chinfo",
                )
            log.debug("ch_Info: %s", r2[:min(80, ci_size)].decode("utf-8", "replace"))

    for attempt in range(3):
        time.sleep(SIGNAL_INTVL)
        with lock:
            r = protocol.send_recv(
                sock, protocol.cmd_signal(), 17,
                f"0x02 signal [{attempt + 1}/3]",
            )
        if len(r) >= 5:
            log.info("Signal: Stärke=%d%%  Qualität=%d", r[3], r[4])
            if r[3] >= 50:
                return
    log.warning("Signal schwach – weiter trotzdem.")


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
) -> None:
    """
    Tunet auf `svc` und schreibt MPEG-TS-Daten nach `output_path` ('-' = stdout).

    keepalive_active: True wenn der Aufrufer bereits einen KA-Thread auf tcp_sock führt
                      (z. B. main_menu) – dann wird kein zweiter gestartet.
    """
    stop = threading.Event()
    dongle_ip = tcp_sock.getpeername()[0]

    # Problem 1: tcp_sock stirbt nach Tune – on_dead signalisiert das sauber.
    tcp_sock_dead = threading.Event()

    ka: Optional[threading.Thread] = None
    if not keepalive_active:
        ka = threading.Thread(
            target=_keepalive_worker,
            args=(tcp_sock, lock, stop, tcp_sock_dead),
            daemon=True,
        )
        ka.start()

    stream_ka_stop: Optional[threading.Event] = None
    stream_ka: Optional[threading.Thread] = None
    stream_ka_sock: Optional[socket.socket] = None
    stream_ka_lock: Optional[threading.Lock] = None

    # UDP-Socket VOR dem ersten TCP-Befehl binden (Problem 3: zu spätes Bind).
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    udp.bind(("", 0))
    udp.settimeout(0.1)

    try:
        # UDP-Initialisierung
        udp.sendto(protocol.cmd_udp_init(), (dongle_ip, protocol.UDP_PORT))
        try:
            udp.recvfrom(256)
        except socket.timeout:
            pass

        # Tune (TCP 0xF6/0x01)
        with lock:
            protocol.send_recv(tcp_sock, protocol.cmd_tune(svc.pat_index), 2, "0x01 tune")
        log.info("Tune: pat_index=%d  sid=%d  (%s)", svc.pat_index, svc.service_id, svc.name)

        # Stream-Freigabe (TCP 0xF8/0x07)
        with lock:
            protocol.send_recv(tcp_sock, protocol.cmd_stream_release(), 0, "0xF8/0x07 release")

        # Erster UDP-Pull (first=True → byte21=0x00)
        udp.sendto(protocol.cmd_udp_ts_block(first=True), (dongle_ip, protocol.UDP_PORT))
        pull_count = 1
        log.debug("0xF9/0x01 Pull #1 (first) gesendet")

        # Tune bestätigen (TCP 0xF6/0x17)
        with lock:
            r = protocol.send_recv(tcp_sock, protocol.cmd_17_confirm(), 4, "0x17 confirm")
        log.info("0x17 confirm: 0x%02X", r[2] if len(r) > 2 else 0xFF)

        # Problem 3: Zweite TCP-Verbindung aufbauen.
        result = protocol.connect(dongle_ip)
        if result is None:
            raise ConnectionError("Keep-Alive-Verbindung nach Tune fehlgeschlagen.")
        stream_ka_sock = result
        stream_ka_lock = threading.Lock()

        try:
            with stream_ka_lock:
                protocol.send_recv(
                    stream_ka_sock, protocol.cmd_tune(svc.pat_index), 2,
                    "0x01 re-tune KA",
                )
                protocol.send_recv(
                    stream_ka_sock, protocol.cmd_stream_release(), 0,
                    "0xF8/0x07 re-release KA",
                )
            log.info("Re-Tune + Stream-Freigabe auf KA-Socket erfolgreich.")
        except OSError as e:
            log.warning("Re-Tune auf KA-Socket fehlgeschlagen (weiter): %s", e)

        stream_ka_stop = threading.Event()
        stream_ka = threading.Thread(
            target=_keepalive_worker,
            args=(stream_ka_sock, stream_ka_lock, stream_ka_stop),
            daemon=True,
        )
        stream_ka.start()

        out = open(output_path, "wb") if output_path != "-" else sys.stdout.buffer
        log.info("Stream → %s  (STRG+C zum Beenden)", output_path)

        t_start = time.monotonic()
        block_num = 0
        ts_bytes = 0
        pull_pending = True
        next_pull_deadline = t_start + UDP_PULL_INTVL
        last_packet_at = t_start
        next_timeout_warning = t_start + 5.0
        speedtest_count = 0

        try:
            while not stop.is_set():
                now = time.monotonic()
                if duration_s > 0 and now - t_start >= duration_s:
                    log.info("Dauer %.0f s erreicht.", duration_s)
                    break

                if not pull_pending or now >= next_pull_deadline:
                    udp.sendto(
                        protocol.cmd_udp_ts_block(first=False),
                        (dongle_ip, protocol.UDP_PORT),
                    )
                    pull_count += 1
                    pull_pending = True
                    next_pull_deadline = now + UDP_PULL_INTVL
                    log.debug("0xF9/0x01 Pull #%d (Fallback-Timer)", pull_count)

                try:
                    data, _ = udp.recvfrom(65535)
                except socket.timeout:
                    now = time.monotonic()
                    if now >= next_timeout_warning and now - last_packet_at >= 5.0:
                        log.warning(
                            "Seit 5 Sekunden keine UDP-Streamdaten; Pulls laufen weiter."
                        )
                        next_timeout_warning = now + 5.0
                    continue

                if data[:4] == b"USBS" or data[:2] == b"\xf9\x0a":
                    continue

                if len(data) == SPEEDTEST_RESPONSE_SIZE:
                    speedtest_count += 1
                    if speedtest_count == 1:
                        log.warning(
                            "Speedtest-Response (%dB) empfangen – zu viele Pulls oder "
                            "falscher Modus. Weitere Speedtest-Blöcke werden still verworfen.",
                            len(data),
                        )
                    else:
                        log.debug("Speedtest-Response #%d verworfen", speedtest_count)
                    pull_pending = False
                    continue

                sync_offset = data.find(bytes([protocol.TS_SYNC]))
                while sync_offset >= 0:
                    if (
                        sync_offset + 3 * protocol.TS_PKT_SIZE < len(data)
                        and all(
                            data[sync_offset + i * protocol.TS_PKT_SIZE] == protocol.TS_SYNC
                            for i in range(4)
                        )
                    ):
                        break
                    sync_offset = data.find(bytes([protocol.TS_SYNC]), sync_offset + 1)

                if sync_offset < 0:
                    log.debug("Kein MPEG-TS-Sync in UDP-Datagramm (%dB) – verworfen", len(data))
                    pull_pending = False
                    continue

                ts_data = data[sync_offset:]
                last_packet_at = time.monotonic()
                next_timeout_warning = last_packet_at + 5.0

                if block_num == 0:
                    log.debug(
                        "Erstes Stream-Datagramm: %dB, TS-Offset %d", len(data), sync_offset
                    )

                complete_len = len(ts_data) - len(ts_data) % protocol.TS_PKT_SIZE
                if complete_len == 0:
                    pull_pending = False
                    continue

                out.write(ts_data[:complete_len])
                out.flush()
                block_num += 1
                ts_bytes += complete_len

                udp.sendto(
                    protocol.cmd_udp_ts_block(first=False),
                    (dongle_ip, protocol.UDP_PORT),
                )
                pull_count += 1
                pull_pending = True
                next_pull_deadline = time.monotonic() + UDP_PULL_INTVL
                log.debug("0xF9/0x01 Pull #%d (nach Block %d)", pull_count, block_num)

                if block_num % 50 == 0:
                    elapsed = time.monotonic() - t_start
                    kbps = (ts_bytes / 1024) / max(elapsed, 0.001)
                    log.info(
                        "Block %4d | %.1f MiB | %.0f KB/s",
                        block_num, ts_bytes / 1_048_576, kbps,
                    )

        except KeyboardInterrupt:
            print()
            log.info("Abgebrochen.")
        finally:
            if output_path != "-":
                out.close()
            log.info(
                "Stream beendet. %d Blöcke, %d Pulls, %.2f MiB",
                block_num, pull_count, ts_bytes / 1_048_576,
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
            protocol.disconnect(stream_ka_sock)
        udp.close()
