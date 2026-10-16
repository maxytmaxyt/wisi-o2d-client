"""
models.py – Datenmodelle für WISI OR S2D
=========================================
Channel         – Kanal aus der <ch_List> XML-Antwort (0xF6/0x21)
ServiceEntry    – Compat-Wrapper mit alten Feldnamen (pat_index, video_pid …)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


# ---------------------------------------------------------------------------
# Channel  (primäres Modell aus der TCP-Kanalliste)
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


# ---------------------------------------------------------------------------
# ServiceEntry  (Compat-Schicht; alte Feldnamen aus Legacy-Code)
# ---------------------------------------------------------------------------
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
        lock = "🔒" if self.is_encrypted else "   "
        return (
            f"[{self.pat_index:3d}] sid={self.service_id:5d} "
            f"vpid={self.video_pid:#06x} apid={self.audio_pid:#06x} "
            f"[{lock}] {self.name}"
        )


# ---------------------------------------------------------------------------
# Konvertierung
# ---------------------------------------------------------------------------
def channel_to_service(ch: Channel, idx: int) -> ServiceEntry:
    """Konvertiert Channel (aus XML) in ServiceEntry (Compat-Schicht)."""
    return ServiceEntry(
        pat_index=idx,
        prog_idx=ch.prog_idx,
        service_id=ch.service_id,
        flags=0x0001 if not ch.is_encrypted else 0x0009,
        name=ch.name,
    )


# ---------------------------------------------------------------------------
# Fallback-Kanal (aus PCAP, wenn ch_List leer)
# ---------------------------------------------------------------------------
FALLBACK_SERVICE = ServiceEntry(
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
