# WISI O2D Dongle – Reverse Engineering

> **Ziel:** Das proprietäre Streaming-Protokoll des **WISI O2D / Tivizen / TiViCon DVB-over-IP-Dongles** zu reverse-engineeren und anschließend eine eigene Anwendung zu bauen, die den Dongle direkt anspricht und DVB-Livestreams abspielt – ohne die originale Tivizen-App.

---

## Hintergrund

Der WISI O2D (auch bekannt als Tivizen / TiViCon) ist ein kompaktes DVB-Empfangsgerät, das sich per WLAN ins Heimnetz einbindet und DVB-T/T2/C-Streams über IP bereitstellt. Die Original-App kommuniziert mit dem Dongle über ein undokumentiertes proprietäres Protokoll auf Basis eines USB-Bulk-Only-Transport (USBC/USBS) Rahmens mit herstellerspezifischen APIX-Befehlen.

---

## Protokoll-Überblick

```
TCP 8802   Steuerkanal – USBC/APIX-Befehle + USBS-Antworten
UDP 8800   Datenpfad   – MPEG-TS-Blöcke (256 × 188 Byte pro Datagramm)
```

### USBC-Container (31 Byte)

| Offset | Länge | Inhalt |
|--------|-------|--------|
| 0–3    | 4     | Signatur `USBC` |
| 4–7    | 4     | Tag (konstant `A0 CB 03 37`) |
| 8–11   | 4     | Datenlänge – Big-Endian |
| 12     | 1     | Flags (`0x80` = Einlesen) |
| 13     | 1     | LUN (`0x00`) |
| 14     | 1     | CDB-Länge (`0x10` = 16 Byte) |
| 15–30  | 16    | Herstellerspezifischer APIX-Befehl |

### Bekannte APIX-Opcodes

| Opcode | Richtung | Funktion |
|--------|----------|----------|
| `0x16` | TCP      | Initialisierung / Statusabfrage (12 Byte Antwort) |
| `0x17` | TCP      | Zweite Initialisierungsabfrage (4 Byte Antwort) |
| `0x30` | TCP      | EPG-Datensatzgröße abfragen (`prog_idx`) |
| `0x31` | TCP      | EPG-XML abrufen |
| `0x35` | TCP      | Ereignisbeschreibungsgröße abfragen |
| `0x36` | TCP      | Ereignisbeschreibung abrufen |
| `0x0A` | TCP      | Vorbereitungsschritt vor MPEG-TS-Stream |
| `0x01` | UDP      | MPEG-TS-Block anfordern (triggert UDP-Datagramm) |
| `0xFF` | TCP      | Keep-Alive / Heartbeat (verhindert Stream-Abbruch) |

### Ablauf

```
Client                          Dongle (192.168.178.32)
  │── TCP connect :8802 ──────────────────────────────▶│
  │── APIX 0x16 (Init) ─────────────────────────────▶  │
  │◀─ 12-Byte-Antwort ─────────────────────────────────│
  │── APIX 0x17 (Init) ─────────────────────────────▶  │
  │◀─ 4-Byte-Antwort ──────────────────────────────────│
  │── APIX 0x30 (EPG-Größe) ────────────────────────▶  │
  │◀─ 6 Byte (Länge als Big-Endian) ───────────────────│
  │── APIX 0x31 (EPG-XML) ──────────────────────────▶  │
  │◀─ XML-Block ───────────────────────────────────────│
  │── APIX 0x0A (Pre-Stream) ───────────────────────▶  │
  │                                                     │
  │ ┌─ Keep-Alive-Thread: APIX 0xFF alle 250 ms ──────▶│
  │ └──────────────────────────────────────────────────┘
  │                                                     │
  │── APIX 0x01 (Stream-Request) ───────────────────▶  │
  │◀─ UDP :8800 → 256 MPEG-TS-Pakete (48 128 Byte) ────│
  │── APIX 0x01 (wiederholt) ───────────────────────▶  │
  │◀─ UDP :8800 → … ───────────────────────────────────│
```

**Wichtig:** Ohne den Keep-Alive-Thread bricht der Dongle den Stream nach dem ersten UDP-Block ab.

---

## Dateien im Repository

| Datei | Inhalt |
|-------|--------|
| `wisi_dongle.py` | Python-Client – Steuerung + UDP-Empfang + EPG-Abfrage |
| `PCAPdroid_11_Okt._17_09_51[1].pcap` | Netzwerk-Mitschnitt (PCAPdroid) der Original-App |
| `chatgpt-answer-for-analysis-the-protocol.md` | KI-gestützte Protokollanalyse des PCAP |
| `chatgpt-deep-research-with-pacap.md` | Detailanalyse mit PCAP-Auswertung (Tuning, Keep-Alive, EPG) |
| `chatgpt-deep-research-without-pacap.md` | Protokollanalyse ohne PCAP (DVB-Standards, Hypothesen) |

---

## Verwendung

```bash
# Stream aufzeichnen
python3 wisi_dongle.py --ip 192.168.178.32 --output kanal.ts

# Mit EPG-Abfrage (prog_idx aus dem PCAP-XML)
python3 wisi_dongle.py --ip 192.168.178.32 --epg-idx 0x40B7008F --output kanal.ts

# Debug-Ausgabe
python3 wisi_dongle.py --ip 192.168.178.32 --debug
```

Die erzeugte `.ts`-Datei kann direkt mit **VLC** oder **ffplay** geöffnet werden:

```bash
ffplay kanal.ts
# oder live streamen:
ffplay udp://0.0.0.0:8800
```

---

## Stand der Analyse

- ✅ USBC/APIX-Rahmenformat vollständig rekonstruiert
- ✅ Init-Sequenz (0x16 / 0x17) identifiziert
- ✅ EPG-Abfrage (0x30/0x31, 0x35/0x36) mit XML-Antwortformat
- ✅ MPEG-TS-Streaming via UDP mit 188-Byte-Paketstruktur
- ✅ Keep-Alive-Mechanismus (0xFF) zur Stream-Stabilisierung
- 🔲 Tuning-Befehl (Kanalwechsel) – Opcode noch nicht vollständig geklärt
- 🔲 Scrambling/CA (Continuity-Counter-Analyse nötig)
- 🔲 Vollständige eigene App (Android / Desktop)

---

## Ziel

Auf Basis dieser Erkenntnisse soll eine plattformübergreifende App entstehen, die:
1. Den Dongle direkt über das APIX-Protokoll anspricht
2. Die Kanalliste per EPG-Abfrage lädt
3. Ausgewählte Kanäle als MPEG-TS empfängt und wiedergibt
4. Ohne die Original-Tivizen-App auskommt
