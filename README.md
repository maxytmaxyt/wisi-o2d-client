# WISI O2D Dongle – Reverse Engineering & Client

> **Ziel:** Das proprietäre Streaming-Protokoll des **WISI O2D / Tivizen / TiViCon DVB-over-IP-Dongles** zu reverse-engineeren und anschließend eine eigene Anwendung zu bauen, die den Dongle direkt anspricht und DVB-Livestreams abspielt – ohne die originale Tivizen-App.

---

## ▶ Schnellstart – Das ist die Datei die du benutzen sollst

```bash
python3 src/wisi_menu.py --ip 192.168.178.32

# Mit Debug-Ausgabe (zeigt alle Roh-Antworten des Dongles)
python3 src/wisi_menu.py --ip 192.168.178.32 --debug
```

`src/wisi_menu.py` ist der **einzige aktive Client** – er wächst mit jedem Schritt der Roadmap.  
Die Dateien in `archive/` sind alte Experimente und müssen nicht mehr angefasst werden.

---

## Ordnerstruktur

```
wisi-dongel/
├── src/
│   └── wisi_menu.py          ← HIER ARBEITEN – aktiver Client
├── archive/
│   ├── wisi_dongle_client.py  ← alte Version v4 (Referenz)
│   ├── wisi_dongle_v1.py      ← alte Version v1 (Referenz)
│   └── wisi_dongle_simple.py  ← minimaler Proof-of-Concept (Referenz)
├── research/
│   ├── deep_research_with_pcap.md       ← Protokollanalyse (wichtig!)
│   ├── deep_research_without_pcap.md
│   ├── protocol_analysis_chatgpt.md
│   ├── script_output_example.txt        ← Beispiel-Ausgabe
│   └── capture_pcapdroid_2024-10-11.pcap ← Original-PCAP-Mitschnitt
└── README.md
```

---

## Projekt-Roadmap

| Schritt | Status | Beschreibung |
|---------|--------|--------------|
| **1** | ✅ Fertig | Dongle verbinden + Init-Handshake + interaktives Hauptmenü |
| **2** | 🔲 Geplant | Kanalliste aus EPG laden, Kanal auswählen |
| **3** | 🔲 Geplant | Stream starten → VLC / ffplay per subprocess |
| **4** | 🔲 Geplant | Kanalwechsel (Tuning-Befehl erforschen) |

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
| `0x02` | UDP      | Pre-Init (einmalig vor 0x0A-Schleife) |
| `0x0A` | UDP      | Vorbereitungsschleife vor MPEG-TS-Stream |
| `0x01` | UDP      | MPEG-TS-Block anfordern (triggert UDP-Datagramm) |
| `0x16` | TCP (KA) | Keep-Alive alle 2,5 s (verhindert Stream-Abbruch) |

### Protokoll-Ablauf

```
Client                          Dongle (192.168.178.32)
  │── TCP connect :8802 ──────────────────────────────▶│
  │── APIX 0x16 (Init) ─────────────────────────────▶  │  ← Schritt 1
  │◀─ 12-Byte-Antwort ─────────────────────────────────│
  │── APIX 0x17 (Init) ─────────────────────────────▶  │  ← Schritt 1
  │◀─ 4-Byte-Antwort ──────────────────────────────────│
  │── APIX 0x30 (EPG-Größe) ────────────────────────▶  │  ← Schritt 2
  │◀─ 6 Byte (Länge als Big-Endian) ───────────────────│
  │── APIX 0x31 (EPG-XML) ──────────────────────────▶  │  ← Schritt 2
  │◀─ XML-Block (Kanalliste) ──────────────────────────│
  │── APIX 0x02 (Pre-Init UDP) ─────────────────────▶  │  ← Schritt 3
  │── APIX 0x0A (Pre-Stream Loop ~5 s) ─────────────▶  │  ← Schritt 3
  │ ┌─ Keep-Alive-Thread: APIX 0x16 alle 2,5 s ──────▶│  ← Schritt 3
  │── APIX 0x01 (Stream-Request via UDP) ───────────▶  │  ← Schritt 3
  │◀─ UDP :8800 → 256 MPEG-TS-Pakete (48 128 Byte) ────│
```

**Wichtig:** Ohne Keep-Alive bricht der Dongle den Stream nach ~20–30 s ab.

---

## Stand der Analyse

- ✅ USBC/APIX-Rahmenformat vollständig rekonstruiert
- ✅ Init-Sequenz (0x16 / 0x17) identifiziert
- ✅ EPG-Abfrage (0x30/0x31, 0x35/0x36) mit XML-Antwortformat
- ✅ MPEG-TS-Streaming via UDP mit 188-Byte-Paketstruktur
- ✅ Keep-Alive-Mechanismus zur Stream-Stabilisierung
- 🔲 Tuning-Befehl (Kanalwechsel) – Opcode noch nicht vollständig geklärt
- 🔲 Scrambling/CA (Continuity-Counter-Analyse nötig)
- 🔲 Vollständige eigene App (Android / Desktop)
