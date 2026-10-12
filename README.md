# WISI OR S2D Dongle – Reverse Engineering & Client

> **Namenskorrektur:** Das Gerät des Nutzers ist laut Typ-/Produktunterlage der **WISI OR S2D** (DVB-S2 Free-To-Air SAT Dongle). In früheren Notizen und im ursprünglichen Projektnamen wurde es ungenau als „WISI O2D“ bezeichnet. OR S2D nicht mit anderen O2D-/Tivizen-/TiViCon-Geräten gleichsetzen: Protokollbeobachtungen in diesem Repository beziehen sich auf die jeweils aufgezeichneten Netzwerk-Mitschnitte.
>
> **Ziel:** Das proprietäre Streaming-Protokoll des WISI-Dongles zu untersuchen und eine eigene Anwendung zu bauen, die ihn über das Netzwerk anspricht und DVB-Livestreams abruft – ohne die originale TV2Smart-App.

---

## ▶ Schnellstart

```bash
# Verbinden + Kanalauswahl + Stream
python3 src/wisi_client.py --ip 192.168.178.32

# Mit Debug-Ausgabe (zeigt alle Roh-Bytes)
python3 src/wisi_client.py --ip 192.168.178.32 --debug

# Stream direkt in VLC pipen
python3 src/wisi_client.py --ip 192.168.178.32 --stream --pat-idx 4 --output - | vlc -
```

`src/wisi_client.py` ist der aktive Client. `src/wisi_menu.py` leitet ältere Aufrufe
als Kompatibilitätseinstieg dorthin weiter. Dateien in `archive/` sind alte Experimente.

## Gerät und Schnittstellen

Das hier identifizierte Modell ist der **WISI OR S2D**, ein DVB-S2-Free-To-Air-SAT-Dongle.
Das offizielle [Produktdatenblatt](https://wisi.at/daten/artikel/pdf/Pro_OR-S2D_de.pdf)
nennt USB-C für **PC/Firmwareupdate** und Ethernet (100 MBit/s); TV-Programme werden
laut Datenblatt über das Heimnetzwerk (LAN oder WLAN) an Endgeräte übertragen.

Die [OR-S2D-Bedienungsanleitung](https://wisi.at/daten/artikel/pdf/BDA_ORS2D_Dongle.pdf)
beschreibt USB für Firmware-Upgrade beziehungsweise eine direkte Verbindung zu einer
Android-TV-Box. Bei dieser direkten USB-Verbindung wird laut Anleitung die
Netzwerkfunktion deaktiviert. Das belegt keine Plug-and-play-TV-Verbindung zu einem
beliebigen Android-Tablet und dokumentiert auch kein PC-Flashprogramm.

Die Anleitung nennt zwei Firmwarewege in TV2Smart: **Dongle Online Upgrade** sowie
Firmware von einem USB-Speicherstick, den eine Android-TV-Box ausliest. Während eines
Upgrades sollen Dongle und Box eingeschaltet und verbunden bleiben, bis TV2Smart neu
gestartet wurde. Öffentlich zugängliche Unterlagen beschreiben weder ein PC-Update-Tool
noch den erforderlichen PC-Treiber, ein Firmwarepaket zum manuellen Flashen oder
Dateisystem/-namen für den USB-Stick. Deshalb keine beliebigen Flash-Tools oder
Firmwaredateien verwenden. Details und Quellen: [research/or_s2d_firmware_update.md](research/or_s2d_firmware_update.md).

---

## Ordnerstruktur

```
.
├── src/
│   ├── wisi_client.py                    # Aktiver Netzwerk-Client
│   └── wisi_menu.py                      # Legacy-Einstieg; leitet an wisi_client.py weiter
├── archive/
│   ├── wisi_dongle_client.py             # Ältere Version v4 (Referenz)
│   ├── wisi_dongle_v1.py                 # Ältere Version v1 (Referenz)
│   └── wisi_dongle_simple.py             # Minimaler Proof of Concept
├── research/
│   ├── or_s2d_firmware_update.md         # OR S2D: Modell, USB-C, Firmware-Update
│   ├── pcap_analysis.md                  # Protokollanalyse der Mitschnitte
│   ├── apk_reverse_engineering.md        # TV2Smart-APK-Analyse
│   ├── protocol_analysis_chatgpt.md      # Protokollnotizen
│   ├── deep_research_gemini.md           # Ältere Recherche, mit Modellhinweis
│   ├── deep_research_with_pcap.md        # Frühere PCAP-Analyse
│   ├── deep_research_without_pcap.md     # Frühere Analyse ohne PCAP
│   ├── script_output_example.txt         # Beispielausgabe
│   └── capture_pcapdroid_2026-10-11.pcap # Früherer PCAP-Mitschnitt
├── PCAPdroid_12_Okt._16_16_04.pcap       # Nutzer-PCAP: App öffnen/schließen
├── PCAPdroid_12_Okt._16_28_17.pcap       # Nutzer-PCAP: Streamablauf
├── pyproject.toml                        # Python-Projekt-/Tool-Konfiguration
└── README.md
```

`.venv/` (lokale virtuelle Umgebung) und `.git/` (Versionsverwaltung) sind
absichtlich nicht als Projektinhalte aufgeführt. PCAP-Dateien können private
Netzwerkdetails enthalten; Mitschnitte vor dem Veröffentlichen prüfen und bei Bedarf
aus der Versionsverwaltung heraushalten.

---

## Projekt-Roadmap

| Schritt | Status | Beschreibung |
|---------|--------|--------------|
| **1** | ✅ Fertig | Dongle verbinden + Init-Handshake (0x16/0x17) |
| **2** | ✅ Fertig | EPG laden, Kanalliste aufbauen, Kanal auswählen |
| **3** | ✅ Fertig | MPEG-TS-Stream starten + in Datei/VLC schreiben |
| **4** | 🔲 Offen | Kanalwechsel (0x01 Payload für andere Kanäle bestätigen) |
| **5** | 🔲 Offen | Android-App oder Web-UI |

---

## Protokoll-Überblick

### Ports

```
TCP 8802  – Steuerkanal (USBC/APIX-Befehle + USBS-Antworten + EPG-XML)
UDP 8800  – Stream-Kanal (aktiv: Client fordert jeden Block an)
```

### USBC-Container (31 Byte, beide Kanäle)

| Offset | Länge | Inhalt |
|--------|-------|--------|
| 0–3 | 4 | Signatur `USBC` |
| 4–7 | 4 | Magic Tag `A0 CB 03 37` (konstant) |
| 8–11 | 4 | Datenlänge Big-Endian |
| 12 | 1 | Flags (`0x80` = Lesen, `0x00` = Schreiben) |
| 13 | 1 | LUN `0x00` |
| 14 | 1 | CDB-Länge `0x10` (16 Byte) |
| 15 | 1 | Prefix: `0xF6` (TCP-Befehle), `0xF8` (Stream-Freigabe), `0xF9` (UDP) |
| 16–19 | 4 | `APIX` (ASCII) |
| 20 | 1 | Opcode |
| 21–30 | 10 | Payload / Padding |

### TCP-Opcodes (Steuerkanal, Prefix 0xF6)

| Opcode | Funktion | Antwort |
|--------|----------|---------|
| `0x16` | Init + Keep-Alive (alle ~2 s) | 12 Byte: `[0]=0x00/0x01` (bereit-Flag) |
| `0x17` | Init Phase 2 / Tune-Bestätigung | 4 Byte: `0x00` oder `0x01` |
| `0x01` | **Kanal aktivieren (Tune-Trigger)** | USBS |
| `0x02` | Signal-Status-Poll (alle ~3 s) | 13 Byte: Byte[1]=Stärke%, Byte[2]=Qualität |
| `0x03` | Kanal vorauswählen (prepare tune) | USBS |
| `0x30` | EPG-Größe abfragen | 6 Byte (Länge BE) |
| `0x31` | EPG-XML abrufen | `<epg_Data>...</epg_Data>` |
| `0x32` | ch_Info-Größe abfragen | 6 Byte |
| `0x33` | ch_Info-XML abrufen | `<ch_Info>...</ch_Info>` |
| `0x35` | Ereignis-Größe abfragen | 6 Byte |
| `0x36` | Ereignis-XML abrufen | `<event_desc .../>` |

| Prefix | Opcode | Funktion |
|--------|--------|----------|
| `0xF8` | `0x07` | Stream-Freigabe (nach Tune, vor erstem UDP-Block) |

### UDP-Opcodes (Stream-Kanal, Prefix 0xF9)

> **Wichtig:** Der UDP-Stream ist **kein passiver Push**. Der Client muss jeden Block aktiv anfordern!

| Opcode | Funktion | Antwort |
|--------|----------|---------|
| `0x02` | Stream initialisieren (einmalig) | – |
| `0x0A` | EPG-Metadaten per UDP anfordern (200×, pre-tune) | 32.740 Byte `F9 0A 00...` |
| `0x01` | **MPEG-TS-Block anfordern** | 32.740 Byte (174 × 188 Byte TS-Pakete) |

### Vollständiger Protokollablauf

```
Phase 1 – TCP Init
  → 0x16                     Dongle meldet Status=0x00
  → 0x17                     Dongle meldet 0x00
  → 0x16 (wiederholen)       Dongle meldet Status=0x01 = BEREIT

Phase 2 – EPG laden (TCP, 252 Kanäle)
  für jeden Kanal:
    → 0x30 [prog_idx]        Größe des EPG-Blocks
    → 0x31 [prog_idx]        <epg_Data><ch s_id="..." evt .../></epg_Data>
  einmalig:
    → 0x35 / 0x36            Ereignis-Detailbeschreibung (XML)
  zwischendurch:
    → 0x16                   Keep-Alive (alle ~2 s)

Phase 3 – UDP EPG-Polling (parallel, t=5–30s)
  → 0xF9/0x02               Stream-Init
  → 0xF9/0x0A (×200)        EPG/Metadaten per UDP

Phase 4 – Kanal vorbereiten (TCP)
  → 0x03 [prog_idx, flag=2]  Kanal vorauswählen
  → 0x32 / 0x33 [prog_idx]  ch_Info: s_id + prog_idx bestätigen
  → 0x02 (alle ~3 s)         Signal pollen (Stärke=100%, Qualität≈60)

Phase 5 – Tune + Stream (TCP + UDP)
  → 0x01 [00 04]             Kanal aktivieren (Index in PAT-Liste)
  → 0xF8/0x07                Stream-Freigabe
  → 0xF9/0x01 [byte21=0x00]  Erster MPEG-TS-Block anfordern
  ← 32.740 Byte MPEG-TS      174 Pakete: H.264 + 2× MPEG-1 Audio
  → 0x17 [01 00 00 00]       Kanalwechsel bestätigen
  → 0xF9/0x01 [byte21=0x01]  Weitere Blöcke (in Schleife)
  → 0x16 (alle ~2 s)         TCP Keep-Alive während Stream läuft
```

---

## Stream-Inhalt (aus PCAP, Programm 4914)

```
PAT: 22 Programme auf ts_id=33079
PMT Prog 4914:
  PID 0x1338  H.264 Video     (94% aller TS-Pakete)
  PID 0x1339  MPEG-1 Audio 1
  PID 0x133A  MPEG-1 Audio 2
  PID 0x133E  Private Data (Teletext?)
```

## EPG-Format

```xml
<epg_Data>
  <ch s_id="11110" ts_id="33079" prog_idx="1085735055">
    <evt id="39442" des="heute Xpress" date="61324" time="13:25" dur="00:05" rating="0" />
  </ch>
</epg_Data>

<event_desc s_id="11110" evt_id="39447"
  name="Terra Xplore"
  short_txt="Angstthema Krieg: Kämpfst du?"
  ext_txt="..." />
```

## prog_idx Struktur

```
0x40xxxxxx  → normaler (FTA) Kanal
0x48xxxxxx  → verschlüsselter Kanal (Pay-TV / CA)

Byte[1..2]  → Transponder-Gruppe (0xB4, 0xB7, 0xDE ...)
Byte[3]     → Sequenz-Nummer innerhalb des Transponders
```

---

## Stand der Analyse

- ✅ USBC/APIX-Rahmenformat vollständig
- ✅ Init-Sequenz (0x16/0x17) und Keep-Alive
- ✅ EPG-Abfrage (0x30/0x31, 0x35/0x36) mit XML-Format
- ✅ Kanal-Vorbereitung (0x03, 0x32/0x33)
- ✅ Signal-Polling (0x02)
- ✅ Tune-Ablauf (0x01 → 0xF8/0x07 → 0x17)
- ✅ UDP-Stream: pull-basiert, 0xF9/0x01 fordert je 174 TS-Pakete an
- ✅ MPEG-TS-Inhalt: H.264 + MPEG-1 Audio, PAT/PMT ausgelesen
- ✅ 252 Kanäle mit EPG auf ts_id=33079 identifiziert
- 🔲 0x01-Payload für andere Kanäle (Index in PAT?) bestätigen
- 🔲 0xF9/0x0A-Antwortformat (proprietäres Binär) dekodieren
- 🔲 Pay-TV / verschlüsselte Kanäle (0x48-prog_idx)
