# WISI OR S2D Dongle – Reverse Engineering & Client

> **Namenskorrektur:** Das Gerät des Nutzers ist laut Typ-/Produktunterlage der **WISI OR S2D** (DVB-S2 Free-To-Air SAT Dongle). In früheren Notizen und im ursprünglichen Projektnamen wurde es ungenau als „WISI O2D“ bezeichnet. OR S2D nicht mit anderen O2D-/Tivizen-/TiViCon-Geräten gleichsetzen: Protokollbeobachtungen in diesem Repository beziehen sich auf die jeweils aufgezeichneten Netzwerk-Mitschnitte.
>
> **Ziel:** Das proprietäre Streaming-Protokoll des WISI-Dongles zu untersuchen und eine eigene Anwendung zu bauen, die ihn über das Netzwerk anspricht und DVB-Livestreams abruft – ohne die originale TV2Smart-App.

---

## ▶ Schnellstart

```bash
# Hilfe zum Überskript
python src/wisi.py --help

# Senderliste anzeigen
python src/wisi.py --ip 192.168.178.32 --channels

# EPG abrufen und als epg.json speichern
python src/wisi.py --ip 192.168.178.32 --epg

# Stream speichern oder direkt an VLC weiterleiten
python src/wisi.py --ip 192.168.178.32 --stream --pat-idx 4 --output stream.ts
python src/wisi.py --ip 192.168.178.32 --stream --pat-idx 4 --output - | vlc -
```

`src/wisi.py` ist das gemeinsame Überskript. Die einzelnen Werkzeuge können auch
direkt gestartet werden. Es werden nur die Python-Standardbibliothek und die im
Repository vorhandenen Dateien benötigt. Für die installierbare Kommandozeile kann
das Projekt mit `python -m pip install -e .` installiert werden; danach steht
`wisi --help` zur Verfügung.

### Befehle

| Aufruf | Funktion |
|--------|----------|
| `python src/wisi.py --ip IP --channels` | Senderliste über UDP 8800 abrufen und dekodieren |
| `python src/wisi.py --ip IP --epg` | EPG der Sender über TCP 8802 laden; Standardausgabe `epg.json` |
| `python src/wisi.py --ip IP --epg --epg-limit 10 --epg-output epg.json` | EPG für die ersten 10 Sender laden |
| `python src/wisi.py --ip IP --stream --pat-idx 4 --duration 60 --output stream.ts` | Stream für 60 Sekunden speichern |
| `python src/wisi.py --ip IP --stream --output - \| vlc -` | Stream direkt an VLC weiterleiten |
| `python src/wisi.py --discover` | Experimentelle TV2S-UDP-Gerätesuche versuchen |
| `python src/wisi.py --pcap capture.pcap` | APIX-Befehle und erkannte Service-DB-Antworten analysieren |
| `python src/wisi.py --pcap capture.pcap --pcap-extract service-db.bin` | Größte gefundene `0xF9/0x0A`-Antwort zusätzlich speichern |
| `python src/wisi.py --decode-service-db service-db.bin` | Gespeicherten `0xF9/0x0A`-Rohblob dekodieren |
| `python src/wisi.py --ip IP --probe-opcode 0x12` | Genau einen ausgewählten unbekannten Opcode senden |

`--output -` gibt den Stream auf stdout aus; `--epg-output -` gibt EPG-JSON auf
stdout aus. Das vollständige EPG kann bei vielen Sendern eine Weile dauern.
Discovery und einige Bedeutungen aus
[WICHTIG_NEUE_MÖGLICHKEITEN.md](./WICHTIG_NEUE_MÖGLICHKEITEN.md) sind Hypothesen und
nicht durch die vorhandenen PCAPs bestätigt. Eine ausbleibende Discovery-Antwort
bedeutet nicht, dass der Dongle offline ist; nutze dann die direkte IP-Adresse.
Der Opcode-Probe sendet nur einen einzeln gewählten Opcode. Unbekannte Befehle
können das Geräteverhalten beeinflussen; es gibt absichtlich keinen Opcode-Sweep.
Die beiden PCAPs im Projektstamm enthalten `0xF9/0x0A`-Anfragen und kurze `USBS`-
Antworten. Im älteren Mitschnitt unter `research/` gibt es 198 Antworten mit je
32.740 Byte, deren Inhalt aber nur aus `F9 0A` und Nullbytes besteht; es wurden daraus
keine Sender dekodiert. Das angenommene Datensatzlayout ist somit noch nicht durch
Nutzdaten vom Dongle bestätigt. Vollständige Antwortblöcke lassen sich mit
`--pcap-extract` speichern und mit `--decode-service-db` untersuchen.

Die Werkzeuge sind auch einzeln startbar, zum Beispiel:

```bash
python src/wisi_channels.py --ip 192.168.178.32
python src/wisi_epg.py --ip 192.168.178.32 --output epg.json
python src/wisi_pcap.py capture.pcap
python src/wisi_probe.py --ip 192.168.178.32 --probe-opcode 0x12
```

`src/wisi_client.py` enthält den APIX-Steuerungs- und Stream-Client.
`src/wisi_menu.py` bleibt ein Legacy-Einstieg. Dateien in `archive/` sind alte Experimente.

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
│   ├── wisi.py                           # Überskript / gemeinsames CLI
│   ├── wisi_client.py                    # APIX-Steuerung und MPEG-TS-Stream
│   ├── wisi_channels.py                  # Senderliste anzeigen
│   ├── wisi_common.py                    # Gemeinsame CLI-Helfer
│   ├── wisi_discovery.py                 # Experimentelle TV2S-Discovery
│   ├── wisi_epg.py                       # EPG als JSON speichern
│   ├── wisi_pcap.py                      # PCAP/APIX-Analyse und Service-DB-Export
│   ├── wisi_probe.py                     # Einzelnen Opcode gezielt testen
│   ├── protocol.py                       # APIX-Builder und Netzwerk-Helfer
│   └── wisi_menu.py                      # Legacy-Einstieg
├── archive/
│   ├── wisi_dongle_client.py             # Ältere Version v4 (Referenz)
│   ├── wisi_dongle_v1.py                 # Ältere Version v1 (Referenz)
│   └── wisi_dongle_simple.py             # Minimaler Proof of Concept
├── research/
│   ├── or_s2d_firmware_update.md         # OR S2D: Modell, USB-C, Firmware-Update
│   ├── pcap_analysis.md                  # Protokollanalyse der Mitschnitte
│   ├── apk_reverse_engineering.md         # TV2Smart-APK-Analyse
│   ├── protocol_spec_or_s2d.md             # Zusammengetragene Protokoll-Spezifikation
│   └── capture_pcapdroid_2026-10-11.pcap # Früherer PCAP-Mitschnitt
├── PCAPdroid_12_Okt._16_16_04.pcap       # Nutzer-PCAP: App öffnen/schließen
├── PCAPdroid_12_Okt._16_28_17.pcap       # Nutzer-PCAP: Streamablauf
├── tests/
│   └── test_wisi_tools.py                 # Tests für Discovery und PCAP-Auswertung
├── pyproject.toml                        # Python-Projekt-/Tool-Konfiguration
└── README.md
```

`.venv/` (lokale virtuelle Umgebung) und `.git/` (Versionsverwaltung) sind
absichtlich nicht als Projektinhalte aufgeführt. PCAP-Dateien können private
Netzwerkdetails enthalten; Mitschnitte vor dem Veröffentlichen prüfen und bei Bedarf
aus der Versionsverwaltung heraushalten.

---

## Umsetzungsstand der neuen Möglichkeiten

| Schritt | Status | Beschreibung |
|---------|--------|--------------|
| Service-Datenbank | ⚠️ Teilweise | Live-Anfrage und Decoder vorhanden; das angenommene Datensatzlayout ist mangels vollständiger Antwort noch nicht mit dem Dongle verifiziert |
| EPG | ✅ Ergänzt | `0x30/0x31` für gefundene Sender abrufen und als JSON exportieren |
| PCAP-Auswertung | ✅ Ergänzt | Klassisches PCAP (Ethernet oder Raw IPv4) nach APIX-Befehlen durchsuchen; falls vorhanden Service-DB-Antwort exportieren/dekodieren |
| Überskript | ✅ Ergänzt | Ein Einstieg für Senderliste, EPG, Stream, Discovery, Opcode-Probe und PCAP |
| Gerätesuche | ⚠️ Experimentell | TV2S-Broadcast-Format aus der Spezifikationsnotiz; noch nicht per Mitschnitt bestätigt |
| Opcode-Scan | ⏸️ Nicht automatisiert | Nur ein einzelner, manuell angegebener Opcode kann getestet werden |
| Authentifizierungsschlüssel | ⏸️ Nicht umgesetzt | Die beschriebene native Bibliothek liegt nicht im Repository; keine Schlüssel-Extraktion oder Token-Umgehung |
| Scan-Modus | ⏸️ Unbekannt | Scan-Opcodes und Payloads sind nicht durch PCAP belegt |
| Kanalwechsel | ⚠️ Teilweise | Streamen anhand eines Service-/PAT-Index ist vorhanden; `0x01` für weitere Kanäle noch nicht unabhängig bestätigt |

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
| `0x0A` | UDP-Datenblock anfordern (in einem Mitschnitt 200×, pre-tune); Inhalt/Semantik unbestätigt | 32.740 Byte; im vorhandenen älteren Mitschnitt nach `F9 0A` nur Nullbytes |
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
- ⚠️ `0xF9/0x0A`: PCAP-Decoder vorhanden, aber in 198 aufgezeichneten Antworten nur `F9 0A` + Nullbytes; noch kein Nutzdaten-/Service-Layout bestätigt
- 🔲 Pay-TV / verschlüsselte Kanäle (0x48-prog_idx)
