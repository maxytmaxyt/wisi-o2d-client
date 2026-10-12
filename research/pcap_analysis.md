# PCAP-Analyse – Detaillierte Ergebnisse

> Analysiert aus `capture_pcapdroid_2024-10-11.pcap` mit Scapy, Oktober 2026  
> Echte Daten direkt aus dem PCAP extrahiert – keine Hypothesen mehr

---

## 1. Übersicht

| Eigenschaft | Wert |
|-------------|------|
| Pakete gesamt | 3.286 |
| Dauer | 48,59 s |
| Dongle-IP | 192.168.178.32 |
| Client-IP | 10.215.173.1 |
| TCP 8802 (Steuer) | 2.652 Pakete |
| UDP 8800 (Stream) | 622 Pakete |
| MPEG-TS Pakete | 18.444 (106 UDP-Datagramme × 174 TS-Pakete) |
| MPEG-TS Daten | ~3,3 MB (ca. 32.740 Byte / Datagramm) |

---

## 2. Vollständige Opcode-Tabelle

### TCP-Kanal (Port 8802) – Steuerung

| Prefix | Opcode | Richtung | Funktion | Antwort |
|--------|--------|----------|----------|---------|
| 0xF6 | 0x01 | C→D | **Kanal aktivieren** (Tune-Trigger) | `F6 01 USBS` |
| 0xF6 | 0x02 | C→D | **Signal-Status-Poll** (alle ~3 s) | `F6 02 00 64 3D ...` 13 Byte |
| 0xF6 | 0x03 | C→D | **Kanal vorauswählen** (prepare tune) | `F6 03 01 01 USBS` |
| 0xF6 | 0x16 | C→D | **Init / Keep-Alive** (alle ~2 s) | `F6 16 [12 Byte] USBS` |
| 0xF6 | 0x17 | C→D | **Init Phase 2 / Tune-Bestätigung** | `F6 17 [0x00 oder 0x01] USBS` |
| 0xF6 | 0x30 | C→D | **EPG-Größe abfragen** | 6 Byte (Länge BE) |
| 0xF6 | 0x31 | C→D | **EPG-XML abrufen** | `<epg_Data>...</epg_Data>` |
| 0xF6 | 0x32 | C→D | **ch_Info-Größe abfragen** | 6 Byte (Länge) |
| 0xF6 | 0x33 | C→D | **ch_Info-XML abrufen** | `<ch_Info>...</ch_Info>` |
| 0xF6 | 0x35 | C→D | **Ereignis-Größe abfragen** | 6 Byte |
| 0xF6 | 0x36 | C→D | **Ereignis-XML abrufen** | `<event_desc>...</event_desc>` |
| 0xF8 | 0x07 | C→D | **Stream-Freigabe** (nach Tune) | Nur USBS |

### UDP-Kanal (Port 8800) – Stream

| Prefix | Opcode | Richtung | Funktion | Antwort |
|--------|--------|----------|----------|---------|
| 0xF9 | 0x02 | C→D | **Stream initialisieren** (einmalig) | – |
| 0xF9 | 0x0A | C→D | **EPG-Daten per UDP anfordern** (200×) | 32.740 Byte `F9 0A 00...` |
| 0xF9 | 0x01 | C→D | **MPEG-TS-Daten anfordern** (116×) | 32.740 Byte MPEG-TS |

---

## 3. Init-Sequenz (bestätigt)

### APIX 0x16 – Geräte-Status (12 Byte Nutzdaten)

```
Erste Antwort (t=0.11s):
  F6 16 00 04 FF 04 A5 2D 00 00 00 00 00 00 00 USBS
          ──
          └─ 0x00 = noch nicht initialisiert

Alle Folge-Antworten (Keep-Alive, alle ~2s):
  F6 16 01 04 FF 04 A5 2D 00 00 00 00 00 00 00 USBS
          ──
          └─ 0x01 = bereit/aktiv

Konstante Gerätekennzeichen: 04 FF 04 A5 2D (unveränderlich)
```

### APIX 0x17 – Init Phase 2 / Tune-Bestätigung

```
Erste Antwort (t=0.15s):  F6 17 00 00 USBS  → 0x00 (nicht bereit)
Zweite Antwort (t=47.62s): F6 17 01 00 USBS  → 0x01 (Kanalwechsel bestätigt)
```

---

## 4. Signal-Status (0x02) – bestätigt

```
Antwort (5 Messungen im PCAP):
  F6 02 00 64 3D 00 00 00 3C A0 00 00 00 00 00 USBS
              ──  ──
              │   └─ Signalqualität: variiert 0x3B–0x3D = 59–61
              └───── Signalstärke:   0x64 = 100 (konstant = 100%)

Byte[6..7] = 0x3C 0xA0 = konstant (Transponder-Info?)
```

---

## 5. UDP-Protokoll – vollständig aufgeklärt

### Korrekturen gegenüber früherer Analyse

Die früheren Annahmen waren teilweise falsch. Das echte UDP-Protokoll:

```
Ablauf (chronologisch):
t=4.98s  0xF9/0x02  (1×)  → Stream-Initialisierung
t=4.99s  0xF9/0x0A  (200×) → EPG-Daten per UDP anfordern
         Antwort: 32.740 Byte, Header: F9 0A 00 00 00... (kein MPEG-TS!)
t=30.41s 0xF9/0x01  (116×) → MPEG-TS-Daten anfordern
         Antwort: 32.740 Byte echtes MPEG-TS (0x47-Sync)
```

### 0xF9/0x0A – EPG per UDP

```
Client sendet USBC:
  55 53 42 43  A0 CB 03 37  00 00 BC 00  80 00 10
  F9 41 50 49 58 0A 00 00 00 00 00 00 00 00 00 00
               ──
               datalen = 0xBC00 = 48.128 Byte

Dongle antwortet:
  F9 0A 00 00 00 00 00 00 ... (32.740 Byte)
  ── ──
  F9 0A = Antwort-Echo des Opcodes
  (kein MPEG-TS-Sync-Byte 0x47)
```

### 0xF9/0x01 – MPEG-TS-Stream

```
Client sendet USBC:
  Byte[21] = 0x00  → erster Block  (t=30.41s)
  Byte[21] = 0x01  → spätere Blöcke (t=45.71s)
  datalen = 0xBC00 = 48.128 Byte

Dongle antwortet: 32.740 Byte MPEG-TS
  → 174 TS-Pakete à 188 Byte (174 × 188 = 32.712 ≈ 32.740)
  → Start mit Sync-Byte 0x47
```

### 0xF9/0x02 – Stream-Init (einmalig)

```
Client sendet:
  55 53 42 43 A0 CB 03 37 00 00 00 00 00 00 10
  F9 41 50 49 58 02 01 00 00 00 00 00 00 00 00 00
               ── ──
               datalen=0, Byte[21]=0x01
```

---

## 6. MPEG-TS Stream-Inhalt (aus PAT/PMT)

### PAT – Program Association Table (PID 0x0000)

Der Dongle liefert einen **Multiplex** mit 22+ Programmen auf einem Transponder:

| Programm-Nr. | PMT-PID |
|-------------|---------|
| 0 (NIT) | 0x0010 |
| 4911 | 0x006B |
| 4912 | 0x006C |
| 4913 | 0x006D |
| **4914** | **0x006E** ← gewählter Kanal (s_id aus ch_Info) |
| 4916 | 0x0074 |
| 4917 | 0x0075 |
| 4920 | 0x0078 |
| ... | ... |

### PMT für Programm 4914 (PID 0x006E)

```
PCR PID: 0x1338 (4920)

Streams:
  PID 0x1338 (4920)  type=0x1B  → H.264 Video      ← Hauptvideo
  PID 0x1339 (4921)  type=0x03  → MPEG-1 Audio      ← Audio 1
  PID 0x133A (4922)  type=0x03  → MPEG-1 Audio      ← Audio 2 (z.B. 2. Sprache)
  PID 0x133E (4926)  type=0x05  → Private Data      ← Teletext/Untertitel?
```

### PID-Verteilung im Stream

| PID | Pakete | Typ |
|-----|--------|-----|
| 0x0000 | 13 | PAT |
| 0x006E | 13 | PMT (Prog 4914) |
| **0x1338** | **17.371** | **H.264 Video** (94% aller Pakete) |
| 0x1339 | 524 | MPEG-1 Audio 1 |
| 0x133A | 523 | MPEG-1 Audio 2 |

---

## 7. EPG-Daten – vollständig extrahiert

### Format

```xml
<epg_Data>
<ch s_id="11110" ts_id="33079" prog_idx="1085735055">
  <evt id="39442" des="heute Xpress" date="61324" time="13:25" dur="00:05" rating="0" />
  <evt id="39627" des="plan b: next BITE" date="..." time="..." dur="..." rating="0" />
</ch>
</epg_Data>
```

### Statistik

- **252 Kanäle** mit EPG-Daten
- Alle auf `ts_id=33079`
- Verschiedene prog_idx-Gruppen (unterschiedliche Transponder)

### Ereignis-Beschreibung (0x36 → `<event_desc>`)

```xml
<event_desc s_id="11110" evt_id="39447" 
  name="Terra Xplore" 
  short_txt="Angstthema Krieg: Kämpfst du?" 
  ext_txt="Deutschland 2026 – Die Angst vor Krieg in Europa..." />
```

**Format:**
- `s_id` = Service-ID (= Programm-Nummer)
- `evt_id` = Ereignis-ID
- `name` = Sendetitel
- `short_txt` = Kurzbeschreibung
- `ext_txt` = Langbeschreibung (UTF-8)

---

## 8. prog_idx Struktur (bestätigt + korrigiert)

```
Format: 32-Bit Integer
  Byte[0] = 0x40 oder 0x48
  Byte[1] = ts_id high nibble?
  Byte[2] = ts_id low byte
  Byte[3] = laufende Sequenz

Alle EPG-ts_ids = 33079 (0x8137)
Aber prog_idx-Gruppen:
  0x40B4xxxx → ts_id-Gruppe B4 (Transponder B4xx)
  0x40B7xxxx → ts_id-Gruppe B7
  0x40DExxxx → ts_id-Gruppe DE
  0x48A5xxxx → 0x48-Flag = verschlüsselt/Premium

0x48-Flag bedeutet: verschlüsselter Kanal (Pay-TV)
→ Prog 4914 hat 0x40B40089 → unverschlüsselt
```

---

## 9. Vollständiger Protokollablauf (finale Version)

```
Phase 1: TCP-INIT
─────────────────
TCP connect :8802
→ 0x16  ← Init, Gerätestatus
← F6 16 00 04 FF 04 A5 2D ... (Status=0x00)
→ 0x17  ← Init Phase 2
← F6 17 00 00 USBS
→ 0x16  ← Wiederholung bis Status=0x01
← F6 16 01 04 FF 04 A5 2D ... (BEREIT)

Phase 2: UDP-STREAM-INIT (parallel zu TCP)
───────────────────────────────────────────
UDP :8800
→ 0xF9/0x02  ← Stream initialisieren (einmalig)
→ 0xF9/0x0A  ← EPG/Metadaten per UDP pollen (200× alle ~0.6s)
← 32.740 Byte F9 0A 00... (Rohdaten)

Phase 3: TCP EPG-SCHLEIFE (alle Kanäle)
────────────────────────────────────────
Für jeden der 252 Kanäle:
  → 0x30 [prog_idx]  ← EPG-Größe
  ← F6 30 [4-Byte-Länge]
  → 0x31 [prog_idx+params]  ← EPG-XML
  ← <epg_Data><ch ...><evt .../></ch></epg_Data>
→ 0x16 (alle ~2s)  ← Keep-Alive

Einmalig (t=2.45s):
  → 0x35  ← Ereignis-Größe
  → 0x36  ← <event_desc>...</event_desc>

Phase 4: KANAL-VORBEREITUNG (t≈28s)
─────────────────────────────────────
→ 0x03 [payload=00000002]  ← Kanal vorauswählen (Flag=2)
← F6 03 01 01 USBS         ← Bestätigt
→ 0x32 [prog_idx=0x40B40089]  ← ch_Info Größe (65 Byte)
→ 0x33 [prog_idx=0x40B40089]  ← ch_Info XML
← <ch_Info><ch s_id="4914" prog_idx="1085538441"/></ch_Info>

Phase 5: SIGNAL-ÜBERWACHUNG (t=31-46s)
────────────────────────────────────────
→ 0x02 (alle ~3s)  ← Signal-Poll
← F6 02 00 64 3B-3D 00 00 00 3C A0 ...
   Stärke=100%, Qualität=59-61 (gut)

Phase 6: TUNE + MPEG-TS-START (t=46-48s)
──────────────────────────────────────────
→ 0x01 [payload=00 04]  ← Kanal aktivieren (Tune-Trigger)
← F6 01 USBS
→ 0xF8/0x07              ← Stream-Freigabe
← USBS
→ 0xF9/0x01 [Byte21=0x00]  ← MPEG-TS-Block anfordern (UDP)
← 32.740 Byte MPEG-TS (174 TS-Pakete, PID 0x1338 = H.264)
→ 0x17 [payload=01 00 00 00]  ← Kanalwechsel bestätigen
← F6 17 01 00 USBS
→ 0xF9/0x01 [Byte21=0x01]  ← Weitere MPEG-TS-Blöcke (Byte21=1 nach erstem Block)
← 32.740 Byte MPEG-TS ...
```

---

## 10. Schlüsselerkenntnisse (neu)

### UDP ist bidirektional und kein passiver Stream

Der UDP-Stream ist **kein Push-Stream**. Der Client muss jeden Block aktiv anfordern:
```
Client → 0xF9/0x01  (Anforderung)
Dongle → 32.740 Byte MPEG-TS  (Antwort)
Client → 0xF9/0x01  (nächste Anforderung)
...
```
Das erklärt warum das alte `hi.py`-Script `0x0A`-Befehle sendete – es hat die EPG-Daten über UDP abgerufen, aber nie `0x01` geschickt um den eigentlichen MPEG-TS-Stream zu bekommen.

### 0xF9/0x0A vs 0xF9/0x01

| | 0xF9/0x0A | 0xF9/0x01 |
|--|-----------|-----------|
| Antwort-Header | `F9 0A 00...` | `47 ...` (TS-Sync) |
| Inhalt | EPG/Metadaten | MPEG-TS Video/Audio |
| Zeitraum | t=5–30s | t=30–48s |
| Anzahl | 200× | 116× |

### Kanalauswahl (0x01 Payload)

```
payload = 00 04

Byte[0] = 0x00 → Flag?
Byte[1] = 0x04 → Kanal-Slot oder Index?

Prog 4914 hat s_id=4914=0x1332, aber Payload ist 0x0004.
→ Wahrscheinlich ein interner Index, nicht die s_id.
  0x04 könnte der 5. Eintrag in der PAT-Liste sein:
  PAT: Prog 0, 4911, 4912, 4913, 4914 → Index 4 ✓
```

---

## 11. Implementierung (korrigiert)

```python
import socket, struct, threading

DONGLE_IP = "192.168.178.32"
TCP_PORT  = 8802
UDP_PORT  = 8800
MAGIC     = b"\xA0\xCB\x03\x37"
CHUNK     = 0xBC00  # 48128 Byte Anforderungsgröße

def build_usbc(prefix, opcode, datalen=0, flags=0x80, payload=b""):
    cdb = (bytes([prefix]) + b"APIX" + bytes([opcode]) + payload).ljust(16, b"\x00")
    return b"USBC" + MAGIC + struct.pack(">I", datalen) + bytes([flags, 0x00, 0x10]) + cdb

def build_udp_usbc(prefix, opcode, datalen=0, flags=0x80, payload=b""):
    """Gleiche Struktur, aber über UDP gesendet."""
    return build_usbc(prefix, opcode, datalen, flags, payload)

# UDP-Stream starten
def start_mpeg_stream(tcp_sock, output_path):
    # UDP-Socket öffnen
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("", UDP_PORT))
    udp.settimeout(3.0)

    # 1. UDP init (0xF9/0x02)
    init_pkt = build_udp_usbc(0xF9, 0x02, datalen=0, flags=0x00, payload=b"\x01")
    udp.sendto(init_pkt, (DONGLE_IP, UDP_PORT))

    # 2. TCP: Tune-Befehl senden (Phase 6)
    tcp_sock.sendall(build_usbc(0xF6, 0x01, datalen=2, flags=0x00, payload=b"\x00\x04"))
    tcp_sock.recv(256)  # USBS lesen
    tcp_sock.sendall(build_usbc(0xF8, 0x07, datalen=4, flags=0x00))
    tcp_sock.recv(256)

    # 3. MPEG-TS Blöcke anfordern (0xF9/0x01)
    with open(output_path, "wb") as f:
        block_num = 0
        while True:
            byte21 = b"\x00" if block_num == 0 else b"\x01"
            req = build_udp_usbc(0xF9, 0x01, datalen=CHUNK, flags=0x80, payload=byte21)
            udp.sendto(req, (DONGLE_IP, UDP_PORT))
            try:
                data, _ = udp.recvfrom(65535)
                if data[0] == 0x47:  # TS-Sync-Check
                    f.write(data)
                    block_num += 1
            except socket.timeout:
                print("Timeout – kein weiterer Stream")
                break

    udp.close()
```

---

## 12. Offene Punkte (reduziert)

- [ ] **0x01 Payload `00 04`** – Index 4 in der PAT-Liste (sehr wahrscheinlich), aber nicht 100% bestätigt. Test: anderen Kanal wählen und Payload ändern.
- [ ] **0xF9/0x0A Antwort-Format** – 32.740 Byte `F9 0A 00...` enthält EPG/Metadaten, aber genaue Struktur noch unbekannt. Wahrscheinlich proprietäres Binärformat.
- [ ] **0xF8/0x07 Payload** – immer `00 00 00 00`, Funktion noch unklar (Stream-Freigabe?).
- [ ] **Kanalwechsel zu anderem Kanal** – neues PCAP mit anderem Kanal würde 0x01-Payload-Hypothese bestätigen.
- [x] ~~UDP ist passiver Push-Stream~~ → **Nein**, Client muss jeden Block aktiv per 0xF9/0x01 anfordern
- [x] ~~MPEG-TS-Sync-Byte nicht in PCAP gefunden~~ → **Doch**, 18.444 TS-Pakete (PID 0x1338 = H.264)
- [x] ~~prog_idx-Struktur unklar~~ → Alle auf ts_id=33079, 0x48-Flag = Pay-TV
- [x] ~~EPG-Format unbekannt~~ → `<epg_Data><ch s_id...><evt des="..." .../></ch></epg_Data>`
- [x] ~~Kanal-Stream-Inhalt unklar~~ → H.264 Video + 2× MPEG-1 Audio + Private Data
