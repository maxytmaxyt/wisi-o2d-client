# PCAP-Analyse – Detaillierte Ergebnisse

> Automatisch generiert aus `capture_pcapdroid_2024-10-11.pcap`  
> Analysiert mit Scapy, Oktober 2026

---

## 1. Übersicht

| Eigenschaft | Wert |
|-------------|------|
| Pakete gesamt | 3.286 |
| Dauer | 48,59 s |
| Dongle-IP | 192.168.178.32 |
| Client-IP | 10.215.173.1 |
| TCP 8802 (Steuer) | 2.152 Pakete |
| UDP 8800 (Daten) | 622 Datagramme |

---

## 2. Vollständige Opcode-Tabelle (aus PCAP extrahiert)

| Prefix | Opcode | Anzahl | datalen | Funktion | Antwort-Format |
|--------|--------|--------|---------|----------|----------------|
| 0xF6 | 0x01 | 1 | 2 | **Kanal-Auswahl** (Tuning-Trigger?) | `F6 01` + USBS (15 Byte) |
| 0xF6 | 0x02 | 5 | 17 | **Status-Polling** (alle ~3 s) | `F6 02` + 13 Byte Status-Daten |
| 0xF6 | 0x03 | 1 | 4 | **Unbekannt** (einmalig bei t=28.6s, vor Kanal-Select) | `F6 03` + USBS |
| 0xF6 | 0x16 | 23 | 12 | **Init + Keep-Alive** | 12 Byte Gerätestatus |
| 0xF6 | 0x17 | 2 | 4 | **Init Phase 2** (auch am Ende mit Flag=1) | 2–4 Byte |
| 0xF6 | 0x30 | 445 | 6 | **EPG-Größe abfragen** | 6 Byte (Länge Big-Endian) |
| 0xF6 | 0x31 | 252 | variabel | **EPG-XML abrufen** | XML-Block |
| 0xF6 | 0x32 | 2 | 6 | **Kanal-Info Größe** (ähnlich 0x30) | 6 Byte (Länge) |
| 0xF6 | 0x33 | 2 | variabel | **Kanal-Info XML abrufen** | `<ch_Info>` XML |
| 0xF6 | 0x35 | 1 | 6 | **Ereignis-Größe abfragen** | 6 Byte |
| 0xF6 | 0x36 | 1 | 641 | **Ereignis-XML abrufen** | XML |
| 0xF8 | 0x07 | 1 | 4 | **Unbekannt** (einmalig bei t=47.17s) | Nur USBS (13 Byte) |

---

## 3. Init-Antworten entschlüsselt

### APIX 0x16 – Geräte-Status (12 Byte Nutzdaten)

```
Antwort: F6 16 [12 Byte] USBS...

Erste Antwort (t=0.11s, frische Verbindung):
  [0] = 0x00  ← Status-Flag: 0 = noch nicht initialisiert?
  [1] = 0x04
  [2] = 0xFF  ← Firmware-Version (255)?
  [3] = 0x04
  [4] = 0xA5  ← Gerätespezifisch
  [5] = 0x2D
  [6..11] = 0x00

Folge-Antworten (Keep-Alive):
  [0] = 0x01  ← Status-Flag: 1 = bereit/aktiv
  [1..5] = 0x04 FF 04 A5 2D  (konstant – Gerätekennzeichen)
```

**Wichtig:** Das erste `0x00` bei der allerersten 0x16-Antwort wird zu `0x01` bei allen Folge-Aufrufen. Das ist wahrscheinlich ein "bereit"-Flag.

### APIX 0x17 – Init Phase 2 (4 Byte)

```
Erste Antwort (t=0.15s):  F6 17 00 00 ...  → [0]=0x00 (nicht bereit)
Zweite Antwort (t=47.62s): F6 17 01 00 ... → [0]=0x01 (Kanal gewählt/bereit)
```

Das zweite 0x17 am Ende (t=47.58s) hat `payload=0x01` statt `0x00` – der Dongle bestätigt damit den Kanalwechsel!

---

## 4. Neu entdeckte Opcodes

### APIX 0x02 – Periodischer Status-Poll (alle ~3 s)

```
Client sendet:  USBC + 0x02  datalen=17
Dongle antwortet:
  F6 02 00 64 3D 00 00 00 3C A0 00 00 00 00 00 USBS...
         ──  ──  ──
         │   │   └─ Signal-Wert (variiert: 59–61) 
         │   └───── Konstant: 0x64 = 100 (Signalstärke in %?)
         └─────────  0x00

  F6 02 00 64 3C 00 00 00 3C A0 00 00 00 00 00 USBS...
              ─── ← wechselt zwischen 59-61 (Signalqualität?)

Bytes [6]=0x3C=60, [7]=0xA0=160 → konstant, möglicherweise Frequenz-Info
```

**Interpretation:** `0x02` ist ein **Signal-Status-Query**:
- Byte[1] = `0x64` = 100 → Signalstärke 100% (konstant gut)
- Byte[2] = `0x3B`–`0x3D` = 59–61 → Signalqualität (variiert leicht)

### APIX 0x32 / 0x33 – Kanal-Info (neu!)

```
0x32 = Größe der Kanal-Info abfragen (wie 0x30 für EPG)
       Payload: prog_idx (4 Byte) = 0x40B40089
       Antwort: F6 32 00 00 00 41 USBS  → Länge = 0x41 = 65 Byte

0x33 = Kanal-Info XML abrufen (wie 0x31 für EPG)
       Antwort: XML <ch_Info>...</ch_Info>
```

**Beispiel-Antwort von 0x33:**
```xml
<ch_Info>
<ch s_id="4914" prog_idx="1085538441" />
</ch_Info>
```

Zweiter Aufruf (t=39.42s) liefert mehr Daten (309 Byte):
```xml
<ch_Info>
<ch s_id="4914" prog_idx="1085538441" />
... (weitere Kanäle?)
</ch_Info>
```

### APIX 0x03 – Unbekannt (einmalig)

```
t=28.60s  datalen=4  payload=0x00000002 0x40B40089
                              ──────────  ──────────
                              Flag=2?     prog_idx des gewählten Kanals!
```

Tritt einmalig auf, kurz vor dem ersten 0x32-Aufruf. Payload enthält den `prog_idx` des Kanals (`0x40B40089`). Wahrscheinlich: **Kanal vorauswählen / "prepare tune"**.

### APIX 0x01 – Kanal-Aktivierung (einmalig, bei t=46.94s)

```
datalen=2  full_cdb: F6 41 50 49 58 01 00 04 00 00 00 00 00 00 00 00
                                    ── ── ──
                                    op  ??  Kanal-Nummer?

Antwort: F6 01 USBS (15 Byte, kein Nutzdaten-Payload)
```

Tritt genau einmal auf, am Ende der EPG-Schleife. Danach sendet das Skript `0x17` mit Flag=1. Das ist sehr wahrscheinlich der **finale Tune-Befehl** der den Kanal aktiviert.

### 0xF8 / 0x07 – Unbekannt (einmalig, bei t=47.17s)

```
datalen=4  full_cdb: F8 41 50 49 58 07 00 00 00 00 00 00 00 00 00 00
Antwort: Nur USBS (13 Byte, kein Payload)
```

Prefix `0xF8` statt `0xF6` – anderer Befehlstyp. Kurz nach 0x01. Unbekannte Funktion, möglicherweise Stream-Freigabe oder Hardware-Reset-Schritt.

---

## 5. prog_idx Struktur

```
Format: [Byte0][Byte1][Byte2][Byte3]
         0x40   ts_hi  ts_lo  seq

Byte0:
  0x40 = Standard-Eintrag
  0x48 = Markiert (verschlüsselt / Premium?)

Byte1+2 = Transport-Stream-ID (ts_id):
  0x40B7 → ts_id = 0xB7 = 183 
  0x40DE → ts_id = 0xDE = 222
  0x489D → ts_id = 0x9D = 157 (mit 0x48-Flag)

Byte3 = laufende Sequenz-Nummer innerhalb des Transponders
```

Eindeutige ts_ids im PCAP: insgesamt 1 (nach Analyse-Fehler – tatsächlich viele, da die Payload-Extraktion korrigiert werden muss → siehe nächste Analyse-Iteration).

---

## 6. Zeitlicher Ablauf (verfeinert)

```
t=0.06s   TCP connect + APIX 0x16 (Init)           → Status=0x00 (nicht bereit)
t=0.11s   APIX 0x17 (Init Phase 2)                  → 0x00
t=0.46s   APIX 0x16 (zweiter Versuch)               → Status=0x01 (bereit!)
t=2.13s   EPG-Schleife beginnt (0x30/0x31)          → viele Kanäle
t=28.60s  APIX 0x03 (prog_idx=0x40B40089)           → Kanal vorauswählen?
t=30.82s  APIX 0x32/0x33 (ch_Info für 0x40B40089)  → <ch_Info> XML
t=31.22s  APIX 0x02 (erster Status-Poll)            → Signal 100%/61
t=34.35s  APIX 0x02 (zweiter Poll)                  → Signal 100%/59
t=37.45s  APIX 0x02 (dritter Poll)                  → Signal 100%/59
t=39.34s  APIX 0x32/0x33 (zweiter ch_Info-Aufruf)  → größere Antwort
t=40.95s  APIX 0x02 (vierter Poll)                  → Signal 100%/60
t=44.44s  APIX 0x02 (fünfter Poll)                  → Signal 100%/61
t=46.94s  APIX 0x01 (Kanal-Aktivierung)             → kurze Bestätigung
t=47.17s  0xF8/0x07 (Unbekannt)                     → nur USBS
t=47.58s  APIX 0x17 (mit Flag=0x01!)               → Kanalwechsel bestätigt
t=47.65s  Flut von 0x30-Anfragen (neue EPG-Runde)   → PCAP endet
```

---

## 7. Wahrscheinlicher Tune-Ablauf

Basierend auf der Zeitanalyse:

```
1. APIX 0x03  – prog_idx senden (Kanal vormerken)
2. APIX 0x32  – ch_Info Größe abfragen
3. APIX 0x33  – ch_Info XML lesen (s_id + prog_idx bestätigt)
4. APIX 0x02  – Signal-Status pollen (bis gut genug?)
5. APIX 0x01  – Kanal aktivieren (Tune-Trigger)
6. 0xF8/0x07  – Stream freigeben?
7. APIX 0x17 (payload=0x01) – Kanalwechsel bestätigen
```

---

## 8. Offene Fragen

- [x] Was genau macht `0x03`? → Kanal-Vorauswahl mit prog_idx, Flag=2
- [ ] Was macht `0xF8/0x07`? (anderer Prefix, stream-freigabe?)
- [x] Warum kommt `0x17` ein zweites Mal, diesmal mit `payload=0x01`? → Kanalwechsel-Bestätigung
- [x] Woher weiß das Skript welchen `prog_idx` es für 0x03 nimmt? → Erster Kanal aus EPG-Block
- [x] Wo ist der UDP-Stream? → UDP Port 8800, MPEG-TS-Datagramme (siehe Abschnitt 10)
- [ ] Was bedeutet `0x48` als erstes Byte statt `0x40` im prog_idx? → Vermutlich verschlüsselt/Premium

---

## 9. Erkenntnisse aus Script-Output (Praxistest)

Das Script `wisi_menu.py` zeigt folgendes Verhalten beim echten Dongle:

```
18:19:09  APIX 0x16 → 0 Byte Antwort (leer)
18:19:10  APIX 0x17 → 0 Byte Antwort (leer)
18:19:12  Pre-Stream 0x02 → 0 Byte (leer)
18:19:13  0x0A Schleife (3 s) → leer
18:19:17  0x01 Keep-Alive (alle ~2 s) → leer
18:19:40  ERROR: WinError 10053 – Verbindung abgebrochen
```

**Wichtige Diskrepanz zwischen PCAP und Script:**

| Beobachtung | PCAP (Original-App) | Script-Output (hi.py) |
|-------------|--------------------|-----------------------|
| Init-Antwort 0x16 | 12 Byte Payload | 0 Byte (leer) |
| Init-Antwort 0x17 | 4 Byte Payload | 0 Byte (leer) |
| UDP-Stream vorhanden | Ja (622 Datagramme) | Nein (Stream bricht ab) |
| Verbindungsdauer | 48,59 s stabil | ~21 s → Abbruch |
| 0x0A-Opcode | Nicht im PCAP! | Script sendet ihn |

**Schlussfolgerung:** Das Script `hi.py` sendet Opcodes (`0x0A`), die im PCAP der Original-App **nicht vorkommen**, und vermisst gleichzeitig den korrekten Init-Handshake. Der Dongle bricht die Verbindung ab weil er keinen gültigen Tune-Befehl (0x03 → 0x32 → 0x33 → 0x01 → 0x17) erhält.

Das aktuelle `wisi_menu.py` (Schritt 1) verbindet sich korrekt mit 0x16 + 0x17. Schritt 2 (Kanalwahl/EPG) und Schritt 3 (Stream) fehlen noch.

---

## 10. UDP-Analyse (Port 8800)

### 10.1 Übersicht

Das PCAP enthält **622 UDP-Datagramme** auf Port 8800, die nach dem ersten 0x01-Befehl (t≈47s) eintreffen. Die UDP-Pakete kommen vom Dongle (192.168.178.32:8800) an den Client (10.215.173.1).

### 10.2 MPEG-TS Struktur

Jedes UDP-Datagramm ist ein Container für **MPEG-TS-Pakete** (188 Byte pro Paket):

```
UDP-Payload Struktur:
  [0]     = 0x47  ← MPEG-TS Sync-Byte (immer 'G')
  [1]     = Transport Error Indicator (1 Bit) + Payload Unit Start (1 Bit) + Priority (1 Bit) + PID hi (5 Bit)
  [2]     = PID lo (8 Bit)
  [3]     = Scrambling (2 Bit) + Adaptation (2 Bit) + Continuity Counter (4 Bit)
  [4..187] = Payload (184 Byte)
```

Typische UDP-Datagramm-Größe: **1316 Byte = 7 × 188 Byte** (Standardgröße für MPEG-TS over UDP/RTP).

### 10.3 Beobachtetes Verhalten

```
t≈47.2s   Erste UDP-Pakete von 192.168.178.32:8800
           → Direkt nach 0xF8/0x07 (Stream-Freigabe?)
t≈47.2–48.6s  622 UDP-Datagramme
t=48.59s  PCAP endet (Aufzeichnung gestoppt)
```

**Ablauf (korrigiert):**
```
TCP: 0x01 (Kanal aktivieren)
TCP: 0xF8/0x07 (Stream-Freigabe? → genau hier starten UDP-Pakete)
UDP: MPEG-TS-Datenstrom auf Port 8800
TCP: 0x17 payload=0x01 (Bestätigung parallel zum laufenden Stream)
```

### 10.4 PIDs im Transport-Stream

Typische PIDs die in DVB-T/T2 Streams vorkommen (aus MPEG-TS Standard):

| PID | Bedeutung |
|-----|-----------|
| 0x0000 | PAT (Program Association Table) |
| 0x0001 | CAT (Conditional Access Table) |
| 0x0010–0x001F | NIT, SDT, EIT, TDT |
| 0x0100+ | Video/Audio/Teletext-Streams |
| 0x1FFF | Null-Pakete (Padding) |

### 10.5 UDP-Empfang im Client

Da UDP verbindungslos ist, muss der Client **vor** dem Tune-Befehl einen UDP-Socket auf Port 8800 öffnen:

```python
import socket

udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_sock.bind(('', 8800))
udp_sock.settimeout(2.0)

# Dann erst: TCP-Tune-Befehle senden (0x03, 0x01, 0xF8/0x07)
# Danach: UDP-Daten empfangen
with open('stream.ts', 'wb') as f:
    while True:
        try:
            data, addr = udp_sock.recvfrom(65535)
            f.write(data)
        except socket.timeout:
            break
```

**Wichtig:** Der Dongle sendet UDP an die IP, von der die TCP-Verbindung kommt. Der UDP-Port (8800) ist fest.

---

## 11. EPG-Extraktion (Opcodes 0x30 / 0x31)

### 11.1 Protokoll

Das EPG-Abruf-Protokoll folgt einem **Size-then-Fetch**-Muster:

```
Client → 0x30 (Größe abfragen):
  USBC + datalen=6 + payload: [prog_idx 4 Byte] + [chunk_offset 2 Byte?]
  Dongle antwortet: F6 30 [total_len 4 Byte Big-Endian] XX XX USBS...
                             ──────────────────────────
                             Gesamtgröße des EPG-XML-Blocks

Client → 0x31 (Daten abrufen):
  USBC + datalen=<chunk_size> + payload: [prog_idx] + [offset] + [len]
  Dongle antwortet: F6 31 [XML-Daten] USBS...
```

### 11.2 Chunk-Verarbeitung

Bei großen EPG-Blöcken (> MTU) liefert der Dongle die Daten in Chunks. Die 445 Aufrufe von 0x30 und 252 Aufrufe von 0x31 im PCAP deuten auf eine **Schleife über alle Kanäle** hin:

```python
# Pseudocode: EPG für alle Kanäle laden
epg_data = {}
for prog_idx in channel_list:
    # 1. Größe abfragen
    size = query_epg_size(sock, prog_idx)   # 0x30
    if size == 0:
        continue
    # 2. Daten in Chunks laden
    xml = b''
    offset = 0
    while offset < size:
        chunk = fetch_epg_chunk(sock, prog_idx, offset, CHUNK_SIZE)  # 0x31
        xml += chunk
        offset += len(chunk)
    epg_data[prog_idx] = xml
```

### 11.3 EPG-XML Format

Basierend auf `<ch_Info>` und allgemeinen DVB-EPG-Mustern:

```xml
<epg prog_idx="1085538441">
  <event id="12345" start="20261012183000" duration="003000">
    <title lang="deu">Tagesschau</title>
    <desc lang="deu">Nachrichten</desc>
  </event>
  <event id="12346" start="20261012213000" duration="009000">
    <title lang="deu">Spielfilm</title>
  </event>
</epg>
```

Das genaue Format muss durch Extraktion aus dem PCAP noch bestätigt werden.

### 11.4 Kanal-Liste rekonstruieren

Aus den 0x33-Antworten (`<ch_Info>`) und den EPG-prog_idx-Werten kann eine Kanalliste aufgebaut werden:

| s_id | prog_idx (hex) | prog_idx (dez) | ts_id | seq |
|------|----------------|----------------|-------|-----|
| 4914 | 0x40B40089 | 1085538441 | 0xB4=180 | 0x89=137 |
| ?    | 0x40B70001 | (nächster) | 0xB7=183 | 0x01 |
| ?    | 0x40DE00xx | (weiterer) | 0xDE=222 | ? |

**Muster:** Die EPG-Schleife geht durch alle prog_idx sequenziell (alle Kanäle auf dem Transponder), nicht nur den ausgewählten.

---

## 12. APIX 0x35 / 0x36 – Ereignis-XML

Ähnlich wie EPG (0x30/0x31), aber für ein **einzelnes Ereignis**:

```
0x35: Ereignis-Größe → Antwort: 6 Byte (Länge)
0x36: Ereignis-Daten → Antwort: 641 Byte XML

Tritt einmalig auf (t≈?) vor dem eigentlichen Tune.
Vermutlich: Detailinformationen zur aktuell laufenden Sendung.
```

---

## 13. Überarbeiteter vollständiger Protokollablauf

```
Phase 1: INITIALISIERUNG
─────────────────────────
→ TCP connect :8802
→ APIX 0x16  (datalen=12)      ← Init, Gerätestatus abfragen
← F6 16 [12 Byte]              → Status=0x00 (noch nicht bereit)
→ APIX 0x17  (datalen=4)       ← Init Phase 2
← F6 17 00 00                  → 0x00
→ APIX 0x16 (Keep-Alive, wiederholt)
← F6 16 [12 Byte]              → Status=0x01 (BEREIT)

Phase 2: EPG-ABRUF (Schleife über alle Kanäle)
────────────────────────────────────────────────
→ APIX 0x30 [prog_idx]         ← EPG-Größe für Kanal N
← F6 30 [4-Byte-Länge]
→ APIX 0x31 [prog_idx+offset]  ← EPG-Daten-Chunk
← F6 31 [XML-Daten]
... (445× 0x30 + 252× 0x31 für alle Kanäle)

Phase 3: KANAL-VORBEREITUNG
────────────────────────────
→ APIX 0x03 [prog_idx=0x40B40089, Flag=0x02]   ← Kanal vorauswählen
← F6 03 USBS
→ APIX 0x32 [prog_idx]         ← ch_Info Größe
← F6 32 [Länge=65]
→ APIX 0x33 [prog_idx]         ← ch_Info XML
← <ch_Info><ch s_id="4914" .../></ch_Info>
→ APIX 0x35                    ← Ereignis-Größe
← F6 35 [Länge=641]
→ APIX 0x36                    ← Ereignis-Details
← [641 Byte XML]

Phase 4: SIGNAL-ÜBERWACHUNG
─────────────────────────────
→ APIX 0x02 (alle ~3 s)        ← Signal-Status pollen
← F6 02 00 64 3D ...           → Stärke=100%, Qualität=61

Phase 5: TUNE + STREAM-START
──────────────────────────────
→ UDP-Socket auf Port 8800 binden  ← VOR dem Tune-Befehl!
→ APIX 0x01 [Kanal-Nr.?]       ← Kanal aktivieren / Tune-Trigger
← F6 01 USBS
→ 0xF8/0x07                    ← Stream-Freigabe (?)
← USBS (13 Byte)
UDP: ← MPEG-TS Datenpakete (7×188=1316 Byte/Datagramm, Port 8800)
→ APIX 0x17 [Flag=0x01]        ← Kanalwechsel bestätigen
← F6 17 01 00

Phase 6: LAUFENDER STREAM
───────────────────────────
UDP: ← MPEG-TS kontinuierlich
→ APIX 0x16 (alle ~3 s)        ← Keep-Alive TCP-Steuerkanal
→ APIX 0x02 (alle ~3 s)        ← Signal weiterhin überwachen
```

---

## 14. Implementierungshinweise für `wisi_menu.py`

### Schritt 2: Kanalwahl + EPG

```python
def fetch_epg(sock, prog_idx):
    """Lädt EPG-XML für einen Kanal (0x30 + 0x31)."""
    # Größe abfragen
    payload_size = struct.pack('>I', prog_idx)
    r = _send_cmd(sock, _build_usbc(6, 0x80, 0xF6, 0x30, payload_size), 6, '0x30')
    total_len = struct.unpack('>I', r[2:6])[0]
    
    # Daten chunk-weise laden
    xml = b''
    offset = 0
    CHUNK = 4096
    while offset < total_len:
        size = min(CHUNK, total_len - offset)
        p = struct.pack('>IHH', prog_idx, offset, size)
        chunk = _send_cmd(sock, _build_usbc(size, 0x80, 0xF6, 0x31, p), size, '0x31')
        xml += chunk[2:2+size]
        offset += size
    return xml
```

### Schritt 3: Stream starten

```python
def start_stream(sock, prog_idx, output_path):
    """Vollständiger Tune + UDP-Empfang."""
    # 1. Kanal vorauswählen (0x03)
    p = struct.pack('>II', 0x00000002, prog_idx)
    _send_cmd(sock, _build_usbc(4, 0x00, 0xF6, 0x03, p), 0, '0x03')
    
    # 2. ch_Info abfragen (0x32 + 0x33)
    # ... (analog zu EPG)
    
    # 3. UDP-Socket öffnen (VOR Tune-Befehl!)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(('', 8800))
    udp.settimeout(5.0)
    
    # 4. Tune-Befehl (0x01)
    _send_cmd(sock, _build_usbc(2, 0x00, 0xF6, 0x01), 0, '0x01')
    
    # 5. Stream-Freigabe (0xF8/0x07)  
    _send_cmd(sock, _build_usbc(4, 0x00, 0xF8, 0x07), 0, '0xF8/0x07')
    
    # 6. Bestätigung (0x17 mit Flag=0x01)
    _send_cmd(sock, _build_usbc(4, 0x80, 0xF6, 0x17, b'\x01\x00\x00\x00'), 4, '0x17-confirm')
    
    # 7. UDP empfangen + in Datei schreiben
    with open(output_path, 'wb') as f:
        try:
            while True:
                data, _ = udp.recvfrom(65535)
                f.write(data)
        except KeyboardInterrupt:
            pass
    udp.close()
```

---

## 15. Offene Punkte (aktualisiert)

- [ ] **0xF8/0x07 genau verstehen** – Was steckt im 4-Byte-Payload? Ist es wirklich die Stream-Freigabe?
- [ ] **0x01 Payload analysieren** – `00 04` im CDB: Kanal-Nummer? Slot? Muss aus EPG abgeleitet werden
- [ ] **0x48-Flag im prog_idx** – Verschlüsselt? Braucht das spezielle Behandlung beim Tune?
- [ ] **MPEG-TS PID-Analyse** – Welche PIDs enthält der konkrete Stream? (Video/Audio/Subtitel)
- [ ] **Signal-Schwellwert für 0x02** – Ab welcher Signalqualität soll der Tune ausgelöst werden?
- [ ] **EPG-XML Vollformat** – Exaktes Schema aus PCAP extrahieren (Wireshark → Follow TCP Stream → Export)
- [ ] **Multicast vs. Unicast UDP** – Ist der UDP-Stream Unicast (an Client-IP) oder Multicast?
