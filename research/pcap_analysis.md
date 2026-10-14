# Merged protocol analysis aus pcap_analysis.md + or_s2d_protocol_analysis.md
MERGED_PROTOCOL = '''# OR S2D – Protokoll-Analyse & PCAP-Ergebnisse

> Zusammengeführt aus `pcap_analysis.md` und `or_s2d_protocol_analysis.md` (Oktober 2026).  
> Basis: `PCAPdroid_12_Okt._16_16_04.pcap` (Kanal-Liste) und `PCAPdroid_12_Okt._16_28_17.pcap` (Stream),  
> aufgezeichnet mit dem echten WISI OR S2D Dongle. Keine Hypothesen – ausschließlich PCAP-Fakten.

---

## Wichtigste Erkenntnis: OR S2D ≠ O2D

Der ältere Code war für den **WISI O2D / Tivizen / TiViCon** entwickelt.  
Der tatsächlich vorhandene Dongle ist ein **WISI OR S2D**. Obwohl das Protokoll dieselbe APIX-Basis verwendet, unterscheidet er sich in mehreren kritischen Punkten.

---

## 1. PCAP-Übersicht

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

## 2. USBC-Paketformat: 66 Byte (statt 31 Byte beim O2D)

Alle USBC-Befehle des OR S2D haben **66 Byte** (TCP und UDP):

```
[00:04]  USBC           – Signatur (4 B)
[04:08]  A0 CB 03 37    – Magic Tag (4 B, konstant)
[08:12]  data_len       – Datenlänge Big-Endian (4 B)
[12]     flags          – 0x80 = Lesen, 0x00 = Schreiben (1 B)
[13]     00             – LUN (1 B)
[14]     10             – CDB-Länge = 16 (1 B)
[15:31]  CDB            – 16 Byte: prefix(1) + APIX(4) + opcode(1) + payload(10)
──── Standard USBC CBW: 31 Byte ────────────────────────────────────────────────
[31:35]  00 00 00 01    – Protokoll-Marker (konstant)
[35:39]  07 20 21 00    – App-Version 7.32.33 (konstant je Firmware)
[39:41]  00 00          – Padding
[41:43]  session_token  – 2-Byte-Session-Token (aus 0x16-Antwort)
[43:51]  TV2Smart\0     – App-Identifier (8 Byte, null-terminiert)
[51:62]  00 × 11        – Padding
[62:66]  CRC (4 B)      – CRC32 unbekannter Algo; Dongle prüft es NICHT
──── Auth-Extension: 35 Byte ───────────────────────────────────────────────────
```

**Wichtig:** Der ältere O2D-Code sendete nur 31-Byte-Pakete. Der OR S2D akzeptiert diese  
für den Basis-Handshake (0x16/0x17), ignoriert aber Auth-lose Requests bei manchen Befehlen.

## 2a. USBS-Antwortformat: 46 Byte Trailer (statt 13 Byte beim O2D)

```
[0:4]    USBS           – Signatur
[4:8]    A0 CB 03 37    – Magic
[8:12]   00 00 00 00    – Status
[12]     40             – Flags
[13:15]  00 01          – ???
[15:19]  07 20 21 00    – Version (echoed)
[19:21]  00 00          – Padding
[21:23]  session_token  – Session-Token (echoed)
[23:31]  TV2Smart\0     – App-Name (echoed)
[31:42]  00 × 11        – Padding
[42:46]  CRC            – CRC (echoed)
```

---

## 3. Session-Token

Der 2-Byte Session-Token (z. B. `0x2794` in den PCAP-Traces) wird vom Dongle vergeben.  
Er steht in der ersten 0x16-Antwort im USBS-Trailer bei **Byte [21:23]** (Trailer-Offset).  
Derselbe Token wird in **jedem** nachfolgenden Befehl (TCP und UDP) im Auth-Feld [41:43] mitgeschickt  
und in jeder Antwort zurückgespiegelt.

---

## 4. Vollständige Opcode-Tabelle

### TCP-Kanal (Port 8802) – Steuerung

| Prefix | Opcode | Richtung | Funktion | Antwort |
|--------|--------|----------|----------|---------| 
| 0xF6 | 0x01 | C→D | **Kanal aktivieren** (Tune-Trigger) | `F6 01 USBS` |
| 0xF6 | 0x02 | C→D | **Signal-Status-Poll** (alle ~3 s) | 13 Byte: Byte[1]=Stärke%, Byte[2]=Qualität |
| 0xF6 | 0x03 | C→D | **Kanal vorauswählen** (prepare tune) | `F6 03 01 01 USBS` |
| 0xF6 | 0x16 | C→D | **Init / Keep-Alive** (alle ~2 s) | 12 Byte: `[0]=0x00/0x01` (bereit-Flag) |
| 0xF6 | 0x17 | C→D | **Init Phase 2 / Tune-Bestätigung** | 4 Byte: `0x00` oder `0x01` |
| 0xF6 | 0x20 | C→D | **ch_List-Größe abfragen** | 8 Byte: XML-Größe (BE uint32) |
| 0xF6 | 0x21 | C→D | **ch_List-XML abrufen** | `<ch_List>...</ch_List>` |
| 0xF6 | 0x22 | C→D | **ch_List Abschluss/Quittung** | – (ob nötig, unklar) |
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
| 0xF9 | 0x0A | C→D | **EPG/Metadaten per UDP anfordern** (200×, pre-tune) | 32.740 Byte `F9 0A 00...`; Zweck unklar |
| 0xF9 | 0x01 | C→D | **MPEG-TS-Block anfordern** (Pull) | 32.740 Byte echtes MPEG-TS (0x47-Sync) |

### Discovery-Prefix 0xFA

| Opcode | Antwort-Inhalt |
|--------|----------------|
| `0xFA/0x00` | Geräte-Info: Session-Token, Netzwerk-Config |
| `0xFA/0x07` | Modellname: `OR S2D` + Seriennummer |
| `0xFA/0x08` | Netzwerk-Konfiguration (IP, Subnetz, Gateway), 526 Byte |

---

## 5. Kanalliste: TCP statt UDP (wichtigste Abweichung vom O2D)

Beim O2D: Kanäle per UDP `0xF9/0x0A` als Binär-Blob.  
Beim OR S2D: Kanalliste **via TCP** als XML (`0xF6/0x20` + `0xF6/0x21`).

```xml
<ch_List>
  <ch type="TV" pol="H" sym="22000" s_id="28721" ts_id="1051"
       freq="10744" prog_idx="1083375616" lcn="69"
       s_name="tagesschau24" fta="1" />
  ...
</ch_List>
```

| Feld | Bedeutung |
|------|-----------|
| `s_id` | DVB Service-ID |
| `ts_id` | Transport-Stream-ID |
| `freq` | Frequenz in MHz |
| `pol` | Polarisation (`H`/`V`) |
| `sym` | Symbolrate in kSym/s |
| `prog_idx` | APIX-interner Kanal-Index (`0x40xxxxxx` FTA, `0x48xxxxxx` Pay-TV) |
| `lcn` | Logical Channel Number |
| `s_name` | Sendername |
| `fta` | Free-to-Air Flag |
| `type` | `TV` oder `RADIO` |

Im PCAP: **440 Kanäle** (303 TV, 137 Radio, 439 FTA). XML-Gesamtgröße: 61.348 Byte (0xEFA4).

**Konsequenz:** `0xF9/0x0A` liefert beim OR S2D keine Kanalliste. `fetch_service_db()` ist obsolet.

---

## 6. Init-Sequenz (bestätigt aus PCAP)

```
0x16 erste Antwort:  F6 16 00 04 FF 04 A5 2D ... (Status=0x00, noch nicht bereit)
0x17 erste Antwort:  F6 17 00 00 USBS
0x16 Folge-Antworten (alle ~2s): F6 16 01 04 FF 04 A5 2D ... (Status=0x01 = BEREIT)

Konstante Gerätekennzeichen: 04 FF 04 A5 2D (unveränderlich)
```

---

## 7. Signal-Status (0x02, bestätigt)

```
Antwort (5 Messungen):
  F6 02 00 64 3D 00 00 00 3C A0 00 00 00 USBS
              ──  ──
              │   └─ Signalqualität: variiert 0x3B–0x3D = 59–61
              └───── Signalstärke:   0x64 = 100 (= 100%)
```

---

## 8. Vollständiger Protokollablauf

```
Phase 1 – TCP-INIT
──────────────────
TCP connect :8802
→ 0xF6/0x16  ← Init (Status=0x00)
→ 0xF6/0x17  ← Init Phase 2 (0x00)
→ 0xF6/0x16 (wiederholen, alle ~2s) bis Status=0x01

Phase 2 – Kanalliste holen (TCP)
─────────────────────────────────
→ 0xF6/0x20  ← ch_List-Größe (8 Byte: XML-Größe)
→ 0xF6/0x21  ← ch_List-XML (440 Kanäle)
→ 0xF6/0x22  ← Abschluss (optional?)

Phase 3 – EPG (TCP, 252 Kanäle mit EPG-Daten)
──────────────────────────────────────────────
für jeden Kanal:
  → 0xF6/0x30 [prog_idx]  ← EPG-Größe
  → 0xF6/0x31 [prog_idx]  ← <epg_Data><ch ...><evt .../></ch></epg_Data>
einmalig:
  → 0xF6/0x35 / 0xF6/0x36  ← Ereignis-Detailbeschreibung
zwischendurch:
  → 0xF6/0x16  ← Keep-Alive (alle ~2s)

Phase 4 – UDP-Polling (parallel, t=5–30s)
──────────────────────────────────────────
→ 0xF9/0x02  ← Stream-Init (einmalig)
→ 0xF9/0x0A (×200)  ← EPG/Metadaten per UDP (Zweck noch unklar)

Phase 5 – Kanal vorbereiten (TCP)
──────────────────────────────────
→ 0xF6/0x03 [prog_idx, flag=2]  ← Kanal vorauswählen
← F6 03 01 01 USBS
→ 0xF6/0x32 / 0xF6/0x33 [prog_idx]  ← ch_Info: s_id + prog_idx bestätigen
→ 0xF6/0x02 (alle ~3s)  ← Signal pollen

Phase 6 – Tune + Stream (TCP + UDP)
────────────────────────────────────
→ 0xF6/0x01 [00 04]  ← Kanal aktivieren (Index in PAT-Liste, nicht s_id)
→ 0xF8/0x07  ← Stream-Freigabe
→ 0xF9/0x01 [byte21=0x00]  ← Erster MPEG-TS-Block (Pull)
← 32.740 Byte MPEG-TS (174 × 188 Byte TS-Pakete)
→ 0xF6/0x17 [01 00 00 00]  ← Kanalwechsel bestätigen
→ 0xF9/0x01 [byte21=0x01]  ← Weitere Blöcke (Pull-Loop)
→ 0xF6/0x16 (alle ~2s)  ← TCP Keep-Alive während Stream
```

---

## 9. MPEG-TS Stream-Inhalt (Programm 4914)

```
PAT: 22 Programme auf ts_id=33079
PMT Prog 4914 (PID 0x006E):
  PID 0x1338  H.264 Video     (94% aller TS-Pakete)
  PID 0x1339  MPEG-1 Audio 1
  PID 0x133A  MPEG-1 Audio 2
  PID 0x133E  Private Data (Teletext?)
```

**0x01 Payload `00 04`:** Byte[1]=`0x04` ist wahrscheinlich der Index in der PAT-Liste  
(PAT: Prog 0, 4911, 4912, 4913, **4914** → Index 4 ✓). Nicht die s_id (4914 = 0x1332 ≠ `00 04`).

---

## 10. EPG-Format

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

---

## 11. prog_idx-Struktur

```
0x40xxxxxx  → normaler (FTA) Kanal
0x48xxxxxx  → verschlüsselter Kanal (Pay-TV / CA)
Byte[1..2]  → Transponder-Gruppe (0xB4, 0xB7, 0xDE ...)
Byte[3]     → Sequenz-Nummer innerhalb des Transponders

Alle EPG-ts_ids = 33079 (Transponder Astra 19.2°E)
```

---

## 12. O2D vs. OR S2D – Vergleich

| Merkmal | O2D / Tivizen | OR S2D |
|---------|--------------|--------|
| USBC-Paketgröße | 31 Byte | 66 Byte (+ Auth-Extension) |
| USBS-Trailer | 13 Byte | 46 Byte |
| Auth-Token | keiner | 2-Byte Session-Token + TV2Smart |
| Kanalliste | UDP 0xF9/0x0A Binär | TCP 0xF6/0x20+0x21 XML |
| Discovery-Prefix | nicht vorhanden | 0xFA |
| Tune-Befehl | 0xF6/0x01 | 0xF6/0x01 (gleich) |
| Stream-Freigabe | 0xF8/0x07 | 0xF8/0x07 (gleich) |
| UDP-Stream | 0xF9/0x01 Pull | 0xF9/0x01 Pull (gleich) |
| Kanäle | 252 (EPG-basiert) | 440 (XML ch_List) |

---

## 13. Offene Punkte

| Priorität | Thema | Hinweis |
|-----------|-------|---------|
| 🔴 1 | Session-Token: robuste Extraktion aus USBS-Trailer | Offset [21:23] im Trailer; alternativ `0xFA/0x00` nutzen |
| 🔴 2 | CRC-Algorithmus | Unbekannt; Dongle prüft es scheinbar nicht → Nullbytes senden |
| 🟡 3 | `0xF9/0x0A` × 200: Zweck klären | Evtl. EPG-Poll oder Scan-Trigger; neues Scan-PCAP nötig |
| 🟡 4 | Kanalwechsel testen | `0xF6/0x01` mit anderem PAT-Index; braucht laufenden Stream |
| 🟡 5 | `0xF6/0x22` Abschluss nach ch_List | Ob nötig oder optional, ist unklar |
| 🟢 6 | Pay-TV / verschlüsselte Kanäle | `0x48`-Prefix = encrypted; CA-Handling fehlt |
'''

# APK RE mit .txt-Inhalt vorne
APK_HEADER = '''# APK-Reverse-Engineering: TV2Smart (com.tivicon.tv2smart.mobile)

> Version: 3.M20260803.0-rev-a14aeb377  
> Analysiert: Oktober 2026  
> Quelle: TV2Smart_3_M20260803_0-rev-a14aeb377_APKPure.xapk  
> Methode: strings auf DEX + .so Bibliotheken

---

## 0. APK-Metadaten (CODECS.COM-Scan, 14.10.2026)

| Eigenschaft | Wert |
|---|---|
| Package | `com.tivicon.tv2smart.mobile` |
| Version | `3.M20260803.0-rev-a14aeb377` (code 202608030) |
| Min Android | Android 8.0 (API 26) |
| Target | API 36 |
| Google Play required | Nein (keine Play-Lizenzprüfung) |
| Signatur | v2/v3 |

**Berechtigungen (23):** FOREGROUND_SERVICE_MEDIA_PLAYBACK, INTERNET, ACCESS_NETWORK_STATE, READ/WRITE_EXTERNAL_STORAGE, REORDER_TASKS, WAKE_LOCK, WRITE_SYNC_SETTINGS, ACCESS_FINE_LOCATION, RECORD_AUDIO, READ_PHONE_STATE, FOREGROUND_SERVICE, USB_PERMISSION, FOREGROUND_SERVICE_CONNECTED_DEVICE, TRANSMIT_IR, ACCESS_WIFI_STATE, CHANGE_WIFI_MULTICAST_STATE, SYSTEM_ALERT_WINDOW, READ_LOGS, WRITE_EPG_DATA, READ_EPG_DATA, DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION

---

'''
