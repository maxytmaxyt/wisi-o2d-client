# OR S2D Protokoll-Analyse (Oktober 2026)

> Ergebnis der PCAP-Analyse von `PCAPdroid_12_Okt._16_16_04.pcap` (Kanal-Liste) und  
> `PCAPdroid_12_Okt._16_28_17.pcap` (Stream), aufgezeichnet mit dem echten WISI OR S2D Dongle.

---

## Wichtigste Erkenntnis: OR S2D ≠ O2D

Der in der Repo enthaltene ältere Code war für den **WISI O2D / Tivizen / TiViCon** entwickelt.  
Der tatsächlich vorhandene Dongle ist ein **WISI OR S2D** (auch „TiViCon OR S2D"). Obwohl das Protokoll dieselbe APIX-Basis verwendet, unterscheidet es sich in mehreren kritischen Punkten.

---

## 1. USBC-Paketformat: 66 Byte statt 31 Byte

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

---

## 2. USBS-Antwortformat: 46 Byte Trailer (statt 13 Byte beim O2D)

Jede Antwort des OR S2D endet mit einem **46-Byte-USBS-Trailer**, der die Auth-Extension zurückspiegelt:

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
Er steht in der ersten 0x16-Antwort im USBS-Trailer bei **Byte [21:23]** (= Trailer-Offset, nicht absolut).

Derselbe Token wird in **jedem** nachfolgenden Befehl (TCP und UDP) im Auth-Feld [41:43] mitgeschickt  
und in jeder Antwort zurückgespiegelt.

**Praxis:** Den Token aus dem ersten vollständigen USBS-Trailer extrahieren, danach für alle Befehle nutzen.

---

## 4. Kanalliste: TCP statt UDP

Beim O2D wurden Kanäle per UDP 0xF9/0x0A als Binär-Blob übertragen.  
Beim OR S2D kommt die Kanalliste **via TCP** als XML:

| Opcode       | Richtung | Bedeutung                                      |
|--------------|----------|------------------------------------------------|
| `0xF6/0x20`  | PC→Dongle | ch_List-Größe abfragen (data_len=8)           |
|              | Dongle→PC | 8 Byte: `[0:4]` = XML-Größe (BE uint32)      |
| `0xF6/0x21`  | PC→Dongle | ch_List-Daten abrufen (data_len = aus 0x20)   |
|              | Dongle→PC | XML-Daten `<ch_List>...</ch_List>`            |
| `0xF6/0x22`  | PC→Dongle | Abschluss/Quittung (data_len=8)               |

Das XML-Format:

```xml
<ch_List>
  <ch type="TV" pol="H" sym="22000" s_id="28721" ts_id="1051"
       freq="10744" prog_idx="1083375616" lcn="69"
       s_name="tagesschau24" fta="1" />
  ...
</ch_List>
```

Felder:
- `s_id` – DVB Service-ID
- `ts_id` – Transport-Stream-ID
- `freq` – Frequenz in MHz
- `pol` – Polarisation (`H`/`V`)
- `sym` – Symbolrate in kSym/s
- `prog_idx` – APIX-interner Kanal-Index (FTA: `0x40xxxxxx`, Pay-TV: `0x48xxxxxx`)
- `lcn` – Logical Channel Number (Sendernummer)
- `s_name` – Sendername
- `fta` – Free-to-Air Flag (`1`/`0`)
- `type` – `TV` oder `RADIO`

Im PCAP wurden **440 Kanäle** gefunden (303 TV, 137 Radio, 439 FTA).  
XML-Gesamtgröße: **61.348 Byte** (0xEFA4).

---

## 5. 0xF9/0x0A: Wird beim OR S2D ANDERS verwendet

Beim O2D lieferte `0xF9/0x0A` die Kanalliste als Binär-Blob via UDP.  
Beim OR S2D sendet der Client ebenfalls `0xF9/0x0A` (200×), aber:

- Das Request-Format ist **66 Byte** (mit Auth-Extension und `TV2Smart`-String)
- Die Antwort kommt als **USBS-Ack** (46 B) zurück, kein Kanal-Blob
- Wozu diese 200 Requests dienen, ist noch **unklar** (evtl. EPG-Polling oder Keepalive)
- Die Kanalliste wird **nicht** dadurch übertragen → unser alter Parser produziert zu Recht 0 Einträge

**Konsequenz:** `fetch_service_db()` via `0xF9/0x0A` ist beim OR S2D obsolet.  
Die Kanalliste muss via `0xF6/0x20` + `0xF6/0x21` (TCP) geholt werden.

---

## 6. Discovery-Befehle (Prefix 0xFA)

Der OR S2D hat einen separaten Discovery-Mechanismus mit Prefix **0xFA**:

| Opcode       | Antwort-Inhalt                                              |
|--------------|-------------------------------------------------------------|
| `0xFA/0x00`  | Geräte-Info: Session-Token, Netzwerk-Config, MAC-Ableitung |
| `0xFA/0x07`  | Modellname: `OR S2D` + Seriennummer                        |
| `0xFA/0x08`  | Netzwerk-Konfiguration (IP, Subnetz, Gateway), 526 Byte    |

Beispiel `0xFA/0x07`-Antwort: `fa 07 01 4f 52 20 53 32 44 ...` → `"OR S2D"` ab Byte 3.

Diese Befehle sind für den normalen Stream-Betrieb nicht nötig, aber nützlich zur  
Geräte-Identifikation und zur Session-Token-Initialisierung.

---

## 7. Tune-Ablauf (bestätigt)

Der Tune-Ablauf ist beim OR S2D identisch zum O2D, nur mit 66-Byte-Paketen:

```
1. 0xF6/0x03  – Kanal vorbereiten (prog_idx)
2. 0xF6/0x32  – ch_Info-Größe abfragen
3. 0xF6/0x33  – ch_Info-Daten abrufen (<ch_Info> XML)
4. 0xF6/0x02  – Signal pollen (Stärke + Qualität), Polling 3×
5. 0xF6/0x01  – Kanal aktivieren: payload = [0x00, pat_index]
6. 0xF8/0x07  – Stream-Freigabe
7. 0xF9/0x01  – UDP-Block anfordern (Pull, first=True: byte21=0x00)
8. 0xF6/0x17  – Tune bestätigen: payload = [0x01, 0x00, 0x00, 0x00]
9. 0xF9/0x01  – weitere UDP-Blöcke (Pull-Loop, byte21=0x01)
```

Der PAT-Index in Schritt 5 entspricht der Position in der nach LCN sortierten Kanalliste  
(nicht dem prog_idx!). Im PCAP wurde PAT-Index `0x04` für das erste gestreamte Programm gesehen.

---

## 8. UDP-Stream-Format

Unverändert gegenüber O2D:

- UDP-Port 8800, pull-basiert (Client fordert jeden Block aktiv an)
- Jeder UDP-Block: bis zu 32.740 Byte MPEG-TS
- MPEG-TS-Sync (`0x47`) suchen, ausrichten auf 188-Byte-Paketgrenzen
- Header am Anfang jedes Blocks verwerfen (Größe variiert; TS-Sync-Suche robuster)

---

## 9. Bekannte Lücken / Offene Punkte

| Priorität | Thema                                             | Hinweis |
|-----------|---------------------------------------------------|---------|
| 🔴 1      | Session-Token: genaue Position im USBS-Trailer    | Aus PCAP bei Byte [21:23] des Trailers, aber per Offset im TCP-Stream unterschiedlich – robuste Extraktion nötig |
| 🔴 2      | CRC-Algorithmus                                   | Unbekannt; Dongle prüft es scheinbar nicht → Nullbytes senden |
| 🟡 3      | `0xF9/0x0A` × 200: Zweck klären                  | Evtl. EPG-Poll oder Scan-Trigger; neues PCAP nach Sendersuchlauf nötig |
| 🟡 4      | Kanalwechsel testen                               | `0xF6/0x01` mit anderem PAT-Index; braucht laufenden Stream |
| 🟡 5      | `0xF6/0x22` Abschluss nach ch_List               | Ob nötig oder optional, ist unklar |
| 🟢 6      | `0xFA/0x00` für Session-Token nutzen             | Robustere Alternative zur Extraktion aus USBS-Trailer |
| 🟢 7      | Pay-TV / verschlüsselte Kanäle                    | `prog_idx` mit `0x48`-Prefix = encrypted; CA-Handling fehlt |

---

## 10. Korrigierter Vergleich O2D vs. OR S2D

| Merkmal                  | O2D / Tivizen       | OR S2D                          |
|--------------------------|---------------------|----------------------------------|
| USBC-Paketgröße          | 31 Byte             | 66 Byte (+ Auth-Extension)       |
| USBS-Trailer             | 13 Byte             | 46 Byte                          |
| Auth-Token               | keiner              | 2-Byte Session-Token + TV2Smart  |
| Kanalliste               | UDP 0xF9/0x0A Binär | TCP 0xF6/0x20+0x21 XML           |
| EPG                      | TCP 0x30/0x31       | vermutlich gleich (nicht getestet)|
| Discovery-Prefix         | nicht vorhanden     | 0xFA                             |
| Tune-Befehl              | 0xF6/0x01           | 0xF6/0x01 (gleich)              |
| Stream-Freigabe          | 0xF8/0x07           | 0xF8/0x07 (gleich)              |
| UDP-Stream               | 0xF9/0x01 Pull      | 0xF9/0x01 Pull (gleich)         |
| Kanäle im PCAP           | 252 (EPG-basiert)   | 440 (XML ch_List)                |
