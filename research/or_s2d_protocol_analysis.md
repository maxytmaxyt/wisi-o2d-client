# OR S2D Protokoll-Analyse (Oktober 2026)

> Ergebnis der PCAP-Analyse von `PCAPdroid_12_Okt._16_16_04.pcap` (Kanal-Liste) und  
> `PCAPdroid_12_Okt._16_28_17.pcap` (Stream), aufgezeichnet mit dem echten WISI OR S2D Dongle.

---

## Wichtigste Erkenntnis: OR S2D ≠ O2D

Der in der Repo enthaltene ältere Code war für den **WISI O2D / Tivizen / TiViCon** entwickelt.  
Der tatsächlich vorhandene Dongle ist ein **WISI OR S2D** (auch „TiViCon OR S2D"). Obwohl das Protokoll dieselbe APIX-Basis verwendet, unterscheidet es sich in mehreren kritischen Punkten.

---

## 1. Frühere Hypothese: USBC mit 66 Byte (nicht bestätigt)

Die ältere Auswertung nahm an, dass OR-S2D-USBC-Befehle generell **66 Byte** lang sind. Die erneute Prüfung der enthaltenen PCAPs zeigt für erkannte APIX-Requests 31-Byte-USBC-Payloads; das generische APK-SDK baut ebenfalls 31 Byte. Die folgende Erweiterungsbelegung ist daher nicht als bestätigter Standard zu lesen:

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

Die beigelegten Mitschnitte zeigen keine 35-Byte-Auth-Erweiterung. Dass einzelne andere Firmware- oder Transportpfade sie verwenden oder benötigen könnten, ist mit diesen Artefakten nicht belegt.

---

## 2. Frühere Hypothese: USBS-Trailer mit 46 Byte (nicht bestätigt)

Die ältere Analyse nahm einen **46-Byte-USBS-Trailer** an, der die Auth-Erweiterung zurückspiegele. In den untersuchten PCAPs enden erkannte Antworten dagegen mit 13 Byte `USBS`; der generische APK-SDK-Transport verwendet ebenfalls einen 13-Byte-Abschluss. Der folgende 46-Byte-Aufbau ist nicht durch die enthaltenen Artefakte bestätigt:

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

## 3. Session-Token: in aktuellen Artefakten nicht bestätigt

Die frühere Zuordnung eines 2-Byte-Tokens auf Offset `[21:23]` hängt von der unbestätigten 46-Byte-Trailerhypothese ab. Die beobachteten 13-Byte-`USBS`-Suffixe enthalten dieses Feld nicht; der generische APK-Builder serialisiert ebenfalls keinen Token. Für die hier belegte 31/13-Byte-Variante deshalb keinen Token-Offset voraussetzen.

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

## 5. `0xF9/0x0A`: Speedtest statt bestätigter Senderliste

Die statische Analyse der hochgeladenen TV2Smart-XAPK zeigt einen konkreten Einsatz von `0xF9/0x0A` in `getSpeedTestMbps()`:

- Der APK-Builder erzeugt einen **31-Byte-USBC-Request** mit `data_len=48.128`, Prefix `0xF9` und Opcode `0x0A`.
- Der Speedtest fordert 48.130 Datenbytes an, zählt erfolgreiche Antworten und berechnet den Durchsatz mit 48.128 Byte pro Antwort.
- Der Netzwerkempfänger liest bei dieser Antwortlänge 13 weitere Abschlussbytes. `48.130 + 13 = 48.143`, exakt die am 13. Oktober protokollierte Gesamtlänge.
- Damit ist die 48.143-Byte-Antwort sehr wahrscheinlich ein Speedtest-Block und keine Senderdatenbank. Der APK-Code prüft oder dekodiert die Daten nicht als Senderliste.

Der Rohblob vom 13. Oktober liegt weiterhin nicht vor; Füllbytes und Abschluss wurden daher nicht bytegenau kontrolliert. Die älteren PCAP-Antworten mit 32.740 Byte sind eine andere beobachtete Größe und bleiben davon getrennt. Die PCAPs vom 12. Oktober zeigen außerdem kurze 13-Byte-`USBS`-Antworten.

**Konsequenz:** `fetch_service_db()` via `0xF9/0x0A` ist für den OR-S2D-Kanallistenpfad ungeeignet. Die Kanalliste wird im PCAP über TCP `0xF6/0x20` + `0xF6/0x21` als XML übertragen.

---

## 6. Discovery-Befehle (Prefix 0xFA)

Der OR S2D hat einen separaten Discovery-Mechanismus mit Prefix **0xFA**:

| Opcode       | Antwort-Inhalt                                              |
|--------------|-------------------------------------------------------------|
| `0xFA/0x00`  | Geräte-Info: Session-Token, Netzwerk-Config, MAC-Ableitung |
| `0xFA/0x07`  | Modellname: `OR S2D` + Seriennummer                        |
| `0xFA/0x08`  | Netzwerk-Konfiguration (IP, Subnetz, Gateway), 526 Byte    |

Beispiel `0xFA/0x07`-Antwort: `fa 07 01 4f 52 20 53 32 44 ...` → `"OR S2D"` ab Byte 3.

Diese Befehle sind für den normalen Stream-Betrieb nicht nötig, aber nützlich zur Geräte-Identifikation. Eine Session-Token-Initialisierung über `0xFA/0x00` ist mit den aktuell geprüften APK-/PCAP-Artefakten nicht bestätigt.

---

## 7. Tune-Ablauf (bestätigt)

Der folgende Tune-Ablauf ist im OR-S2D-PCAP beobachtet. Die dort erkannten `USBC`-Requests sind 31 Byte; eine pauschale 66-Byte-Erweiterung ist nicht belegt:

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
| 🔴 1      | Session-Token/Auth-Feld anderer Varianten         | Für die 31-Byte-Requests und 13-Byte-Suffixe in APK/PCAP nicht belegt; abweichende Firmwarepfade offen |
| 🔴 2      | CRC-Algorithmus                                   | Unbekannt; Dongle prüft es scheinbar nicht → Nullbytes senden |
| 🟡 3      | `0xF9/0x0A`-Antwortbytes vergleichen              | Speedtest-Rolle ist im APK-Code belegt; die abweichenden 32.740-Byte-PCAP-Antworten sind bytegenau noch nicht zugeordnet |
| 🟡 4      | Kanalwechsel testen                               | `0xF6/0x01` mit anderem PAT-Index; braucht laufenden Stream |
| 🟡 5      | `0xF6/0x22` Abschluss nach ch_List               | Ob nötig oder optional, ist unklar |
| 🟢 6      | `0xFA/0x00`-Antwortstruktur weiter verifizieren  | Geräteinfo beobachtet; Session-Token-Bedeutung nicht bestätigt |
| 🟢 7      | Pay-TV / verschlüsselte Kanäle                    | `prog_idx` mit `0x48`-Prefix = encrypted; CA-Handling fehlt |

---

## 10. Korrigierter Vergleich O2D vs. OR S2D

| Merkmal                  | O2D / Tivizen       | OR S2D                          |
|--------------------------|---------------------|----------------------------------|
| USBC-Paketgröße          | 31 Byte             | 31 Byte in APK/PCAP; 66 Byte nicht bestätigt |
| USBS-Trailer             | 13 Byte             | 13 Byte in den untersuchten PCAPs |
| Auth-Token               | keiner              | Für die untersuchte 31/13-Byte-Variante nicht belegt |
| Kanalliste               | UDP 0xF9/0x0A Binär | TCP 0xF6/0x20+0x21 XML           |
| EPG                      | TCP 0x30/0x31       | vermutlich gleich (nicht getestet)|
| Discovery-Prefix         | nicht vorhanden     | 0xFA                             |
| Tune-Befehl              | 0xF6/0x01           | 0xF6/0x01 (gleich)              |
| Stream-Freigabe          | 0xF8/0x07           | 0xF8/0x07 (gleich)              |
| UDP-Stream               | 0xF9/0x01 Pull      | 0xF9/0x01 Pull (gleich)         |
| Kanäle im PCAP           | 252 (EPG-basiert)   | 440 (XML ch_List)                |
