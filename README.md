# WISI OR S2D – DVB-over-IP Reverse Engineering & Client

Python-Client und Protokollanalyse für den **WISI OR S2D** (DVB-S2-Free-to-Air-Satelliten-Dongle) auf Basis eigener PCAP-Mitschnitte und der Analyse der TV2Smart-App.

> **Modell korrekt unterscheiden:** Dieses Repository beschreibt den WISI **OR S2D**. Ältere Notizen und Codeversionen verwenden teilweise „O2D“, „Tivizen“ oder „TiViCon“ als Sammelbezeichnung. Die Modelle verwenden zwar APIX-Grundframes ähnlicher Länge, aber Kommandobedeutungen und Abläufe dürfen nicht ungeprüft übertragen werden.

**Stand der Dokumentation: 14. Oktober 2026.** Das Protokoll ist teilweise aus Mitschnitten abgeleitet. Ein beobachteter App-Ablauf ist nicht automatisch ein unabhängig funktionierender Client-Ablauf; die offenen Punkte und Implementierungsgrenzen sind unten dokumentiert.

## Aktueller Stand auf einen Blick

- **Kanalliste:** Im OR-S2D-Mitschnitt wurde eine XML-Kanalliste über TCP mit `0xF6/0x20` (Länge) und `0xF6/0x21` (Daten) beobachtet. Die analysierte Liste enthält **440 Sender: 303 TV, 137 Radio, 439 als FTA markiert**. Die XML-Antwort ist 61.348 Byte groß.
- **USBC-Anfragen:** Der APK-Builder und die APIX-Requests in den vorhandenen Mitschnitten verwenden 31-Byte-CBWs. Eine 35-Byte-Auth-Erweiterung ist in diesen Artefakten nicht belegt.
- **USBS-Antworten:** Die untersuchten TCP- und UDP-Antworten enden mit einem 13-Byte-`USBS`-Suffix. Ein 46-Byte-Trailer ist in den enthaltenen Artefakten nicht bestätigt.
- **Stream:** Der Ablauf `0xF6/0x03` → `0xF6/0x01` → `0xF8/0x07` → UDP-Pulls mit `0xF9/0x01` ist im Stream-Mitschnitt zu sehen. Die Pull-Anfragen holen jeweils einen MPEG-TS-Block ab.
- **`0xF9/0x0A`:** Im hochgeladenen TV2Smart-APK-SDK als Speedtest belegt, nicht als Senderliste. Der APK-Code fordert 48.128 Testbytes an; 48.130 Datenbytes plus 13 Abschlussbytes ergeben exakt die gemeldeten 48.143 Byte. Die 32.740-Byte-PCAP-Antworten vom 11. Oktober bleiben ein getrenntes, nicht bytegenau erklärtes Muster.
- **Status:** Analyse und Client-Code sind vorhanden, aber nicht jede Funktion ist live gegen das Gerät erfolgreich end-to-end verifiziert. Offene Punkte und Implementierungsgrenzen stehen unter [Offene Punkte](#offene-punkte--bekannte-einschränkungen).

Die Detailauswertung und eine Einordnung der Forschungsnotizen stehen in [research/README.md](research/README.md).

## Voraussetzungen und Installation

- Python **3.10 oder neuer**
- Für die Protokollanalyse und den Client werden keine zusätzlichen Python-Laufzeitpakete benötigt.
- VLC ist optional, wenn ein erzeugter MPEG-TS-Stream abgespielt werden soll.

```bash
python -m venv .venv
```

Linux/macOS:

```bash
source .venv/bin/activate
python -m pip install -e .
```

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
```

Nach der Installation ist der CLI-Einstieg `wisi` verfügbar. Ohne Installation können die folgenden Beispiele direkt mit `python src/wisi.py` ausgeführt werden.

## Tests

```bash
python -m unittest discover -s tests -v
```

## Schnellstart

Zuerst die Hilfe ansehen:

```bash
python src/wisi.py --help
```

Die bisherige Standard-IP in den Beispielen lautet `192.168.178.32`. Ersetze sie durch die IP-Adresse deines Dongles.

### Kanalliste laden

```bash
python src/wisi.py --ip 192.168.178.32 --channels
```

Der aktuelle Pfad initialisiert TCP `8802` und fragt die XML-Kanalliste über `0xF6/0x20` und `0xF6/0x21` ab. Dieser Clientpfad ist weiterhin nicht end-to-end live verifiziert; offene Framing- und Laufzeitfragen stehen unten.

### Streamversuch starten

```bash
python src/wisi.py --ip 192.168.178.32 --stream --pat-idx 4 --duration 60 --output stream.ts
```

`--duration 0` bedeutet unbegrenzte Laufzeit. Der Index `4` stammt aus dem aufgezeichneten Beispielablauf und ist **kein universell gültiger Senderindex**. Bei der Aufnahme entsprach er dem gestreamten Programm 4914; vor dem Test sollte die Kanalliste geprüft werden.

Ein erzeugtes File kann danach beispielsweise mit VLC geöffnet werden:

```bash
vlc stream.ts
```

Direkte Ausgabe an VLC ist ebenfalls vorgesehen, sollte aber erst nach erfolgreichem lokalem Stream-Test verwendet werden:

```bash
python src/wisi.py --ip 192.168.178.32 --stream --pat-idx 4 --output - | vlc -
```

### PCAP untersuchen

```bash
python src/wisi.py --pcap "PCAPdroid_12_Okt._16_16_04.pcap"
python src/wisi.py --pcap "PCAPdroid_12_Okt._16_28_17.pcap"
```

Eine ältere `0xF9/0x0A`-Antwort kann für die Untersuchung unverändert extrahiert werden:

```bash
python src/wisi.py --pcap "research/capture_pcapdroid_2026-10-11.pcap" --pcap-extract service-db.bin
python src/wisi.py --decode-service-db service-db.bin
```

Der Service-DB-Decoder ist ein **Legacy-Werkzeug**. Beim bisherigen Mitschnitt konnte er daraus keine bestätigten Sender-Einträge gewinnen; ein Fehler oder null Einträge bedeuten nicht, dass keine Senderliste am Gerät vorhanden ist.

### Weitere CLI-Optionen

| Aufruf | Zweck | Status |
|---|---|---|
| `--channels` | Kanalliste vom Gerät anzeigen | Implementiert; Live-Ablauf weiter validieren |
| `--stream --pat-idx N --output DATEI` | Streamversuch und MPEG-TS-Ausgabe | Implementiert; Index und Live-Daten prüfen |
| `--epg --epg-output epg.json` | EPG-Daten als JSON anfordern | Im aktuellen Stand **nicht end-to-end verifiziert**; siehe unten |
| `--discover` | TV2S-JSON-UDP-Discovery versuchen | Experimentell, nicht durch die Mitschnitte als gültiges Discovery-Verfahren bestätigt |
| `--probe-opcode 0xNN` | Einen einzelnen Opcode testen | Experimentell; kann den Gerätezustand beeinflussen |
| `--pcap DATEI` | APIX-Befehle und erkannte Service-DB-Antworten zählen | Analysewerkzeug, kein vollständiger TCP-Reassembler |
| `--decode-service-db DATEI` | Legacy-UDP-Service-DB-Blob parsen | Für OR S2D derzeit nicht als verlässlich bestätigt |
| `--debug` | Debug-Ausgaben aktivieren | Für die unterstützten CLI-Aktionen |

Unbekannte Opcodes nicht in einer automatisierten Schleife durchprobieren. Für Tests möglichst einen kontrollierten Mitschnitt anfertigen und nur einzelne, bewusst gewählte Befehle senden.

## Neue Erkenntnisse aus den Mitschnitten

Die aktuellen OR-S2D-Erkenntnisse stammen vor allem aus den beiden Mitschnitten vom 12. Oktober 2026 und den vorangegangenen Analyseaufzeichnungen in `research/`.

### 1. Request-Framing in APK und Mitschnitten

Der generische Builder im hochgeladenen APK-SDK und die `USBC`-Requests in den enthaltenen APIX-Mitschnitten verwenden diesen 31-Byte-CBW:

| Offset | Länge | Inhalt |
|---|---:|---|
| `0–30` | 31 Byte | USBC-CBW: `USBC`, Magic `A0 CB 03 37`, Datenlänge, Flags, LUN, CDB-Länge und APIX-CDB |
| `15` | 1 Byte | APIX-Prefix |
| `16–19` | 4 Byte | `APIX` |
| `20` | 1 Byte | Opcode |
| `21–30` | 10 Byte | CDB-Payload/Padding |

Die früher in den Notizen beschriebene 35-Byte-Erweiterung mit Session-Token, App-Kennung und CRC ist in den vorhandenen PCAPs und im generischen APK-Builder nicht enthalten. Auch ein Session-Token in einem 46-Byte-`USBS`-Trailer ist damit nicht bestätigt. Der Client sendet jetzt den belegten 31-Byte-CBW und liest ein 13-Byte-Antwortsuffix; TCP bleibt dennoch ein Bytestrom ohne Anwendungsnachrichtengrenzen.

### 2. Kanalliste über TCP statt `0xF9/0x0A`

Im Mitschnitt mit der Kanallisten-Aktion wurden `0xF6/0x20`, `0xF6/0x21` und `0xF6/0x22` beobachtet:

1. `0xF6/0x20` fragt die Größe von `<ch_List>` ab. Die Antwort enthält die XML-Länge als Big-Endian-Integer.
2. `0xF6/0x21` fordert die XML-Nutzdaten an.
3. `0xF6/0x22` folgt im Mitschnitt als Abschluss-/Quittungs-Kommando; ob es immer notwendig ist, ist noch offen.

Ein ausgewerteter XML-Datensatz umfasst 440 Kanäle (303 TV, 137 Radio, 439 `fta=1`) und 61.348 Byte. Typische Felder sind `s_id`, `ts_id`, `freq`, `pol`, `sym`, `prog_idx`, `lcn`, `s_name`, `fta` und `type`.

### 3. `0xF9/0x0A` ist keine bestätigte Kanalliste

`0xF9/0x0A` taucht in mehreren Aufzeichnungen auf. Die statische APK-Analyse ordnet den Befehl dem Speedtest zu: `getSpeedTestMbps()` sendet den Request mit `data_len=48.128`, verwendet die Antworten nur für eine Durchsatzberechnung und erwartet 48.130 Datenbytes plus 13 Abschlussbytes. Das erklärt die am 13. Oktober gemeldeten 48.143 Byte, nicht aber die abweichenden 32.740-Byte-Antworten im PCAP vom 11. Oktober. In den Mitschnitten vom 12. Oktober wird die Kanalliste separat über TCP übertragen.

Daher gilt:

- Der frühere Ansatz „`0xF9/0x0A` = Senderdatenbank“ ist für den OR S2D nicht belegt; im APK ist es ein Speedtest.
- Die Füllbytes der 48.143-Byte-Antwort und die abweichenden 32.740-Byte-Antworten sind ohne Rohdaten nicht vollständig erklärt.
- `fetch_service_db()` in `src/wisi_client.py` ist beim OR S2D ausdrücklich ein veralteter Kompatibilitätspfad und liefert keine Senderliste.

### 4. Streamablauf und MPEG-TS

Der Stream-Mitschnitt enthält unter anderem folgende Sequenz:

1. TCP-Initialisierung über `0xF6/0x16` und `0xF6/0x17`; `0x16` zeigt zunächst `0x00` und später `0x01` als Bereitschaftsstatus.
2. Kanalvorbereitung über `0xF6/0x03`, gefolgt von `0xF6/0x32`/`0xF6/0x33` für `ch_Info`.
3. Signalabfragen über `0xF6/0x02`.
4. Tune-Befehl `0xF6/0x01`; im konkreten Mitschnitt war die Payload `00 04`.
5. Stream-Freigabe `0xF8/0x07`.
6. Wiederholte UDP-Pulls über `0xF9/0x01`.

Die UDP-Antwort kann 32.740 Byte umfassen. Davon sind 32.712 Byte genau **174 MPEG-TS-Pakete à 188 Byte**; der verbleibende Teil ist nicht als MPEG-TS zu behandeln. Der Code sucht nach dem `0x47`-Sync-Byte und richtet den Datenstrom anhand der 188-Byte-Paketgrenze aus.

Im Beispielstrom wurde in der PAT das Programm 4914 auf Index 4 beobachtet. Dessen PMT beschreibt Video-PID `0x1338` (H.264), Audio-PIDs `0x1339` und `0x133A` (MPEG-1 Audio) sowie PID `0x133E` für private Daten (Teletext ist eine Vermutung). Der einzelne Mitschnitt belegt nicht, dass Index 4 auf jeder Senderliste dasselbe Programm auswählt.

### 5. EPG und zusätzliche Opcodes

Im älteren Mitschnitt vom 11. Oktober sind `0xF6/0x30` und `0xF6/0x31` für EPG-Länge und EPG-Daten sowie `0xF6/0x35` und `0xF6/0x36` für Ereignisbeschreibungen zu sehen. Der Mitschnitt enthält 252 `0xF6/0x31`-Anfragen. Das stützt die beobachtete EPG-Sequenz, ist aber kein Beleg dafür, dass der gegenwärtige `--epg`-Aufruf als eigenständiger Client schon korrekt funktioniert.

In den neueren Mitschnitten treten außerdem `0xFA/0x00`, `0xFA/0x07` und `0xFA/0x08` auf. Die Bedeutungen sind in `research/or_s2d_protocol_analysis.md` anhand der beobachteten Antworten beschrieben. Nicht damit verwechseln: `src/wisi_discovery.py` implementiert derzeit einen **separaten, experimentellen TV2S-JSON-UDP-Broadcast**. Die Gültigkeit dieses JSON-Formats wurde durch die vorliegenden Mitschnitte nicht bestätigt.

## Protokoll-Kurzreferenz

| Kanal | Prefix/Opcode | Beobachtete Funktion | Sicherheit der Aussage |
|---|---|---|---|
| TCP `8802` | `0xF6/0x16` | Initialisierung/Keep-Alive; Status `0x00` → `0x01` | Im Mitschnitt beobachtet |
| TCP `8802` | `0xF6/0x17` | Zweite Init-Phase bzw. Tune-Bestätigung | Im Mitschnitt beobachtet; genaue Semantik kontextabhängig |
| TCP `8802` | `0xF6/0x20` + `0x21` | Länge und XML der Kanalliste | Im Mitschnitt beobachtet |
| TCP `8802` | `0xF6/0x03` | Kanal vorbereiten | Im Stream-Mitschnitt beobachtet |
| TCP `8802` | `0xF6/0x32` + `0x33` | `ch_Info`-Länge und XML | Im Stream-Mitschnitt beobachtet |
| TCP `8802` | `0xF6/0x02` | Signalstatus abfragen | Im Stream-Mitschnitt beobachtet |
| TCP `8802` | `0xF6/0x01` | Tune-/Kanalaktivierungsbefehl | Im Mitschnitt beobachtet; Payload-Zuordnung nur am Beispiel bestätigt |
| TCP `8802` | `0xF8/0x07` | Stream-Freigabe | Im Stream-Mitschnitt beobachtet |
| UDP `8800` | `0xF9/0x02` | Stream-Initialisierung | Im Mitschnitt beobachtet |
| UDP `8800` | `0xF9/0x01` | MPEG-TS-Block per Pull anfordern | Im Stream-Mitschnitt beobachtet |
| UDP `8800` | `0xF9/0x0A` | Speedtest-Request im APK-SDK; keine bestätigte Senderliste | Builder und Durchsatzrechnung im APK; Antworten variieren zwischen den PCAPs |
| APIX | `0xFA/0x00`, `0x07`, `0x08` | Geräte-/Netzwerkinformationen laut Analyse | Befehle beobachtet; Details siehe Forschungsnotiz |

## Projektstruktur

```text
.
├── README.md
├── AGENTS.md                              # Arbeitsnotizen; teilweise älterer Debug-Stand
├── WICHTIG_NEUE_MÖGLICHKEITEN.md          # Ideensammlung, nicht alle Aussagen verifiziert
├── pyproject.toml                         # Paket-/CLI-Konfiguration
├── src/
│   ├── wisi.py                            # Gemeinsames CLI-Überskript
│   ├── wisi_client.py                     # OR-S2D-Client, 31-B-Builder und Streamlogik
│   ├── wisi_channels.py                   # Kanalliste ausgeben
│   ├── wisi_common.py                     # Gemeinsamer Einstieg zum Laden von Sendern
│   ├── wisi_epg.py                        # EPG-Export; derzeit nicht end-to-end verifiziert
│   ├── wisi_discovery.py                  # Experimenteller TV2S-JSON-UDP-Broadcast
│   ├── wisi_pcap.py                       # PCAP-/APIX-Auswertung, Legacy-Service-DB-Export
│   ├── wisi_probe.py                      # Einzelnen Opcode testen
│   ├── wisi_menu.py                       # Älterer/Legacy-Menüeinstieg
│   └── protocol.py                        # Älterer 31-B-APIX-Helper; nicht mit OR-S2D-Builder verwechseln
├── research/
│   ├── README.md                         # Zusammenfassung und Einordnung der Forschung
│   ├── or_s2d_protocol_analysis.md        # Wichtigste Analyse der Mitschnitte vom 12. Oktober
│   ├── pcap_analysis.md                   # Zusammengeführte Analyse-Notizen
│   ├── protocol_spec_or_s2d.md            # Spezifikationsnotizen; einzelne Abschnitte sind Hypothesen
│   ├── apk_reverse_engineering.md         # Analyse der TV2Smart-App
│   ├── apk-report-com.tivicon.tv2smart.mobile.txt
│   ├── or_s2d_firmware_update.md          # Öffentliche Firmware-Update-Informationen
│   └── capture_pcapdroid_2026-10-11.pcap # Älterer PCAP-Mitschnitt
├── archive/
│   ├── wisi_dongle_client.py              # Älterer Client-Experimentstand
│   ├── wisi_dongle_v1.py                  # Früherer Client
│   └── wisi_dongle_simple.py              # Minimaler Proof of Concept
├── tests/
│   └── test_wisi_tools.py                 # CLI-, PCAP- und Framingtests
├── PCAPdroid_12_Okt._16_16_04.pcap        # Mitschnitt: Kanallisten-/App-Ablauf
└── PCAPdroid_12_Okt._16_28_17.pcap        # Mitschnitt: Tune und Stream
```

`__pycache__/`, `.venv/` und `.git/` sind lokale Laufzeit-/Entwicklungsverzeichnisse und gehören nicht zur fachlichen Projektstruktur. PCAPs können private Netzwerkdaten enthalten; vor Veröffentlichung prüfen und gegebenenfalls aus dem Repository entfernen.

## Offene Punkte & bekannte Einschränkungen

1. **Session-Token/Auth-Framing anderer Firmwarepfade verifizieren.** Für die untersuchte APK/PCAP-Variante ist kein Tokenfeld im 31-Byte-Request belegt; der Client sendet dafür Null als internen Platzhalter. Das schließt abweichende Firmwarepfade nicht aus.
2. **EPG-CLI vervollständigen.** `connect()` gibt in `wisi_client.py` ein Tupel `(socket, session_token)` zurück; `src/wisi_epg.py` behandelt das Ergebnis aktuell an einer Stelle wie einen einzelnen Socket. Der `--epg`-Ablauf ist deshalb nicht als funktionierend dokumentiert.
3. **TCP-Nachrichten robust lesen.** TCP kann Nutzdaten und Trailer auf beliebige Segmentgrenzen verteilen. Antwortlängen, Trailer und Timeouts müssen explizit und konsistent behandelt werden.
4. **Live-Kanalliste und Stream wiederholen.** Die PCAPs belegen den App-Ablauf. Sie belegen nicht, dass jeder aktuelle Clientpfad, Token-Wert und PAT-Index ohne weitere Korrekturen live funktioniert.
5. **`0xF9/0x0A`-PCAP-Abweichung und `0xF6/0x22` prüfen.** Das APK belegt `0xF9/0x0A` als Speedtest; die 48.143 Byte sind damit erklärt. Die abweichenden 32.740-Byte-Antworten und die Notwendigkeit von `0xF6/0x22` bleiben offen.
6. **Discovery verifizieren.** Die `0xFA`-APIX-Befehle und der experimentelle TV2S-JSON-UDP-Broadcast sind bislang nicht als derselbe Mechanismus belegt.
7. **Pay-TV/CA nicht implementiert.** `prog_idx`-Werte mit `0x48`-Präfix werden in den Notizen verschlüsselten Kanälen zugeordnet. Die freie Senderliste und der freie MPEG-TS-Stream sind von einer autorisierten Entschlüsselung getrennt; CA-/Pay-TV-Funktionalität ist nicht Teil dieses Clients.

## Forschungsnotizen und Quellenreihenfolge

Die Forschungsdateien sind in [research/README.md](research/README.md) zusammengefasst und nach Beleglage eingeordnet. Protokollhypothesen, insbesondere zu Authentifizierung, CRC, Scan-Opcodes und variantenabhängigem Framing, gelten nicht als bestätigt, solange kein reproduzierbarer Mitschnitt oder unabhängiger Test sie stützt.

Gerätemodell und Firmware-Update-Hinweise:

- [WISI OR S2D Produktdatenblatt (PDF)](https://wisi.at/daten/artikel/pdf/Pro_OR-S2D_de.pdf)
- [WISI OR S2D Bedienungsanleitung (PDF)](https://wisi.at/daten/artikel/pdf/BDA_ORS2D_Dongle.pdf)
- [TV2Smart für Android-Mobilgeräte](https://play.google.com/store/apps/details?id=com.tivicon.tv2smart.mobile&hl=de)

Die öffentlich verfügbaren Unterlagen beschreiben kein vollständig verifiziertes allgemeines PC-Flashverfahren. Keine Firmware anderer Gerätemodelle und keine generischen Flash-Tools verwenden.
