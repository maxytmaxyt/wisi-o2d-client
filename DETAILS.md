# WISI OR S2D – Protokoll, Forschungsstand & Details

> Kurzversion mit Ausführungsanleitung: [README.md](README.md)

**Stand: 14. Oktober 2026.** Das Protokoll ist teilweise aus Mitschnitten abgeleitet. Beobachtete App-Abläufe sind nicht automatisch unabhängig funktionierende Client-Abläufe.

> **Modellunterschied beachten:** Dieses Repository beschreibt den WISI **OR S2D**. Ältere Notizen verwenden teils „O2D", „Tivizen" oder „TiViCon". Kommandobedeutungen anderer Modelle nicht ungeprüft übertragen.

---

## Aktueller Stand

- **Kanalliste:** XML-Kanalliste via TCP `0xF6/0x20` (Länge) + `0xF6/0x21` (Daten). Analysierter Datensatz: **440 Sender** (303 TV, 137 Radio, 439 FTA), 61.348 Byte XML.
- **USBC-Framing:** 31-Byte-CBW. Eine 35-Byte-Auth-Erweiterung ist in den vorhandenen Artefakten nicht belegt.
- **USBS-Trailer:** 13 Byte. Ein 46-Byte-Trailer ist nicht bestätigt.
- **Stream:** `0xF6/0x03` → `0xF6/0x01` → `0xF8/0x07` → UDP-Pulls mit `0xF9/0x01` im Mitschnitt beobachtet.
- **`0xF9/0x0A`:** Im TV2Smart-APK als **Speedtest** belegt, nicht als Senderliste.
- **Status:** Analyse und Code vorhanden, aber nicht jede Funktion ist live end-to-end verifiziert.

---

## Neue Erkenntnisse aus den Mitschnitten

### 1. Request-Framing (31-Byte-CBW)

| Offset | Länge | Inhalt |
|---|---:|---|
| 0–3 | 4 | `USBC` |
| 4–7 | 4 | Magic `A0 CB 03 37` |
| 8–11 | 4 | Datenlänge (Big-Endian) |
| 12 | 1 | Flags: `0x80` = Lesen, `0x00` = Schreiben |
| 13 | 1 | LUN `0x00` |
| 14 | 1 | CDB-Länge `0x10` |
| 15 | 1 | APIX-Prefix |
| 16–19 | 4 | `APIX` |
| 20 | 1 | Opcode |
| 21–30 | 10 | CDB-Payload / Padding |

Die früher beschriebene 35-Byte-Erweiterung mit Session-Token, App-Kennung und CRC ist in den vorhandenen PCAPs und im generischen APK-Builder nicht enthalten.

### 2. Kanalliste via TCP (nicht `0xF9/0x0A`)

1. `0xF6/0x20` → Größe der `<ch_List>`-XML (Big-Endian-Integer in Antwort)
2. `0xF6/0x21` → XML-Nutzdaten
3. `0xF6/0x22` → Quittung (ob immer nötig: offen)

Typische XML-Felder: `s_id`, `ts_id`, `freq`, `pol`, `sym`, `prog_idx`, `lcn`, `s_name`, `fta`, `type`.

### 3. `0xF9/0x0A` = Speedtest, keine Senderliste

`getSpeedTestMbps()` im APK sendet `0xF9/0x0A` mit `data_len=48.128` und wertet die Antwort nur als Durchsatzmessung aus. 48.130 Datenbytes + 13 Abschlussbytes = 48.143 Byte (erklärt die gemeldete Größe). Die abweichenden 32.740-Byte-Antworten im PCAP vom 11. Oktober sind ohne Rohdaten nicht vollständig erklärt.

### 4. Streamablauf und MPEG-TS

Beobachtete Sequenz im Mitschnitt:

1. `0xF6/0x16` + `0xF6/0x17` – TCP-Init; `0x16` zeigt Status `0x00` → `0x01`
2. `0xF6/0x03` – Kanalvorbereitung
3. `0xF6/0x32` / `0xF6/0x33` – `ch_Info`-Länge und XML
4. `0xF6/0x02` – Signalabfrage
5. `0xF6/0x01` mit Payload `00 04` – Tune (PAT-Index 4 = Programm 4914 im Beispiel)
6. `0xF8/0x07` – Stream-Freigabe
7. `0xF9/0x01` (wiederholt) – UDP-Pull

UDP-Antwort: typisch 32.740 Byte, davon 32.712 Byte = **174 MPEG-TS-Pakete à 188 Byte**. Der Code sucht den `0x47`-Sync und richtet an 188-Byte-Grenzen aus.

PAT im Beispielstream: Programm 4914 → Index 4. PMT: Video-PID `0x1338` (H.264), Audio-PIDs `0x1339`/`0x133A` (MPEG-1), PID `0x133E` (privat, vermutl. Teletext).

### 5. EPG und weitere Opcodes

Im Mitschnitt vom 11. Oktober beobachtet:
- `0xF6/0x30` / `0xF6/0x31` – EPG-Länge und EPG-Daten (252 Anfragen)
- `0xF6/0x35` / `0xF6/0x36` – Ereignisbeschreibungen

Neuere Mitschnitte zeigen außerdem `0xFA/0x00`, `0xFA/0x07`, `0xFA/0x08` (Geräte-/Netzwerkinfos, Details in `research/or_s2d_protocol_analysis.md`).

---

## Protokoll-Kurzreferenz

| Kanal | Prefix/Opcode | Funktion | Sicherheit |
|---|---|---|---|
| TCP 8802 | `0xF6/0x16` | Init / Keep-Alive; Status `0x00`→`0x01` | Beobachtet |
| TCP 8802 | `0xF6/0x17` | Init Phase 2 / Tune-Bestätigung | Beobachtet; Semantik kontextabhängig |
| TCP 8802 | `0xF6/0x20` + `0x21` | ch_List-Länge und XML | Beobachtet |
| TCP 8802 | `0xF6/0x22` | ch_List-Quittung | Beobachtet; Notwendigkeit offen |
| TCP 8802 | `0xF6/0x03` | Kanal vorbereiten | Beobachtet |
| TCP 8802 | `0xF6/0x32` + `0x33` | ch_Info-Länge und XML | Beobachtet |
| TCP 8802 | `0xF6/0x02` | Signalstatus | Beobachtet |
| TCP 8802 | `0xF6/0x01` | Tune / Kanalaktivierung | Beobachtet; Payload nur am Beispiel bestätigt |
| TCP 8802 | `0xF8/0x07` | Stream-Freigabe | Beobachtet |
| TCP 8802 | `0xF6/0x30` + `0x31` | EPG-Länge und XML | Beobachtet |
| UDP 8800 | `0xF9/0x02` | Stream-Initialisierung | Beobachtet |
| UDP 8800 | `0xF9/0x01` | MPEG-TS-Block per Pull | Beobachtet |
| UDP 8800 | `0xF9/0x0A` | Speedtest (kein Senderlisten-Format) | APK-Beleg; Antwortgrößen variieren |
| APIX | `0xFA/0x00`, `0x07`, `0x08` | Geräte-/Netzwerkinfos | Beobachtet; Details in research/ |

---

## Offene Punkte & bekannte Einschränkungen

1. **Session-Token/Auth-Framing anderer Firmwarepfade.** Im 31-Byte-CBW kein Tokenfeld belegt; schließt abweichende Firmwarepfade nicht aus.
2. **EPG-CLI nicht end-to-end verifiziert.** `--epg`-Aufruf ist noch nicht als vollständig funktionierend dokumentiert.
3. **TCP-Nachrichten robust lesen.** Antwortlängen, Trailer und Timeouts müssen explizit behandelt werden (TCP ist ein Bytestrom).
4. **Live-Kanalliste und Stream wiederholen.** PCAPs belegen den App-Ablauf, nicht jeden Clientpfad ohne weitere Korrekturen.
5. **`0xF9/0x0A`-Abweichung und `0xF6/0x22`.** 32.740-Byte-Antworten und Notwendigkeit der Quittung noch offen.
6. **Discovery verifizieren.** `0xFA`-APIX-Befehle und TV2S-JSON-UDP-Broadcast sind nicht als derselbe Mechanismus belegt.
7. **Pay-TV/CA nicht implementiert.** `prog_idx`-Werte mit `0x48`-Präfix = verschlüsselte Kanäle. CA-Funktionalität ist nicht Teil dieses Clients.

---

## Forschungsnotizen & Quellen

Alle Dateien in `research/` sind in [research/README.md](research/README.md) eingeordnet.

| Datei | Inhalt |
|---|---|
| `research/or_s2d_protocol_analysis.md` | Hauptanalyse der Mitschnitte vom 12. Oktober |
| `research/pcap_analysis.md` | Zusammengeführte Analysenotizen |
| `research/protocol_spec_or_s2d.md` | Spezifikationsnotizen (teils Hypothesen) |
| `research/apk_reverse_engineering.md` | Analyse der TV2Smart-App |
| `research/neue_erkenntnisse.md` | Neuere Einzelerkenntnisse |
| `AGENTS.md` | Arbeitsnotizen (teils älterer Debug-Stand) |

Externe Quellen:
- [WISI OR S2D Produktdatenblatt (PDF)](https://wisi.at/daten/artikel/pdf/Pro_OR-S2D_de.pdf)
- [WISI OR S2D Bedienungsanleitung (PDF)](https://wisi.at/daten/artikel/pdf/BDA_ORS2D_Dongle.pdf)
- [TV2Smart im Play Store](https://play.google.com/store/apps/details?id=com.tivicon.tv2smart.mobile&hl=de)
