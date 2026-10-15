# Research-Zusammenfassung: WISI OR S2D

> Stand: 15. Oktober 2026. Kompakte Übersicht aller verifizierten Erkenntnisse.
> Detailbelege in den verlinkten Einzeldokumenten.

---

## Gerät

**WISI OR S2D** (auch: TiViCon OR S2D). Nicht zu verwechseln mit dem älteren O2D/Tivizen.
FTA DVB-S2 SAT-Dongle mit Ethernet/WLAN. USB-C nur für Firmware-Update oder direkte Android-TV-Box-Verbindung – kein regulärer Streaming-Weg für Tablets.

---

## Protokoll: was sicher bestätigt ist

### Paketformat (USBC/APIX über TCP)

```
Offset  Länge  Inhalt
00–03   4      Signatur "USBC"
04–07   4      Magic Tag A0 CB 03 37 (konstant)
08–11   4      Datenlänge Big-Endian
12      1      Flags: 0x80 = Lesen, 0x00 = Schreiben
13      1      LUN 0x00
14      1      CDB-Länge 0x10 (= 16)
15      1      Prefix: F6 (TCP), F8 (Stream-Freigabe), F9 (UDP)
16–19   4      "APIX" (ASCII)
20      1      Opcode
21–30   10     Payload / Padding
───────────────────────────────────────────────
Gesamt: 31 Byte (USBC Command Block)

Antwort endet mit 13 Byte USBS-Suffix.
Keine Auth-Extension (66 Byte, 46 Byte USBS) in den vorhandenen PCAPs.
```

### TCP-Befehle (Port 8802, Prefix 0xF6)

| Opcode | Funktion | Antwort |
|---|---|---|
| `0x16` | Init / Keep-Alive (alle ~2 s) | 12 B: Byte[0] = 0x00 (warten) → 0x01 (bereit) |
| `0x17` | Init Phase 2 / Tune-Bestätigung | 4 B |
| `0x01` | **Kanal aktivieren (Tune)** | USBS; Payload = `[0x00, pat_index]` |
| `0x02` | Signal-Status-Poll (alle ~3 s) | 13 B: Byte[1]=Stärke%, Byte[2]=Qualität |
| `0x03` | Kanal vorbereiten (prepare tune) | USBS |
| `0x20` | ch_List-Größe abfragen | 8 B: XML-Größe BE uint32 |
| `0x21` | ch_List-Daten abrufen | `<ch_List>...</ch_List>` XML |
| `0x22` | ch_List-Abschluss/Quittung | – |
| `0x30` | EPG-Größe abfragen | 6 B |
| `0x31` | EPG-XML abrufen | `<epg_Data>...</epg_Data>` |
| `0x32` | ch_Info-Größe abfragen | 6 B |
| `0x33` | ch_Info-XML abrufen | `<ch_Info>...</ch_Info>` |
| `0x35` | Ereignis-Größe abfragen | 6 B |
| `0x36` | Ereignis-XML abrufen | `<event_desc .../>` |

| Prefix | Opcode | Funktion |
|---|---|---|
| `0xF8` | `0x07` | Stream-Freigabe (nach Tune, vor erstem UDP-Block) |

### UDP-Befehle (Port 8800, Prefix 0xF9) – pull-basiert

| Opcode | Funktion | Antwort |
|---|---|---|
| `0x02` | Stream initialisieren (einmalig) | – |
| `0x01` | **MPEG-TS-Block anfordern** | ~32.740 B (174 × 188 B TS-Pakete) |
| `0x0A` | Speedtest (APK: `getSpeedTestMbps()`) | 48.143 B (48.130 Daten + 13 USBS) |

### Discovery (Prefix 0xFA, Beobachtung aus OR-S2D-PCAPs)

| Opcode | Antwort |
|---|---|
| `0xFA/0x00` | Geräte-Info (Session-Token-Bedeutung unklar) |
| `0xFA/0x07` | Modellname: `OR S2D` + Seriennummer |
| `0xFA/0x08` | Netzwerk-Konfiguration, 526 B |

### Vollständiger Protokollablauf (bestätigt aus PCAP)

```
Phase 1 – TCP Init
  → 0x16          Antwort Byte[0] = 0x00 → wiederholen
  → 0x16          Antwort Byte[0] = 0x01 = BEREIT

Phase 2 – Senderliste laden (TCP, 440 Kanäle)
  → 0x20          XML-Größe (61.348 Byte)
  → 0x21          <ch_List> XML mit 440 Einträgen
  → 0x22          Abschluss
  → 0x16          Keep-Alive (alle 2 s, während der gesamten Session)

Phase 3 – Kanal vorbereiten (TCP)
  → 0x03 [prog_idx]     Kanal vorauswählen
  → 0x32 / 0x33         ch_Info XML (s_id, Transponder-Parameter)
  → 0x02 (alle 3 s)     Signal pollen

Phase 4 – Tune + Stream (TCP + UDP)
  → 0x01 [0x00, pat_idx]   Kanal aktivieren (PAT-Index, nicht Service-ID!)
  → 0xF8/0x07              Stream-Freigabe
  → 0xF9/0x01 [byte21=0x00] Erster MPEG-TS-Block
  ← 32.740 Byte MPEG-TS    174 Pakete
  → 0x17 [01 00 00 00]     Tune bestätigen
  → 0xF9/0x01 [byte21=0x01] Weitere Blöcke (Loop)
  → 0x16 (alle 2 s)        Keep-Alive
```

---

## Senderliste (ch_List XML)

```xml
<ch_List>
  <ch type="TV" pol="H" sym="22000" s_id="28721" ts_id="1051"
       freq="10744" prog_idx="1083375616" lcn="69"
       s_name="tagesschau24" fta="1" />
</ch_List>
```

**440 Kanäle** auf ts_id=1051 (303 TV, 137 Radio, 439 FTA, 1 verschlüsselt).

`prog_idx` Struktur:
- `0x40xxxxxx` → FTA-Kanal
- `0x48xxxxxx` → verschlüsselter Kanal (Pay-TV / CA)

---

## APK / Native Libraries

Analysiertes Artefakt: `TV2Smart_3.M20260803.0-rev-a14aeb377_APKPure.xapk`

| Library | Funktion |
|---|---|
| `libsecure_module.so` (229 KB) | CI+-artige Content-Control-Auth (SAC/CC, DH), **nur für Pay-TV** |
| `libpimbridge.so` (5 KB) | JNI-Wrapper für PIM-CA-Decoder |
| `libpimdec.so` (68 KB) | PIM-Decoder (proprietäre CA-Entschlüsselung, separater Multicast-Pfad) |
| `librtmp-jni.so` (90 KB) | RTMP für externe Streams |
| `libvlc.so` / `libvlcjni.so` (44 MB) | VLC-Player-Core |

**Kein** `libtivicon_dvb.so` oder `libstream_decoder.so` in diesem XAPK.

### Hardcodierter Key in `libsecure_module.so`

```
THVrZVJhbkRvbHBoQ0krMQ==  →  LukeRanDolphCI+1
```

Root-Key/Seed für die CNKEY-Derivation-Chain im CI+-Protokoll.
**Nur für Pay-TV relevant.** FTA-Streaming braucht diese Auth nicht.

Die frühere Hypothese `MD5(Challenge ‖ SharedSecret ‖ Timestamp)` ist falsch:
`libsecure_module.so` nutzt SHA-256 + AES, kein MD5.

### USBC-Builder (DEX)

`com.crenova.tv.dongle.dvb.sdk.messages.e1` baut **31-Byte-USBC-Requests**:
- Byte 8–11: `data_len` Big-Endian
- Byte 12: Flags (`0x80` = Lesen)
- Byte 15: Prefix (`0xF6`/`0xF8`/`0xF9`)
- Byte 16–19: `APIX`
- Byte 20: Opcode

`0xF9/0x0A` wird in `getSpeedTestMbps()` verwendet – **nicht** als Senderliste.

---

## Verwirf diese alten Annahmen

| Alte Annahme | Korrekt |
|---|---|
| USBC-Requests sind 66 Byte | **31 Byte** (APK + PCAPs) |
| USBS-Trailer ist 46 Byte | **13 Byte** in allen untersuchten PCAPs |
| `0xF9/0x0A` = Senderliste / Service-DB | **Speedtest** (`getSpeedTestMbps()`) |
| Senderliste kommt per UDP | **TCP** `0xF6/0x20 + 0x21` XML |
| MD5-basierte Session-Auth nötig für FTA | **Nein**, FTA-PCAPs zeigen keine Auth-Phase |
| `libtivicon_dvb.so` im APK | **Nicht vorhanden** in diesem XAPK |
| 32.740 B und 48.143 B Speedtest-Antwort sind dasselbe | **Unterschiedliche Beobachtungen**, nicht gleichsetzen |

---

## Offene Punkte

| Priorität | Thema |
|---|---|
| 🔴 | `0xF6/0x01`-Payload für Kanalwechsel: Payload `00 04` = PAT-Index 4, aber wie ändert sich das für andere Kanäle? |
| 🔴 | Live-Stream-Erfolg nicht bestätigt: bekannte Bugs (USBS-Lese-Timing, zu spätes UDP-Bind) |
| 🟡 | Scan-PCAP fehlt (würde `0x01`-Payload-Frage lösen) |
| 🟡 | `0xF6/0x22` nach ch_List: nötig oder optional? |
| 🟢 | Unbekannte Opcodes `0x04`–`0x1F` (z. B. `CMD_GET_ABOUT_DONGLE_INFO`) per Probe finden |
| 🟢 | Pay-TV / `0x48xxxxxx`-Kanäle: CA-Handling fehlt komplett |

---

## Wo was steht

| Datei | Inhalt |
|---|---|
| `pcap_analysis.md` | Paket-Zählungen, PCAP-Grenzen |
| `or_s2d_protocol_analysis.md` | Detaillierter Befehlsablauf aus PCAP vom 12. Okt. |
| `apk_reverse_engineering.md` | APK-Befunde inkl. Native-Lib-Analyse (15. Okt.) |
| `neue_erkenntnisse.md` | Hypothesen aus Spec-Matching (teilweise veraltet/überholt) |
| `or_s2d_firmware_update.md` | Firmware-Update-Wege laut WISI-Datenblatt |
| `protocol_spec_or_s2d.md` | ⚠️ Breite Hypothesen, HTTP/REST/USB-Details **nicht bestätigt** – nur als Ideenquelle |
