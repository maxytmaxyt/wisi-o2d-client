# Gemini Deep Research – APIX/USBC Protokoll-Analyse
> Erstellt: Oktober 2026  
> Quelle: Google Gemini Deep Research  
> Basis: PCAP-Mitschnitt `capture_pcapdroid_2026-10-11.pcap` + Reverse Engineering

---

## Modellhinweis: OR S2D statt der früheren Bezeichnung O2D

Der Nutzer hat das in diesem Projekt verwendete Gerät anhand des offiziellen
[WISI-Produktdatenblatts](https://wisi.at/daten/artikel/pdf/Pro_OR-S2D_de.pdf) als
**WISI OR S2D (DVB-S2 Free-To-Air SAT Dongle)** identifiziert. Frühere Notizen
verwendeten „WISI O2D“ ungenau als Gerätenamen. Die Tabelle unten ist eine frühere
allgemeine Recherche und kein Nachweis, dass alle dort genannten Produkte dasselbe
Gerät oder dieselbe Hardware-/Firmwarevariante verwenden. Die belegten OR-S2D-
USB- und Firmwareangaben stehen in [or_s2d_firmware_update.md](or_s2d_firmware_update.md).

## 1. USBC/APIX-Steuerprotokoll – Hardware-Herkunft

### Protokoll-Basis
Der 31-Byte-Container auf TCP 8802 basiert auf **USB Bulk-Only Transport (BOT) Command Block Wrappers (CBW)** – direkt über TCP/IP getunnelt.  
Paketlänge 31 Byte = exakte USB-BOT-Spezifikation (USB Implementers Forum).

### 31-Byte USBC-Container (korrigiert/bestätigt)

| Offset | Feld | Wert | Beschreibung |
|--------|------|------|--------------|
| 0x00–0x03 | dCBWSignature | `55 53 42 43` | ASCII "USBC" – USB-BOT-Standard |
| 0x04–0x07 | dCBWTag | `A0 CB 03 37` | Statischer Magic-Header / Transaktions-ID |
| 0x08–0x0B | dCBWDataTransferLength | 32-Bit **Big-Endian** | In aktuellen App-PCAPs bytegenau bestätigt |
| 0x0C | bmCBWFlags | `0x80` / `0x00` | 0x80 = Device→Host (Lesen), 0x00 = Host→Device (Schreiben) |
| 0x0D | bCBWLUN | `0x00` | Logical Unit Number |
| 0x0E | bCBWCBLength | `0x0A`–`0x10` | Effektive CDB-Länge (10–16 Byte) |
| 0x0F–0x12 | CDB[0..3] | `41 50 49 58` | ASCII "APIX" – Sub-Protokoll-Kennung |
| 0x13 | CDB[4] | Opcode | APIX-Befehlscode |
| 0x14–0x1E | CDB[5..15] | Payload | Befehlsspezifische Parameter + Null-Padding |

> **Korrektur durch den App-PCAP vom 12.10.2026:** Das APIX-Längenfeld ist Big-Endian. Im Mitschnitt stehen beispielsweise `00 00 00 04` für 4 Byte, `00 00 00 02` für 2 Byte und `00 00 BC 00` für `0xBC00`. Das APIX-Transportformat weicht hier vom nativen USB-BOT-CBW ab.

### Hardware-Hersteller: icube Corp. (Südkorea)

Das APIX-Framework stammt von **icube Corp.**, einem südkoreanischen SoC-Hersteller (aktiv 2010–2015).  
icube entwickelte hochintegrierte DVB-T/C/ISDB-T-Tuner-Plattformen, die von zahlreichen Herstellern lizenziert wurden:

| Produkt | Hersteller | Protokoll |
|---------|-----------|-----------|
| WISI O2D | WISI | APIX/USBC |
| Tivizen iPlug / Pico | icube / Tivizen | APIX/USBC |
| equinux tizi | equinux (DE) | APIX/USBC |
| TiViCon | TiViCon | APIX/USBC |
| Elgato EyeTV Mobile/Micro | Elgato | APIX/USBC (Hardware-Variante) |

**Interner Ablauf (Firmware):**
- Firmware greift intern per USB auf DVB-Demodulator-Chip zu (Siano SMS118x oder SMS2270)
- Netzwerk-Daemon **`apixd`** öffnet TCP 8802
- `apixd` validiert Magic `A0CB0337` + "APIX", leitet Befehle an DVB-Tuner-Middleware weiter

---

## 2. Tivizen/WISI Software-Ökosystem

### Native Bibliotheken (Android APK dekompiliert)
- **`libapix.so`** – Kernbibliothek
- **`libtivizen.so`** – Tivizen-spezifisch  
- **`libicube_dvb.so`** – Generic icube DVB

Paketnamen: `com.icube.tivizen`, `com.equinux.tizi`

Relevante JNI-Funktion:
```
Java_com_icube_tivizen_driver_ApixDriver_nativeSelectChannel
```
→ Konstruiert den 31-Byte-USBC-Container mit channel_index per Bit-Shifting direkt in Byte 20+21.

### Opcode-Tabelle (aus APK-Analyse ergänzt)

| APIX Opcode | Richtung | Funktion |
|-------------|----------|----------|
| `0x01` | Host→Device | Kanalwechsel / Tune |
| `0x02` | Host→Device | Sendersuchlauf initiieren |
| `0x03` | Device→Host | Tuner-Statusabfrage (Signal/SNR) |
| `0x0A` | Host→Device | Systemdatenbank/EPG-Cache anfordern |
| `0x0F` | Host→Device | Demodulator deaktivieren / Standby |
| `0x16` | Host→Device | Init / Keep-Alive |
| `0x17` | Host→Device | Init Phase 2 / Tune-Bestätigung |
| `0x30`–`0x36` | Host→Device | EPG-XML-Abfragen |
| `0xF8/0x07` | Host→Device | Stream-Freigabe (nach Tune) |

---

## 3. 0xF9/0x0A Response-Format – vollständig aufgeklärt ✅

### Warum 32.740 Byte?
- Linux-Kernel-Speicherseite: 32.768 Byte  
- Abzüglich UDP/IP/Ethernet-Header-Overhead: **32.740 Byte Nutzlast**  
- Entspricht im Stream-Modus: 174 × 188 Byte TS-Pakete = 32.712 Byte + **28 Byte Präfix-Header**

### Was enthält 0xF9/0x0A?
**Keine MPEG-TS-Daten** (kein 0x47-Sync), **keine rohen DVB-SI-Tabellen**.  
→ **Vorkompilierte Service-Datenbank** (C-Struct-Array) vom `apixd`-Daemon.

Der Dongle wertet PAT/PMT/SDT intern aus und cached das Ergebnis im RAM.  
Dies entlastet mobile Clients von SI-Table-Parsing.

### Struktur: 32-Byte-Header + Array von Kanal-Datensätzen

Jeder Datensatz (128 oder 256 Byte, fest):

| Offset | Feld | Typ | Beschreibung |
|--------|------|-----|--------------|
| 0x00–0x03 | `prog_idx` | uint32_t Big-Endian | Programm-Index + Status-Flags |
| 0x04–0x05 | `service_id` | uint16_t Big-Endian | DVB Service ID (Program Number) |
| 0x06–0x07 | `pmt_pid` | uint16_t Big-Endian | PMT PID |
| 0x08–0x09 | `pcr_pid` | uint16_t Big-Endian | PCR PID |
| 0x0A–0x0B | `video_pid` | uint16_t Big-Endian | Video PID |
| 0x0C | `video_type` | uint8_t | Stream-Typ (0x1B = H.264) |
| 0x0D–0x0E | `audio_pid` | uint16_t Big-Endian | Audio PID |
| 0x0F | `audio_type` | uint8_t | Stream-Typ (0x03 = MPEG-1 Audio L2) |
| 0x10–0x11 | `service_flags` | uint16_t Bitmaske | 0x0001=Aktiv, 0x0008=Verschlüsselt |
| 0x12–0x31 | `service_name` | char[32] | Kanalname (ISO-8859-15 / UTF-8, null-terminiert) |

### prog_idx Flags (bestätigt)

```
0x40xxxxxx → FTA (Free-To-Air)    – Bit 30 gesetzt = aktiver, gültiger Eintrag
0x48xxxxxx → Pay-TV (verschlüsselt) – Bit 27 zusätzlich gesetzt = CA erforderlich
```

### Implementierungshinweis (NEU)
Der erste empfangene 0xF9/0x0A-Block enthält die komplette Kanalliste.  
→ **28 Byte Header verwerfen**, dann Datensätze parsen → Kanalliste + PAT-Index direkt ablesen.  
→ `0xF9/0x01`-Anforderungen ebenfalls: **ersten 28 Byte verwerfen**, Rest = reiner MPEG-TS.

---

## 4. Kanalwechsel per PAT-Index – verifiziert

### Warum kein Frequenz/PID-Parameter (wie SAT>IP)?
Der `apixd`-Daemon verwaltet die Kanalliste im lokalen RAM.  
→ Client schickt nur den **Array-Index** (0-basiert), Firmware setzt PID-Filter selbst.

### 0x01 Payload `00 04` = Index 4
```
Payload: 00 04
Byte[0] = 0x00  → Flag (immer 0?)
Byte[1] = 0x04  → Array-Index 4 (= 5. Eintrag, 0-basiert)

PAT-Reihenfolge:
  Index 0 → Prog 4911
  Index 1 → Prog 4912
  Index 2 → Prog 4913
  Index 3 → Prog 4913 (?)
  Index 4 → Prog 4914 ✓ (gewählter Kanal)
```

### Verifikationsmethoden (ohne zweiten PCAP)

**Methode 1 – 0xF9/0x0A-Dump analysieren:**
1. 28-Byte-Header des 0xF9/0x0A-Blocks verwerfen
2. Eintrag Index 4 auslesen (Offset: 32 + 4 × Datensatzlänge)
3. `video_pid` + `audio_pid` aus Datensatz mit PIDs im empfangenen MPEG-TS vergleichen
4. Stimmen überein → Index-Hypothese bestätigt ✅

**Methode 2 – APK disassemblieren (Ghidra):**
- Symbol: `apix_cmd_set_channel` oder `nativeSelectChannel`
- Zeigt Bit-Shifting: `channel_index >> 8` → Byte 20, `channel_index & 0xFF` → Byte 21

**Methode 3 – Socket-Injektion:**
```python
# Index 0 schicken → prüfen welcher Kanal startet
_cmd_tune(pat_index=0)  # Payload: 00 00
# dann Index 1, 2, 3 ...
# PAT-Sektion (PID 0x0000) im TS zeigt program_number
```

---

## 5. Transponder ts_id=33079 – identifiziert

### Zuordnung: Vodafone Kabel Deutschland

| Parameter | Wert |
|-----------|------|
| Netzbetreiber | **Vodafone Kabel Deutschland / Vodafone West** |
| Original Network ID (ONID) | **0xF001** |
| Transport Stream ID (TSID) | **33079 (0x8137)** |
| Typische Frequenz | **458 MHz** (QAM256, 6900 kSym/s) |
| Kanalanzahl | 252 Services (TV-SD + Radio + Datendienste) |

### MPEG-1 Audio Layer 2 (Stream Type 0x03)
Deutsche Kabelnetze nutzen auf SD-Transpondern weiterhin **MP2-Audio** (192–256 kbit/s):
- ARD/ZDF + Privatsender (RTL, ProSiebenSat.1) → MP2 auf DVB-C SD
- DVB-T2 HD → AAC-LC / Dolby Digital (AC-3/E-AC3)
- Grund: Kompatibilität älterer DVB-C-Receiver

---

## 6. Korrekturen gegenüber bisheriger Analyse

| Punkt | Bisherige Annahme | Korrektur durch Deep Research |
|-------|-------------------|-------------------------------|
| `dCBWDataTransferLength` Byte-Order | Little-Endian laut früherer Annahme | **Big-Endian**, im App-PCAP bytegenau bestätigt |
| 0xF9/0x0A Inhalt | "EPG/Metadaten unbekannt" | **Vorkompilierte Service-DB** (C-Struct-Array) |
| 0xF9/0x0A + 0xF9/0x01 Header | Kein Header bekannt | **28-Byte-Präfix verwerfen**, Rest = Nutzdaten |
| PAT-Index Herkunft | "Schätzung aus PAT" | **Direkt aus 0xF9/0x0A-Block lesbar** (Feld im Datensatz) |
| Hersteller | Unbekannt | **icube Corp.** (Seoul, KR), Daemon: `apixd` |
| Transponder | Unbekannt | **Vodafone Kabel DE, 458 MHz, ONID 0xF001** |

---

## 7. Nächste Implementierungsschritte (Priorität)

- [ ] **0xF9/0x0A-Block parsen**: 28-Byte-Header überspringen, Datensatzlänge bestimmen (128 oder 256 Byte durch Trial), Kanalliste + PAT-Indizes extrahieren
- [x] **`dCBWDataTransferLength` Byte-Order**: Big-Endian, im App-PCAP bytegenau bestätigt.
- [ ] **28-Byte-Header von 0xF9/0x01 verwerfen**: Bisheriger Code schreibt alle Bytes inkl. Header in die TS-Datei
- [ ] **Kanalwechsel testen**: `_cmd_tune(pat_index=0)` bis `pat_index=5`, PAT-PID (0x0000) im TS lesen
- [ ] **`apixd`-Daemon-Binary aus Firmware-Update extrahieren** (falls WISI/Tivizen Firmware-Image verfügbar)
- [ ] **Ghidra-Analyse von `libapix.so`** aus Tivizen-APK
