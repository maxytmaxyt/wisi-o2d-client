# APK-Reverse-Engineering: TV2Smart (com.tivicon.tv2smart.mobile)
> Version: 3.M20260803.0-rev-a14aeb377  
> Analysiert: Oktober 2026  
> Quelle: TV2Smart_3_M20260803_0-rev-a14aeb377_APKPure.xapk  
> Methode: strings auf DEX + .so Bibliotheken

---

## 1. App-Identität

| Eigenschaft | Wert |
|---|---|
| Package | `com.tivicon.tv2smart.mobile` |
| Hersteller | **Crenova** (`com.crenova.tv.dongle.*`) |
| SDK-Paket | `com.crenova.tv.dongle.dvb.sdk` |
| Dongle-Daemon | `apixd` (Firmware-seitig) |
| Server | `wms.tiviconsolutions.com`, `cdms.tiviconsolutions.com` |

---

## 2. Native Bibliotheken (arm64-v8a)

| Bibliothek | Größe | Funktion |
|---|---|---|
| `libvlc.so` | 45 MB | VLC Media Player (Stream-Wiedergabe) |
| `libvlcjni.so` | 96 KB | JNI-Bridge zu libvlc |
| `libpimbridge.so` | 5,5 KB | **PIM (Proprietäres CA-System) JNI-Bridge** |
| `libpimdec.so` | 69 KB | **PIM Decoder (verschlüsselte Kanäle)** |
| `libsecure_module.so` | 234 KB | **Sicherheits-Modul (DH-Key-Exchange, AES, CI+)** |
| `libc++_shared.so` | 1,25 MB | C++ Stdlib |
| `librtmp-jni.so` | 96 KB | RTMP-Streaming |

### libpimbridge.so – JNI-Funktionen

```
Java_com_android_tv_crenova_pim_PimNative_nativeGetVersion  → pim_get_version
Java_com_android_tv_crenova_pim_PimNative_nativeInit        → pim_custom_init
Java_com_android_tv_crenova_pim_PimNative_nativeSetPmtPid   → pim_set_pmt_pid
Java_com_android_tv_crenova_pim_PimNative_nativeSetKey      → pim_set_key
Java_com_android_tv_crenova_pim_PimNative_nativeStatus      → pim_status
Java_com_android_tv_crenova_pim_PimNative_nativeDecode      → pim_decode
```

**PIM = Proprietäres Middleware-CA-System** (kein Standard-CI+).  
`pim_set_pmt_pid` + `pim_set_key` → Entschlüsselung verschlüsselter DVB-Streams.

### libsecure_module.so – Sicherheits-Funktionen (CI+ SAC)

```
SecureNativeModule_init
SecureNativeModule_msgCreateAuthReqNoncePacket    → CCMSGCreateAuthReqNoncePacket
SecureNativeModule_msgCreateAuthReqDHSigCertPacket → Diffie-Hellman Schlüsselaustausch
SecureNativeModule_msgCreateAuthReqCnfAkhPacket   → Auth-Key-Handshake
SecureNativeModule_msgCreateCCDataReqPacket       → Common Interface Datenübertragung
SecureNativeModule_msgCreateCCSACKeyingReqPacket  → SAC-Key-Exchange (CI+)
SecureNativeModule_hostGenerateRandomYNComputeDHPH → DH-Parameter generieren
SecureNativeModule_hostCreateSignatureB           → SECTK_Sign
SecureNativeModule_hostDeriveCIVnCCK             → CC_CalculateCcKeys + SECTK_AesEncrypt
SecureNativeModule_getDongleID / setDongleID      → Dongle-Identifikation
```

**Fazit:** Das Gerät unterstützt **CI+ (Common Interface Plus)** mit vollständigem SAC-Key-Exchange und AES-Entschlüsselung. Dies erklärt die `0x48xxxxxx` prog_idx-Flags für Pay-TV.

---

## 3. Datenbank-Schema (SQLite, aus DEX extrahiert)

### channels-Tabelle (vollständig)

```sql
CREATE TABLE IF NOT EXISTS channels (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  chType      TEXT,
  chCategory  TEXT,
  s_id        INTEGER NOT NULL,      -- DVB Service ID
  ts_id       INTEGER NOT NULL,      -- Transport Stream ID
  prog_idx    INTEGER NOT NULL,      -- APIX prog_idx (0x40/0x48 Präfix)
  freq        INTEGER,               -- Frequenz (kHz)
  s_name      INTEGER,               -- Service Name (Referenz)
  chLogo      TEXT,
  cardType    TEXT,
  chNumber    INTEGER,
  chLcnNumber INTEGER,               -- Logical Channel Number
  fta         INTEGER DEFAULT 1,     -- Free-To-Air Flag
  fav         INTEGER DEFAULT 0,
  lock        INTEGER DEFAULT 0,
  chVPid      INTEGER DEFAULT 0,     -- Video PID ← direkt verwendbar!
  chAPid      INTEGER DEFAULT 0,     -- Audio PID ← direkt verwendbar!
  chPPid      INTEGER DEFAULT 0,     -- PCR PID
  chIpAddr    TEXT,                  -- für IPTV-Kanäle
  chIpPort    INTEGER DEFAULT 0,
  chOTTUrl    TEXT,                  -- für OTT-Kanäle
  sym         INTEGER DEFAULT 0,     -- Symbolrate
  qam         INTEGER DEFAULT 0,     -- Modulation
  bw          INTEGER DEFAULT 0,     -- Bandbreite
  pol         TEXT,                  -- Polarität (DVB-S)
  tunerType   TEXT,                  -- DVBC/DVBT/DVBS/IPTV/OTT
  lnb         INTEGER DEFAULT 0,
  satPos      TEXT,
  satLongitude INTEGER DEFAULT 0,
  signalKhz   TEXT,
  diseqc11    INTEGER DEFAULT 0,
  isDynamicOTT INTEGER DEFAULT 0,
  dishChId    TEXT,
  genre       TEXT,
  isDirectTune INTEGER DEFAULT 1,    -- ← Direktes Tune via APIX 0x01
  UNIQUE(prog_idx)
)
```

**Wichtig:** `chVPid`, `chAPid`, `chPPid` werden direkt in der DB gespeichert → die App sendet bei `CMD_CHANGE_CHANNEL_BY_SID_AND_PID` sowohl s_id als auch die PIDs mit!

### Weitere Tabellen

```sql
-- EPG
CREATE TABLE programs (prog_idx, ts_id, title, start/end_time_utc_millis, short/long_description, ...)

-- Bouquets (Senderlisten-Gruppen)  
CREATE TABLE bouquets (bq_id, bq_name, s_id, s_id_order, ts_id)

-- Timer/Aufnahmen
CREATE TABLE reminder (prog_idx, s_id, title, start/end_time, evt_id, record, status)
```

---

## 4. Vollständige CMD_-Befehlsliste (App → Dongle)

### Kanal-Steuerung
```
CMD_CHANGE_CHANNEL_BY_PROGIDX       ← Tune via prog_idx (wie unser 0x01 + PAT-Index)
CMD_CHANGE_CHANNEL_BY_SID           ← Tune via Service ID
CMD_CHANGE_CHANNEL_BY_SID_AND_PID  ← Tune via s_id + Video/Audio PIDs → WICHTIG!
CMD_CHANGE_CHANNEL_BY_PROGIDX_AND_PID ← Tune via prog_idx + PIDs
CMD_CHANGE_CHANNEL_UP / _DOWN
CMD_CHANGE_CHANNEL_TO_IPTV / _IPTV_SID / _OTT / _DVR_FILE
CMD_FORCE_CH_SWITCH / CMD_FORCE_SET_CH_SOURCE
```

### EPG
```
CMD_GET_CHEPG_XML       → XML aller EPG-Einträge
CMD_GET_CHEPG_EVENT_XML → Einzelereignis-Details
CMD_GET_CHINFO_XML      → Kanal-Infos (ch_Info)
CMD_GET_CHLIST_XML      → Kanalliste als XML
CMD_GET_CURRENT_EPG / CMD_GET_LIST_EPG / CMD_GET_SEARCH_EPG
CMD_CH_EPG_LENGTH / CMD_CH_EPG_DATA         ← entspricht unseren 0x30/0x31
CMD_CH_EPG_DESC_LENGTH / CMD_CH_EPG_DESC_DATA ← entspricht 0x35/0x36
CMD_CH_INFO_LENGTH / CMD_CH_INFO_DATA        ← entspricht 0x32/0x33
CMD_CH_LIST_LENGTH / CMD_CH_LIST_DATA        ← Kanalliste (Länge + Daten)
```

### Scan
```
CMD_START_SCAN / CMD_STOP_SCAN
CMD_PERFORM_AUTO_SCAN_RF / CMD_PERFORM_AUTO_SCAN_IPTV
CMD_START_SCAN_DVBS / CMD_START_SCAN_DVB_IPTV
CMD_CB_START_SCAN_RESULT / CMD_CB_START_SCAN_STATUS
CMD_CB_STOP_SCAN_RESULT
CMD_CH_MANUAL_SCAN_LIST_LENGTH / _DATA
```

### Signal & Tuner
```
CMD_GET_SIGNAL_STATUS   ← entspricht 0x02 Signal-Poll
CMD_GET_TUNER_STATUS
CMD_TUNER_SET / CMD_TUNER_SCAN / CMD_TUNER_SET_MODE
CMD_TUNER_DVBS2_SET / _SET_DISEQC / _SET_LNB / _SET_SATELLITE
CMD_TUNER_STANDBY / CMD_TUNER_DONGLE_REBOOT / CMD_TUNER_DONGLE_REBOOT_AND_FRESH
```

### Player
```
CMD_PLAYER_SWITCH_CHANNEL / CMD_PLAYER_FORCE_CH_SWITCH
CMD_PLAYER_CHANGE_AUDIO_MODE / CMD_PLAYER_CHANGE_SUBTITLE
CMD_PLAYER_REC (Aufnahme starten) / CMD_PLAYER_STOP_PLAYBACK
CMD_VLC_STOP_PLAY / CMD_VLC_DESTROY_PLAYER
```

### Sicherheit (CI+/CAS)
```
CMD_SECURE_CH_FUSE_OTP
CMD_SECURE_CH_GET_DONGLE_INFO
CMD_SECURE_CH_START_AUTH
CMD_SECURE_CH_START_CKC_KEYING  ← Content Key Confirmation
CMD_SECURE_CH_START_SAC_KEYING  ← Secure Authenticated Channel
CMD_CAS_IMCL_FORCE_TUNE
CMD_CAS_SHOW_MMI_MENU / CMD_CAS_HIDE_FINGERPRINT
CMD_GET_CAS_FLAG
```

### Dongle-Verwaltung
```
CMD_GET_ABOUT_DONGLE_INFO    → Firmware, Hardware, Seriennummer
CMD_NETWORK_DONGLE_DISCONNECTED
CMD_UPDATE_DONGLE_START / CMD_OTA_FIRMWARE_START
CMD_REBOOT_STB / CMD_POWER_OFF / CMD_CLOSE_APP
```

---

## 5. PIM-System (Proprietäres CA)

```
PIM = Proprietäres Middleware-System (kein Standard-CI+, parallel zu SAC)

Klassen:
  PimCarouselClient      ← EPG-Carousel über UDP
  PimCarouselClient-EPG  ← EPG-Daten
  PimCarouselClient-JSON ← JSON-Metadaten
  PimChannelMapper       ← prog_idx ↔ PIM-Kanal-Mapping
  PimDataSource          ← Datenquelle für Player
  PimDecrypt             ← pim_decode() / pim_set_key()

Konfiguration:
  PIM_CUST_CODE          ← Kundenschlüssel
  PIM_PMT_PID            ← PMT PID für CA-Descriptor
  PIM_UDP_TIMEOUT_MS     ← Timeout für UDP-Carousel
  PIM_CAROUSEL_TIMEOUT_MS

PIM-Modi:
  isPimMode / isPimScan / isPimDecrypt
  PimChannelSource (Enum)
  PIM;enc= (Stream-URL-Präfix für verschlüsselte PIM-Kanäle)
```

---

## 6. Kritische Erkenntnisse für Client-Implementierung

### CMD_CHANGE_CHANNEL_BY_SID_AND_PID – der echte Tune-Befehl

Die App nutzt **nicht nur den PAT-Index** (0x01 Payload=`00 04`), sondern hat mindestens 4 Tune-Varianten:
- `CMD_CHANGE_CHANNEL_BY_PROGIDX` → unser bisheriger Ansatz (0x01 + PAT-Index)
- `CMD_CHANGE_CHANNEL_BY_SID` → Service-ID direkt
- `CMD_CHANGE_CHANNEL_BY_SID_AND_PID` → Service-ID + Video-PID + Audio-PID
- `CMD_CHANGE_CHANNEL_BY_PROGIDX_AND_PID` → prog_idx + PIDs

**→ Vermutung:** Beim 0x01-Befehl könnte der Payload mehr als nur `00 04` enthalten.  
Evtl: `[0x00, PAT-Index, VPid-Hi, VPid-Lo, APid-Hi, APid-Lo]`

### chVPid / chAPid direkt verfügbar

Die DB speichert `chVPid=0x1338` und `chAPid=0x1339` direkt.  
**→ Diese PIDs können direkt für den 0x01-Tune-Befehl verwendet werden**, statt aus dem TS zu parsen.

### isDirectTune = 1

Das Feld `isDirectTune INTEGER DEFAULT 1` deutet darauf hin, dass Direktes Tune (APIX 0x01) der Standardweg ist, und IPTV/OTT alternative Wege sind.

### CMD_ALLOW_TO_WRITE_TO_GET_STREAM

Dieser Befehl entspricht wahrscheinlich unserem `0xF8/0x07` Stream-Freigabe-Befehl.

---

## 7. Offene Punkte nach APK-Analyse

- [ ] **0x01-Payload-Struktur** verifizieren: Enthält er neben PAT-Index auch VPid/APid? → Ghidra auf DEX
- [ ] **CMD_CH_LIST_LENGTH / CMD_CH_LIST_DATA** – entspricht das dem `0xF9/0x0A`-Block oder einem eigenen TCP-Befehl?
- [ ] **PIM-Protokoll**: Wie wird `pim_set_pmt_pid` + `pim_set_key` mit dem APIX-Protokoll kombiniert?
- [ ] **DongleCommunicationManager**: Unterschied des internen Protokolls zwischen `initNetworkDongleCommunication` (TCP/UDP) und `initUsbDongleCommunication` weiter untersuchen. Für den konkret identifizierten WISI OR S2D beschreibt das Handbuch USB für Firmware-Upgrade beziehungsweise direkte Verbindung zu einer Android-TV-Box; bei direkter USB-Verbindung wird die Netzwerkfunktion deaktiviert. Das belegt keinen USB-Streamingmodus für beliebige Android-Tablets oder PCs. Siehe [OR-S2D-Update- und USB-Recherche](or_s2d_firmware_update.md).
- [ ] **dongleUsbProtocol / dongleUsbProtocolVariant**: Welche Werte? Könnten die Protokoll-Version angeben
- [ ] **dongleIsNewIPTVProtocolEnabled**: Anderes Protokoll für IPTV-Kanäle?
