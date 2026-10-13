# Systemanalyse und Protokoll-Spezifikation — WISI OR S2D / Schwaiger DSRD0100 / TiViCon DVB-S2 Dongle

> **Hinweis:** Dieses Dokument basiert auf eigener Systemanalyse, USB-Protokoll-Mitschnitten (PCAPdroid) und Dekompilierungsdaten der zugehörigen Android-Applikationen (`com.tivicon.tv2smart.mobile` und `com.tivicon.tv2smart.atv`). Es beschreibt das **WISI OR S2D** – nicht den OR O2D.

---

## Hardware-Architektur und Systemplattform

Der Schwaiger DSRD0100 und der WISI OR S2D greifen auf ein gemeinsames OEM-Referenzdesign des Herstellers **TiViCon** zurück. Die Hardwarearchitektur kombiniert:

- HF-Tuner für DVB-S/S2
- Demodulator-Baustein
- Eingebettetes System-on-Chip (SoC) auf ARM-Basis
- Fast-Ethernet- bzw. Dual-Band-WLAN-Schnittstelle (2,4 GHz und 5 GHz)
- Physischer USB-C-Anschluss (Stromversorgung oder bidirektionale Datenschnittstelle)

### Betriebsmodi

| Modus | Beschreibung |
|---|---|
| **Netzwerk-Streaming-Modus** | Dongle als eigenständiger Server im LAN/WLAN. Embedded-Linux verwaltet Tuner-Hardware, demultiplext Transportströme und verteilt Elementary Streams via UDP-Unicast oder HTTP. |
| **USB-Host/OTG-Modus** | Direkte Anbindung an Android-Set-Top-Box, Tablet oder Smartphone. WLAN deaktiviert; gesamte Steuerung und Nutzdatenübertragung über herstellerspezifische USB-Control- und Bulk-Endpunkte. |

---

## Netzwerkbasierte Protokoll-Spezifikation (WLAN/LAN)

### 1. Broadcast Discovery und Gerätelokalisierung

Die App sendet eine Discovery-Anfrage an `255.255.255.255:8802` (UDP). Das Suchpaket nutzt einen fest definierten **16-Byte-Header** gefolgt von einer JSON-codierten Payload.

| Offset (Bytes) | Feldbezeichnung | Datentyp | Wert / Beschreibung |
|---|---|---|---|
| `0x00–0x03` | Magic Value | `uint32_t` | `0x54563253` (ASCII: `"TV2S"`) |
| `0x04–0x05` | Protocol Version | `uint16_t` | `0x0100` (Version 1.0) |
| `0x06–0x07` | Opcode | `uint16_t` | `0x0001` (`DISCOVERY_REQUEST`) |
| `0x08–0x0B` | Sequence ID | `uint32_t` | Fortlaufender Transaktionszähler der App |
| `0x0C–0x0F` | Payload Length | `uint32_t` | Länge des nachfolgenden JSON-Strings |
| `0x10–End` | Payload Data | ASCII/JSON | `{"cmd":"DISCOVER_DONGLE","app_id":"com.tivicon.tv2smart"}` |

**Antwort des Dongles** (Unicast-UDP an Quell-IP/-Port):

```json
{
  "status": "OK",
  "device_name": "Schwaiger DSRD0100",
  "hw_version": "v2.1",
  "fw_version": "3.M2026",
  "mac": "00:1A:9B:XX:XX:XX",
  "tuner_type": "DVB-S2",
  "http_port": 8080,
  "control_port": 8802,
  "stream_port": 9000,
  "busy": false
}
```

---

### 2. Kontrollkanal und Session-Token-Handshake

TCP-Steuerverbindung zu Port `8080` oder `8802`. Da der DVB-S2-Tuner nur auf eine Transponderfrequenz gleichzeitig abgestimmt werden kann, erzwingt das Protokoll **exklusives Sitzungsmanagement**.

- **Session starten:** `POST /api/v1/session/start`
- **Keepalive (alle 10 s):** `POST /api/v1/session/keepalive`
- Jeder Steuerbefehl muss den Token im HTTP-Header `X-TiViCon-Token` mitsenden.
- Bleibt Keepalive aus → Firmware bricht Transportstream ab und gibt Tuner frei.

**Tune-Befehl:**

```json
{
  "action": "TUNE_CHANNEL",
  "session_token": "a14aeb377...",
  "params": {
    "frequency_khz": 12544000,
    "symbol_rate_ksps": 22000,
    "polarization": "H",
    "fec": "5/6",
    "standard": "DVB-S",
    "modulation": "QPSK",
    "diseqc": {
      "port": "DiseqcA",
      "tone_burst": "None",
      "22khz": true,
      "voltage": "18V"
    },
    "pids": [0, 16, 17, 18, 98, 255, 256]
  }
}
```

LNB-Spannungsschaltung: **13 V** = vertikal, **18 V** = horizontal. Das 22-kHz-Signal schaltet zwischen Low- und High-Band.

---

### 3. Transportstream-Übertragung und IP-Kapselung

Die Firmware gruppiert exakt **7 DVB-TS-Pakete à 188 Bytes** in einer UDP-Payload:

```
Nutzdatenlänge = 7 × 188 Bytes = 1316 Bytes
Gesamtrahmen   = 1316 + 20 (IP) + 8 (UDP) = 1344 Bytes  (< 1500 Byte MTU → keine Fragmentierung)
```

Alternativ HTTP-Chunked-Streaming: `http://<DONGLE_IP>:8080/live/stream.ts?sid=<TOKEN>`

---

## Direct-USB-C-Kommunikation und USB-Host/OTG-Protokoll

### USB-Schnittstellenspezifikation und Deskriptoren

Der Dongle meldet sich als **Vendor-Specific Device (Class 0xFF)**:

| Parameter | Wert |
|---|---|
| Vendor ID (idVendor) | `0x1F3A` oder `0x0BDA` (OEM-SoC-Kennung) |
| Product ID (idProduct) | `0x8802` oder `0x0100` (TiViCon DVB-S2) |
| USB-Spezifikation | USB 2.0 High-Speed (480 Mbit/s brutto) |

**Endpunkte:**

| Endpunkt | Richtung | Funktion |
|---|---|---|
| Bulk OUT `0x01` | Host → Gerät | Steuerkommandos, Filterkonfigurationen |
| Bulk IN `0x81` | Gerät → Host | Kontinuierlicher Demultiplexer-Datenstrom |

---

### USB Vendor-Control-Requests (EP0)

`bmRequestType = 0x40` (Host-to-Device, Vendor, Device)

| `bRequest` | Befehlsname | `wValue` | `wIndex` | Funktion |
|---|---|---|---|---|
| `0x10` | `CMD_TUNER_INIT` | `0x0001` | `0x0000` | Tuner-Frontend initialisieren, LNB-Versorgung aktivieren |
| `0x12` | `CMD_SET_FREQ` | Frequenz High-Word | Frequenz Low-Word | Zwischenfrequenz in kHz setzen |
| `0x13` | `CMD_SET_SR` | SR High-Word | SR Low-Word | Symbolrate in kS/s konfigurieren (z. B. 22000) |
| `0x14` | `CMD_SET_LNB` | Spannung/Polarisation | 22-kHz-Schaltung | `0x00`=13 V, `0x01`=18 V; Index `0x01`=22kHz an |
| `0x18` | `CMD_SET_PID_FILTER` | Filter-Slot Index | PID-Wert | PID in Hardware-Filterregister schreiben |
| `0x20` | `CMD_STREAM_CTRL` | `0x0001`/`0x0000` | `0x0000` | Stream auf Bulk EP `0x81` starten/stoppen |
| `0x80` | `CMD_GET_STATUS` | `0x0000` | `0x0000` | Tuner-Status lesen (Signal Lock, CNR, BER) – Device-to-Host (`0xC0`) |

---

### Ringpuffer-Verwaltung und USB-Streaming

Nach `CMD_STREAM_CTRL` liefert der Dongle den Demux-Datenstrom ununterbrochen über Bulk IN `0x81`. Pufferkonzept der Tv2Smart-App:

- Dedizierter C++-Hintergrund-Thread ruft `UsbDeviceConnection.bulkTransfer()` auf.
- Zirkuläre **Ringpuffer à 64 KB** (= 128 USB-HS-Pakete à 512 Bytes).
- Separater Verarbeitungs-Thread sucht DVB-Synchronisationsbyte `0x47`, richtet auf 188-Byte-Grenzen aus, verwirft fehlerhafte Sequenzen.

---

## Dekompilierungs-Analyse der Tv2Smart-Applikation

### Manifest-Analyse und Systemintegration

- `android.permission.USB_PERMISSION` + Intent-Filter `USB_DEVICE_ATTACHED` → App startet automatisch beim Einstecken des Dongles.
- `FOREGROUND_SERVICE_CONNECTED_DEVICE` + `FOREGROUND_SERVICE_MEDIA_PLAYBACK` → priorisierter Hintergrundbetrieb.
- `READ_EPG_DATA` / `WRITE_EPG_DATA` → DVB-EIT-Tabellen werden in nativen Android-TV-Programmführer geschrieben.

### Software-Architektur und Native JNI-Schnittstellen

Dreischichtige Architektur:

| Schicht | Technologie | Funktion |
|---|---|---|
| Obere Schicht | Java/Kotlin | UI, Programmlisten, Benachrichtigungen |
| Mittlere Schicht | Java/Kotlin | `DvbUsbController`, `DvbNetworkController` |
| Untere Schicht (native) | C/C++ via JNI | Zeitkritische Hardware-Kommunikation |

**Native Bibliotheken:**

- `libtv2smart_native.so` – Sitzungsverwaltung, Challenge-Response, Protokoll-Serialisierung
- `libtivicon_dvb.so` – DVB-PSI/SI-Parsing (PAT, PMT, SDT, EIT), Hardware-PID-Filtering, USB-Direktkommunikation
- `libstream_decoder.so` – TS-Vorverarbeitung, Android MediaCodec-Ansteuerung

**JNI-Methodensignaturen (aus `libtivicon_dvb.so`):**

```c
Java_com_tivicon_tv2smart_service_DvbUsbController_nativeInitUsb(
    JNIEnv* env, jobject thiz, jint fd, jint endpoint_in, jint endpoint_out)

Java_com_tivicon_tv2smart_service_DvbUsbController_nativeTune(
    JNIEnv* env, jobject thiz, jint freq_khz, jint symbol_rate, jint pol, jint diseqc)
```

---

### Kryptografische Authentifizierung

Challenge-Response-Verfahren mit in `libtv2smart_native.so` abgelegtem Schlüssel:

```
SessionToken = MD5(Challenge ‖ SharedSecret ‖ Timestamp)
```

Bei ungültigem Token bricht die Firmware die Steuerbefehle ab und verweigert die Demux-Ausgabe. Schützt vor ungewollten Zugriffen im Heimnetz, stellt jedoch **keine Barriere gegen professionelles Reverse-Engineering** dar.

---

## Vergleichende Systemmatrix

| Systemparameter | Netzwerk-Modus (WLAN/LAN) | USB-Host / OTG-Modus |
|---|---|---|
| Übertragungsmedium | Wi-Fi 802.11a/b/g/n/ac oder Ethernet RJ-45 | USB 2.0 High-Speed direkt via USB-C |
| Topologie | Punkt-zu-Multipunkt (1 Master-Tuner + N Slaves) | Punkt-zu-Punkt (1 Dedicated Host) |
| Geräte-Erkennung | UDP-Broadcast auf Port 8802 | USB Bus Enumeration (VID:PID-Filter) |
| Steuerungskanal | HTTP/JSON-REST an Port 8080/8802 | USB Control Requests an EP0 |
| Nutzdaten-Transport | UDP Unicast (7 TS-Pakete / Frame) | USB Bulk IN Transfers an EP `0x81` |
| Latenzverhalten | Mittel (150–400 ms Netzwerk-Puffer) | Sehr gering (< 30 ms Direktübertragung) |
| Energieversorgung | Externes Netzteil an USB-C Buchse | Bus-Powered durch das Android-Hostgerät |
| EPG-Bereitstellung | Vorverarbeitetes JSON oder DVB-EIT Stream | DVB-EIT Demultiplexing auf dem Host |

---

## Technische Bewertung und Ausblick

Das Design des WISI OR S2D / Schwaiger DSRD0100 / TiViCon DVB-S2 Dongles zeigt eine Architektur, die traditionelle DVB-Empfangstechnik mit IP-basierten Heimnetz-Szenarien verbindet. Die Auslagerung der DVB-PSI/SI-Filterung auf das eingebettete System des Dongles reduziert die CPU-Last auf mobilen Empfangsgeräten deutlich.

Die Aufteilung in Netzwerk-Modus und USB-Host-Modus erlaubt flexible Nutzung:
- **USB-OTG:** Autarke Nutzung ohne WLAN-Netzwerk
- **LAN/WLAN:** Kompakter SAT>IP-kompatibler Server für das ganze Haus

Für zukünftige Hardware-Revisionen ist eine Umstellung auf standardisierte TLS-Verschlüsselung sowie die strikte Implementierung des offenen **SAT>IP-Standards (RTSP/HTTP)** zu erwarten, um Abhängigkeiten von proprietären Apps zu verringern und Interoperabilität mit herstellerunabhängigen Playern zu gewährleisten.
