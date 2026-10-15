# Projekt-Hinweise für Agenten

## Schnellorientierung

Dieses Repo enthält einen reverse-engineerten Python-Client für den **WISI OR S2D / TiViCon DVB-over-IP-Dongle**.

| Was | Wo |
|---|---|
| Aktiver Client | `src/wisi_client.py` (Hauptimplementierung) |
| CLI-Einstieg | `src/wisi.py --help` |
| Protokoll-Layer | `src/protocol.py` (USBC-Builder, Konstanten) |
| Legacy-Referenz | `archive/` (nicht anfassen) |
| Forschungsstand | `research/README.md` ← zuerst lesen |
| Neue Erkenntnisse (APK+Spec) | `research/neue_erkenntnisse.md` |
| PCAP-Auswertung | `research/pcap_analysis.md`, `research/or_s2d_protocol_analysis.md` |
| APK-Befunde | `research/apk_reverse_engineering.md` |
| Mitschnitte | `research/*.pcap` |

---

## Belastbarer Stand (Oktober 2026)

- ✅ USBC/APIX-Rahmenformat (31 Byte CBW + 13 Byte USBS-Trailer) bestätigt
- ✅ TCP-Init-Sequenz (`0x16`/`0x17`) und Keep-Alive implementiert
- ✅ Senderliste via TCP `0xF6/0x20` + `0xF6/0x21` (XML, 440 Kanäle)
- ✅ EPG via TCP `0x30/0x31`, `0x32/0x33`, `0x35/0x36`
- ✅ Signal-Polling via `0x02`
- ✅ Tune-Ablauf: `0x03` → `0x01` → `0xF8/0x07` → `0x17`
- ✅ UDP-Pull-Schleife: `0xF9/0x02` → `0xF9/0x01` (MPEG-TS-Blöcke)
- ✅ `0xF9/0x0A` als Speedtest (nicht Senderliste!) identifiziert
- ✅ APK statisch analysiert: APIX-Methoden, USBC-Builder, Native-Lib bekannt

---

## Nächste Schritte (Priorität)

### 🔴 1 – `0x01`-Payload für Kanalwechsel klären

**Problem:** Der aktuelle Client verwendet hardcodierten `pat_idx=4`. Kanalwechsel zu anderen Sendern funktioniert vermutlich nicht.

**Was zu tun ist:**
- Neues PCAP aufzeichnen: In der TV2Smart-App auf einen *anderen* Sender wechseln (z. B. Kanal 2, dann Kanal 50)
- In `research/PCAPdroid_12_Okt._16_28_17.pcap` sind die `0x01`-Bytes `00 04` – das entspricht PAT-Index 4. Vergleich mit einem zweiten PCAP würde zeigen, ob sich Byte[21] oder Byte[22] im USBC ändert.
- Alternativ: `src/wisi_probe.py` erweitern, um `0x01` mit verschiedenen Payloads zu senden und die USBS-Antwort zu vergleichen.
- Zieldatei: `src/wisi_client.py` → Methode `_cmd_tune()` bzw. `_cmd_prepare()`.

**Hypothesen (aus `research/neue_erkenntnisse.md`):**
- Payload könnte `[s_id_hi, s_id_lo]` (Service-ID) sein
- Oder `[prog_idx_byte3, slot]`
- Oder LNB-Voltage + DiSEqC-Port (weniger wahrscheinlich da konstant)

---

### 🔴 2 – Livestream live testen und Fehler beheben

**Problem:** Der Tune+Stream-Ablauf ist implementiert aber nie als vollständiger Live-Erfolg bestätigt worden. Bekannte Bugs in `wisi_menu.py`-Kommentar: falsches `_cmd_prepare`-Payload, gemischtes USBS-Lesen, zu spätes UDP-Bind.

**Was zu tun ist:**
- Client gegen echten Dongle laufen lassen: `python src/wisi.py --ip 192.168.178.32 --stream --output - | vlc -`
- Wenn kein Bild: `--debug` aktivieren und Paket-Trace mit PCAP vergleichen
- USBS-Lesefehler: in `wisi_client.py` sicherstellen, dass nach jedem TCP-Command der 13-Byte-USBS-Trailer vollständig gelesen wird (kein Mixing mit dem nächsten Antwort-Payload)
- UDP-Bind-Timing: UDP-Socket muss **vor** dem ersten `0xF8/0x07`-Befehl gebunden sein

---

### 🟡 3 – Scan-PCAP aufzeichnen

**Problem:** Es existiert kein Mitschnitt eines Sendersuchlaufs. Ein Scan-PCAP würde die `0x01`-Payload-Frage (Schritt 1) direkt lösen, weil alle Kanäle sequenziell durchlaufen werden.

**Was zu tun ist:**
- PCAPdroid auf Android starten
- TV2Smart-App öffnen → Einstellungen → Sendersuchlauf starten
- PCAP aufzeichnen und in `research/` ablegen
- Mit `python src/wisi.py --pcap research/scan_DATUM.pcap` auswerten

---

### ✅ 4 – `SharedSecret` aus Native-Lib extrahieren (abgeschlossen, 15. Oktober 2026)

**Ergebnis:** Analyse von `libsecure_module.so` aus `config.arm64_v8a.apk` abgeschlossen. Details in `research/apk_reverse_engineering.md` → Abschnitt "Native-Library-Analyse".

**Wichtigste Erkenntnisse:**
- In `libsecure_module.so` (.rodata) gefunden: `THVrZVJhbkRvbHBoQ0krMQ==` → dekodiert: **`LukeRanDolphCI+1`**
- Dieser String ist ein Root-Key/Seed für die `CNKEY`-Derivation-Chain im CI+-artigen Content-Control-Protokoll
- Das CC/SAC-Protokoll ist **ausschließlich für Pay-TV** (verschlüsselte Kanäle, `0x48xxxxxx`-prog_idx)
- Für **FTA-Streaming braucht man diese Auth nicht** – keine SAC-Handshake-Pakete in FTA-PCAPs
- Die frühere Formel `MD5(Challenge ‖ SharedSecret ‖ Timestamp)` ist falsch: `libsecure_module.so` nutzt SHA-256 + AES, kein MD5
- Die App enthält weder `libtivicon_dvb.so` noch `libstream_decoder.so` (frühere Notizen falsch)

**Offen für spätere Pay-TV-Arbeit:** DH-Parameter (`dh_g`, `dh_p`, `dh_q`) und CNKEY-Chain-Werte sind im Binary, aber ohne Ghidra-Disassembly nicht vollständig extrahierbar.

---

### 🟢 5 – Unbekannte Opcodes durch Trial-and-Error finden

**Problem:** Einige Opcodes aus dem APK-SDK (`CMD_GET_ABOUT_DONGLE_INFO`, `CMD_START_SCAN_DVBS`, etc.) haben keinen bestätigten Opcode-Wert.

**Was zu tun ist:**
- `src/wisi_probe.py` verwenden: `python src/wisi.py --ip 192.168.178.32 --probe-opcode 0x12`
- Alle Opcodes `0x04` bis `0x1F` testen (die laut APK noch unbekannt sind)
- Antworten loggen: USBS-Status-Byte[0] = `0x00` → Erfolg, `0x01` → Fehler
- Ergebnisse in `research/pcap_analysis.md` unter "Bekannte Opcodes" ergänzen

---

### 🟢 6 – `0xF9/0x0A`-Rohblob vollständig analysieren (optional)

**Problem:** Der 48.143-Byte-Blob vom 13. Oktober liegt nicht im Repo. Seine genaue Struktur (Füllmuster, Abschlussbytes) ist unbestätigt.

**Was zu tun ist:**
- Nur relevant wenn ein neuer vollständiger Mitschnitt entsteht
- Prüfen: Beginnt der Blob mit `f9 0a`? Folgt danach ein Null-Bereich? Wie sind die letzten 13 Bytes (USBS-Trailer)?
- `src/wisi_pcap.py` kann mit `--pcap-extract` den Rohblob aus einem PCAP extrahieren
- **Nicht** als Senderliste interpretieren – das ist ein Speedtest-Buffer (APK-SDK bestätigt)

---

## Wichtige Nicht-Ziele / Fallen

- `0xF9/0x0A` ist **kein** Senderlisten-Befehl → nicht als Service-DB dekodieren
- `wisi_menu.py` ist **Legacy** → Änderungen gehören in `wisi_client.py`
- `protocol_spec_or_s2d.md` enthält **unbestätigte Spekulation** → nicht als Implementierungsgrundlage nutzen
- `fetch_service_db()` in `wisi_client.py` ist **deaktivierter Legacy-Code** → nicht reaktivieren

---

## Hintergrund-Notizen (aus vergangener Analyse)

Die `0xF9/0x0A`-Antworten in den PCAPs (32.740 Byte) und der beschriebene 48.143-Byte-Speedtest-Buffer sind **unterschiedliche Dinge** – nicht gleichsetzen. Die PCAP-Antworten beginnen zwar mit `f9 0a`, enthalten aber fast nur Null-Bytes und ergeben null geparste Einträge. Der APK-Code liest 48.130 Datenbytes + 13 USBS-Bytes = 48.143 Byte total und berechnet damit Mbps – das ist die korrekte Einordnung.

Forschungsübersicht: `research/README.md`  
APK-Befunde: `research/apk_reverse_engineering.md`  
PCAP-Auswertung: `research/pcap_analysis.md`  
Relevante Implementierung: `src/wisi_client.py`, `src/protocol.py`, `src/wisi_pcap.py`
