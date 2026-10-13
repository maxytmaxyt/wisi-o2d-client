## Was die neue Spezifikation konkret freischaltet

Die alte "Deep Research" war KI-Spekulation über einen unbekannten Dongle. Die neue Spezifikation ist **gematchtes Wissen** – sie beschreibt exakt dein Gerät (OR S2D / TiViCon) und deckt sich an vielen Stellen mit dem was wir aus dem PCAP und APK schon wissen. Das eröffnet mehrere konkrete Angriffsvektoren:

---

### 1. Die USBC-Paketstruktur ist jetzt erklärbar

Das PCAP zeigt Pakete mit dem Header `55 53 42 43 A0 CB 03 37` — also `USBC` gefolgt von Magic-Bytes. Die neue Spec bestätigt: der TCP-Port **8802** ist derselbe wie der UDP-Discovery-Port. **Neu erkannt:** Der Magic Value `0x54563253` = `TV2S` gilt für Discovery-UDP. Der `USBC`-Header im TCP-Stream ist das **Bulk-Transfer-Wrapping** des APIX-Protokolls über TCP — also dieselbe Paketstruktur wie im USB-Modus, aber über TCP getunnelt. Das erklärt warum TCP 8802 und USB dieselben Opcodes (`0xF6`, `0xF8`, `0xF9`) verwenden.

**Konsequenz:** Wir können jetzt die PCAP-Pakete direkt mit der USB-Befehlstabelle mappen:
- `0xF6 0x02` = `CMD_GET_STATUS` (Signal Lock, CNR, BER) ✓ passt zu den 13-Byte-Antworten mit Stärke/Qualität
- `0xF6 0x01` = Tune-Trigger → entspricht `CMD_STREAM_CTRL 0x20` (Start)
- `0xF8 0x07` = wahrscheinlich `CMD_TUNER_INIT 0x10` oder der PID-Filter-Flush

---

### 2. Die `0x01`-Payload-Frage ist lösbar

Das PCAP zeigt `0x01` Payload `00 04` und wir wussten nicht ob das ein PAT-Index ist. Die neue Spec sagt: Tuning geht über **PID-Liste** (`CMD_SET_PID_FILTER 0x18`, Slot-Index + PID-Wert). Die APK zeigt `CMD_CHANGE_CHANNEL_BY_SID_AND_PID` mit `chVPid=0x1338`, `chAPid=0x1339`.

**Konsequenz:** Das `0x01`-Paket enthält höchstwahrscheinlich `[s_id_hi, s_id_lo]` oder `[prog_idx_byte, slot]` — **nicht** den PAT-Index. Prog 4914 = `0x1332`. Payload `00 04` passt nicht als s_id. Aber: die Spec sagt LNB 13V = Byte `0x00`, 18V = `0x01` — Payload `00 04` könnte `[LNB-Voltage=13V, DiSEqC-Port=A]` sein. Das wäre der Pre-Tune-Setup-Befehl, nicht der eigentliche Kanal-Select. **Test-Kandidat #1.**

---

### 3. Die EPG-Sequenz ist vollständig verstehbar

PCAP: `0x30/0x31` = Länge/Daten EPG-XML, `0x32/0x33` = ch_Info, `0x35/0x36` = Event-Desc. Die APK bestätigt:
- `CMD_CH_EPG_LENGTH` / `CMD_CH_EPG_DATA` → `0x30/0x31`
- `CMD_CH_INFO_LENGTH` / `CMD_CH_INFO_DATA` → `0x32/0x33`
- `CMD_CH_LIST_LENGTH` / `CMD_CH_LIST_DATA` → **noch nicht im PCAP gesehen** — das könnte `0xF9/0x0A` sein, der 32.740-Byte-UDP-Block der bisher unbekannt ist

**Konsequenz:** `0xF9/0x0A` ist wahrscheinlich `CMD_CH_LIST_DATA` — die komplette Senderliste als Binär-Blob. Das erklärt die 200 Requests à 32 KB und warum der Inhalt kein MPEG-TS ist.

---

### 4. Die kryptografische Auth ist entkopselbar

Die Spec beschreibt: `SessionToken = MD5(Challenge ‖ SharedSecret ‖ Timestamp)`. Das `SharedSecret` liegt in `libtv2smart_native.so`. Die APK haben wir bereits analysiert. **Wir haben die .so-Datei** (war Teil des APK-Reverse-Engineerings).

**Konsequenz:** Mit `strings libtv2smart_native.so | grep -E '[a-f0-9]{16,}'` oder `radare2`/`Ghidra` lässt sich der hardcoded Key extrahieren. Sobald der Key bekannt ist, können wir gültige Session-Tokens für beliebige Challenges generieren — ohne die App.

---

### 5. Der Scan-Modus öffnet eine neue Methode

Die APK listet `CMD_START_SCAN_DVBS` / `CMD_CB_START_SCAN_STATUS`. Das bedeutet: der Dongle kann selbstständig scannen und liefert Ergebnisse zurück. Das PCAP wurde bei einem laufenden Kanal aufgezeichnet — **wir haben noch kein Scan-PCAP**.

**Konsequenz:** Ein Scan-PCAP wäre der einfachste Weg, die `0x01`-Payload-Struktur zu verstehen, weil beim Scan alle Kanäle sequenziell durchgegangen werden. Payload-Unterschiede zwischen Kanal 1 und Kanal 2 würden sofort zeigen was sich ändert.

---

### 6. `CMD_GET_ABOUT_DONGLE_INFO` — Firmware-Info abgreifbar

Die APK kennt diesen Befehl. Die Spec bestätigt dass Firmware-Version im Discovery-Response steht (`"fw_version": "3.M2026"`). **Wir können diesen Befehl direkt auslösen** ohne PCAP — einfach den passenden Opcode senden und schauen welcher TCP-Befehl eine Antwort mit `fw_version` liefert. Brute-force-sicher da nur ~10 unbekannte Opcodes übrig sind.

---

### Prioritätsliste für nächste Schritte

| Priorität | Aufgabe | Methode |
|---|---|---|
| 🔴 1 | `SharedSecret` aus `libtv2smart_native.so` extrahieren | `strings` / Ghidra |
| 🔴 2 | `0xF9/0x0A`-Blob-Inhalt dekodieren | Python-Script auf PCAP-Rohdaten |
| 🟡 3 | Scan-PCAP aufzeichnen | PCAPdroid + TV2Smart: Sendersuchlauf starten |
| 🟡 4 | `0x01`-Payload mit anderem Kanal testen | 2. PCAP mit anderem Sender |
| 🟢 5 | `CMD_GET_ABOUT_DONGLE_INFO` Opcode durch Trial finden | Python-Client, alle Opcodes 0x04–0x1F testen |
| 🟢 6 | Vollständigen Client ohne Auth-Token implementieren | Basierend auf bekannten Opcodes |

Die wichtigste Erkenntnis: **das Protokoll ist kein HTTP/JSON** wie die Spec spekuliert — es ist das APIX-Binärprotokoll über TCP 8802, das wir aus dem PCAP bereits fast vollständig kennen. Die neue Spezifikation liefert hauptsächlich die **Semantik** der Bytes die wir sehen, aber nicht die Struktur selbst.
