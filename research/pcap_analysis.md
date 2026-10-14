# PCAP-Auswertung

Stand: 14. Oktober 2026. Die Zahlen wurden mit `src/wisi_pcap.py` und einer zusätzlichen Auswertung der UDP-Payloads auf Port 8800 ermittelt. APIX-Zählungen erkennen `USBC`-Muster, rekonstruieren aber keine vollständigen TCP-Nachrichten.

## Mitschnitte

| Mitschnitt | IPv4-Pakete | `0xF9/0x0A`-Anfragen | Beobachtete UDP-Antwort auf Port 8800 |
|---|---:|---:|---|
| `research/capture_pcapdroid_2026-10-11.pcap` | 3.284 | 200 | 198 Antworten zu je 32.740 Byte |
| `PCAPdroid_12_Okt._16_16_04.pcap` | 940 | 400 | zwei 13-Byte-`USBS`-Antworten |
| `PCAPdroid_12_Okt._16_28_17.pcap` | 1.197 | 200 | eine 13-Byte-`USBS`-Antwort |

Im Mitschnitt vom 11. Oktober beginnen die großen Antworten mit `f9 0a`; über die gesamten 32.740 Byte sind jeweils nur zwei Bytes ungleich null. Der Legacy-Service-DB-Parser dekodiert daraus null Einträge. Die Antworten der beiden Mitschnitte vom 12. Oktober sind kurze `USBS`-Antworten; dort ist kein großer `0xF9/0x0A`-Blob aufgezeichnet.

Laut separat übermittelter Konsolenausgabe erhielt der Nutzer am 13. Oktober fünfmal eine 48.143-Byte-Antwort mit `f9 0a`-Präfix und Nullbytes am Anfang. Diese Größe und Antwortstruktur tauchen in keinem der drei gespeicherten Mitschnitte auf. Ohne Rohblob lässt sich weder der Unterschied erklären noch ein Datensatzlayout bestätigen.

## Weitere Beobachtungen

- Die Kanallisten-Aufzeichnung vom 12. Oktober enthält `0xF6/0x20`, `0xF6/0x21` und `0xF6/0x22` über TCP/8802. Das XML wurde in einer separaten Analyse mit 440 Einträgen ausgewertet.
- Der Stream-Mitschnitt enthält `0xF6/0x03`, `0xF6/0x32`, `0xF6/0x33`, `0xF6/0x01`, `0xF8/0x07` und `0xF9/0x01` sowie UDP-Streamverkehr.
- Die UDP-`0xF9/0x0A`-Requests in den neueren Mitschnitten sind 31 Byte lang; die sichtbaren Antworten sind 13 Byte. Das allein widerlegt oder bestätigt keine anders gerahmten TCP-Kommandos.

## Grenzen der Auswertung

`src/wisi_pcap.py` liest klassisches PCAP für Ethernet oder Raw IPv4 und extrahiert IPv4-/TCP-/UDP-Payloads. Es verwirft fragmentierte IPv4-Pakete, reassembliert TCP nicht und erkennt APIX-Kommandos durch Suche nach der Signatur `USBC`. Paket- und Kommandazahlen sind daher keine vollständige Rekonstruktion des TCP-Bytestroms. Insbesondere belegen sie kein allgemeingültiges USBS-Trailerformat.

Wiederholbare Analyse:

```bash
python src/wisi.py --pcap "PCAPdroid_12_Okt._16_16_04.pcap"
python src/wisi.py --pcap "PCAPdroid_12_Okt._16_28_17.pcap"
python src/wisi.py --pcap "research/capture_pcapdroid_2026-10-11.pcap"
```
