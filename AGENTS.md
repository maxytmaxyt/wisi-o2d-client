# Projekt-Hinweise für Agenten

## Abgeschlossen: Vergleich der Service-DB-Antworten

Die vorhandenen PCAPs wurden am 14.10.2026 mit `src/wisi_pcap.py` und einer direkten UDP-Payload-Auswertung verglichen:

- `research/capture_pcapdroid_2026-10-11.pcap`: 200 `0xF9/0x0A`-Anfragen, 198 Antworten mit je 32.740 Byte. Die Antworten beginnen mit `f9 0a`, enthalten nur zwei Nicht-Null-Bytes und ergeben null geparste Einträge.
- `PCAPdroid_12_Okt._16_16_04.pcap`: 400 `0xF9/0x0A`-Anfragen; auf UDP/8800 sind zwei 13-Byte-`USBS`-Antworten enthalten, kein großer Service-DB-Blob.
- `PCAPdroid_12_Okt._16_28_17.pcap`: 200 `0xF9/0x0A`-Anfragen; eine 13-Byte-`USBS`-Antwort, kein großer Service-DB-Blob.
- Die am 13.10. gemeldeten 48.143 Byte sind in keinem vorhandenen PCAP enthalten. Der Rohblob wurde nicht bereitgestellt. Sein Header-/Nullbereichs- und Nutzdatenlayout bleibt daher unbestätigt.

Damit ist der verfügbare PCAP-Vergleich erledigt, nicht aber die Dekodierung des 48.143-Byte-Blobs. Keine Senderdatenbank als decodiert ausgeben und die 48.143-Byte-Antwort nicht mit den 32.740-Byte-PCAP-Antworten gleichsetzen.

## Aktueller Implementierungspfad

`--channels` lädt die OR-S2D-Kanalliste über TCP `0xF6/0x20` und `0xF6/0x21` (XML). `fetch_service_db()` ist ein deaktivierter Legacy-Pfad; `0xF9/0x0A` ist keine bestätigte Kanalliste. Ein erfolgreicher TCP-Handshake allein belegt noch keinen erfolgreichen Live-Abruf der XML-Liste.

Für einen erneuten Vergleich den 48.143-Byte-UDP-Rohblob oder einen vollständigen PCAP mit Anfrage und Antwort sichern. Zu prüfen sind Richtung/Ports, UDP-Länge, tatsächliche Paketgrenzen, Header und Nicht-Nullbereiche. Ping belegt nur IP-Erreichbarkeit.

Forschungsübersicht: `research/README.md`. PCAP-Auswertung: `research/pcap_analysis.md`. Relevante Implementierung: `src/wisi_client.py`, `src/wisi_common.py` und `src/wisi_pcap.py`.
