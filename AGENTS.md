# Projekt-Hinweise für Agenten

## Abgeschlossen: `0xF9/0x0A`-Antwort eingeordnet

Die vorhandenen PCAPs wurden am 14.10.2026 mit `src/wisi_pcap.py` und einer direkten UDP-Payload-Auswertung verglichen. Zusätzlich wurde die am 14.10. hochgeladene TV2Smart-XAPK statisch untersucht:

- `research/capture_pcapdroid_2026-10-11.pcap`: 200 `0xF9/0x0A`-Anfragen, 198 Antworten mit je 32.740 Byte. Die Antworten beginnen mit `f9 0a`, enthalten nur zwei Nicht-Null-Bytes und ergeben null geparste Einträge.
- `PCAPdroid_12_Okt._16_16_04.pcap`: 400 `0xF9/0x0A`-Anfragen; auf UDP/8800 sind zwei 13-Byte-`USBS`-Antworten enthalten, kein großer Service-DB-Blob.
- `PCAPdroid_12_Okt._16_28_17.pcap`: 200 `0xF9/0x0A`-Anfragen; eine 13-Byte-`USBS`-Antwort, kein großer Service-DB-Blob.
- Im APK-SDK baut `getSpeedTestMbps()` einen `0xF9/0x0A`-Request mit `data_len=48.128` und verwendet die Antwort ausschließlich zur Durchsatzmessung. Der SDK-Transport liest 48.130 Datenbytes plus 13 Abschlussbytes, also genau 48.143 Byte. Die gemeldete Antwortlänge und das `f9 0a`-Präfix passen damit zum Speedtest, nicht zu einer Senderdatenbank.
- Der Rohblob vom 13.10. liegt weiterhin nicht vor. Seine vollständige Byteverteilung ist daher nicht direkt bestätigt; Rolle und Länge sind durch den APK-Code jedoch schlüssig erklärt.

Der PCAP-Vergleich und die funktionale Einordnung der 48.143-Byte-Antwort sind abgeschlossen. Keine Senderdatenbank als decodiert ausgeben und die 48.143-Byte-Antwort nicht mit den 32.740-Byte-PCAP-Antworten gleichsetzen.

## Aktueller Implementierungspfad

`--channels` lädt die OR-S2D-Kanalliste über TCP `0xF6/0x20` und `0xF6/0x21` (XML). `fetch_service_db()` ist ein deaktivierter Legacy-Pfad. `0xF9/0x0A` ist im APK-SDK als Speedtest belegt, nicht als OR-S2D-Senderliste. Ein erfolgreicher TCP-Handshake allein belegt noch keinen erfolgreichen Live-Abruf der XML-Liste.

Für eine bytegenaue Bestätigung bleibt ein vollständiger Mitschnitt der 48.143-Byte-Antwort nützlich. Zu prüfen sind Richtung/Ports, UDP-Länge, Paketgrenzen und Abschlussbytes. Ping belegt nur IP-Erreichbarkeit.

Forschungsübersicht: `research/README.md`. APK-Befunde: `research/apk_reverse_engineering.md`. PCAP-Auswertung: `research/pcap_analysis.md`. Relevante Implementierung: `src/wisi_client.py`, `src/wisi_common.py` und `src/wisi_pcap.py`.
