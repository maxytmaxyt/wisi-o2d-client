# Research-Übersicht: WISI OR S2D

Stand: 14. Oktober 2026. Diese Seite bündelt die Ergebnisse und ordnet die vorhandenen Notizen nach Beleglage. Die Mitschnitte dokumentieren App-Verkehr; sie beweisen nicht automatisch, dass jeder Client-Ablauf live funktioniert.

## Belastbare Beobachtungen

- Die Kanallisten-Aufzeichnung vom 12. Oktober enthält TCP-Kommandos `0xF6/0x20`, `0xF6/0x21` und `0xF6/0x22`. Die Nutzdaten der Listenabfrage sind XML; die ausgewertete Liste umfasst 440 Kanäle (303 TV, 137 Radio). Der aktuelle Client lädt die Liste über TCP/8802.
- Der Stream-Mitschnitt enthält Kanalvorbereitung, Signalabfragen, Tune, Stream-Freigabe und UDP-Pulls auf Port 8800. Der Ablauf ist in der Implementierung vorhanden, aber nicht als vollständiger Live-Client-Erfolg bestätigt.
- `0xF9/0x0A` ist im hochgeladenen TV2Smart-APK-SDK als Speedtest belegt: `getSpeedTestMbps()` sendet dafür Requests mit `data_len=48.128`, zählt erfolgreiche Antworten und berechnet den Durchsatz mit 48.128. Im Netzwerkpfad werden 48.130 Datenbytes plus 13 Abschlussbytes gelesen, also 48.143 Byte. Der alte Client hat diese Testdaten fälschlich als Service-DB interpretiert.
- Im Mitschnitt vom 11. Oktober sind 200 Anfragen und 198 UDP-Antworten mit je 32.740 Byte vorhanden. Jede untersuchte Antwort beginnt mit `f9 0a`, enthält nur zwei Nicht-Null-Bytes und ergibt null Einträge im Legacy-Parser.
- Die beiden Mitschnitte vom 12. Oktober enthalten zusammen 600 `0xF9/0x0A`-Anfragen. Auf UDP/8800 sind darin zwei beziehungsweise eine 13-Byte-`USBS`-Antwort enthalten, aber keine große Service-DB-Antwort.
- Für den 13. Oktober wurde außerhalb der PCAPs eine Antwortlänge von 48.143 Byte mit `f9 0a`-Präfix und folgendem Nullbereich protokolliert. Diese Größe passt exakt zum Speedtest-Antwortpuffer im APK. Der Rohblob liegt nicht im Repository; Füllmuster und Abschlussbytes sind daher nicht direkt überprüft.

## Einordnung der Dokumente

| Datei | Inhalt und Vertrauensgrenze |
|---|---|
| [`or_s2d_protocol_analysis.md`](or_s2d_protocol_analysis.md) | Detaillierte Interpretation der beiden PCAPs vom 12. Oktober. Für Befehlsabläufe nützlich; Aussagen zu universellen Paketgrößen und Trailerformaten gegen den jeweiligen Transport und Mitschnitt prüfen. |
| [`pcap_analysis.md`](pcap_analysis.md) | Kompakte, paketbezogene Zählungen und Grenzen der verfügbaren PCAPs. |
| [`apk_reverse_engineering.md`](apk_reverse_engineering.md) | Statische Analyse von Manifest, DEX-Methoden, APIX-Request-Buildern und Native-Libraries; Befunde sind von echter Geräteausführung getrennt gekennzeichnet. |
| [`apk-report-com.tivicon.tv2smart.mobile.txt`](apk-report-com.tivicon.tv2smart.mobile.txt) | Automatisierter APK-Metadaten-/Berechtigungsbericht; keine Protokollspezifikation. |
| [`protocol_spec_or_s2d.md`](protocol_spec_or_s2d.md) | Breite System- und Protokollhypothesen. HTTP/REST, USB-Endpunkte, Discovery-JSON und einige Hardwaredetails sind durch die hier enthaltenen OR-S2D-PCAPs nicht bestätigt; nicht als Implementierungsgrundlage verwenden, ohne Primärbeleg. |
| [`or_s2d_firmware_update.md`](or_s2d_firmware_update.md) | Zusammenfassung der öffentlich dokumentierten Modell-, USB-C- und Update-Informationen samt Quellen. Keine vollständige PC-Flash-Anleitung gefunden. |

## Wichtige Abweichungen und offene Fragen

- In den neueren PCAPs sind die UDP-`0xF9/0x0A`-Anfragen 31 Byte und die sichtbaren UDP-Antworten 13 Byte lang. Das bestätigt nicht pauschal die in anderen Notizen genannten 66-Byte-Anfragen oder 46-Byte-`USBS`-Trailer; Framing muss pro Transport und Mitschnitt betrachtet werden.
- Der APK-Code erklärt die 48.143 Byte als Speedtest-Response-Größe; ohne Rohdaten bleiben konkrete Füll- und Abschlussbytes ungeprüft. Der TCP-Handshake ist davon unabhängig.
- Die APK-Message-Builder und die in den PCAPs erkannten APIX-Request-Payloads sind 31 Byte. Die frühere pauschale 66-Byte-Aussage ist durch die enthaltenen Artefakte nicht belegt; TCP wurde vom Analyzer nicht reassembliert.
- Die PCAP-Auswertung zählt APIX-Muster und dekodiert IPv4/UDP, reassembliert aber keine TCP-Streams und verwirft fragmentierte IPv4-Pakete. Ihre Zählungen sind kein vollständiger Protokoll-Reassembler.
- Derzeit ist die TCP-XML-Kanalliste der implementierte Senderlistenpfad. Die Funktion `fetch_service_db()` bleibt nur als deaktivierter Legacy-Einstieg bestehen.

Für eine bytegenaue Fortsetzung der `0xF9/0x0A`-Analyse ist ein vollständiger Mitschnitt samt Anfrage/Antwort oder der unveränderte 48.143-Byte-Rohblob hilfreich. Ports, Richtung, Paketgrenzen und Nicht-Nullbereiche müssen dabei erhalten bleiben.

## Verifikation

Die verfügbaren Mitschnitte lassen sich mit dem CLI untersuchen:

```bash
python src/wisi.py --pcap "PCAPdroid_12_Okt._16_16_04.pcap"
python src/wisi.py --pcap "PCAPdroid_12_Okt._16_28_17.pcap"
python src/wisi.py --pcap "research/capture_pcapdroid_2026-10-11.pcap"
```
