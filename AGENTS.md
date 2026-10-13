# Projekt-Hinweise für Agenten

## Aktueller Debug-Stand: Service-Datenbank

Am 13.10.2026 wurde `--channels` gegen `192.168.178.32` ausgeführt. Der TCP/APIX-Handshake auf Port 8802 ist erfolgreich: `0x16` meldet erst `0x00`, danach `0x01` (bereit). Die UDP-Abfrage `0xF9/0x0A` erhält in jedem der fünf Versuche 48.143 Byte, aber der vorhandene Parser findet darin keine Sender. Der Anfang der Antwort ist `f9 0a` gefolgt von Nullbytes.

**Wichtig für die Fortsetzung:** Der TCP-Handshake wurde inzwischen vor der UDP-Abfrage ergänzt und ist laut Ausgabe erfolgreich. Den Fehler daher nicht erneut auf fehlendes TCP-Init zurückführen. Ping bestätigt nur IP-Erreichbarkeit. Als Nächstes die tatsächlichen UDP-Antworten und das Protokollformat vergleichen: insbesondere Antwortlänge `48.143` (entspricht 31 + 48.112 Bytes), Header, Nullbereiche und Unterschiede zu den PCAP-Antworten prüfen. Nicht behaupten, dass die Sender-DB decodiert ist, solange die Nutzdaten nicht beobachtet und das Layout bestätigt sind.

Relevante Implementierung: `src/wisi_client.py` (`fetch_service_db`, `parse_service_db`) und `src/wisi_common.py` (`load_services`). PCAP-Werkzeug: `src/wisi_pcap.py`.

## Vom Nutzer beobachtete Konsolenausgabe

```text
(.venv) PS C:\Users\Danie\wisi-o2d-client> python src/wisi.py --ip 192.168.178.32 --channels
18:31:34  INFO     Verbinde 192.168.178.32:8802 ...
18:31:34  INFO     0x16 status=0x00  gerät=04ff04a52d
18:31:34  INFO     0x17 flag=0x00
18:31:34  INFO     Warte auf Bereitschaft ...
18:31:34  INFO     Dongle bereit.
18:31:34  INFO     Service-DB geparst: 0 Einträge.
18:31:34  WARNING  0xF9/0x0A lieferte 48143 Byte, aber keine erkennbaren Sender (Versuch 1, Anfang=f9 0a00 00 00 00 00 00 00 00 00 00 00 00 00 00).
18:31:35  INFO     Service-DB geparst: 0 Einträge.
18:31:35  WARNING  0xF9/0x0A lieferte 48143 Byte, aber keine erkennbaren Sender (Versuch 2, Anfang=f9 0a00 00 00 00 00 00 00 00 00 00 00 00 00 00).
18:31:35  INFO     Service-DB geparst: 0 Einträge.
18:31:36  WARNING  0xF9/0x0A lieferte 48143 Byte, aber keine erkennbaren Sender (Versuch 3, Anfang=f9 0a00 00 00 00 00 00 00 00 00 00 00 00 00 00).
18:31:36  INFO     Service-DB geparst: 0 Einträge.
18:31:36  WARNING  0xF9/0x0A lieferte 48143 Byte, aber keine erkennbaren Sender (Versuch 4, Anfang=f9 0a00 00 00 00 00 00 00 00 00 00 00 00 00 00).
18:31:37  INFO     Service-DB geparst: 0 Einträge.
18:31:37  WARNING  0xF9/0x0A lieferte 48143 Byte, aber keine erkennbaren Sender (Versuch 5, Anfang=f9 0a00 00 00 00 00 00 00 00 00 00 00 00 00 00).
18:31:37  WARNING  Service-DB nach 5 Versuchen nicht dekodiert. Prüfe TCP-Initialisierung, Dongle-Status/Sendersuchlauf und UDP-Port 8800.
18:31:37  INFO     Verbindung getrennt.
18:31:37  ERROR    Keine Senderliste von 192.168.178.32:8800 empfangen. TCP-Handshake war erfolgreich, aber UDP 0xF9/0x0A lieferte keine dekodierbaren Sender. Dongle-Status/Sendersuchlauf und UDP-Port 8800 prüfen; Ping allein bestätigt den APIX-Dienst nicht.
(.venv) PS C:\Users\Danie\wisi-o2d-client> python src/wisi.py --ip 192.168.178.32 --channels --debug
18:31:43  INFO     Verbinde 192.168.178.32:8802 ...
18:31:43  DEBUG    0x16 init              tx=31B rx=25B head=f6160004ff04
18:31:43  INFO     0x16 status=0x00  gerät=04ff04a52d
18:31:43  DEBUG    0x17 init              tx=31B rx=17B head=f6170000
18:31:43  INFO     0x17 flag=0x00
18:31:43  INFO     Warte auf Bereitschaft ...
18:31:44  DEBUG    0x16 poll              tx=31B rx=25B head=f6160104ff04
18:31:44  INFO     Dongle bereit.
18:31:44  INFO     Service-DB geparst: 0 Einträge.
18:31:44  WARNING  0xF9/0x0A lieferte 48143 Byte, aber keine erkennbaren Sender (Versuch 1, Anfang=f9 0a00 00 00 00 00 00 00 00 00 00 00 00 00 00).
18:31:44  INFO     Service-DB geparst: 0 Einträge.
18:31:44  WARNING  0xF9/0x0A lieferte 48143 Byte, aber keine erkennbaren Sender (Versuch 2, Anfang=f9 0a00 00 00 00 00 00 00 00 00 00 00 00 00 00).
18:31:45  INFO     Service-DB geparst: 0 Einträge.
18:31:45  WARNING  0xF9/0x0A lieferte 48143 Byte, aber keine erkennbaren Sender (Versuch 3, Anfang=f9 0a00 00 00 00 00 00 00 00 00 00 00 00 00 00).
18:31:45  INFO     Service-DB geparst: 0 Einträge.
18:31:45  WARNING  0xF9/0x0A lieferte 48143 Byte, aber keine erkennbaren Sender (Versuch 4, Anfang=f9 0a00 00 00 00 00 00 00 00 00 00 00 00 00 00).
18:31:46  INFO     Service-DB geparst: 0 Einträge.
18:31:46  WARNING  0xF9/0x0A lieferte 48143 Byte, aber keine erkennbaren Sender (Versuch 5, Anfang=f9 0a00 00 00 00 00 00 00 00 00 00 00 00 00 00).
18:31:46  WARNING  Service-DB nach 5 Versuchen nicht dekodiert. Prüfe TCP-Initialisierung, Dongle-Status/Sendersuchlauf und UDP-Port 8800.
18:31:46  INFO     Verbindung getrennt.
18:31:46  ERROR    Keine Senderliste von 192.168.178.32:8800 empfangen. TCP-Handshake war erfolgreich, aber UDP 0xF9/0x0A lieferte keine dekodierbaren Sender. Dongle-Status/Sendersuchlauf und UDP-Port 8800 prüfen; Ping allein bestätigt den APIX-Dienst nicht.
(.venv) PS C:\Users\Danie\wisi-o2d-client>
```
