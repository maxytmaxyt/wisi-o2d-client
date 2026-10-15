Problem 1: Der Keep-Alive läuft auf dem ersten TCP-Socket, aber nach dem Tune schließt der Dongle diese Verbindung (WinError 10053). Die zweite Verbindung (stream_ka_sock) bekommt keinen Keep-Alive-Fehler — der läuft korrekt. Der erste ka-Thread kann also ignoriert werden.

Problem 2: Die 48205-Byte-Blöcke ohne TS-Sync: 48205 = 48128 + 77 — das ist ein Speed-Test-Response-Format (0xF9/0x0A-ähnlich), nicht MPEG-TS. Nach ~23 Blöcken mit echtem TS beginnt der Dongle Nicht-TS-Pakete zu senden — das passiert weil der Pull-Mechanismus zu schnell ist (alle 0,5s) und der Dongle Speedtest-Antworten zurückschickt. Das Protokoll-Doc sagt: 0xF9/0x01 mit byte21=0x00 = erster Pull, byte21=0x01 = weitere. Das data[:2] == b"\xf9\x0a" Filter greift nicht auf diese Pakete.

Problem 3: Die echten TS-Pakete haben sync_offset=0 (erster Block: “TS-Offset 0”), also kein Header-Strip. Die 48205-Byte-Blöcke die verworfen werden haben weder USBS noch \xf9\x0a Prefix — ihr TS-Sync-Check schlägt einfach fehl weil es kein TS ist.

Die Kernfrage: Warum kommen nach Block 23 keine echten TS-Pakete mehr? → Der Dongle braucht nach jedem 0xF9/0x01-Pull eine ACK/Bestätigung oder der Pull-Timer ist falsch. Aus dem PCAP: Pull-Interval ist tatsächlich ~0.5s. Aber 25 Pulls für 23 Blöcke heißt es laufen 2 Pulls “leer”.

Das eigentliche Problem: der erste TCP-Socket stirbt (WinError 10053 bei 19:44:39). Danach versucht der Keep-Alive auf stream_ka_sock, aber diese zweite Verbindung hat evtl. den Stream nicht “übernommen”. Der Dongle sendet weiterhin, aber nach einem Timeout stoppt er.
