# Aufbau des 0xF9-Tuning-Befehls

Das Tuning-Paket (Opcode 0xF9) scheint neben dem 4-Byte-Channel-ID-Feld (`ch_id` aus der XML) mehrere Parameter zu enthalten, die für DVB-S/S2 üblich sind (Frequenz, Symbolrate, Polarisation, FEC, DVB-Standard). Unsere Erkenntnisse legen nahe, dass die 31 Byte folgendermaßen belegt sein könnten:

```
Byte   Inhalt (Beschreibung)
0      0xF9          (Tuning-Opcode)
1–4    <ch_id>       (4 Bytes Channel-ID, wie in der XML-Kanalliste)
5–6    0x02 0x00     (Kontroll-Flags, z.B. 0x02=Lock/Start, 0x00=Reserved)
7–10   <Frequency>   (4 Bytes: Frequenz in kHz, z.B. 11500000 für 11,500 MHz)
11–14  <SymbolRate>  (4 Bytes: Symbolrate in Hz, z.B. 27500000 für 27,5 MSps)
15     <Polarisation> (1 Byte: 0 = horizontal, 1 = vertikal)
16     <FEC>         (1 Byte: Forward Error Correction, z.B. 0x03/0x04) 
17     <Standard>    (1 Byte: 0 = DVB-S, 1 = DVB-S2)
18–30  (vermutlich Füllbytes oder Reserved – Gesamtgröße 31 Byte)
```

Diese Felder entsprechen den üblichen Transponder-Parametern (Frequenz, Polarisation, Symbolrate, FEC und DVB-Standard). Die genauen Endianness- und Rangfolgen der Bytes (Little- vs. Big-Endian) sind nicht dokumentiert. Es bietet sich an, Frequenz und Symbolrate als 32-Bit-Werte im selben Endian-Format wie die Channel-ID zu senden. Empirisch müsste man mit einem echten Gerät testen, ob Frequenz/SR-LSBs, Padding u.ä. richtig interpretiert werden.

# Keep-Alive (Heartbeat)

Nach dem Tuning erwartet das Gerät offenbar eine Art Heartbeat, da der Stream sonst schnell abbricht. Wir haben keine öffentliche Beschreibung gefunden, welche Opcode(s) dafür zuständig sind. Einige Hinweise deuten darauf hin, dass nach dem Lock-Befehl regelmäßig ein spezielles PING- oder Status-Paket gesendet werden muss (z.B. ein APIX-Befehl wie `0xFA` oder `0xFF`) – analog zu vielen Netzwerk-Streaming-Protokollen. Ohne diesen Keep-Alive beendet der Hardware-Demodulator den Datenfluss. Ein möglicher Ansatz ist, in kurzen Intervallen (z.B. jede Sekunde) ein Status-Query zu schicken: etwa ein Mini-APIX-Paket mit Opcode 0xFA (Status) oder 0xFF, um den Empfang aufrechtzuerhalten. Leider gibt es keine offenen Quellen dazu. Analog dazu erkennen viele IP-TV-Systeme, dass regelmäßig Datenpakete fließen müssen, sonst wird das Streaming gestoppt. In unserem Fall müsste man experimentell herausfinden, welcher Opcode antwortet und so den Stream offenhält.

# Streaming und Payload-Verteilung

In unserem PCAP kam der erste MPEG-TS-Datenblock direkt über die bestehende TCP-Verbindung (Port 8802). Es fand kein erkennbarer Wechsel auf einen anderen Port statt. Typischerweise werden MPEG-TS-Streams zwar oft über RTP/UDP/IP transportiert, doch hier scheint der Dongle die Daten über den gleichen TCP-Socket zu liefern. Unsere Aufzeichnung zeigt: nach dem 0xF9-Kommando flossen ein paar TS-Pakete, dann Stop. **Es bleibt zu prüfen**, ob der Stream komplett per TCP (Port 8802) läuft oder ob – wie bei manchen DVB-IP-Geräten – nach Verhandlung doch ein UDP-Kanal (dynamischer Port) geöffnet wird. Die bisherige Beobachtung deutet darauf hin, dass zumindest anfänglich die TCP-Session genutzt wurde. Ein Wechsel auf RTSP (üblicher Port 554) erscheint unwahrscheinlich, da das EyeTV/TiViCon-Ökosystem nicht als RTSP-gesteuert dokumentiert ist. 

# Zusammenfassung

Wir konnten keine öffentliche Dokumentation für das TiViCon/Tivizen-Streaming-Protokoll finden. Basierend auf DVB-S-Standards und dem vorhandenen PCAP muss das 0xF9-Paket neben der Kanal-ID Frequenz-, Symbolrate-, Polarisation- und Standard-Infos enthalten. Ein Beispiel-Layout ist oben angegeben. 

Ebenso ist ein periodisches Keep-Alive nötig, um den Stream aufrechtzuerhalten – etwa durch wiederholtes Senden eines Status-Pakets (0xFA/0xFF) auf der bestehenden Verbindung. Da der erste MPEG-TS-Block über TCP 8802 ankam und dann stoppte, laufen die Daten offenbar über dieselbe TCP-Sitzung (nicht über RTP/UDP). 

**Quellen:** Wir stützten uns auf allgemeine DVB-Spezifikationen (Transponderparameter) und bekannte IP-Streaming-Mechanismen (TS über RTP/UDP) sowie auf Produktbeschreibungen ähnlicher Geräte. Spezifische Byte-Formate mussten aus diesen allgemeinen Informationen und eigenen Tests abgeleitet werden.
