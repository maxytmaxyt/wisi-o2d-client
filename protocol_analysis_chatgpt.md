# Protokollanalyse: WISI / Tivizen-Dongle

Der Mitschnitt enthält einen sehr wichtigen Hinweis: Port 8802 transportiert keine gewöhnlichen Textbefehle, sondern Befehle im USB-Massenspeicher-Transportformat mit einer proprietären `APIX`-Erweiterung. Außerdem kommuniziert der Client über UDP mit Port 8800. Beide Verbindungen scheinen unterschiedliche Aufgaben im selben Gerätesystem zu übernehmen.

## 1. Überblick über den Mitschnitt

Aufgezeichnete Pakete

# 3.286

Aufzeichnungsdauer

# 48,6 s

TCP-Verbindung

## Port 8802

2.152 Pakete

UDP-Verbindung

## Port 8800

622 Datagramme

Gerät: `192.168.178.32` · Client: `10.215.173.1`

Die Zahlen beziehen sich auf den untersuchten Mitschnitt. Die Aufnahme ist auf 32.768 Byte pro Paket begrenzt, wodurch einige große UDP-Datagramme nur teilweise enthalten sind.

## 2. Der entscheidende Fund: `USBC` und `USBS`

Die TCP-Verbindung zeigt einen wiederkehrenden Ablauf. Der Client sendet einen 31 Byte großen Befehl mit diesem Anfang:

```
55 53 42 43 A0 CB 03 37 00 00 00 0C
80 00 10 F6 41 50 49 58 16 ...
```

Die Bytefolge `55 53 42 43` entspricht ASCII `USBC`. Die Antworten beginnen bei mehreren Transaktionen mit Daten wie `F6 16 ...` und enthalten anschließend `55 53 42 53` (`USBS`).

Das passt zum USB Bulk-Only Transport (BOT):

- `USBC`: Command Block Wrapper (CBW), also der Befehlsrahmen.
- `USBS`: Command Status Wrapper (CSW), also der Statusrahmen am Ende einer Transaktion.
- `F6` mit anschließender Zeichenfolge `APIX`: ein herstellerspezifischer SCSI-Befehl beziehungsweise eine Erweiterung.

Damit haben wir einen belastbaren Ansatzpunkt für das Reverse Engineering: Wir können die Rahmenstruktur und einen Teil der Befehlssequenz direkt aus dem Mitschnitt rekonstruieren.

## 3. Aufbau eines Befehls

Der 31-Byte-Request lässt sich in Felder zerlegen. Besonders wichtig ist, dass das Längenfeld in diesem Mitschnitt Big-Endian codiert ist. Das unterscheidet sich vom üblichen Little-Endian-Längenfeld des nativen USB-Bulk-Only-Transportformats.

| Byteposition | Länge | Bedeutung                             |
| ------------ | ----- | ------------------------------------- |
| `0–3`        | 4     | Signatur `USBC`                       |
| `4–7`        | 4     | Tag `A0 CB 03 37`                     |
| `8–11`       | 4     | Datenlänge, Big-Endian                |
| `12`         | 1     | Richtung/Flags, oft `80` für Einlesen |
| `13`         | 1     | LUN, hier `00`                        |
| `14`         | 1     | CDB-Länge `10` = 16 Byte              |
| `15–30`      | 16    | Herstellerspezifischer APIX-Befehl    |

Der Tag bleibt über die untersuchten Transaktionen hinweg konstant. Die erfolgreichen TCP-Antworten enthalten denselben Tag im Statusrahmen und enden in den sichtbaren Beispielen mit Status `00`.

## 4. Die wichtigsten APIX-Befehle

Der Mitschnitt erlaubt, mehrere Befehle recht zuverlässig zuzuordnen.

| Befehl               | Belegte Funktion                                                   |
| -------------------- | ------------------------------------------------------------------ |
| `APIX 0x16`          | Initialisierungs- oder Statusabfrage; 12 Byte Antwortdaten         |
| `APIX 0x17`          | Weitere kurze Status-/Initialisierungsabfrage; 4 Byte Antwortdaten |
| `APIX0` (`0x30`)     | Größe eines EPG-Datensatzes für einen `prog_idx` abfragen          |
| `APIX1` (`0x31`)     | EPG-Datensatz für diesen `prog_idx` auslesen                       |
| `APIX5` (`0x35`)     | Größe einer Ereignisbeschreibung abfragen                          |
| `APIX6` (`0x36`)     | Ereignisbeschreibung abrufen                                       |
| `APIX 0x01` über UDP | Abruf eines MPEG-Transportstrom-Datenblocks                        |
| `APIX 0x0A` über UDP | Wiederholte große Leseanforderung; genaue Funktion noch offen      |

Bei den Befehlen `0x16`, `0x17`, `0x02`, `0x03` und `0x07` ist die genaue interne Bedeutung mit dieser Aufnahme allein noch nicht vollständig geklärt.

### Beispiel: EPG-Datensatz lesen

Bei ungefähr `2,13 s` sendet der Client einen `APIX0`-Befehl. Das Gerät antwortet mit:

```
F6 30 00 00 59 2A
```

Die sechs Antwortbytes enthalten die Länge `0x592A`, also 22.826 Byte. Danach folgt ein `APIX1`-Request mit derselben Program-ID und genau dieser angeforderten Datenlänge.

Die Antwort beginnt mit `F6 31`, gefolgt von XML. Ein sichtbarer Ausschnitt lautet:

```
<epg_Data>
  <ch s_id="11110"
      ts_id="33079"
      prog_idx="1085735055">
    <evt id="39442"
         des="heute Xpress"
         ... />
  </ch>
</epg_Data>
```

Die XML-Struktur und die Größenabfrage passen zusammen. Damit ist die Funktion von `APIX0` und `APIX1` sehr gut belegt.

Auch der Program-Index lässt sich nachvollziehen: Die vier Bytes `40 B7 00 8F` ergeben als Big-Endian-Zahl `1085735055` – exakt den Wert von `prog_idx` im XML.

### Beispiel: Sendungsdetails auslesen

Bei ungefähr `2,45 s` fragt der Client mit `APIX5` Details zur Sendung mit der ID `39447` ab. Die Antwort enthält:

```
F6 35 00 00 02 81
```

`0x0281` entspricht 641 Byte. Danach folgt ein `APIX6`-Request mit einer erwarteten Länge von 641 Byte. Die Antwort enthält XML mit einer Struktur wie:

```
<event_desc
    s_id="11110"
    evt_id="39447"
    name="Terra Xplore"
    ... />
```

Damit ergibt sich ein zweistufiges Abfragemuster: erst die Größe ermitteln, dann den eigentlichen Datensatz lesen. Der konkrete Ausschnitt belegt dieses Muster direkt.

## 5. UDP 8800: Der eigentliche Transportstrom

Der wichtigste weitere Fund liegt in der UDP-Verbindung. Ab ungefähr `30,407 s` wechselt der Client von wiederholten `APIX 0x0A`-Anfragen zu `APIX 0x01`.

Die Antworten sehen nun grundlegend anders aus. Sie beginnen mit Binärdaten wie:

```
47 13 38 98 E4 84 89 D3 7A F2 C4 FA ...
```

Das erste Byte `47` ist das Sync-Byte eines MPEG-Transportstroms. Die Daten bestätigen diesen Zusammenhang auch strukturell:

- Das Sync-Byte erscheint in den untersuchten Antworten im Abstand von 188 Byte.
- Die Transportstrom-Continuity-Counter laufen für wiederkehrende PIDs zyklisch von 0 bis 15 weiter.
- Die häufigsten PIDs im sichtbaren Datenbereich sind `0x1338`, `0x1339` und `0x133A`.
- Bei fast allen untersuchten Paketen zeigen die MPEG-TS-Header den Scrambling-Control-Wert `2`. Das deutet auf gemäß MPEG-TS-Header verschlüsselte beziehungsweise scrambling-markierte Nutzdaten hin; die Ursache lässt sich allein aus diesem Mitschnitt nicht bestimmen.

Das ist ein belastbarer Nachweis für MPEG-TS-Daten und nicht lediglich eine Vermutung aufgrund der Portnummer.

### Größe der Datenblöcke

Die UDP-Anfragen setzen die Datenlänge auf `0x0000BC00`:

\\[ 0xBC00 = 48.128 = 256 \times 188 \\]

Ein angeforderter Datenblock entspricht also exakt 256 MPEG-TS-Paketen.

Für die Antworten weist der IP-/UDP-Header eine UDP-Nutzlast von 48.205 Byte aus. Das sind 77 Byte mehr als der angeforderte Datenblock. Was diese zusätzlichen Bytes genau enthalten, kann ich noch nicht abschließend bestimmen, weil die Pakete beim Mitschnitt abgeschnitten wurden.

Die wiederholten `APIX 0x0A`-Antworten davor beginnen dagegen mit `F9 0A` und bestehen im aufgezeichneten Teil überwiegend aus Nullbytes. Ihre interne Funktion bleibt offen; die späteren `APIX 0x01`-Antworten sind dagegen eindeutig als MPEG-TS erkennbar.

## 6. Zeitlicher Ablauf

## 0,05 s

TCP-Verbindung auf Port 8802

Der Client öffnet die Verbindung und beginnt mit `APIX 0x16` und `APIX 0x17`.

## 2,13 s

EPG-Abfragen über TCP

Größenabfrage und XML-Abruf über `APIX0`/`APIX1`, anschließend eine Ereignisbeschreibung über `APIX5`/`APIX6`.

## 4,98 s

UDP-Kommunikation beginnt

Eine kurze `APIX 0x02`-Transaktion wird von wiederholten `APIX 0x0A`-Anfragen gefolgt.

## 30,41 s

MPEG-TS-Daten sichtbar

Die UDP-Anfragen wechseln zu `APIX 0x01`. Ab hier sind korrekt ausgerichtete Transportstrompakete erkennbar.

## 47,6 s+

Viele EPG-Größenabfragen

Gegen Ende folgen zahlreiche `APIX0`-Anfragen mit unterschiedlichen Program-Indizes. Ihre vollständigen Folgeabfragen liegen nicht mehr alle innerhalb des Mitschnitts.

## 7. Einschränkungen des Mitschnitts

Die globale PCAP-Aufzeichnung verwendet eine maximale Paket-Aufzeichnungslänge von 32.768 Byte. Das ist für diesen Datenverkehr zu wenig: Die großen UDP-Datagramme enthalten laut ihren Headern mehr als 48.000 Byte, aber nur die ersten 32.768 Byte des IP-Pakets sind verfügbar.

Dadurch fehlen bei den großen Antworten der hintere Teil des Datenblocks und mögliche Status- beziehungsweise Abschlussdaten. Insbesondere lässt sich so die genaue UDP-Antwortstruktur nicht vollständig rekonstruieren.

Für die nächste Aufnahme wäre eine Snaplen von mindestens 65.535 Byte sinnvoll. Bei den TCP-Verbindungen ist außerdem zu beachten, dass TCP ein Bytestrom ist: Netzwerkpakete sind nicht automatisch identisch mit vollständigen Protokollantworten. Ein Decoder muss deshalb Datenlängen und Statusrahmen berücksichtigen, statt allein anhand von Paketgrenzen zu parsen.

## Fazit

Die wesentlichen Teile des Protokolls sind jetzt deutlich besser eingegrenzt:

1. TCP 8802: ein USB-Bulk-Only-Transport-ähnlicher Rahmen mit proprietären APIX-Befehlen. Der Client kann EPG-Daten und Ereignisbeschreibungen durch eine Größenabfrage mit anschließendem Datenabruf lesen.
2. UDP 8800: derselbe allgemeine APIX-/USB-nahe Befehlsansatz, aber mit anderem Antwortverhalten. `APIX 0x01` liefert nachweislich MPEG-TS-Datenblöcke mit 188-Byte-Paketstruktur.
3. Noch ungeklärt: die genaue Bedeutung der übrigen APIX-Kommandos, die zusätzlichen UDP-Bytes und die Ursache der Scrambling-Kennzeichnung in den Transportstrompaketen.

Für ein funktionierendes eigenes Client-Programm ist es daher sinnvoll, die TCP-EPG-Kommandos und den UDP-Transportstrom als zwei getrennte Teile zu implementieren. Die TCP-Seite lässt sich bereits recht präzise nachbilden; bei UDP fehlen noch die vollständigen Abschlussdaten und die genaue Interpretation einiger Kommandos.
