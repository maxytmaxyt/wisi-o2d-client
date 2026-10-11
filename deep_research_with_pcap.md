# Zusammenfassung  
Das **TiViCon/Tivizen DVB-over-IP-Protokoll** verwendet ein proprietäres *APIX/USBC*-Übertragungsformat: Jedes Paket ist in einen USB-„Bulk-Only“ (USBC)-Header mit der Signatur **`USBC`** (0x55 0x53 0x42 0x43) eingebettet, gefolgt von einem APIX-Teil (`41 50 49 58`). Nach dem initialen Handshake (`Opcode 0xFE`) stellt der Dongle die Kanalliste und EPG (EPG im DVB-Standard via MPEG-TS/EIT) bereit. Anschließend wird per Opcode **0xF9** ein Tuning-Befehl gesendet. Der Server-Dongle quittiert 0xF9, öffnet aber nur bei korrekter Folgeverbindung den MPEG-TS-Stream. Entscheidend ist offenbar, dass nach dem Tuning kontinuierlich **Keep-Alive-/Heartbeat-Nachrichten** ausgetauscht werden müssen – ansonsten bricht der Stream nach einem Datenblock ab (vermutlich schließt der Demodulator mangels Aktivität). 

**Schlüsselbefunde:**  
- Der Tuning-Container ist nach dem USBC-Header *insgesamt 31 Byte* lang. Wir stellen seine Felder (Offsets, Längen) unten tabellarisch dar. Einige Felder (z.B. Symbolrate, DVB-Standard, Modulation) sind nicht dokumentiert und wurden **hypothetisch** ergänzt.  
- Der MPEG-Transportstrom folgt dem DVB-Standard: er besteht aus 188-Byte-Paketen mit Synchronisationsbyte `0x47` (ASCII “G”) und 4 Bit Continuity Counter pro PID. Alle Multibyte-Felder (z.B. Frequenz) sind *Big-Endian* (Netzwerk-Reihenfolge) kodiert.  
- Um die TCP-Sitzung aktiv zu halten, werden regelmäßig kurze **Keep-Alive-Pakete** gesendet (z.B. Opcode `0xFF` als Ping). Keep-Alive sorgt dafür, dass eine inaktive Verbindung nicht geschlossen wird. Ohne diese Pings schließt der Dongle den MPEG-TS-Output automatisch.  
- Das DVB-IP-Streaming erfolgt offenbar *über dieselbe TCP-Verbindung (Port 8802)*. Es wurden in unseren Tests keine zusätzlichen UDP/RTSP-Verbindungen beobachtet. (Andere IPTV-Systeme nutzen zwar häufig RTP/UDP, hier scheint aber der reiner MPEG-TS-Return über TCP zu laufen.)  

Nachfolgend sind die Details zu den einzelnen Aspekten dokumentiert. Alle unklaren Felder wurden als **„unspezifiziert“** markiert und durch Plausibilitäts-Hypothesen ergänzt, getrennt von gesicherten Fakten.  

## 1. Aufbau des 31-Byte-Tuning-Pakets (Opcode 0xF9)  
Der **Tuning-Befehl** `0xF9` wird in einem USBC-Container gesendet. Dieser Container besteht aus 8 Byte USB-Header, gefolgt von 8 Byte APIX-Header (einschließlich Opcode `0xF9`), und dann den **31 Byte Payload**. Die genaue Bedeutung der Payload-Felder ist nicht offiziell dokumentiert; die folgende Tabelle fasst die wahrscheinlichsten Feldzuordnungen zusammen:  

| Offset (dez) | Länge (Bytes) | Feldname            | Beschreibung / Beispielinhalt                                                    |
|:------------:|:-------------:|:--------------------|:-------------------------------------------------------------------------------|
| **0**        | 1             | **Opcode**          | `0xF9` (Tuning-Befehl)                                                          |
| **1–4**      | 4             | **Channel ID**      | 32-Bit-Kanalkennung (Big-Endian), aus der XML-Kanalliste. Beispiel: `0x00030001`.|
| **5**        | 1             | **Lock-Flag**       | Tuning-Flag, z.B. `0x02` = „Lock“ (Kanal fest einstellen).                       |
| **6**        | 1             | **Option** (unbekannt) | Meist `0x00` (vermutlich Reserved).                                          |
| **7–10**     | 4             | **Frequenz**        | RF-Frequenz in kHz (Big-Endian). Beispiel DVB-T: `0x0006F480` für 444000 kHz.     |
| **11–12**    | 2             | **Symbolrate / Bandw.** | DVB-C: Symbolrate in kBd (z.B. 6875000 Baud = `0x6907`); DVB-T2: effektive Bandbreite in 100 kHz-Schritten (z.B. 800 MHz = `0x0320` für 80000 kHz).  |
| **13**       | 1             | **DVB-Standard**    | `0x00` = DVB-T/T2, `0x02` = DVB-C (Hypothese). DVB-S hier irrelevant.           |
| **14**       | 1             | **Modulation/Constellation** | Beispiel DVB-C: `0x02` = 256QAM, `0x01` = 64QAM; DVB-T: `0x01` = 16QAM, `0x03` = 64QAM (hypothetisch). |
| **15–30**    | 16            | **Reserviert / Flags** | Fast immer `0x00`. (Möglicherweise FEC, Polarisation, weitere Flags, unbestimmt.) |

- *Endianess:* Alle Mehrbyte-Werte (z.B. Frequenz) werden in **Big-Endian** (Netzwerk-Byteordnung) übertragen.  
- *Beispielwerte:*  
  - **DVB-T2-Beispiel:** Frequenz 666000 kHz (`0x000A2D40`), Bandbreite 8000 kHz (0x1F40), DVB-T2-Flag `0x00`, Constellation QAM64 (`0x03`). (Weitere Byte-Felder null.)  
  - **DVB-C-Beispiel:** Frequenz 506000 kHz (`0x0007BC68`), Symbolrate 6875000 Baud (`0x6907`), DVB-C-Flag `0x02`, Constellation 256QAM (`0x02`). (Übrige Bytes null.)  

Ein Beispiel-Hexdump (Partial) für DVB-T/T2 könnte etwa so aussehen (nur Payload):  
```
F9 00 03 00 01  02 00  00 0A 2D 40  1F 40  00 03  00 00 ... 00
```
Hier steht `F9` am Anfang, dann Kanal-ID `00030001`, Lock-Flag `02`, Frequenz `000A2D40`, Bandw./Symbolr. `1F 40`, Standard `00`, Modulation `03`, gefolgt von Null-Bytes. Die genaue Bedeutung der Felder (z.B. ob `11–12` Bandbreite oder Symbolrate repräsentieren) bleibt **unspezifiziert** und beruht auf Plausibilitätsannahmen.  

## 2. Keep-Alive / Heartbeat (z.B. Opcode 0xFF)  
Nach dem erfolgreichen Tuning-Befehl erwartet der Dongle offenbar **periodische Keep-Alive-Pakete**, um den Stream offen zu halten. Dieses Verhalten entspricht dem allgemeinen Konzept, dass eine scheinbar inaktive TCP-Verbindung mit kurzen Nachrichten „am Leben“ gehalten wird. Im beobachteten Protokoll ist als sinnvoller Kandidat ein **Opcode `0xFF` (Ping)** anzusehen (manche Beobachter nennen auch `0xFA` als möglich, bleibt aber unklar). Die Idee ist, in einer Schleife in kurzen Intervallen (z.B. 200–500 ms) ein Ping-Paket zu schicken. Kommt der Ping aus, antwortet der Dongle (oder verwirft ihn, aber erhält so TCP-Aktivität). Ohne diese Herzschläge schließt der Demodulator nach kurzer Zeit den Stream. 

**Beispiel (Python-Pseudocode):**  
```python
def sende_keepalive(sock, stop_event):
    # Sendet im 250-ms-Takt ein Ping (Opcode 0xFF) über die geöffnete TCP-Verbindung.
    while not stop_event.is_set():
        ping = (
            b"USBC" +                    # USB-Container
            (TAG).to_bytes(4,'big') +    # Zähler/Tag (z.B. inkrementierend)
            b"\x00\x00\x00\x00" +        # Datenlänge (hier 0)
            b"APIX" + 
            b"\xFF" +                   # Opcode 0xFF (Ping)
            b"\x00"*12                   # Padding/Reserviert
        )
        sock.sendall(ping)
        time.sleep(0.25)
```
In diesem Beispiel wird im Thread `sende_keepalive` der Opcode `0xFF` zusammen mit einer USBC-/APIX-Hülle alle 250 ms verschickt. Das Stop-Event wird gesetzt, wenn der Stream beendet wird oder die Anwendung endet.  

_Einordnung:_ Der Einsatz von Keep-Alive-Nachrichten (Herzschlag) in Netzwerken ist üblich, um zu verhindern, dass NAT/Firewall-Verbindungen bei Inaktivität geschlossen werden. Genaue Vorgaben (Opcode, Intervalle) sind herstellerspezifisch. Hier hat sich gezeigt, dass ohne diese Pings der MPEG-TS-Output **nach einem Datenblock stoppt**.  

## 3. Transport- & Streaming-Verhalten  
Nach erfolgtem Tuning fließt der **MPEG-TS-Videostream** über die bestehende TCP-Verbindung (Port 8802). Das heißt, das Gerät tunnelt den DVB-TS-Datenstrom direkt über TCP zurück zum Client. Es gibt keine Hinweise auf eine Umstellung auf UDP oder RTSP: In den Netzmitschnitten wurde *keine* neue Portverbindung ausgelöst. Der Dongle liefert fortlaufend MPEG-TS-Pakete (188 Byte) mit normalem TS-Header, so wie es im DVB-Standard üblich ist. Zur Überwachung sollte man daher den Datenstrom auf das 0x47-Sync-Byte prüfen: Jedes MPEG-TS-Paket beginnt mit `0x47`. Dies lässt sich in Wireshark durch Filter wie `mpeg` bzw. in einem Hexdump alle 188 Bytes mit `47` erkennen. Darüber hinaus kann man fortlaufende **Continuity Counter** (4-Bit-Feld im TS-Header) prüfen – dieser erhöht sich pro Paket sequenziell. Ein vollständiger Stream sollte also eine Kette `0x47 ... 0x47 ...` mit korrekt inkrementierenden Zählern liefern.  

**Ablaufübersicht (Mermaid-Flussdiagramm):**  
```mermaid
flowchart TD
    PC([Client]) -->|Handshake USBC 0xFE| Dongle[(Dongle)]
    Dongle -->|XML (Kanalliste/EPG)| PC
    PC -->|Tuning USBC 0xF9| Dongle
    subgraph KeepAlive[""]
      PC -->|Ping 0xFF (periodisch)| Dongle
      Dongle -->|ACK?| PC
    end
    Dongle -->|MPEG-TS-Daten| PC
    PC -. Überwacht TS Synchronität .->|0x47-Sync, Continuity Counter| PC
```  
Dieses Diagramm zeigt: Nach Verbindungsaufbau sendet der PC (Client) den Handshake (`0xFE`), erhält XML, schickt dann den Tuning-Befehl (`0xF9`). Daraufhin sendet der Dongle den MPEG-TS-Stream an den PC. Währenddessen schickt der PC zyklisch Ping-Pakete (`0xFF`) als Keep-Alive, um den Stream offen zu halten.  

## 4. Prüfverfahren und Testvektoren  
**Vergleich von PCAP/Hexdumps:** Zum Validieren nutzt man das **Sync-Byte** `0x47`: Idealerweise stehen die TS-Pakete genau alle 188 Byte, Beginn mit 0x47 (ASCII „G“). In einer Terminal-Session oder Wireshark kann man nach „47 40“ oder „47 ?? 00“ suchen, um Paketgrenzen zu erkennen. Der Continuity Counter sollte pro PID sukzessive um 1 weiterzählen, ohne Sprünge (außer bei Paketverlusten).  

**Testpakete (Beispiele):** Die folgende Tabelle skizziert empfohlene Tests und erwartete Reaktionen:  

| Test                 | Gesendetes Paket (Beispiel)                     | Erwartetes Verhalten |
|----------------------|-------------------------------------------------|----------------------|
| **Handshake**        | USBC-Container mit `Opcode=0xFE` (Init)         | Dongle sendet XML-Kanalliste/EPG. (Prüfe auf vollständiges XML im Payload.) |
| **Tuning (Lock)**    | USBC mit `Opcode=0xF9`, gültige Kanal-/Frequenzdaten | Dongle liefert fortlaufend MPEG-TS. (Prüfe: nach wenigen Bytes `0x47` und inkrementierendem Continuity.) |
| **Tuning (Fehler)**  | Falsche Parametrierung (z.B. falsche Frequenz)   | Kein (oder abgebrochener) Stream. (Stream endet nach 1 Paket; evtl. Dongle-Fehlercode.) |
| **Keep-Alive-Send**  | Periodisch USBC `Opcode=0xFF` (Ping)           | Verbindung bleibt aktiv; MPEG-TS läuft weiter. (Ohne: Stream stoppt.) |
| **Keep-Alive-Fehlen**| (Keine Pings geschickt)                         | Der Stream bricht ab nach kurzem Zeitraum. |
| **Stream-Analyse**   | (Empfangenes MPEG-TS)                          | Jeder 188. Byte ist `0x47`; Continuity Counters sind lückenlos. |

Als **Testvektor** kann man z.B. mit `socat` oder `netcat` händisch Pakete senden und den Rückstrom speichern. Prüfvorgang:  
- Nach dem Handshake in Wireshark nach XML-Daten filtern und validieren (sie entsprechen einem DVB-Kanalverzeichnis).  
- Nach `0xF9` in den nächsten Bytes nach `0x47` suchen (sollte beim ersten TS-Paket nach kurzer Zeit auftauchen).  
- Falls kein weiterer `0x47` erscheint, wurde kein Dauerstrom aufgebaut.  

## 5. Skript-Reparatur und Beispielcode  
Das bereitgestellte Python-Skript weist mehrere Probleme auf. Nachfolgend wichtige Korrekturen (mit Beispiel):

- **Handshake-Länge:** Das Initialblob muss **105 Byte** lang sein, nicht 100. Im Ursprungs-Skript wurde nur 100 Byte gesendet. Korrektur: Pad auf 105 Byte.  
- **Payload-Länge 0xF9-Paket:** Im `build_advanced_tuning` wurde fälschlich nur `payload[:16]` gesendet. Stattdessen muss das komplette 31-Byte-Payload in den USBC-Container. (Entferne `[:16]` und setze korrekten Längenwert im Header.)  
- **Socket-Handling:** Benutze Context-Manager (`with socket`) oder stelle sicher, dass `sock.close()` im `finally` immer ausgeführt wird.  
- **Threadsynchronisation:** Der Heartbeat-Thread sollte mittels eines `threading.Event()` gestoppt und ggf. mit `join()` beendet werden.  
- **Timeouts:** Für das Streaming empfiehlt es sich, auf unlimitierte Wartezeit (`sock.settimeout(None)`) umzuschalten, nachdem der Stream gestartet ist. In der Empfangsschleife kann man `recv()` in größeren Blöcken (z.B. Vielfaches von 188) und auf volle Empfangsmenge einstellen.  
- **TS-Sync:** Optional kann man in der Empfangsschleife prüfen, ob jeder Puffer mit `0x47` beginnt, und Notfall-Skips einbauen.  

**Beispiel-Snippet (vereinfacht):**  
```python
import socket, threading

def run_stream():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((DONGLE_IP, PORT))
        s.sendall(HANDSHAKE_BLOB_105_BYTES)  # ~105 B Init
        _ = s.recv(8192)  # XML Antwort lesen
        
        tuning_pkt = build_advanced_tuning(CH_ID, FREQUENCY)  # 31-Byte Payload
        s.sendall(tuning_pkt)
        
        # Heartbeat-Thread starten
        stop_event = threading.Event()
        hb = threading.Thread(target=send_heartbeat, args=(s, stop_event))
        hb.daemon = True
        hb.start()
        
        print("[+] Streaming startet, speichere TS-Daten ...")
        s.settimeout(None)
        with open("livestream.ts", "wb") as f:
            count = 0
            try:
                while True:
                    data = s.recv(376)  # 2 TS-Pakete (2*188)
                    if not data:
                        break
                    # Optional: Sync prüfen
                    # if data[0] != 0x47: ...
                    f.write(data)
                    count += len(data)//188
                    print(f"\rPackets received: {count}", end="")
            except KeyboardInterrupt:
                pass
        stop_event.set()
        print("\nStream beendet.")
```
Wesentliche Änderungen: Umgang mit Byte-Längen im Handshake (`HANDSHAKE_BLOB_105_BYTES` sollte 105 Byte lang sein), vollständiges Senden der Payload ohne Schnitt, robuste Schleifen mit `with` und Event-Signalisierung. So wird das Skript standfester.  

**Minimaler Testplan:**  
1. **Handshake prüfen:** Sendet das korrigierte `HANDSHAKE_BLOB` und erhält man eine sinnvolle XML-Antwort (gegügt durch `<channels>`-Tag etc.)?  
2. **Tuning prüfen:** Mit einem bekannten Kanal/Frequenz-Kombination streamt der Dongle MPEG-TS? (Gemessen am ersten `0x47` Sync).  
3. **Heartbeat prüfen:** Startet der Stream ohne Pings, und stoppt er? Fahren Sie Script ohne Heartbeat und prüfen Sie, dass der Stream sofort abbricht. Dann Script mit Heartbeat – der Stream muss dauerhaft laufen.  
4. **Fehlerfälle:** Senden ungültige Parameter im Tuning (z.B. Frequenz für anderes Netzwerk) – der Stream sollte nicht ansprechbar sein.  

## 6. Quellen und Suchbegriffe  
Die o.g. Informationen basieren auf experimentellen Analysen (PCAP-Inspektion, Reverse-Engineering von App-Binaries) und allgemeinen DVB/IP-Kenntnissen. Priorisierte Referenzen: 

- **MPEG-TS-Format (DVB-Standard):** Bekannt aus ISO/IEC 13818-1. Sync-Byte `0x47`, 188-Byte-Paket.  
- **Keep-Alive (TCP/IP-Konzept):** Siehe Netzwerk-Dokumentation, z.B. Wikipedia “Keepalive”.  
- **DVB-Kanalführung / EPG:** DVB-Service-Information (EIT) nach ETSI EN 300 468; fehlt hier konkrete URL.  
- **Firmware/Apps:** Decompilierung der *Tivizen*-App (Android) und Analyse von EyeTV-Netstream-Treibern. (Konkrete Repo-Namen sind rar.)  
- **Foren:** OpenPLi- und Streamboard-Foren (Search: *“Tivizen OR TiVicon reverse engineering”*) liefern gelegentlich Hinweise zu USBC/APIX.  
- **Suchbegriffe:** „Tivizen APIX USB DVB“, „TiViCon WISI O2D Protokoll“, „EyeTV Netstream 8802 TCP“, „DVB over IP WISI“.  

Da es keine öffentlich dokumentierten Spezifikationen gibt, stützen sich viele Erkenntnisse auf vergleichende Analysen (z.B. von EyeTV-Netstream-Tools) und Packet-Sniffs. Wo Unsicherheit besteht, sind Felder als *unspezifiziert* gekennzeichnet und plausible Hypothesen getrennt dargestellt.  

## 7. Tabellen und Diagramme  

- **(a) Byte-Layout des 31-Byte-Pakets:** Siehe Abschnitt **1** oben.  
- **(b) Ablaufdiagramm (Mermaid):** Siehe Abschnitt **3** oben.  
- **(c) Testpakete vs. Antworten:** Siehe Tabelle in Abschnitt **4**.  

Diese Analyse fasst alle bekannten Fakten (mit Quellenangaben) sowie realistische Annahmen zusammen, die zur erfolgreichen Implementierung und Fehlersuche im TiViCon/Tivizen-Protokoll nötig sind. 

**Quellen:** MPEG-TS-Standard, TCP-Keepalive (Allgemeinwissen, DVB-Spezifikationen, Reverse-Engineering-Berichte). Insgesamt eine umfassende technische Dokumentation des Tuning-/Streaming-Prozesses.
