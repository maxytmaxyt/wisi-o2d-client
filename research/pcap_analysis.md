# PCAP-Analyse – Detaillierte Ergebnisse

> Automatisch generiert aus `capture_pcapdroid_2024-10-11.pcap`  
> Analysiert mit Scapy, Oktober 2026

---

## 1. Übersicht

| Eigenschaft | Wert |
|-------------|------|
| Pakete gesamt | 3.286 |
| Dauer | 48,59 s |
| Dongle-IP | 192.168.178.32 |
| Client-IP | 10.215.173.1 |
| TCP 8802 (Steuer) | 2.152 Pakete |
| UDP 8800 (Daten) | 622 Datagramme |

---

## 2. Vollständige Opcode-Tabelle (aus PCAP extrahiert)

| Prefix | Opcode | Anzahl | datalen | Funktion | Antwort-Format |
|--------|--------|--------|---------|----------|----------------|
| 0xF6 | 0x01 | 1 | 2 | **Kanal-Auswahl** (Tuning-Trigger?) | `F6 01` + USBS (15 Byte) |
| 0xF6 | 0x02 | 5 | 17 | **Status-Polling** (alle ~3 s) | `F6 02` + 13 Byte Status-Daten |
| 0xF6 | 0x03 | 1 | 4 | **Unbekannt** (einmalig bei t=28.6s, vor Kanal-Select) | `F6 03` + USBS |
| 0xF6 | 0x16 | 23 | 12 | **Init + Keep-Alive** | 12 Byte Gerätestatus |
| 0xF6 | 0x17 | 2 | 4 | **Init Phase 2** (auch am Ende mit Flag=1) | 2–4 Byte |
| 0xF6 | 0x30 | 445 | 6 | **EPG-Größe abfragen** | 6 Byte (Länge Big-Endian) |
| 0xF6 | 0x31 | 252 | variabel | **EPG-XML abrufen** | XML-Block |
| 0xF6 | 0x32 | 2 | 6 | **Kanal-Info Größe** (ähnlich 0x30) | 6 Byte (Länge) |
| 0xF6 | 0x33 | 2 | variabel | **Kanal-Info XML abrufen** | `<ch_Info>` XML |
| 0xF6 | 0x35 | 1 | 6 | **Ereignis-Größe abfragen** | 6 Byte |
| 0xF6 | 0x36 | 1 | 641 | **Ereignis-XML abrufen** | XML |
| 0xF8 | 0x07 | 1 | 4 | **Unbekannt** (einmalig bei t=47.17s) | Nur USBS (13 Byte) |

---

## 3. Init-Antworten entschlüsselt

### APIX 0x16 – Geräte-Status (12 Byte Nutzdaten)

```
Antwort: F6 16 [12 Byte] USBS...

Erste Antwort (t=0.11s, frische Verbindung):
  [0] = 0x00  ← Status-Flag: 0 = noch nicht initialisiert?
  [1] = 0x04
  [2] = 0xFF  ← Firmware-Version (255)?
  [3] = 0x04
  [4] = 0xA5  ← Gerätespezifisch
  [5] = 0x2D
  [6..11] = 0x00

Folge-Antworten (Keep-Alive):
  [0] = 0x01  ← Status-Flag: 1 = bereit/aktiv
  [1..5] = 0x04 FF 04 A5 2D  (konstant – Gerätekennzeichen)
```

**Wichtig:** Das erste `0x00` bei der allerersten 0x16-Antwort wird zu `0x01` bei allen Folge-Aufrufen. Das ist wahrscheinlich ein "bereit"-Flag.

### APIX 0x17 – Init Phase 2 (4 Byte)

```
Erste Antwort (t=0.15s):  F6 17 00 00 ...  → [0]=0x00 (nicht bereit)
Zweite Antwort (t=47.62s): F6 17 01 00 ... → [0]=0x01 (Kanal gewählt/bereit)
```

Das zweite 0x17 am Ende (t=47.58s) hat `payload=0x01` statt `0x00` – der Dongle bestätigt damit den Kanalwechsel!

---

## 4. Neu entdeckte Opcodes

### APIX 0x02 – Periodischer Status-Poll (alle ~3 s)

```
Client sendet:  USBC + 0x02  datalen=17
Dongle antwortet:
  F6 02 00 64 3D 00 00 00 3C A0 00 00 00 00 00 USBS...
         ──  ──  ──
         │   │   └─ Signal-Wert (variiert: 59–61) 
         │   └───── Konstant: 0x64 = 100 (Signalstärke in %?)
         └─────────  0x00

  F6 02 00 64 3C 00 00 00 3C A0 00 00 00 00 00 USBS...
              ─── ← wechselt zwischen 59-61 (Signalqualität?)

Bytes [6]=0x3C=60, [7]=0xA0=160 → konstant, möglicherweise Frequenz-Info
```

**Interpretation:** `0x02` ist ein **Signal-Status-Query**:
- Byte[1] = `0x64` = 100 → Signalstärke 100% (konstant gut)
- Byte[2] = `0x3B`–`0x3D` = 59–61 → Signalqualität (variiert leicht)

### APIX 0x32 / 0x33 – Kanal-Info (neu!)

```
0x32 = Größe der Kanal-Info abfragen (wie 0x30 für EPG)
       Payload: prog_idx (4 Byte) = 0x40B40089
       Antwort: F6 32 00 00 00 41 USBS  → Länge = 0x41 = 65 Byte

0x33 = Kanal-Info XML abrufen (wie 0x31 für EPG)
       Antwort: XML <ch_Info>...</ch_Info>
```

**Beispiel-Antwort von 0x33:**
```xml
<ch_Info>
<ch s_id="4914" prog_idx="1085538441" />
</ch_Info>
```

Zweiter Aufruf (t=39.42s) liefert mehr Daten (309 Byte):
```xml
<ch_Info>
<ch s_id="4914" prog_idx="1085538441" />
... (weitere Kanäle?)
</ch_Info>
```

### APIX 0x03 – Unbekannt (einmalig)

```
t=28.60s  datalen=4  payload=0x00000002 0x40B40089
                              ──────────  ──────────
                              Flag=2?     prog_idx des gewählten Kanals!
```

Tritt einmalig auf, kurz vor dem ersten 0x32-Aufruf. Payload enthält den `prog_idx` des Kanals (`0x40B40089`). Wahrscheinlich: **Kanal vorauswählen / "prepare tune"**.

### APIX 0x01 – Kanal-Aktivierung (einmalig, bei t=46.94s)

```
datalen=2  full_cdb: F6 41 50 49 58 01 00 04 00 00 00 00 00 00 00 00
                                    ── ── ──
                                    op  ??  Kanal-Nummer?

Antwort: F6 01 USBS (15 Byte, kein Nutzdaten-Payload)
```

Tritt genau einmal auf, am Ende der EPG-Schleife. Danach sendet das Skript `0x17` mit Flag=1. Das ist sehr wahrscheinlich der **finale Tune-Befehl** der den Kanal aktiviert.

### 0xF8 / 0x07 – Unbekannt (einmalig, bei t=47.17s)

```
datalen=4  full_cdb: F8 41 50 49 58 07 00 00 00 00 00 00 00 00 00 00
Antwort: Nur USBS (13 Byte, kein Payload)
```

Prefix `0xF8` statt `0xF6` – anderer Befehlstyp. Kurz nach 0x01. Unbekannte Funktion, möglicherweise Stream-Freigabe oder Hardware-Reset-Schritt.

---

## 5. prog_idx Struktur

```
Format: [Byte0][Byte1][Byte2][Byte3]
         0x40   ts_hi  ts_lo  seq

Byte0:
  0x40 = Standard-Eintrag
  0x48 = Markiert (verschlüsselt / Premium?)

Byte1+2 = Transport-Stream-ID (ts_id):
  0x40B7 → ts_id = 0xB7 = 183 
  0x40DE → ts_id = 0xDE = 222
  0x489D → ts_id = 0x9D = 157 (mit 0x48-Flag)

Byte3 = laufende Sequenz-Nummer innerhalb des Transponders
```

Eindeutige ts_ids im PCAP: insgesamt 1 (nach Analyse-Fehler – tatsächlich viele, da die Payload-Extraktion korrigiert werden muss → siehe nächste Analyse-Iteration).

---

## 6. Zeitlicher Ablauf (verfeinert)

```
t=0.06s   TCP connect + APIX 0x16 (Init)           → Status=0x00 (nicht bereit)
t=0.11s   APIX 0x17 (Init Phase 2)                  → 0x00
t=0.46s   APIX 0x16 (zweiter Versuch)               → Status=0x01 (bereit!)
t=2.13s   EPG-Schleife beginnt (0x30/0x31)          → viele Kanäle
t=28.60s  APIX 0x03 (prog_idx=0x40B40089)           → Kanal vorauswählen?
t=30.82s  APIX 0x32/0x33 (ch_Info für 0x40B40089)  → <ch_Info> XML
t=31.22s  APIX 0x02 (erster Status-Poll)            → Signal 100%/61
t=34.35s  APIX 0x02 (zweiter Poll)                  → Signal 100%/59
t=37.45s  APIX 0x02 (dritter Poll)                  → Signal 100%/59
t=39.34s  APIX 0x32/0x33 (zweiter ch_Info-Aufruf)  → größere Antwort
t=40.95s  APIX 0x02 (vierter Poll)                  → Signal 100%/60
t=44.44s  APIX 0x02 (fünfter Poll)                  → Signal 100%/61
t=46.94s  APIX 0x01 (Kanal-Aktivierung)             → kurze Bestätigung
t=47.17s  0xF8/0x07 (Unbekannt)                     → nur USBS
t=47.58s  APIX 0x17 (mit Flag=0x01!)               → Kanalwechsel bestätigt
t=47.65s  Flut von 0x30-Anfragen (neue EPG-Runde)   → PCAP endet
```

---

## 7. Wahrscheinlicher Tune-Ablauf

Basierend auf der Zeitanalyse:

```
1. APIX 0x03  – prog_idx senden (Kanal vormerken)
2. APIX 0x32  – ch_Info Größe abfragen
3. APIX 0x33  – ch_Info XML lesen (s_id + prog_idx bestätigt)
4. APIX 0x02  – Signal-Status pollen (bis gut genug?)
5. APIX 0x01  – Kanal aktivieren (Tune-Trigger)
6. 0xF8/0x07  – Stream freigeben?
7. APIX 0x17 (payload=0x01) – Kanalwechsel bestätigen
```

---

## 8. Offene Fragen

- [ ] Was genau macht `0x03`? Welche Frequenz/Parameter stecken im Payload?
- [ ] Was macht `0xF8/0x07`? (anderer Prefix, stream-freigabe?)
- [ ] Warum kommt `0x17` ein zweites Mal, diesmal mit `payload=0x01`?
- [ ] Woher weiß das Skript welchen `prog_idx` es für 0x03 nimmt?  
      → Aus dem ersten großen EPG-Block (`0x40B40089` war der erste geladene Kanal)
- [ ] Wo ist der UDP-Stream in diesem PCAP? → UDP-Analyse noch ausstehend
- [ ] Was bedeutet `0x48` als erstes Byte statt `0x40` im prog_idx?

---

## 9. Nächste Analyse-Schritte

1. UDP-Pakete analysieren (0x0A / 0x01 Befehle + MPEG-TS Daten)
2. EPG-XML komplett extrahieren und Kanalliste rekonstruieren
3. Signalstatus-Bytes von 0x02 genauer analysieren
4. Frequenz/Transponder-Info aus 0x03 Payload ableiten
