# Research-Übersicht: WISI OR S2D

→ **[SUMMARY.md](SUMMARY.md)** – kompakte Zusammenfassung aller verifizierten Erkenntnisse (aktuell)

## Einzeldokumente

| Datei | Inhalt | Vertrauen |
|---|---|---|
| [`SUMMARY.md`](SUMMARY.md) | Kompakte Zusammenfassung aller Erkenntnisse | ✅ aktuell |
| [`or_s2d_protocol_analysis.md`](or_s2d_protocol_analysis.md) | Detaillierter Befehlsablauf aus PCAPs vom 12. Oktober | ✅ belegt |
| [`pcap_analysis.md`](pcap_analysis.md) | Paket-Zählungen und Grenzen der verfügbaren PCAPs | ✅ belegt |
| [`apk_reverse_engineering.md`](apk_reverse_engineering.md) | Statische APK-Analyse inkl. Native-Libs (zuletzt: 15. Okt.) | ✅ belegt |
| [`neue_erkenntnisse.md`](neue_erkenntnisse.md) | Hypothesen aus Spec-Matching; teils überholt | ⚠️ veraltet |
| [`or_s2d_firmware_update.md`](or_s2d_firmware_update.md) | Firmware-Update-Wege laut WISI-Datenblatt | ✅ belegt |
| [`protocol_spec_or_s2d.md`](protocol_spec_or_s2d.md) | Breite Systemhypothesen; HTTP/REST/USB-Details nicht bestätigt | ⚠️ Ideenquelle, kein Implementierungsbeleg |

## Mitschnitte (PCAPs)

| Datei | Inhalt |
|---|---|
| `capture_pcapdroid_2026-10-11.pcap` | 200× `0xF9/0x0A`-Anfragen + 198 Antworten à 32.740 B |
| `PCAPdroid_12_Okt._16_16_04.pcap` | Kanallisten-Abruf (TCP 0xF6/0x20+0x21), 440 Kanäle |
| `PCAPdroid_12_Okt._16_28_17.pcap` | Tune-Ablauf + UDP-Stream-Start |

```bash
# Mitschnitte analysieren:
python src/wisi.py --pcap "research/PCAPdroid_12_Okt._16_16_04.pcap"
python src/wisi.py --pcap "research/PCAPdroid_12_Okt._16_28_17.pcap"
python src/wisi.py --pcap "research/capture_pcapdroid_2026-10-11.pcap"
```
