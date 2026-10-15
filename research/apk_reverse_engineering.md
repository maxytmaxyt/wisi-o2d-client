# TV2Smart: verifizierte APK-Analyse

Statische Analyse des am 14.10.2026 hochgeladenen XAPK. DEX-Methoden wurden mit Androguard disassembliert/dekompiliert; Native-Symbole wurden aus den ARM64-ELF-Dateien gelesen. Das belegt implementierte App-Pfade, nicht automatisch Verhalten auf jedem Dongle oder jeder Firmware.

## Artefakt

| Merkmal | Verifizierter Wert |
|---|---|
| XAPK | `TV2Smart_3.M20260803.0-rev-a14aeb377_APKPure.xapk` |
| Paket / Version | `com.tivicon.tv2smart.mobile`, `3.M20260803.0-rev-a14aeb377` |
| Version-Code | `202608030` |
| Android | min API 26, target API 36 |
| Split-Aufbau | Base, `config.arm64_v8a`, `config.xxxhdpi` |
| Base-DEX | `classes.dex`, `classes2.dex`, `classes3.dex` |
| Signatur | v2 und v3; Zertifikats-SHA1 `c61d91b663949e65be1326e58e0c9394daf4a386` |
| XAPK-SHA256 | `c116914f0c66e38c0b1c4318d0c5bd00541b94cc0efd555a54ffc3997e92ff7f` |
| Base-APK-SHA256 | `a8801eb98194e4d35aaf1a8057b761571e87e30d394c2bd4950a8735dd771cd6` |

Der ARM64-Split enthält `libpimbridge.so`, `libpimdec.so`, `libsecure_module.so`, `libvlc.so`, `libvlcjni.so`, `librtmp-jni.so` und `libc++_shared.so`. In diesem XAPK liegen weder `libtivicon_dvb.so` noch `libstream_decoder.so`; diese Namen aus älteren Notizen beschreiben nicht den Inhalt dieses Artefakts.

## APIX-Builder und Speedtest

Die DEX-Klasse `com.crenova.tv.dongle.dvb.sdk.messages.e1` baut einen klassischen USBC-CBW mit **31 Byte** plus optionalem Payload. Der Builder schreibt die Nutzdatenlänge big-endian in Bytes 8–11, Flags in Byte 12, `APIX` in Bytes 16–19, Prefix in Byte 15 und Opcode in Byte 20. In diesem Builder gibt es keine 35-Byte-Erweiterung.

`com.crenova.tv.dongle.dvb.sdk.messages.CreNovaDongleInitListener.onGetChannelListXml()` baut konkret einen Request mit `data_len=48.128`, Flags `0x80`, Prefix `0xF9` und Opcode `0x0A`. Trotz des dekompilierten Methodennamens zeigt die Aufrufstelle die tatsächliche Verwendung: `CrenovaDongleInit.getSpeedTestMbps()` ruft diesen Builder in einer Schleife auf, zählt erfolgreiche Antworten und berechnet den Durchsatz anhand von 48.128 Byte pro Antwort.

Der Netzwerk-Responsepfad wird mit einer erwarteten Datenlänge von 48.130 Byte aufgerufen. Für die 48-KB-Antwort liest er weitere 13 Abschlussbytes und trennt diese vom Datenbereich:

```text
48.130 Datenbytes + 13 Abschlussbytes = 48.143 empfangene Bytes
```

Das erklärt die am 13. Oktober gemeldete Länge und das `f9 0a`-Präfix sehr gut als Speedtest-Antwort, nicht als Senderdatenbank. Der APK-Code interpretiert deren Inhalt nicht als Senderdatensätze. Weil der konkrete Rohblob fehlt, bleiben seine Füllbytes und der 13-Byte-Abschluss bytegenau ungeprüft. Die älteren PCAP-Antworten mit 32.740 Byte sind eine andere Beobachtung und werden durch diesen Codepfad nicht erklärt.

## Kanalliste und Tune-API

- Die vorhandenen OR-S2D-PCAPs zeigen die XML-Kanalliste über TCP `0xF6/0x20` und `0xF6/0x21`. Der APK-Builder enthält mehrere ähnlich benannte Methoden; Methodennamen wie `onGetChannelListXml` reichen allein nicht aus, um ein Wire-Opcode zuzuordnen.
- Das öffentliche SDK-API `tuneChannelByProgIdx(int)` sendet den internen Dispatcher-Auftrag 802. `tuneChannelByProgIdxAndPid(int, int)` sendet Auftrag 808 und akzeptiert genau einen zusätzlichen PID-Integer, nicht separate Video- und Audio-PIDs.
- Der dekompilierte Handler für Auftrag 808 übergibt Program-Index und PID an einen Builder, der einen `0xF6/0x03`-Request mit 10-Byte-Payload konstruiert. Daraus folgt **nicht**, dass diese Werte Bestandteil des im PCAP beobachteten `0xF6/0x01`-Payloads sind.
- Die genaue Zuordnung aller App-internen Tune-Varianten zum OR-S2D-Wireablauf ist aus diesem APK allein nicht abschließend bestätigt. Für `0xF6/0x01` bleibt der Mitschnitt mit Payload `00 04` der direkte Beleg.

## PIM und Sicherheit

`PimCarouselClient` startet getrennte Multicast-Empfänger für EPG-XML und JSON-Nachrichten (`chanmap`/`echan`). Die JSON-Kanalmetadaten enthalten unter anderem `major`, `minor`, Name, IP und Port. PIM-Streams werden als `udp://IP:Port` geöffnet; `PimDataSource` richtet eingehende TS-Daten an 188-Byte-Grenzen aus und ruft `PimNative.decode()` auf.

`PimNative.init(customerCode, pmtPid)` ruft nativ erst `nativeInit(customerCode)` und danach `nativeSetPmtPid(pmtPid)` auf. `libpimbridge.so` exportiert die JNI-Wrapper und bindet die Symbole `pim_custom_init`, `pim_set_pmt_pid`, `pim_set_key`, `pim_status` und `pim_decode` ein. Das belegt einen separaten proprietären PIM-Entschlüsselungspfad in der App, aber keine Kombination dieses Pfads mit dem beobachteten OR-S2D-APIX-Tune-Befehl.

Das DEX enthält außerdem `SecureNativeModule` mit JNI-Methoden für Authentifizierungs-/DH-/SAC-Nachrichten und die ARM64-Datei `libsecure_module.so`. Das belegt, dass die App CI+-artige Sicherheitsfunktionen mitbringt. Es beweist weder, dass diese Funktionen beim WISI OR S2D verwendet werden, noch einen bestimmten APIX-Shared-Secret- oder Challenge-Response-Algorithmus. Die früher notierte Formel `MD5(Challenge || SharedSecret || Timestamp)` ist durch diese APK-Analyse nicht bestätigt.

## Native-Library-Analyse (15. Oktober 2026)

Die ARM64-Bibliotheken aus `config.arm64_v8a.apk` wurden mit `strings` und `nm` statisch ausgelesen. Die Analyse wurde ohne Laufzeitumgebung durchgeführt und belegt keine Ausführung auf echtem Gerät.

### Übersicht der Native-Libs

| Datei | Größe | Funktion |
|---|---|---|
| `libsecure_module.so` | 229 KB | CI+-artige Content-Control-Auth (SAC/CC-Protokoll, DH-Key-Exchange) |
| `libpimbridge.so` | 5,4 KB | JNI-Wrapper für PIM-Entschlüsselung (ruft `libpimdec.so` auf) |
| `libpimdec.so` | 68 KB | Eigentlicher PIM-Decoder (proprietäre CA-Entschlüsselung, Key-Table aus `libpimbridge.so`) |
| `librtmp-jni.so` | 90 KB | RTMP-Streaming (für externe Streams, nicht OR S2D APIX) |
| `libvlc.so` / `libvlcjni.so` | 44 MB / 94 KB | VLC-Player-Core; `libvlc.so` enthält MD5-Implementierung für interne Zwecke |

### Hardcodierter String in `libsecure_module.so`

In der `.rodata`-Sektion von `libsecure_module.so` wurde ein Base64-kodierter String gefunden, der direkt über dem `CCMSG_CreateAuthReqNoncePacket`-Symbol steht:

```
THVrZVJhbkRvbHBoQ0krMQ==  →  dekodiert: LukeRanDolphCI+1
```

**Kontext im Binary:**
```
CCMSG_CreateAuthReqNoncePacket    ← Symbol (Nonce-Paket-Builder)
Chunk- %s
AUTH_SEND_NONCE
THVrZVJhbkRvbHBoQ0krMQ==         ← Base64-String im .rodata
%02X
nonce
```

Der String liegt im Nur-Lese-Datensegment, nicht auf dem Stack oder in einer Funktion. Er wird wahrscheinlich als statisches Argument an `CNKEY_Init()` oder `SECTK_Initialise()` übergeben, die beide am Anfang der Init-Kette stehen.

**Weitere relevante Symbole in derselben Lib:**
- `CNKEY_Init`, `CNKEY_GetHostKey`, `CNKEY_CalculateRootKey` – Key-Derivation-Chain
- `SECTK_GenerateDhKeys`, `SECTK_CalculateDhShared`, `SECTK_CheckDhPublicKey` – Diffie-Hellman-Schlüsselaustausch
- `SECTK_Sha256`, `CE_Sha256`, `CE_Sha1` – Hashfunktionen (kein MD5 in dieser Lib)
- `SECTK_AesEncrypt`, `SECTK_AesCbcEncrypt` – AES-Verschlüsselung des SAC-Kanals
- Chunk-Keys: `dh_g`, `dh_p`, `dh_q` – DH-Parameter (in `.rodata`, Werte binär kodiert)
- Debugpfad: `/home/paul/ANDROID/Android-Studio-Projects/CreTV/tivicon-dvb-sdk-internal-network-eventbus/...` – bestätigt CreNova als Hersteller

### Einordnung: Wofür wird das gebraucht?

Das CI+-artige SAC/CC-Protokoll in `libsecure_module.so` ist für **Pay-TV / Conditional Access** zuständig, nicht für normales FTA-Streaming. Die Package-Struktur bestätigt das eindeutig:

- `com.crenova.tv.dongle.dvb.sdk.cas.*` – CAS = **Conditional Access System**
- `com.crenova.tv.dongle.dvb.sdk.security.*` – Sicherheits-Layer für CA
- `SecureNativeModule` mit `msgCreateAuthReqNoncePacket`, `msgCreateCCSACKeyingReqPacket` etc. – SAC = Secure Authenticated Channel (CI+-Protokoll)

**Für FTA-Streaming (Schritt 1–3 im normalen Ablauf) wird `libsecure_module.so` nicht benötigt.**

`LukeRanDolphCI+1` ist wahrscheinlich ein **Root-Key oder Seed** für die CNKEY-Derivation-Chain, die ausschließlich im CA-Pfad (Pay-TV) aktiv wird. Die bisherigen PCAPs zeigen keine CC/SAC-Handshake-Pakete im normalen Stream-Betrieb – was zu FTA-Kanälen passt.

### Was `libpimbridge.so` / `libpimdec.so` macht

PIM (Programme Integration Module) ist ein separater proprietärer CA-Pfad über Multicast-UDP. `PimCarouselClient` empfängt Kanal-Metadaten per Multicast (`chanmap`/`echan` als JSON), öffnet UDP-Streams und ruft `pim_decode()` mit den TS-Paketen auf. Das ist **unabhängig vom APIX/USBC-Protokoll** und nicht Teil des OR S2D Streaming-Pfads.

### Fazit für den Client

| Frage | Antwort |
|---|---|
| Braucht normales FTA-Streaming die CC/SAC-Auth? | **Nein.** Kein SAC-Handshake in FTA-PCAPs sichtbar. |
| Was ist `LukeRanDolphCI+1`? | Root-Key/Seed für CI+-artige Pay-TV-Authentifizierung (CNKEY-Chain). |
| Braucht man `libsecure_module.so` für den Python-Client? | Nur wenn verschlüsselte Kanäle (`0x48xxxxxx`-prog_idx) geöffnet werden sollen. |
| War die Formel `MD5(Challenge || SharedSecret || Timestamp)` korrekt? | **Nicht bestätigt.** `libsecure_module.so` verwendet SHA-256 und AES, kein MD5 im CC-Pfad. |

## Korrigierte Aussagen und verbleibende Grenzen

| Frühere Aussage | Ergebnis aus dem hochgeladenen Artefakt |
|---|---|
| `0xF9/0x0A` ist eine Senderdatenbank oder EPG-Abfrage | Nicht bestätigt. Der konkrete APK-Aufruf ist ein Speedtest mit 48.128 Testbytes. |
| Die 48.143 Byte sind ein dekodierbarer Kanalblob | Sehr wahrscheinlich Speedtest-Antwort: 48.130 Datenbytes plus 13 Abschlussbytes. Null-/Füllmuster nicht roh geprüft. |
| Alle APK-Requests sind 66 Byte lang | Falsch für den eingebetteten generischen Builder: er erzeugt 31-Byte-USBC-Requests. Andere Mitschnitte/Transportpfade können abweichen. |
| `...ByProgIdxAndPid` liefert Program-Index plus Video- und Audio-PID | In diesem SDK hat die Methode zwei Integer-Parameter insgesamt: Program-Index und einen PID-Wert. |
| Die App enthält `libtivicon_dvb.so` und `libstream_decoder.so` | Diese Bibliotheken fehlen im hochgeladenen XAPK. |
| Die APK beweist den OR-S2D-`0xF6/0x01`-Payload | Nein. Dafür bleibt der vorhandene PCAP mit Payload `00 04` der direkte Beleg. |

Statische Analyse kann Bytecodepfade zeigen, aber keine Live-Ausführung des SDKs auf dem OR S2D ersetzen. Das 48.143-Byte-Rohpaket wäre weiterhin nötig, um einzelne Payload- und Footerbytes zu verifizieren.
