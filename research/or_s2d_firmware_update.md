# WISI OR S2D: Modell, USB-C und Firmware-Update

> Recherche: 12. Oktober 2026  
> Primärquellen: WISI OR S2D Produktdatenblatt und Bedienungsanleitung.

## Modellbezeichnung

Das Gerät, das der Nutzer als „WISI OR S2D“ identifiziert hat, ist das
**WISI OR S2D – DVB-S2 Free-To-Air SAT Dongle**. Die Modellbezeichnung steht
auf dem [offiziellen Produktdatenblatt](https://wisi.at/daten/artikel/pdf/Pro_OR-S2D_de.pdf).

In früheren Chat-Notizen und im ursprünglichen Repository-Namen wurde das Gerät
ungenau „WISI O2D“ genannt. In diesem Projekt ist daher zwischen dem konkreten
Modell OR S2D und älteren, allgemeineren O2D-/Tivizen-/TiViCon-Bezeichnungen zu
unterscheiden. Die Netzwerkprotokoll-Notizen beschreiben Mitschnitte; ihre
Übertragbarkeit auf andere Modelle ist nicht belegt.

## Was der USB-C-Anschluss laut WISI macht

Das Produktdatenblatt führt **USB-C: PC/Firmwareupdate** auf. Es nennt außerdem
Ethernet mit 100 MBit/s. Die Kurzbeschreibung sagt, dass der SAT-Dongle die
unverschlüsselten SAT-Signale über das Heimnetzwerk überträgt; Endgeräte verbinden
sich per LAN oder WLAN.

Die [OR-S2D-Bedienungsanleitung](https://wisi.at/daten/artikel/pdf/BDA_ORS2D_Dongle.pdf)
beschreibt den USB-Anschluss für Firmware-Upgrade oder eine direkte Verbindung des
Dongles mit einer **Android-TV-Box**. Bei direkter USB-Verbindung wird laut Handbuch
die Netzwerkfunktion deaktiviert. Das Handbuch sagt nicht, dass ein beliebiges
Android-Tablet den Dongle per USB als TV-Empfänger erkennen muss.

Der USB-C-Anschluss ist somit nicht als regulärer Streamingweg für ein Huawei-Tablet
dokumentiert. Dass das Tablet nach dem Anstecken nichts angezeigt hat, ist mit den
Unterlagen vereinbar, beweist aber nicht, dass über USB überhaupt keine Daten
übertragen werden.

## In der Anleitung beschriebene Firmware-Updatewege

Das Kapitel „Firmware Update“ der Bedienungsanleitung nennt:

1. **Dongle Online Upgrade:** TV2Smart prüft auf verfügbare Firmware-Updates. Die
   Anwendung prüft beim Start außerdem auf Firmware- und App-Updates. Nach Bestätigung
   des Benutzers startet das Upgrade.
2. **Dongle USB Upgrade über USB-Speicherstick:** Firmware wird auf einen USB-Stick
   kopiert; eine **Android-TV-Box** kann die Firmware vom eingesteckten Stick lesen.

Die Anleitung sagt, das Update könne einige Minuten dauern. Währenddessen dürfen
weder Dongle noch Android-TV-Box ausgeschaltet und der Dongle nicht vom Netzwerk oder
der Box getrennt werden. Es soll gewartet werden, bis TV2Smart neu gestartet wurde.

Die Anleitung legt in den betreffenden Passagen Dateisystem, Firmware-Dateinamen,
Paketformat oder Prüfsummen nicht fest. Diese Details deshalb nicht erraten.

## PC-Update: öffentlich nicht ausreichend dokumentiert

Obwohl das Produktdatenblatt USB-C mit „PC/Firmwareupdate“ beschriftet, konnte in den
öffentlich auffindbaren WISI-Unterlagen kein vollständiges PC-Updateverfahren
verifiziert werden. Insbesondere wurden kein freigegebenes PC-Flashprogramm, kein
benötigter PC-Treiber, keine Betriebssystemanforderung und kein öffentliches
OR-S2D-Firmwarepaket zum manuellen Flashen gefunden.

Das ist **kein Beweis**, dass es kein internes Serviceverfahren gibt. Es bedeutet,
dass ein sicheres PC-Update aus den hier verfügbaren Informationen nicht
reproduzierbar ist. Keine generischen Flash-Tools und keine Firmwaredateien anderer
Modelle verwenden. Für ein PC-Update sollte WISI um die freigegebene Software, die
passende Firmware für Hardware-Revision/Version und die vollständige Anleitung
gebeten werden.

## Quellen

- [WISI OR S2D Produktdatenblatt (PDF)](https://wisi.at/daten/artikel/pdf/Pro_OR-S2D_de.pdf)
- [WISI OR S2D Bedienungsanleitung (PDF)](https://wisi.at/daten/artikel/pdf/BDA_ORS2D_Dongle.pdf)
- [WISI Österreich – Software-Downloads](https://wisi.at/de/Software-Downloads.asp)
- [WISI Österreich – Downloads](https://wisi.at/de/downloads/index.asp)
- [TV2Smart für Android-Mobilgeräte](https://play.google.com/store/apps/details?id=com.tivicon.tv2smart.mobile&hl=de)
- [TV2Smart für Android TV](https://play.google.com/store/apps/details?id=com.tivicon.tv2smart.atv&hl=de)

Die App-Store-Einträge belegen TV2Smart-Apps, nicht ein PC-Flashtool. Ein dort
beschriebener Online-Updateweg belegt außerdem nicht, dass der Update-Server heute
noch erreichbar ist oder ein Update anbietet.
