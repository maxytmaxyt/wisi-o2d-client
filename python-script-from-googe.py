import socket
import time
import sys
import threading

# ==========================================
# KONFIGURATION
# ==========================================
DONGLE_IP = "192.168.178.32"
TCP_PORT = 8802
UDP_PORT = 8800

# Statischer Tag aus deinem PCAP
MAGIC_TAG = b"\xA0\xCB\x03\x37"

# 1. Der korrekte APIX 0x01 Befehl im Big-Endian USBC-Container
# Fordert exakt 0xBC00 Bytes (= 48.128 Bytes = 256 MPEG-TS Pakete) via UDP an
def build_apix_udp_stream_request():
    usbc_header = b"\x55\x53\x42\x43" + MAGIC_TAG
    length_big_endian = b"\x00\x00\xBC\x00"  # 48128 Bytes (0xBC00) laut Analyse
    flags_and_lun = b"\x80\x00\x10"          # Richtung Einlesen (80), LUN 00, CDB 10
    
    # Der herstellerspezifische APIX 0x01 Befehl für den Transportstrom
    apix_payload = b"\xF6\x01\x41\x50\x49\x58" + b"\x00" * 10
    
    return usbc_header + length_big_endian + flags_and_lun + apix_payload

def udp_receiver_thread(stop_event):
    """Dieser Thread lauscht auf UDP Port 8800 und fängt die echten TV-Daten ab"""
    print(f"[*] UDP-Empfänger auf Port {UDP_PORT} gestartet...")
    
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind(("0.0.0.0", UDP_PORT))
    udp_sock.settimeout(3.0)
    
    filename = "live_tv_stream.ts"
    packet_count = 0
    
    with open(filename, "wb") as f:
        while not stop_event.is_set():
            try:
                # Maximale UDP-Paketgröße für die 48.205 Byte großen TiViCon-Blöcke
                data, addr = udp_sock.recvfrom(65535)
                
                # Wir schneiden die 77 Byte TiViCon-Header ab, um den reinen MPEG-TS (Startbyte 0x47) zu isolieren
                if data.startswith(b"\x47") or b"\x47" in data[:100]:
                    # Wenn das Sync-Byte 0x47 verschoben ist, richten wir es aus
                    start_idx = data.find(b"\x47")
                    f.write(data[start_idx:])
                else:
                    # Fallback: Schreibe den Block roh, VLC korrigiert das im Hintergrund
                    f.write(data)
                
                packet_count += 1
                sys.stdout.write(f"\rEmpfangene UDP-Videoblöcke: {packet_count}")
                sys.stdout.flush()
            except socket.timeout:
                continue
            except Exception as e:
                print(f"\n[!] Fehler im UDP-Stream: {e}")
                break
                
    udp_sock.close()
    print("\n[*] UDP-Empfänger gestoppt.")

def run_main_apix_controller():
    print(f"[*] Verbinde mit Steuerungs-Port {DONGLE_IP}:{TCP_PORT}...")
    stop_event = threading.Event()
    
    try:
        # 1. TCP Steuerleitung aufbauen
        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_sock.connect((DONGLE_IP, TCP_PORT))
        print("[+] TCP-Steuerkanal steht.")
        
        # 2. UDP-Empfänger im Hintergrund starten
        receiver = threading.Thread(target=udp_receiver_thread, args=(stop_event,))
        receiver.daemon = True
        receiver.start()
        
        time.sleep(0.5)
        
        # 3. Den unendlichen APIX-0x01-Loop starten (Füttern des Dongles)
        print("[*] Trigger den Dongle via APIX 0x01 auf UDP-Umlenkung...")
        stream_cmd = build_apix_udp_stream_request()
        
        print("[!] Live-Streaming läuft! Drücke STRG + C zum Beenden.")
        while True:
            # Wir fordern kontinuierlich neue Blöcke über die Steuerleitung an
            tcp_sock.sendall(stream_cmd)
            
            # Kurze Pause zwischen den Leseanforderungen (analog zu den 30,41s im PCAP)
            time.sleep(0.05) 
            
    except KeyboardInterrupt:
        print("\n\n[*] Streaming durch Nutzer beendet.")
    finally:
        stop_event.set()
        tcp_sock.close()

if __name__ == "__main__":
    run_main_apix_controller()
