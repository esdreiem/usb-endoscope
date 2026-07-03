#!/usr/bin/env python3
"""Replug capture #8: iAP2-Link-Handshake.

Capture #7: Nach dem Detect-Echo schaltet das Geraet auf iAP2-Link-Pakete um
und sendet alle ~2 s ein SYN (FF 5A, ctrl 0x80, eine Control-Session 0x0A).
Jetzt: als "Apple-Geraet" mit SYN/ACK (ctrl 0xC0) antworten, Link etablieren,
beobachten (Identification? weitere Sessions? Re-Enumeration?) und danach
BB-AA-Connect auf useeplus probieren.
"""
import time
import threading
import usb.core
import usb.util

DETECT = bytes([0xFF, 0x55, 0x02, 0x00, 0xEE, 0x10])
CONNECT = bytes([0xBB, 0xAA, 0x05, 0x00, 0x00])

t0 = time.monotonic()
def log(m):
    print(f"[{time.monotonic()-t0:7.2f}] {m}", flush=True)

def cks(bs):
    return (0x100 - (sum(bs) & 0xFF)) & 0xFF

def iap2_packet(ctrl, seq, ack, session, payload=b""):
    hdr = bytes([0xFF, 0x5A]) + (9 + len(payload) + (1 if payload else 0)).to_bytes(2, "big") \
        + bytes([ctrl, seq, ack, session])
    hdr += bytes([cks(hdr)])
    if payload:
        payload = payload + bytes([cks(payload)])
    return hdr + payload

def parse_iap2(data):
    if len(data) < 9 or data[0] != 0xFF or data[1] != 0x5A:
        return None
    return {"len": int.from_bytes(data[2:4], "big"), "ctrl": data[4], "seq": data[5],
            "ack": data[6], "sess": data[7], "payload": bytes(data[9:-1]) if len(data) > 9 else b""}

def find_dev():
    return usb.core.find(idVendor=0x2CE3, idProduct=0x3828)

log("warte auf ABSTECKEN ...")
while find_dev() is not None:
    time.sleep(0.3)
log("abgesteckt. warte auf ANSTECKEN ...")
while True:
    dev = find_dev()
    if dev is not None:
        break
    time.sleep(0.15)
log("angesteckt! claim If0 ONLY")
t_plug = time.monotonic()
dev.set_configuration()
usb.util.claim_interface(dev, 0)

def wr(data, tag, ep=0x01):
    try:
        dev.write(ep, data, timeout=800)
        log(f">> {tag} -> {ep:#04x}: {data.hex(' ')}")
        return True
    except usb.core.USBError as e:
        log(f">> {tag} -> {ep:#04x}: FEHLER {e}")
        return False

# ---- Phase A: Detect-Echo nach dem 1. Beat
echoed = False
my_seq = 0x0B
link_up = False
synack_sent = False
last_rx = time.monotonic()
sessions = []
while time.monotonic() - t_plug < 90:
    try:
        data = bytes(dev.read(0x81, 4096, timeout=500))
    except usb.core.USBError as e:
        if "No such device" in str(e):
            log("GERAET WEG (Re-Enumeration!) - Abbruch dieser Phase")
            break
        if time.monotonic() - last_rx > 12 and link_up:
            log("12 s Stille nach Link-Up - weiter zu Phase B")
            break
        if time.monotonic() - last_rx > 20:
            log("20 s Stille - weiter zu Phase B")
            break
        continue
    last_rx = time.monotonic()
    log(f"<< iAP-in: {data.hex(' ')}")
    if data == DETECT and not echoed:
        echoed = True
        wr(DETECT, "DETECT-ECHO")
        continue
    p = parse_iap2(data)
    if p is None:
        log("   (kein iAP2-Paket)")
        continue
    log(f"   iAP2: ctrl={p['ctrl']:#04x} seq={p['seq']:#04x} ack={p['ack']:#04x} sess={p['sess']:#04x} payload={p['payload'].hex(' ')}")
    if p["ctrl"] & 0x80 and not link_up:  # SYN (ggf. Retransmit)
        if not synack_sent:
            synack_sent = True
            # Session-Liste aus dem SYN uebernehmen (ab Byte 9 der Payload)
            sp = p["payload"]
            for i in range(9, len(sp) - 2, 3):
                sessions.append((sp[i], sp[i+1], sp[i+2]))
            log(f"   Sessions des Geraets: {[(hex(a), hex(b), hex(c)) for a, b, c in sessions]}")
        # SYN/ACK: gleiche Parameter zurueck, ack = deren seq
        wr(iap2_packet(0xC0, my_seq, p["seq"], 0x00, p["payload"]), "SYN/ACK")
    elif p["ctrl"] == 0x40 and not link_up:  # ACK auf unser SYN/ACK
        link_up = True
        log(f"   *** LINK UP *** (ack={p['ack']:#04x})")
    elif p["ctrl"] & 0x40 and p["payload"]:
        # Datenpaket einer Session: quittieren
        wr(iap2_packet(0x40, (my_seq + 1) & 0xFF, p["seq"], 0x00), f"ACK fuer seq {p['seq']:#04x}")

log(f"Phase A fertig: echo={echoed} link_up={link_up}")

# ---- Phase B: useeplus aktivieren und Connect probieren, weiter iAP2 acken
dev2 = find_dev()
if dev2 is None:
    log("Geraet weg - warte 10 s aufs Wiederkommen")
    t_w = time.monotonic()
    while time.monotonic() - t_w < 10:
        dev2 = find_dev()
        if dev2 is not None:
            break
        time.sleep(0.2)
    if dev2 is None:
        log("kommt nicht wieder - ENDE")
        raise SystemExit
    log(f"wieder da! bcdDevice={dev2.bcdDevice:#06x}")
    dev = dev2
    dev.set_configuration()
    usb.util.claim_interface(dev, 0)

usb.util.claim_interface(dev, 1)
dev.set_interface_altsetting(interface=1, alternate_setting=1)
log("If1 -> Alt1")

state = {"stop": False, "rx": 0, "frames": 0, "bytes": 0}
def sniffer(ep, tag):
    buf, in_frame = bytearray(), False
    while not state["stop"]:
        try:
            data = bytes(dev.read(ep, 65536, timeout=300))
        except usb.core.USBError:
            continue
        state["rx"] += 1
        state["bytes"] += len(data)
        if state["rx"] <= 20:
            log(f"<< {tag}: {len(data)}B: {data[:32].hex(' ')}")
        payload = data[12:] if len(data) >= 12 and data[0] == 0xAA and data[1] == 0xBB else data
        if not in_frame:
            p = payload.find(b"\xff\xd8")
            if p >= 0:
                in_frame, buf = True, bytearray(payload[p:])
        else:
            buf.extend(payload)
        if in_frame:
            p = buf.find(b"\xff\xd9")
            if p >= 0:
                state["frames"] += 1
                if state["frames"] <= 5:
                    fn = f"tools/replug8_frame_{state['frames']}.jpg"
                    open(fn, "wb").write(bytes(buf[:p+2]))
                    log(f"** FRAME {state['frames']}: {p+2}B -> {fn}")
                buf, in_frame = bytearray(), False

for ep in (0x81, 0x82):
    threading.Thread(target=sniffer, args=(ep, f"EP{ep:#04x}"), daemon=True).start()
time.sleep(0.3)

wr(CONNECT, "CONNECT", ep=0x02)
time.sleep(20)
state["stop"] = True
time.sleep(0.5)
log(f"ENDE: {state['frames']} Frames, {state['rx']} RX-Events, {state['bytes']} B")
