#!/usr/bin/env python3
"""Replug capture #7: iAP2-DETECT-ECHO statt Magic.

Erkenntnisse aus Capture #6 (adaptiver Magic-Knock):
- Die Firmware LIEST iAP-out im Fenster (8 Magic-Writes angenommen), aber die
  Magic stoppt den Detect-Loop NICHT und triggert nichts -> Magic ist wohl
  nicht der Knock.
- Der Detect-Loop laeuft weit ueber eine Minute, solange der Host die Beats
  mitliest -> das "Fenster" ist kein kurzer Timeout; Beats-Stopp in #1 kam
  vermutlich vom Lese-Stopp des Watchers, nicht von der Magic.

Neuer Versuch: `FF 55 02 00 EE 10` ist das standardmaessige iAP2-Detect, die
protokollkonforme Host-Antwort ist das ECHO derselben Bytes. Phasen:
  A) Beats lesen; nach Beat 2 Detect-ECHO -> iAP-out. 4 Beats beobachten
     (Stopp? anderes Payload? Re-Enumeration?).
  B) Falls unveraendert: nach Beat 6 EINE Magic (Replikation von #1, dort kam
     der 0E-Ack). Bis Beat 8 weiterlesen.
  C) Lese-Stopp-Gap 10 s (in #1 stoppten die Beats waehrend der Lesepause).
  D) If1+Alt1, Sniffer auf 0x81+0x82, Connect -> 0x02, danach cid07/HELLO6.
"""
import time
import threading
import usb.core
import usb.util

MAGIC = bytes([0xFF, 0x55, 0xFF, 0x55, 0xEE, 0x10])
DETECT = bytes([0xFF, 0x55, 0x02, 0x00, 0xEE, 0x10])
CONNECT = bytes([0xBB, 0xAA, 0x05, 0x00, 0x00])
HELLO6 = bytes([0xBB, 0xAA, 0x05, 0x00, 0x00, 0x0E])

t0 = time.monotonic()
def log(m):
    print(f"[{time.monotonic()-t0:7.2f}] {m}", flush=True)

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

def gone():
    if find_dev() is None:
        log("!! GERAET WEG (Re-Enumeration?) - warte aufs Wiederkommen")
        return True
    return False

def wr(ep, data, tag, timeout=800):
    try:
        dev.write(ep, data, timeout=timeout)
        log(f">> {tag} -> {ep:#04x}: {data.hex(' ')} ok")
        return True
    except usb.core.USBError as e:
        log(f">> {tag} -> {ep:#04x}: {e}")
        return False

# ---- Phasen A + B: Beats lesen, Echo nach Beat 2, ggf. Magic nach Beat 6
beats = 0
echo_sent = magic_sent = False
last_beat = time.monotonic()
while time.monotonic() - t_plug < 40 and beats < 8:
    try:
        data = bytes(dev.read(0x81, 512, timeout=500))
        beats += 1
        last_beat = time.monotonic()
        log(f"<< beat {beats}: {data.hex(' ')}")
        if beats == 2 and not echo_sent:
            echo_sent = True
            wr(0x01, DETECT, "DETECT-ECHO")
        if beats == 6 and not magic_sent:
            magic_sent = True
            wr(0x01, MAGIC, "MAGIC (einmalig, #1-Replikation)")
    except usb.core.USBError as e:
        if "No such device" in str(e) or gone():
            break
        now = time.monotonic()
        if beats > 0 and now - last_beat > 4.5:
            log(f"beats GESTOPPT (nach Echo={echo_sent}, Magic={magic_sent})")
            break
        if beats == 0 and now - t_plug > 8:
            log("keine Beats gesehen?!")
            break

# Re-Enumeration abfangen
if find_dev() is None:
    log("Geraet ist weg - warte bis 10 s aufs Wiederkommen")
    t_w = time.monotonic()
    dev2 = None
    while time.monotonic() - t_w < 10:
        dev2 = find_dev()
        if dev2 is not None:
            break
        time.sleep(0.2)
    if dev2 is None:
        log("kommt nicht wieder - ENDE")
        raise SystemExit
    log(f"wieder da! bcdDevice={dev2.bcdDevice:#06x} - neu aufsetzen")
    dev = dev2
    dev.set_configuration()
    usb.util.claim_interface(dev, 0)

# ---- Phase C: Lese-Stopp-Gap (in #1 stoppten die Beats in der Lesepause)
log("Phase C: 10 s NICHT lesen (Gap wie in #1)")
time.sleep(10)

# ---- Phase D: If1+Alt1, Sniffer, Connect + Probes
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
        if state["rx"] <= 15:
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
                    fn = f"tools/replug7_frame_{state['frames']}.jpg"
                    open(fn, "wb").write(bytes(buf[:p+2]))
                    log(f"** FRAME {state['frames']}: {p+2}B -> {fn}")
                buf, in_frame = bytearray(), False

for ep in (0x81, 0x82):
    threading.Thread(target=sniffer, args=(ep, f"EP{ep:#04x}"), daemon=True).start()
time.sleep(0.3)

wr(0x02, CONNECT, "CONNECT")
time.sleep(5)
if state["frames"] == 0 and state["rx"] <= 1:
    for data, tag in [(bytes([0xBB, 0xAA, 0x07, 0x00, 0x00]), "cid07"), (HELLO6, "HELLO6")]:
        wr(0x02, data, tag)
        time.sleep(3.5)

time.sleep(10)
state["stop"] = True
time.sleep(0.5)
log(f"ENDE: {state['frames']} Frames, {state['rx']} RX-Events, {state['bytes']} B")
