#!/usr/bin/env python3
"""Replug capture #3: reproduce capture #1 exactly (claim If0 only ->
detect -> magic->iAP-out -> knock stop -> claim If1+alt1 -> connect->0x02
-> ack), then probe follow-up commands to find the stream trigger.
"""
import sys
import time
import threading
import usb.core
import usb.util

MAGIC = bytes([0xFF, 0x55, 0xFF, 0x55, 0xEE, 0x10])
DETECT = bytes([0xFF, 0x55, 0x02, 0x00, 0xEE, 0x10])
CONNECT = bytes([0xBB, 0xAA, 0x05, 0x00, 0x00])

def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

def find_dev():
    return usb.core.find(idVendor=0x2CE3, idProduct=0x3828)

state = {"dev": None, "stop": False, "frames": 0, "rx": []}

def wr(ep, data, tag, timeout=800):
    try:
        state["dev"].write(ep, data, timeout=timeout)
        log(f">> {tag} -> {ep:#04x}: {data.hex(' ')} ok")
        return True
    except usb.core.USBError as e:
        log(f">> {tag} -> {ep:#04x}: FAILED ({e})")
        return False

def sniffer(ep, tag):
    buf, in_frame = bytearray(), False
    while not state["stop"]:
        dev = state["dev"]
        if dev is None:
            time.sleep(0.1)
            continue
        try:
            data = bytes(dev.read(ep, 65536, timeout=300))
        except usb.core.USBError:
            continue
        except Exception:
            time.sleep(0.2)
            continue
        state["rx"].append((tag, data))
        log(f"<< {tag}: {len(data)}B: {data[:32].hex(' ')}")
        payload = data
        if len(data) >= 12 and data[0] == 0xAA and data[1] == 0xBB:
            payload = data[12:]
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
                fn = f"replug3_frame_{state['frames']}.jpg"
                open(fn, "wb").write(bytes(buf[:p+2]))
                log(f"** {tag} FRAME {state['frames']}: {p+2}B -> {fn}")
                buf, in_frame = bytearray(), False

# ---- wait for replug
log("waiting for device to be UNPLUGGED ...")
while find_dev() is not None:
    time.sleep(0.3)
log("unplugged. waiting for RE-PLUG ...")
while True:
    dev = find_dev()
    if dev is not None:
        break
    time.sleep(0.15)
log("re-plugged! claiming If0 ONLY (like capture #1)")
t_plug = time.monotonic()

dev.set_configuration()
usb.util.claim_interface(dev, 0)
state["dev"] = dev

# ---- phase 1: wait for detect on 0x81 (main thread, like capture #1)
detect_n = 0
deadline = time.monotonic() + 8
while time.monotonic() < deadline and detect_n < 2:
    try:
        data = bytes(dev.read(0x81, 512, timeout=400))
        detect_n += 1
        log(f"<< EP81 detect #{detect_n} ({time.monotonic()-t_plug:.2f}s): {data.hex(' ')}")
    except usb.core.USBError:
        pass

# ---- phase 2: magic -> iAP OUT 0x01
wr(0x01, MAGIC, "MAGIC")

# confirm knock: read 0x81 — detect should stop within ~3s
end = time.monotonic() + 3.5
while time.monotonic() < end:
    try:
        data = bytes(dev.read(0x81, 512, timeout=400))
        log(f"<< EP81 post-magic: {data.hex(' ')}")
    except usb.core.USBError:
        pass
log("detect loop should have stopped now")

# ---- phase 3: claim If1, alt1, start sniffers, connect
usb.util.claim_interface(dev, 1)
dev.set_interface_altsetting(interface=1, alternate_setting=1)
try:
    dev.clear_halt(0x02)
except Exception:
    pass
t1 = threading.Thread(target=sniffer, args=(0x81, "EP81"), daemon=True)
t2 = threading.Thread(target=sniffer, args=(0x82, "EP82"), daemon=True)
t1.start(); t2.start()
time.sleep(0.3)

def probe(data, tag, wait=2.5, ep=0x02):
    n_before = len(state["rx"])
    wr(ep, data, tag)
    time.sleep(wait)
    return len(state["rx"]) > n_before  # did anything come back?

probe(CONNECT, "CONNECT", 3.0)

# ---- phase 4: follow-up probes (stop early if frames start)
followups = [
    (CONNECT,                                   "CONNECT again"),
    (bytes([0xBB, 0xAA, 0x07, 0x00, 0x00]),     "cid07 (video?)"),
    (bytes([0xBB, 0xAA, 0x0B, 0x00, 0x00]),     "cid0B"),
    (bytes([0xBB, 0xAA, 0x05, 0x01, 0x00, 0x00]), "connect+payload 00"),
    (bytes([0xBB, 0xAA, 0x05, 0x01, 0x00, 0x01]), "connect+payload 01"),
    (bytes([0xBB, 0xAA, 0x01, 0x00, 0x00]),     "cid01"),
    (bytes([0xBB, 0xAA, 0x02, 0x00, 0x00]),     "cid02"),
    (bytes([0xBB, 0xAA, 0x03, 0x00, 0x00]),     "cid03"),
    (bytes([0xBB, 0xAA, 0x04, 0x00, 0x00]),     "cid04"),
    (bytes([0xBB, 0xAA, 0x06, 0x00, 0x00]),     "cid06"),
    (bytes([0xBB, 0xAA, 0x08, 0x00, 0x00]),     "cid08"),
    (bytes([0xBB, 0xAA, 0x00, 0x00, 0x00]),     "cid00"),
]
for data, tag in followups:
    if state["frames"] > 0:
        break
    probe(data, tag)

# detect-echo fallback via iAP out (may jam if FIFO full — that's informative too)
if state["frames"] == 0:
    probe(DETECT, "DETECT-echo", 2.0, ep=0x01)
    probe(CONNECT, "CONNECT final", 4.0)

# let any stream run
time.sleep(6)
state["stop"] = True
time.sleep(0.5)
log(f"CAPTURE COMPLETE: {state['frames']} frames, {len(state['rx'])} rx events")
