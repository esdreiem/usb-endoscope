#!/usr/bin/env python3
"""Replug capture #4: knock, then WAIT PASSIVELY on iAP-in for the device
hello (bb aa 05 00 00 0e) WITHOUT touching If1. Only after the hello (or
15s timeout): claim If1 + alt1, reply/connect variants, stream watch.
"""
import sys
import time
import threading
import usb.core
import usb.util

MAGIC = bytes([0xFF, 0x55, 0xFF, 0x55, 0xEE, 0x10])
DETECT = bytes([0xFF, 0x55, 0x02, 0x00, 0xEE, 0x10])
CONNECT = bytes([0xBB, 0xAA, 0x05, 0x00, 0x00])
HELLO6 = bytes([0xBB, 0xAA, 0x05, 0x00, 0x00, 0x0E])

def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

def find_dev():
    return usb.core.find(idVendor=0x2CE3, idProduct=0x3828)

state = {"dev": None, "stop": False, "frames": 0, "rx": 0}

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
    pkts = 0
    while not state["stop"]:
        dev = state["dev"]
        try:
            data = bytes(dev.read(ep, 65536, timeout=300))
        except usb.core.USBError:
            continue
        except Exception:
            time.sleep(0.2)
            continue
        state["rx"] += 1
        pkts += 1
        if pkts <= 12 or state["frames"] == 0:
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
                fn = f"replug4_frame_{state['frames']}.jpg"
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
log("re-plugged! claiming If0 ONLY")
t_plug = time.monotonic()
dev.set_configuration()
usb.util.claim_interface(dev, 0)
state["dev"] = dev

def rd81(timeout=400, size=512):
    try:
        return bytes(dev.read(0x81, size, timeout=timeout))
    except usb.core.USBError:
        return None

# ---- phase 1: detect beats, knock after the 2nd
n = 0
deadline = time.monotonic() + 8
while time.monotonic() < deadline and n < 2:
    data = rd81()
    if data:
        n += 1
        log(f"<< EP81 ({time.monotonic()-t_plug:.2f}s): {data.hex(' ')}")
wr(0x01, MAGIC, "MAGIC")

# ---- phase 2: passively read 0x81 up to 18s, waiting for the device hello
hello = None
deadline = time.monotonic() + 18
while time.monotonic() < deadline:
    data = rd81(timeout=500)
    if not data:
        continue
    log(f"<< EP81 ({time.monotonic()-t_plug:.2f}s): {data.hex(' ')}")
    if data[:2] == b"\xbb\xaa":
        hello = data
        log(f"DEVICE HELLO after {time.monotonic()-t_plug:.2f}s!")
        break
if hello is None:
    log("no device hello within 18s — continuing anyway (capture-#1 timing)")

# ---- phase 3: claim If1 + alt1, sniffers on, connect
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

def probe(data, tag, wait=3.0, ep=0x02):
    if state["frames"] > 0:
        return
    wr(ep, data, tag)
    time.sleep(wait)

probe(CONNECT, "CONNECT", 4.0)
probe(HELLO6, "HELLO6-echo", 3.0)          # echo the 6-byte hello back
probe(CONNECT, "CONNECT again", 3.0)
probe(bytes([0xBB, 0xAA, 0x07, 0x00, 0x00]), "cid07", 3.0)
probe(DETECT, "DETECT-echo", 2.0, ep=0x01)
probe(CONNECT, "CONNECT final", 4.0)

time.sleep(8)
state["stop"] = True
time.sleep(0.5)
log(f"CAPTURE COMPLETE: {state['frames']} frames, {state['rx']} rx events")
