#!/usr/bin/env python3
"""Replug capture #5: reproduce #1 INCLUDING the silent gap.
Knock after 2 beats, read ~2 more beats, then GO SILENT (no reads, no
claims) until t=15s. Then poll iAP-in for the vendor hello
bb aa 05 00 00 0e. Only after the hello: reply probes (iAP channel first),
then If1+alt1+connect, sniffing both IN EPs.
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
        if state["frames"] < 3:
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
                fn = f"replug5_frame_{state['frames']}.jpg"
                open(fn, "wb").write(bytes(buf[:p+2]))
                log(f"** {tag} FRAME {state['frames']}: {p+2}B -> {fn}")
                buf, in_frame = bytearray(), False

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

def rd81(timeout=400):
    try:
        return bytes(dev.read(0x81, 512, timeout=timeout))
    except usb.core.USBError:
        return None

# phase 1: 2 beats -> magic -> read ~2 more beats until t=7s
n = 0
while time.monotonic() - t_plug < 8 and n < 2:
    data = rd81()
    if data:
        n += 1
        log(f"<< EP81 ({time.monotonic()-t_plug:.2f}s): {data.hex(' ')}")
wr(0x01, MAGIC, "MAGIC")
while time.monotonic() - t_plug < 7.0:
    data = rd81()
    if data:
        log(f"<< EP81 ({time.monotonic()-t_plug:.2f}s): {data.hex(' ')}")

# phase 2: SILENCE until t=15s — no reads, no claims
log("going silent (no reads) until t=15s ...")
time.sleep(max(0, 15.0 - (time.monotonic() - t_plug)))

# phase 3: poll for the hello
hello = None
while time.monotonic() - t_plug < 28:
    data = rd81(timeout=500)
    if not data:
        continue
    log(f"<< EP81 ({time.monotonic()-t_plug:.2f}s): {data.hex(' ')}")
    if data[:2] == b"\xbb\xaa":
        hello = data
        log(f"DEVICE HELLO at t={time.monotonic()-t_plug:.2f}s")
        break

# phase 4: reply on the iAP channel FIRST (no If1 involvement yet)
t81 = threading.Thread(target=sniffer, args=(0x81, "EP81"), daemon=True)
t81.start()
if hello:
    wr(0x01, HELLO6, "HELLO6-echo(iAP)")
    time.sleep(4)
    if state["frames"] == 0:
        wr(0x01, CONNECT, "CONNECT(iAP)")
        time.sleep(4)

# phase 5: If1 + alt1 + useeplus-channel probes
if state["frames"] == 0:
    usb.util.claim_interface(dev, 1)
    dev.set_interface_altsetting(interface=1, alternate_setting=1)
    try:
        dev.clear_halt(0x02)
    except Exception:
        pass
    t82 = threading.Thread(target=sniffer, args=(0x82, "EP82"), daemon=True)
    t82.start()
    time.sleep(0.3)
    for data, tag, ep in [
        (CONNECT, "CONNECT", 0x02),
        (HELLO6, "HELLO6-echo", 0x02),
        (bytes([0xBB, 0xAA, 0x07, 0x00, 0x00]), "cid07", 0x02),
        (CONNECT, "CONNECT again", 0x02),
    ]:
        if state["frames"] > 0:
            break
        wr(ep, data, tag)
        time.sleep(3.5)

time.sleep(8)
state["stop"] = True
time.sleep(0.5)
log(f"CAPTURE COMPLETE: {state['frames']} frames, {state['rx']} rx events")
