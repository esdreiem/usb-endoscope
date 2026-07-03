#!/usr/bin/env python3
"""Replug capture #6: ADAPTIVE knock. Resend the magic after every detect
beat until the beats stop (= knock accepted; hypothesis: firmware ignores
the knock during its first ~4s of boot). Then mimic capture #1's ~10s gap,
claim If1+alt1, connect -> expect ack -> probe stream triggers.
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

def wr(ep, data, tag, timeout=600):
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
                fn = f"replug6_frame_{state['frames']}.jpg"
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

# ---- adaptive knock: after each beat (from beat 2 on), send magic;
# beats stopping = knock accepted
beats = 0
knocks = 0
t_last_beat = time.monotonic()
t_stop = None
while time.monotonic() - t_plug < 30:
    data = rd81(timeout=500)
    now = time.monotonic()
    if data:
        beats += 1
        t_last_beat = now
        log(f"<< beat {beats} ({now-t_plug:.2f}s): {data.hex(' ')}")
        if beats >= 2 and knocks < 6:
            knocks += 1
            wr(0x01, MAGIC, f"MAGIC #{knocks}")
    elif now - t_last_beat > 4.5:
        t_stop = now
        log(f"beats STOPPED ({now-t_plug:.2f}s after plug, {knocks} knocks, {beats} beats)")
        break
if t_stop is None:
    t_stop = time.monotonic()
    log("beats never stopped within 30s — continuing anyway")

# ---- capture-#1 gap: ~10s of total silence after acceptance
time.sleep(9)

# ---- claim If1 + alt1, sniffers, connect
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

wr(0x02, CONNECT, "CONNECT")
time.sleep(4)

if state["frames"] == 0:
    for data, tag, ep in [
        (bytes([0xBB, 0xAA, 0x07, 0x00, 0x00]), "cid07", 0x02),
        (HELLO6, "HELLO6->0x02", 0x02),
        (HELLO6, "HELLO6->0x01", 0x01),
        (CONNECT, "CONNECT->0x01", 0x01),
        (CONNECT, "CONNECT again", 0x02),
    ]:
        if state["frames"] > 0:
            break
        wr(ep, data, tag)
        time.sleep(3.5)

time.sleep(12)
state["stop"] = True
time.sleep(0.5)
log(f"CAPTURE COMPLETE: {state['frames']} frames, {state['rx']} rx events")
