#!/usr/bin/env python3
"""Replug capture #2: this time send the MAGIC to the useeplus OUT EP (0x02)
inside the live detect window (hypothesis: that is what triggered the
re-enumeration on Android). Fallbacks: connect on 0x02, then 0x01, then
detect-echo + connect. Sniffs both IN EPs the whole time.
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

def dump(dev, tag):
    lines = [f"--- descriptors ({tag}) addr={dev.address} ---"]
    for cfg in dev:
        for intf in cfg:
            lines.append(f"  If{intf.bInterfaceNumber} alt{intf.bAlternateSetting} "
                         f"proto={intf.bInterfaceProtocol} EPs={[hex(e.bEndpointAddress) for e in intf]}")
    log("\n".join(lines))

state = {"dev": None, "stop": False, "frames": 0}

def open_dev(d):
    d.set_configuration()
    usb.util.claim_interface(d, 0)
    usb.util.claim_interface(d, 1)
    try:
        d.set_interface_altsetting(interface=1, alternate_setting=1)
    except Exception as e:
        log(f"altsetting: {e}")
    state["dev"] = d
    return d

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
            data = bytes(dev.read(ep, 65536, timeout=400))
        except usb.core.USBError:
            continue
        except Exception:
            time.sleep(0.2)
            continue
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
                fn = f"replug2_frame_{state['frames']}.jpg"
                open(fn, "wb").write(bytes(buf[:p+2]))
                log(f"** {tag} FRAME {state['frames']}: {p+2}B -> {fn}")
                buf, in_frame = bytearray(), False

# ---- wait for replug
log("waiting for device to be UNPLUGGED ...")
while find_dev() is not None:
    time.sleep(0.3)
log("unplugged. waiting for RE-PLUG ...")
while True:
    d = find_dev()
    if d is not None:
        break
    time.sleep(0.15)
log("re-plugged! opening")
t_plug = time.monotonic()
open_dev(d)

t1 = threading.Thread(target=sniffer, args=(0x81, "EP81"), daemon=True)
t2 = threading.Thread(target=sniffer, args=(0x82, "EP82"), daemon=True)
t1.start(); t2.start()

# small pause so we see the detect arrive in the sniffer first
time.sleep(1.2)

# ---- step 1: MAGIC -> useeplus OUT 0x02 inside the live window
old_addr = d.address
wr(0x02, MAGIC, "MAGIC")

# watch for re-enumeration
reenum = False
end = time.monotonic() + 10
while time.monotonic() < end:
    time.sleep(0.25)
    d2 = find_dev()
    if d2 is None:
        if not reenum:
            log("device DROPPED (re-enumeration!)")
            state["dev"] = None
        reenum = True
        continue
    if reenum:
        log(f"device BACK addr {old_addr} -> {d2.address} "
            f"({time.monotonic()-t_plug:.1f}s after plug)")
        dump(d2, "after re-enum")
        open_dev(d2)
        break

if not reenum:
    log("no re-enumeration after MAGIC->0x02")

# ---- step 2: connect -> 0x02
time.sleep(0.4)
wr(0x02, CONNECT, "CONNECT")
time.sleep(6)

# ---- step 3 fallback: connect -> 0x01
if state["frames"] == 0:
    wr(0x01, CONNECT, "CONNECT-alt")
    time.sleep(6)

# ---- step 4 fallback: detect-echo -> 0x01, connect -> 0x02
if state["frames"] == 0:
    wr(0x01, DETECT, "DETECT-echo")
    time.sleep(2)
    wr(0x02, CONNECT, "CONNECT-2")
    time.sleep(6)

# ---- step 5: keep sniffing a while
time.sleep(8)
state["stop"] = True
time.sleep(0.6)
log(f"CAPTURE COMPLETE: {state['frames']} frames")
