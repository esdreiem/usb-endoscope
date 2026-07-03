#!/usr/bin/env python3
"""Interactive protocol probing: detect-echo, connect on both OUT EPs,
command-id scan. Logs every byte both IN EPs return."""
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

dev = usb.core.find(idVendor=0x2CE3, idProduct=0x3828)
if dev is None:
    sys.exit("not found")
dev.set_configuration()
usb.util.claim_interface(dev, 0)
usb.util.claim_interface(dev, 1)
dev.set_interface_altsetting(interface=1, alternate_setting=1)
log(f"open, addr={dev.address}")

stop = False
def sniffer(ep, tag):
    while not stop:
        try:
            data = bytes(dev.read(ep, 65536, timeout=400))
            log(f"  << {tag}({ep:#04x}): {len(data)}B: {data[:48].hex(' ')}")
        except usb.core.USBError:
            pass

t1 = threading.Thread(target=sniffer, args=(0x81, "EP81"), daemon=True)
t2 = threading.Thread(target=sniffer, args=(0x82, "EP82"), daemon=True)
t1.start(); t2.start()

def wr(ep, data, tag):
    try:
        dev.write(ep, data, timeout=800)
        log(f"  >> {tag} -> {ep:#04x}: {data.hex(' ')} ok")
        return True
    except usb.core.USBError as e:
        log(f"  >> {tag} -> {ep:#04x}: FAILED ({e})")
        return False

log("--- phase 0: 4s passive listen (detect loop still running?)")
time.sleep(4)

log("--- phase A: echo detect -> 0x01, listen 4s")
wr(0x01, DETECT, "detect-echo")
time.sleep(4)

log("--- phase B: connect -> 0x02, listen 6s")
wr(0x02, CONNECT, "connect")
time.sleep(6)

log("--- phase C: connect -> 0x01, listen 6s")
wr(0x01, CONNECT, "connect")
time.sleep(6)

log("--- phase D: repeated connect -> 0x02 (5x, 1s apart)")
for i in range(5):
    wr(0x02, CONNECT, f"connect#{i}")
    time.sleep(1.0)
time.sleep(3)

log("--- phase E: cid scan bb aa XX 00 00 -> 0x02")
for cid in [0x00, 0x01, 0x02, 0x03, 0x04, 0x06, 0x07, 0x08, 0x0B, 0x10]:
    wr(0x02, bytes([0xBB, 0xAA, cid, 0x00, 0x00]), f"cid={cid:#04x}")
    time.sleep(0.8)
time.sleep(3)

log("--- phase F: connect with trailing 0x0e (6-byte form) -> 0x02")
wr(0x02, bytes([0xBB, 0xAA, 0x05, 0x00, 0x00, 0x0E]), "connect+0e")
time.sleep(4)

stop = True
time.sleep(0.6)
log("probe done")
