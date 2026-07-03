#!/usr/bin/env python3
"""Systematic permutation test of the useeplus init sequence.

For each variant: reset device, claim If0+If1, set If1 alt1,
optionally send a knock, send connect, then listen on BOTH IN EPs
concurrently and report any traffic.
"""
import sys
import time
import threading
import usb.core
import usb.util

MAGIC = bytes([0xFF, 0x55, 0xFF, 0x55, 0xEE, 0x10])
DETECT = bytes([0xFF, 0x55, 0x02, 0x00, 0xEE, 0x10])  # iAP2 detect echo
CONNECT = bytes([0xBB, 0xAA, 0x05, 0x00, 0x00])

def log(msg):
    print(f"[{time.monotonic():8.3f}] {msg}", flush=True)

def find_dev(retries=40):
    for _ in range(retries):
        d = usb.core.find(idVendor=0x2CE3, idProduct=0x3828)
        if d is not None:
            return d
        time.sleep(0.25)
    return None

def open_dev():
    dev = find_dev()
    if dev is None:
        return None
    dev.set_configuration()
    usb.util.claim_interface(dev, 0)
    usb.util.claim_interface(dev, 1)
    dev.set_interface_altsetting(interface=1, alternate_setting=1)
    return dev

def listen(dev, ep, seconds, results, tag):
    end = time.monotonic() + seconds
    got = 0
    while time.monotonic() < end:
        try:
            data = bytes(dev.read(ep, 16384, timeout=500))
        except usb.core.USBError:
            continue
        got += len(data)
        if got <= 4 * 16384:
            log(f"    {tag} EP {ep:#04x}: {len(data)}B: {data[:24].hex(' ')}")
        results[ep] = results.get(ep, 0) + len(data)
    return got

VARIANTS = [
    # (name, knock_bytes, knock_ep, connect_ep)
    ("no-knock, connect->0x01",          None,   None, 0x01),
    ("no-knock, connect->0x02",          None,   None, 0x02),
    ("magic->0x01, connect->0x02",       MAGIC,  0x01, 0x02),
    ("magic->0x02, connect->0x01",       MAGIC,  0x02, 0x01),
    ("magic->0x01, connect->0x01",       MAGIC,  0x01, 0x01),
    ("magic->0x02, connect->0x02",       MAGIC,  0x02, 0x02),
    ("detect-echo->0x01, connect->0x02", DETECT, 0x01, 0x02),
    ("detect-echo->0x01, connect->0x01", DETECT, 0x01, 0x01),
]

for name, knock, knock_ep, connect_ep in VARIANTS:
    log(f"=== VARIANT: {name} ===")
    dev = open_dev()
    if dev is None:
        log("  device not found, aborting")
        break

    # quick pre-drain both IN EPs, log anything pending
    for ep in (0x81, 0x82):
        try:
            data = bytes(dev.read(ep, 512, timeout=150))
            log(f"  pending on {ep:#04x}: {data.hex(' ')}")
        except usb.core.USBError:
            pass

    ok = True
    if knock is not None:
        try:
            dev.write(knock_ep, knock, timeout=1000)
            log(f"  knock {knock.hex(' ')} -> {knock_ep:#04x} ok")
        except usb.core.USBError as e:
            log(f"  knock write failed: {e}")
            ok = False
        # give it a moment, check for immediate reply/re-enum
        time.sleep(0.4)
        d2 = usb.core.find(idVendor=0x2CE3, idProduct=0x3828)
        if d2 is None:
            log("  DEVICE DROPPED after knock! waiting for re-enum")
            usb.util.dispose_resources(dev)
            dev = open_dev()
            if dev is None:
                log("  did not come back")
                break
            log("  device back, continuing")

    if ok:
        try:
            dev.write(connect_ep, CONNECT, timeout=1000)
            log(f"  connect -> {connect_ep:#04x} ok")
        except usb.core.USBError as e:
            log(f"  connect write failed: {e}")

        results = {}
        t1 = threading.Thread(target=listen, args=(dev, 0x81, 5, results, "  "))
        t2 = threading.Thread(target=listen, args=(dev, 0x82, 5, results, "  "))
        t1.start(); t2.start(); t1.join(); t2.join()
        log(f"  totals: 0x81={results.get(0x81,0)}B 0x82={results.get(0x82,0)}B")

    # reset for next variant
    try:
        dev.reset()
    except Exception as e:
        log(f"  reset: {e}")
    usb.util.dispose_resources(dev)
    time.sleep(1.5)

log("matrix done")
