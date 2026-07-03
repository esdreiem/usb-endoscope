#!/usr/bin/env python3
"""Waits for the endoscope to be re-plugged (power cycle), then immediately
runs the full capture: descriptors -> iAP detect -> magic knock -> re-enum
watch -> descriptors again -> connect -> stream. Logs everything.
"""
import sys
import time
import threading
import usb.core
import usb.util

MAGIC = bytes([0xFF, 0x55, 0xFF, 0x55, 0xEE, 0x10])
CONNECT = bytes([0xBB, 0xAA, 0x05, 0x00, 0x00])

def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

def find_dev():
    return usb.core.find(idVendor=0x2CE3, idProduct=0x3828)

def dump(dev, tag):
    lines = [f"--- descriptors ({tag}) bcdDevice={dev.bcdDevice:04x} addr={dev.address} ---"]
    for cfg in dev:
        lines.append(f"cfg {cfg.bConfigurationValue}: {cfg.bNumInterfaces} interfaces")
        for intf in cfg:
            lines.append(f"  If{intf.bInterfaceNumber} alt{intf.bAlternateSetting} "
                         f"cls={intf.bInterfaceClass}/{intf.bInterfaceSubClass}/{intf.bInterfaceProtocol} "
                         f"EPs={[hex(e.bEndpointAddress) for e in intf]}")
    log("\n".join(lines))

def resolve(dev):
    roles = {}
    for cfg in dev:
        for intf in cfg:
            eps = list(intf)
            if not eps:
                continue
            ep_in = next((e.bEndpointAddress for e in eps if e.bEndpointAddress & 0x80), None)
            ep_out = next((e.bEndpointAddress for e in eps if not e.bEndpointAddress & 0x80), None)
            role = "iap" if intf.bInterfaceProtocol == 0 else "useeplus"
            roles[role] = dict(intf=intf.bInterfaceNumber, ep_in=ep_in, ep_out=ep_out)
    return roles

# ---- Phase 0: wait for UNPLUG, then RE-PLUG
log("waiting for device to be UNPLUGGED ...")
while find_dev() is not None:
    time.sleep(0.3)
log("device unplugged. waiting for RE-PLUG ...")
while True:
    dev = find_dev()
    if dev is not None:
        break
    time.sleep(0.2)
log("device re-plugged! starting capture")
t_plug = time.monotonic()

dump(dev, "fresh plug")
roles = resolve(dev)
log(f"roles: {roles}")
iap, up = roles["iap"], roles["useeplus"]

dev.set_configuration()
usb.util.claim_interface(dev, iap["intf"])
log(f"claimed iAP If{iap['intf']}; listening on {iap['ep_in']:#04x} for detect ...")

# ---- Phase 1: catch iAP detect message(s)
detect_seen = []
deadline = time.monotonic() + 6
while time.monotonic() < deadline:
    try:
        data = bytes(dev.read(iap["ep_in"], 512, timeout=300))
        log(f"iAP IN ({time.monotonic()-t_plug:.2f}s after plug): {data.hex(' ')}")
        detect_seen.append(data)
        if len(detect_seen) >= 3:
            break
    except usb.core.USBError:
        pass

# ---- Phase 2: magic knock on iAP OUT, immediately after detect
old_addr = dev.address
log(f"write MAGIC -> iAP OUT {iap['ep_out']:#04x}")
try:
    dev.write(iap["ep_out"], MAGIC, timeout=1000)
    log("  write ok")
except usb.core.USBError as e:
    log(f"  write FAILED: {e}")

# listen briefly for a reply on iAP IN, and watch the bus for re-enum
def iap_listener():
    end = time.monotonic() + 3
    while time.monotonic() < end:
        try:
            data = bytes(dev.read(iap["ep_in"], 512, timeout=300))
            log(f"  iAP reply: {data.hex(' ')}")
        except usb.core.USBError:
            pass

lt = threading.Thread(target=iap_listener)
lt.start()

reenum = False
end = time.monotonic() + 12
while time.monotonic() < end:
    time.sleep(0.25)
    d2 = find_dev()
    if d2 is None:
        if not reenum:
            log("  device DROPPED (re-enumeration)")
        reenum = True
        continue
    if reenum:
        log(f"  device BACK after {time.monotonic()-t_plug:.2f}s, addr {old_addr} -> {d2.address}")
        lt.join(timeout=0)
        usb.util.dispose_resources(dev)
        dev = d2
        break
lt.join()

if reenum:
    dump(dev, "after magic re-enum")
    roles = resolve(dev)
    log(f"roles after re-enum: {roles}")
    iap, up = roles["iap"], roles["useeplus"]
    dev.set_configuration()
else:
    log("no re-enumeration after magic")

# ---- Phase 3: claim useeplus, alt1, connect, stream
usb.util.claim_interface(dev, up["intf"])
dev.set_interface_altsetting(interface=up["intf"], alternate_setting=1)
try:
    dev.clear_halt(up["ep_out"])
except Exception:
    pass
time.sleep(0.3)
log(f"write CONNECT -> useeplus OUT {up['ep_out']:#04x}")
try:
    dev.write(up["ep_out"], CONNECT, timeout=1000)
    log("  write ok")
except usb.core.USBError as e:
    log(f"  write FAILED: {e}")

log(f"reading stream from useeplus IN {up['ep_in']:#04x} + iAP IN {iap['ep_in']:#04x} ...")
frames = {"n": 0}

def stream_reader(ep, tag):
    buf, in_frame = bytearray(), False
    total, pkts = 0, 0
    end = time.monotonic() + 15
    while time.monotonic() < end and frames["n"] < 10:
        try:
            data = bytes(dev.read(ep, 65536, timeout=1000))
        except usb.core.USBError:
            continue
        total += len(data)
        pkts += 1
        if pkts <= 5:
            log(f"  {tag} pkt {len(data)}B: {data[:24].hex(' ')}")
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
                frames["n"] += 1
                fn = f"replug_frame_{frames['n']}.jpg"
                open(fn, "wb").write(bytes(buf[:p+2]))
                log(f"  {tag} FRAME {frames['n']}: {p+2}B -> {fn}")
                rest = buf[p+2:]
                buf, in_frame = bytearray(), False
                q = rest.find(b"\xff\xd8")
                if q >= 0:
                    in_frame, buf = True, bytearray(rest[q:])
    log(f"  {tag} done: {total}B in {pkts} pkts")

t1 = threading.Thread(target=stream_reader, args=(up["ep_in"], "useeplus"))
t2 = threading.Thread(target=stream_reader, args=(iap["ep_in"], "iAP"))
t1.start(); t2.start(); t1.join(); t2.join()

log(f"CAPTURE COMPLETE: {frames['n']} frames")
if frames["n"] > 0:
    log("SUCCESS — streaming sequence verified")
else:
    log("no frames — see log above for where it diverged")
