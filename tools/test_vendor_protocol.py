#!/usr/bin/env python3
"""Repliziert das ECHTE Protokoll der i4season-App (aus Frida-Mitschnitt) am Mac:
zwei Vendor-Control-Transfers, dann rohes YUYV von EP 0x82. KEIN iAP2, KEIN BB-AA.

Sequenz (tools/app_capture_init_sequence.txt):
  1. GET_CONFIGURATION (implizit via set_configuration)
  2. CTRL-IN  bmReqType=0xa0 bReq=0x00 wValue=0x0005 wIndex=0 wLen=512  -> Geräte-Info
  3. CTRL-OUT bmReqType=0x20 bReq=0x01 wValue=0x0005 wIndex=0 data=64x '0'
  4. Bulk-IN EP 0x82: YUYV422 640x480 (~614400 B/Frame)
"""
import sys
import time
import usb.core
import usb.util

def log(m): print(m, flush=True)

dev = usb.core.find(idVendor=0x2CE3, idProduct=0x3828)
if dev is None:
    log("Gerät nicht gefunden (Endoskop am Mac angesteckt?)"); sys.exit(1)
log(f"Gerät da: bcdDevice={dev.bcdDevice:#06x}")

dev.set_configuration()

# useeplus-Interface (If1) + Alt 1 aktivieren (dort liegt EP 0x82)
try:
    usb.util.claim_interface(dev, 1)
    dev.set_interface_altsetting(interface=1, alternate_setting=1)
    log("If1 -> Alt1 (EP 0x82 aktiv)")
except usb.core.USBError as e:
    log(f"If1/Alt1: {e}")

# 2) CTRL-IN: Geräte-Info holen
try:
    info = dev.ctrl_transfer(0xa0, 0x00, 0x0005, 0x0000, 512, timeout=2000)
    b = bytes(info)
    log(f"CTRL-IN ({len(b)} B): {b[:64].hex(' ')}")
    # Klartext-Strings zeigen
    txt = ''.join(chr(c) if 32 <= c < 127 else '.' for c in b[:80])
    log(f"  ascii: {txt}")
except usb.core.USBError as e:
    log(f"CTRL-IN FEHLER: {e}")

# 3) CTRL-OUT: Start-Kommando (64x '0')
try:
    n = dev.ctrl_transfer(0x20, 0x01, 0x0005, 0x0000, b'0' * 64, timeout=2000)
    log(f"CTRL-OUT gesendet: {n} B")
except usb.core.USBError as e:
    log(f"CTRL-OUT FEHLER: {e}")

# 4) EP 0x82 lesen
log("Lese EP 0x82 (bis zu 8 s) …")
frames, total = 0, 0
t0 = time.monotonic()
while time.monotonic() - t0 < 8:
    try:
        data = bytes(dev.read(0x82, 614400, timeout=2000))
        frames += 1
        total += len(data)
        if frames <= 4:
            log(f"  EP0x82 #{frames}: {len(data)} B  {data[:32].hex(' ')}")
        if frames == 1 and len(data) > 100000:
            open("tools/vendor_frame1.yuyv", "wb").write(data)
            log(f"  -> tools/vendor_frame1.yuyv gespeichert ({len(data)} B)")
    except usb.core.USBError as e:
        log(f"  read: {e}")
log(f"ENDE: {frames} Reads, {total/1024:.0f} KB von EP 0x82")
