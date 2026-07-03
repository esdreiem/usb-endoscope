#!/usr/bin/env python3
"""Dump full USB descriptors of the useeplus endoscope (2ce3:3828)."""
import sys
import usb.core
import usb.util

dev = usb.core.find(idVendor=0x2CE3, idProduct=0x3828)
if dev is None:
    print("DEVICE NOT FOUND")
    sys.exit(1)

def s(idx):
    try:
        return usb.util.get_string(dev, idx) if idx else "(none)"
    except Exception as e:
        return f"(err: {e})"

print(f"Device 2ce3:3828  bus={dev.bus} addr={dev.address} speed={dev.speed}")
print(f"  bcdUSB={dev.bcdUSB:04x} class={dev.bDeviceClass:#04x} sub={dev.bDeviceSubClass:#04x} proto={dev.bDeviceProtocol:#04x} ep0={dev.bMaxPacketSize0}")
print(f"  bcdDevice={dev.bcdDevice:04x} numConfigs={dev.bNumConfigurations}")
print(f"  iManufacturer: {s(dev.iManufacturer)}")
print(f"  iProduct:      {s(dev.iProduct)}")
print(f"  iSerial:       {s(dev.iSerialNumber)}")

for cfg in dev:
    print(f"\nConfiguration {cfg.bConfigurationValue}: numInterfaces={cfg.bNumInterfaces} "
          f"attrs={cfg.bmAttributes:#04x} maxPower={cfg.bMaxPower*2}mA totalLen={cfg.wTotalLength}")
    for intf in cfg:
        print(f"  Interface {intf.bInterfaceNumber} alt {intf.bAlternateSetting}: "
              f"class={intf.bInterfaceClass}/{intf.bInterfaceSubClass}/{intf.bInterfaceProtocol} "
              f"numEP={intf.bNumEndpoints} iInterface={intf.iInterface} ({s(intf.iInterface)})")
        for ep in intf:
            direction = "IN " if usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_IN else "OUT"
            types = {0: "ctrl", 1: "iso", 2: "bulk", 3: "intr"}
            t = types[usb.util.endpoint_type(ep.bmAttributes)]
            print(f"    EP {ep.bEndpointAddress:#04x} {direction} {t} maxPacket={ep.wMaxPacketSize} interval={ep.bInterval}")

# Raw config descriptor bytes for exact comparison with hbens' desktop dump
import usb.control
raw = dev.ctrl_transfer(0x80, 6, (2 << 8) | 0, 0, 1024)
print("\nRaw config descriptor:")
hexstr = " ".join(f"{b:02x}" for b in raw)
for i in range(0, len(hexstr), 96):
    print(" ", hexstr[i:i+96])
