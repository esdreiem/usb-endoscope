# tools/

The tools that actually mattered for reverse-engineering the i4season / "Usee Plus"
endoscope (USB `2ce3:3828`) and verifying the vendor protocol the app now speaks over
WebUSB. Each one earns its place; the full story is in
[`../docs/REVERSE_ENGINEERING.md`](../docs/REVERSE_ENGINEERING.md).

## Scripts

- **`dump_descriptors.py`** — dumps the plugged-in device's full USB descriptor tree
  (interfaces, alt-settings, endpoints, string descriptors). This is what revealed the
  class-255 vendor interfaces (`iAP Interface`, `com.useeplus.protocol`) and proved the
  device is not standard UVC.
- **`frida_usbfs_hook.js`** — **the hook that cracked it.** Attaches to the real Android
  app and hooks libc `ioctl`, decoding the USBDEVFS URBs (SUBMITURB / REAPURB, control and
  bulk) that the app sends over the native USB interface. This captured the actual init
  sequence — two simple vendor control transfers, then raw YUYV bulk reads — and put an end
  to the iAP2 red herring.
- **`test_vendor_protocol.py`** — pyusb reference implementation. Replays the exact captured
  sequence on a PC (claim interface 1, select alt-setting 1, the info control-IN, the 64×`0x30`
  START control-OUT, then bulk-IN of 614400-byte YUYV frames on EP `0x82`) and streams real
  frames end-to-end. Use this to confirm the protocol works before trusting the WebUSB port.

## Captured data (reference / evidence)

- **`descriptors_mac_fresh_bcd0111.txt`** — real descriptor dump from a device
  (`bcdDevice 0x0111`), the ground truth behind the constants used in `index.html`.
- **`app_capture_init_sequence.txt`** — the exact init byte sequence captured from the real
  app via the Frida hook, i.e. what the working protocol replays.
- **`vendor_frame.png`** — an actual frame captured from the device by
  `test_vendor_protocol.py`, decoded YUYV422 → RGB. Proof the pipeline produces a real image.

## Dependencies

- **Python scripts** (`dump_descriptors.py`, `test_vendor_protocol.py`): Python 3 with
  [`pyusb`](https://pypi.org/project/pyusb/) and a working **libusb** backend.
  On macOS: `brew install libusb && pip install pyusb`.
- **Frida hook** (`frida_usbfs_hook.js`): **Frida 17.x** on the host (`pip install frida-tools`),
  a **rooted Android device** running a matching **frida-server**, and the vendor app
  (`com.i4season.useeplus`) installed. Attach with e.g.
  `frida -U -f com.i4season.useeplus -l frida_usbfs_hook.js`.

---

For how these pieces fit together — and the dead ends they replaced — read
[`../docs/REVERSE_ENGINEERING.md`](../docs/REVERSE_ENGINEERING.md).
