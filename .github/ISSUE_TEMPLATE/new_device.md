---
name: New device / add endoscope support
about: Help us support a USB endoscope that doesn't work yet
title: "[New device]: "
labels: enhancement
---

Awesome — thanks for helping grow the list of supported devices! 🔎

USB-Endoscope talks to its camera over **WebUSB** using a reverse-engineered
vendor protocol (two vendor control transfers + raw YUYV422 over an endpoint).
Right now the only device confirmed working is the i4season / "Usee Plus"
family (VID `0x2ce3` / PID `0x3828`). If you have a different endoscope,
this template helps us gather what we need to teach the app about it.

If you're curious how the vendor protocol for the Usee Plus was worked out,
the whole story — descriptor dumps, capturing the real app's USB traffic,
and decoding the video — is in
[docs/REVERSE_ENGINEERING.md](../../docs/REVERSE_ENGINEERING.md). That's the
worked example to follow for a new device.

## Device name and where you bought it

<!-- The marketed name (e.g. "Geek szitman useepluscam") and the
     store / listing link if you have it. Anything printed on the device
     or its packaging is helpful too. -->

## USB VID / PID

<!-- The USB Vendor ID and Product ID, e.g. VID 0x2ce3 / PID 0x3828.
     tools/dump_descriptors.py prints these at the top of its output. -->

- VID:
- PID:

## Output of tools/dump_descriptors.py

<!-- Run the descriptor dumper and paste the full output. This tells us
     the device's interfaces, classes, and endpoints — exactly what we
     need to understand how it exposes its video stream.

     python3 tools/dump_descriptors.py
-->

```
(paste dump_descriptors.py output here)
```

## Which browser and OS did you try?

<!-- WebUSB is Chromium-only. Tell us which browser (Chrome, Edge, Brave,
     Opera, or Chrome/Chromium on Android) and which OS you were on when
     you clicked "Verbinden", plus what happened — did the device show up
     in the browser's USB picker? Any error in the page or the DevTools
     console? -->

- Browser + version:
- OS:
- What happened:

## Can you help capture the real app's USB traffic?

<!-- For a new vendor device we usually need a capture of what its own
     vendor app sends over USB, so we can replay the same control transfers
     and decode the stream. docs/REVERSE_ENGINEERING.md shows how this was
     done for the Usee Plus (Frida on the USBDEVFS ioctl interface on a
     rooted Android phone). No worries if you can't — every detail still
     helps. -->

- [ ] I can help capture USB traffic from the device's original app
- [ ] I can run tools/dump_descriptors.py and provide output
- [ ] I can test builds in a Chromium browser and report back
- [ ] I'm just reporting the device
