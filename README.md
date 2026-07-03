# USB-Endoscope

**An installable, fully local web app that streams the i4season / "Usee Plus" USB endoscope directly in your browser over WebUSB — a trustworthy, open alternative to the sketchy vendor app this endoscope ships with.**

🇬🇧 English | [🇩🇪 Deutsch](README.de.md)

[![License: GPL-3.0-or-later](https://img.shields.io/badge/License-GPL--3.0--or--later-blue.svg)](LICENSE)
[![PWA](https://img.shields.io/badge/PWA-installable-blueviolet.svg)](manifest.webmanifest)
[![offline-capable](https://img.shields.io/badge/offline-capable-success.svg)](sw.js)
[![no dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)](index.html)
[![WebUSB](https://img.shields.io/badge/WebUSB-vendor%20protocol-orange.svg)](#how-it-works)

![USB-Endoscope — live camera preview with capture, rotate, zoom and fullscreen controls](docs/screenshot.png)

## What it is

Cheap USB endoscopes almost always ship with a proprietary phone app of dubious provenance — closed source, ad-laden, and asking for permissions a camera viewer has no business wanting. This project is the opposite: **an installable web app, no build step, no dependencies, and zero network requests.** The camera image never leaves your device.

It does exactly one thing: connect the **i4season / "Usee Plus"** USB endoscope (USB `VID 0x2ce3` / `PID 0x3828`, marketed as "Geek szitman useepluscam") over **WebUSB** and show its live video — no native app, no vendor software.

## How it works

This endoscope is **not** a standard **UVC** (USB Video Class) device. Because of that, your operating system never sees it as a webcam, and the browser cannot open it with the usual camera APIs — which is exactly why the vendor ships a proprietary Android app instead.

So the app takes a different route: it claims the device's vendor interface via **WebUSB** and speaks the **reverse-engineered vendor protocol** directly in the browser. In practice that means two simple vendor **control transfers** to start the stream, then reading raw **YUYV422** frames over bulk endpoint `0x82` and converting them to RGB on a canvas.

The full story, captures, and exact protocol constants live in
**[docs/REVERSE_ENGINEERING.md](docs/REVERSE_ENGINEERING.md)** and **[PROTOCOL_NOTES.md](PROTOCOL_NOTES.md)**.

## Install it as an app

USB-Endoscope is an installable **Progressive Web App (PWA)**:

- Click the **⤓ Installieren** button in the header when it appears, or use your browser's **install icon** in the address bar.
- Once installed, it runs to the home screen / desktop and works **fully offline** — the service worker caches the app shell, and there are still zero external requests.
- On **iOS / iPadOS** you can add it to the home screen via Safari's **"Add to Home Screen"**, but note it **cannot stream** there — no browser on iOS has WebUSB (see [Platform support](#platform-support)).

## Features

- **Live preview** — auto-connects when the known endoscope is plugged in
- 📷 **Photo capture** — JPEG, timestamped filename
- ⏺ **Video recording** — WebM
- ⏸ **Freeze frame** — handy with a shaky probe
- ↻ **Rotate** / ⇋ **Mirror** — endoscope images are often upside-down; the transform is applied to the saved photo too
- 🔍 **Digital zoom**
- ⛶ **Fullscreen**
- ⤓ **Installable / works offline** — as a PWA

## Quick start

WebUSB requires a **Chromium-based browser** and a **secure context**: `https://` or `http://localhost`. Opening `index.html` directly by double-click (`file://`) is blocked by browsers, so serve it locally.

### On a PC / laptop

Plug in the endoscope, then:

```bash
git clone https://github.com/esdreiem/usb-endoscope.git
cd usb-endoscope
python3 -m http.server 8000
# → open http://localhost:8000 in Chrome / Edge / Brave
```

Press **Verbinden** (Connect) to start the stream, **Stopp** to end it.

### Or use the hosted version

The app is served statically via **GitHub Pages** — it still makes no network requests, so the image stays local:

**<https://esdreiem.github.io/usb-endoscope/>**

## Platform support

WebUSB is a **Chromium-only** API, so support comes down to the browser engine.

| Platform | Browser | WebUSB streaming | Notes |
|---|---|---|---|
| **Desktop** (Windows / macOS / Linux) | Chrome, Edge, Brave, Opera | ✅ Works | The recommended way to use the app. |
| **Desktop** | Firefox | ❌ No | Mozilla declined to implement WebUSB. |
| **Desktop** | Safari | ❌ No | No WebUSB support. |
| **Android** | Chrome / Chromium | ✅ Works | Any Chromium-based Android browser. |
| **iOS / iPadOS** | any browser | ❌ No | Every iOS browser is forced onto WebKit, so none has WebUSB — you can install the PWA but cannot stream. |

In a non-Chromium browser the app shows a clear **"open this in Chrome / Edge / Brave"** message instead of a dead UI. In all cases a **secure context** (`https://` or `http://localhost`) is required.

## Supported devices

| Device | VID / PID | Interface | Status |
|---|---|---|---|
| i4season "Usee Plus" — "Geek szitman useepluscam" (model `su4p-002`) | `0x2ce3` / `0x3828` | WebUSB vendor protocol | ✅ Tested |

Have a **different vendor endoscope**? Help us add it — see [CONTRIBUTING.md](CONTRIBUTING.md).

## How the WebUSB protocol was reverse-engineered

The "Usee Plus" endoscope's USB descriptors advertise vendor interfaces named `iAP Interface` and `com.useeplus.protocol` — not UVC — which sent the investigation through some elaborate dead ends (a legacy "BB AA" / MJPEG bulk protocol, then a deep detour into Apple's iAP2 accessory handshake). The breakthrough came from a rooted phone and a Frida hook on the native `USBDEVFS` ioctl interface, capturing what the **real** Android app actually sends over USB. It turned out to be just two simple vendor control transfers followed by raw YUYV422 bulk reads — the fancy handshake was a red herring all along.

The full story, captures, and the exact protocol constants live in
**[docs/REVERSE_ENGINEERING.md](docs/REVERSE_ENGINEERING.md)** and **[PROTOCOL_NOTES.md](PROTOCOL_NOTES.md)**.

## Privacy

Privacy is a core goal of this project, not an afterthought:

- **Self-contained** — no external or third-party requests, no CDN fonts, no analytics. All assets are same-origin.
- **Fully offline-capable** — once installed as a PWA it works with no network at all.
- **The camera image never leaves your device.**
- Photos (JPEG) and videos (WebM) are saved **only as local downloads**.
- The entire source is readable and auditable — start with [`index.html`](index.html).

## Contributing

This is the author's first open-source project, and contributions are very welcome. The most useful thing you can do is **help add your endoscope**: if you have a non-UVC vendor device, a descriptor dump and a protocol capture go a long way. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to get started.

## Acknowledgements

Prior art that served as valuable early signposts. Note honestly: these describe the legacy BB-AA / MJPEG path, which is **not** what the working WebUSB implementation uses — but they pointed the way early on.

- [hbens/geek-szitman-supercamera](https://github.com/hbens/geek-szitman-supercamera)
- [MAkcanca/useeplus-linux-driver](https://github.com/MAkcanca/useeplus-linux-driver)
- [linux-media V4L2 driver patch](https://marc.info/?l=linux-media&m=175756642100535)

## License

Licensed under **GPL-3.0-or-later**. See [LICENSE](LICENSE) for the full text.

Copyright © 2026 [esdreiem](https://github.com/esdreiem).
