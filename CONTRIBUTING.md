# Contributing to usb-endoscope

> 🇩🇪 **Deutsch:** kurze Hinweise am Ende dieser Datei — oder öffne einfach ein Issue auf Deutsch, das ist völlig in Ordnung. 🙂

Thank you for being here! 🎉 This is the author's first open-source project, so
**every** contribution is genuinely appreciated — a typo fix, a device report, a
question, a clarification, or a whole new endoscope protocol. There are no
contributions too small. If something in this guide is unclear, that's a bug in
the guide, and pointing it out already helps.

The whole point of this app is to be a **trustworthy, auditable, fully local,
offline-capable** alternative to the proprietary companion apps that cheap USB
endoscopes ship with. It exists solely to stream the i4season / "Usee Plus"
endoscope (USB VID `0x2ce3` / PID `0x3828`) directly in the browser over WebUSB.
Please keep that spirit in mind — the golden rules below exist to protect it.

---

## Running it locally

There is no build step, no package manager, no dependencies. You need a browser
and a way to serve the app over a **secure context** (see below). The simplest
way is Python's built-in server:

```bash
git clone https://github.com/esdreiem/usb-endoscope.git
cd usb-endoscope
python3 -m http.server 8000
```

Then open <http://localhost:8000/> in your browser.

> ⚠️ **Opening `index.html` directly (`file://`) will not work.** WebUSB (and the
> service worker) require a **secure context** — that means `https://` or
> `http://localhost`. `localhost` counts as secure, so the local server above is
> all you need for development. `file://` is blocked by browsers and the app will
> never connect to the device.

> 🧭 **WebUSB is Chromium-only.** Use **Chrome, Edge, Brave, or Opera** on desktop
> (or Chrome/Chromium on Android) for anything that touches the device. Firefox
> and Safari — and every browser on iOS/iPadOS — do not implement WebUSB, so the
> app can't stream there. It will show a clear "open this in Chrome/Edge/Brave"
> message instead of a dead UI.

That's it. No `npm install`, nothing to compile, nothing to watch.

---

## The architecture (read this first — it's short)

**The whole app lives in [`index.html`](index.html)** (~680 lines). HTML, CSS, and
JavaScript all live inside it. To change something, you **edit `index.html`
directly** and reload the browser. There is no bundler, no transpiler, no
framework.

Around that single-file app there is a small **PWA shell** that makes it
installable and offline-capable:

- [`manifest.webmanifest`](manifest.webmanifest) — the web app manifest (name,
  icons, display mode) that lets the browser offer "Install".
- [`sw.js`](sw.js) — the service worker. It caches the app shell so the app runs
  **fully offline** once installed. It's still zero external requests: every
  cached asset is same-origin.
- [`icons/`](icons/) — `icon.svg`, `icon-192.png`, `icon-512.png`, and
  `apple-touch-icon.png`, referenced by the manifest and the page.

A couple of things to know when you touch the shell:

- **Bump the `CACHE` version in [`sw.js`](sw.js) whenever the app shell changes.**
  The service worker serves cached assets, so a stale cache name means users keep
  getting the old files. Changing the cache name is what triggers the update.
- **During local dev the service worker is network-first for navigations**, so
  your edits to `index.html` show up on a normal reload. (If you're ever chasing a
  ghost, a hard reload or toggling "Update on reload" in DevTools → Application →
  Service Workers clears it up.)

The app talks to the device over **WebUSB**: it opens the vendor-specific
interface of the i4season / "Usee Plus" endoscope, runs a reverse-engineered init
sequence (two vendor control transfers), and reads raw YUYV422 frames from the
video endpoint (`EP 0x82`), decoding them to a canvas. The protocol itself is
documented in [`PROTOCOL_NOTES.md`](PROTOCOL_NOTES.md) and
[`docs/REVERSE_ENGINEERING.md`](docs/REVERSE_ENGINEERING.md).

---

## Testing a change

**UI and markup changes can be eyeballed without any hardware.** If you're
touching layout, wording, the header, the install button, buttons, the zoom
slider, or the non-Chromium fallback message, just start the local server
(`python3 -m http.server 8000`), open <http://localhost:8000/>, and look at it.
No device required.

**Testing the actual stream requires the real device.** There is no generic
webcam fallback anymore — the app is vendor-only. To exercise the connect flow,
the live video, photo/video capture, freeze, rotate/mirror, zoom, or fullscreen
against a real image, you need:

- an actual **i4season / "Usee Plus"** endoscope (VID `0x2ce3`, PID `0x3828`),
- a **Chromium-based browser** (Chrome / Edge / Brave), and
- a **secure context** (`http://localhost` for local dev, or `https://`).

Plug the device in — the app auto-connects when it sees the known VID/PID — or
press **Verbinden** (Connect), then try the feature you changed. For example, if
you touched rotate/mirror, confirm the transform is also applied to the **saved**
photo, not just the live preview.

**Please note in your PR what you tested on:** which **browser**, which **OS**,
and **whether you had the device**. Something like "UI only, eyeballed on
Firefox/macOS, no device" or "Streamed on Chrome/Windows with the Usee Plus" is
exactly the kind of note that helps a reviewer.

---

## 🚦 The golden rules

These are non-negotiable because they *are* the product. A PR that breaks any of
them can't be merged, no matter how nice the feature:

- **No external / third-party / CDN requests.** No CDN `<script>` tags, no remote
  JS, no external fonts, stylesheets, or images. Inline or embed everything (data
  URIs are fine). The **local PWA files** — `manifest.webmanifest`, `sw.js`, and
  everything under `icons/` — are same-origin and expected; those are not
  "external."
- **No analytics, no telemetry, no trackers.** None. Ever.
- **Nothing leaves the device.** The camera image must never be uploaded. If your
  change makes the app talk to *any* remote server, it's out of scope here.
- **Keep it auditable.** The app code stays in `index.html` so someone can read
  the whole thing and trust it. No build step, no dependency to install, no
  hidden bundling.
- **Keep it offline-capable.** The app must keep working fully offline once
  installed. Don't add anything that only works with a network connection, and if
  you add an asset to the app shell, make sure the service worker still caches
  everything it needs (and bump the `CACHE` version).

If you ever feel like you *need* an external library to do something, please open
an issue first and let's talk about it — there's almost always a small vanilla
way to do it that keeps the audit story intact.

---

## 🔌 Adding support for a new endoscope

This is one of the most valuable things you can contribute, and it's how the
vendor protocol came to exist in the first place.

### Step 1 — Dump the USB descriptors (always do this first)

Run the descriptor dumper and share its output:

```bash
python3 tools/dump_descriptors.py
```

(You'll need `pyusb` — `pip install pyusb` — and on macOS/Linux you may need to
run it with the right permissions to access the raw USB device.)

Open an issue titled something like *"New device: <name> (VID:PID)"* and paste
the full descriptor dump. If the device exposes only vendor-specific (class 255)
interfaces — like the "Usee Plus" family did, with interfaces named
`iAP Interface` and `com.useeplus.protocol` — then it needs a reverse-engineered
protocol, and we go to Step 2. You can compare your dump against the reference one
at
[`tools/descriptors_mac_fresh_bcd0111.txt`](tools/descriptors_mac_fresh_bcd0111.txt).

### Step 2 — Capture what the real app actually sends

The single most important lesson from the existing reverse-engineering effort:
**descriptor strings and plausible-looking handshakes can send you down elaborate
dead ends. Capturing what the real vendor app actually does over USB is worth
more than all the protocol guessing combined.**

There are two practical ways to capture the truth:

- **Frida on a rooted Android phone** (this is what cracked the Usee Plus
  protocol). Run the vendor's Android app and hook the low-level USB traffic with
  [`tools/frida_usbfs_hook.js`](tools/frida_usbfs_hook.js) — it hooks libc
  `ioctl` and decodes the USBDEVFS URBs (`SUBMITURB` / `REAPURB` / control /
  bulk). This matters: the earlier attempt to hook the *Java* `UsbDeviceConnection`
  API caught nothing, because the app talks to USB through the native USBDEVFS
  `ioctl` interface, not the Java API.
- **`usbmon` + Wireshark on Linux** (or a hardware USB analyzer) — capture the
  bus while the vendor app streams, then read off the control and bulk transfers.

Either way, you're looking for the real init sequence: the control transfers that
start the stream and the format of the bulk frames that come back. For the Usee
Plus device that turned out to be two simple vendor control transfers followed by
raw YUYV422 bulk reads — see the captured reference at
[`tools/app_capture_init_sequence.txt`](tools/app_capture_init_sequence.txt).

### Step 3 — Verify with pyusb, then port to WebUSB

Before touching `index.html`, prove the sequence works from a plain script.
[`tools/test_vendor_protocol.py`](tools/test_vendor_protocol.py) is the reference
pyusb implementation that replays the Usee Plus sequence and streams real frames
(a captured frame lives at [`tools/vendor_frame.png`](tools/vendor_frame.png)).
Adapt it to your device's init sequence and pixel format. Once it streams
reliably from pyusb, porting to WebUSB (`controlTransferIn` / `controlTransferOut`
+ `transferIn` on the video endpoint, then decode to a canvas) is a
straightforward translation.

### The worked example

The full story — including the dead ends, the red-herring iAP2 handshake, and how
Frida-on-USBDEVFS finally captured the real protocol — is written up in
[`docs/REVERSE_ENGINEERING.md`](docs/REVERSE_ENGINEERING.md). Read it before you
start; it will save you days. The dead-end investigation itself is preserved in
[`archive/`](archive/) for full transparency.

### Prior art & acknowledgements

These references were valuable early signposts for the Usee Plus work. Note
honestly: they describe a **legacy "BB AA" bulk / MJPEG path**, which is *not*
what the working WebUSB implementation uses (that path turned out to be a dead
end for this device) — but they helped point the way:

- [hbens/geek-szitman-supercamera](https://github.com/hbens/geek-szitman-supercamera)
- [MAkcanca/useeplus-linux-driver](https://github.com/MAkcanca/useeplus-linux-driver)
- [linux-media V4L2 driver patch](https://marc.info/?l=linux-media&m=175756642100535)

---

## Opening issues & pull requests

**Issues** are welcome for anything: bugs, questions, device reports, feature
ideas, or "I couldn't figure out how to X." Please use the
[issue templates](.github/ISSUE_TEMPLATE/) where they fit — for example the
[bug report template](.github/ISSUE_TEMPLATE/bug_report.md). If none fits (a
question, a new-device report), just open a blank issue and tell us what's on
your mind. Screenshots, your browser + OS, and whether you had the device are
always helpful.

**Pull requests:**

1. Fork the repo and create a branch for your change.
2. Keep the change focused, and keep it within the golden rules above.
3. In the PR description, say **what you changed** and **what you tested it on**
   (browser, OS, and whether you had the device).
4. Small, readable diffs are easier to review — and easier to audit, which is the
   whole point of this project.

Don't worry about getting everything perfect on the first try. Open the PR, and
we'll work through anything together. Friendly review is the norm here.

---

## Code of Conduct

By participating in this project you agree to abide by our
[Code of Conduct](CODE_OF_CONDUCT.md). In short: be kind, be patient, assume good
faith. This is a welcoming space, especially for first-time contributors.

## License

usb-endoscope is licensed under **GPL-3.0-or-later** (see [`LICENSE`](LICENSE)). By
contributing, you agree that your contributions are licensed under the same
license.

---

## 🇩🇪 Kurze Hinweise auf Deutsch

Alles Wichtige steht oben auf Englisch, aber hier das Wesentliche in Kürze:

- **Lokal starten:** Repo klonen, dann `python3 -m http.server 8000` ausführen und
  <http://localhost:8000/> öffnen. Wichtig: Ein direkter Doppelklick auf
  `index.html` (`file://`) funktioniert **nicht** — Browser verlangen einen
  sicheren Kontext (`https://` oder `http://localhost`). WebUSB gibt es nur in
  Chromium-Browsern (Chrome/Edge/Brave/Opera), nicht in Firefox, Safari oder auf
  iOS.
- **Aufbau:** Die App selbst ist [`index.html`](index.html) — plus ein paar kleine
  PWA-Dateien: [`manifest.webmanifest`](manifest.webmanifest), der Service Worker
  [`sw.js`](sw.js) und die [`icons/`](icons/). Kein Build, keine Abhängigkeiten.
  Du bearbeitest `index.html` direkt. Wenn sich die App-Shell ändert, bitte die
  `CACHE`-Version in `sw.js` hochzählen.
- **Goldene Regeln:** Keine externen/CDN-Requests, keine Analytics, es verlässt
  nichts das Gerät — Datenschutz ist der Sinn des Projekts. Die lokalen
  PWA-Dateien (Manifest, Service Worker, Icons) sind in Ordnung und erwünscht.
  Auditierbar und offline-fähig bleiben.
- **Testen:** UI-/Markup-Änderungen kannst du ohne Hardware im Browser ansehen.
  Den echten Stream testest du nur mit dem passenden Gerät (VID `0x2ce3` / PID
  `0x3828`) in einem Chromium-Browser über einen sicheren Kontext. Bitte im PR
  notieren: Browser, OS und ob du das Gerät hattest.
- **Neues Endoskop:** Zuerst `python3 tools/dump_descriptors.py` laufen lassen und
  die Ausgabe in einem Issue teilen. Details oben.
- **Issues/PRs auf Deutsch sind völlig willkommen.** Schreib einfach los. 🙂

Danke, dass du hier bist! 💙
