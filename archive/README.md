# archive/ — the preserved dead-end investigation

**Nothing in this folder is used by the working app.** It is kept for transparency: it is the
paper trail of the long detour — the iAP2 and legacy "BB AA" / MJPEG rabbit hole — that came
*before* the real protocol was captured. The actual working path (two vendor control transfers
+ raw YUYV bulk reads over WebUSB) lives in [`../index.html`](../index.html), and the tools that
cracked it are in [`../tools/`](../tools/).

Why keep a folder full of things that didn't work? Because the story is the point. The
descriptor strings (`iAP Interface`, an Apple-certificate hint) and a handshake the device
happily ACKed sent this investigation deep into Apple's iAP2 accessory protocol — and it
*never* streamed video. That whole dead end, and the decisive pivot away from it, is narrated
in [`../docs/REVERSE_ENGINEERING.md`](../docs/REVERSE_ENGINEERING.md). These files are the
evidence behind that narrative.

## What's in here

- **`captures/`** — 17 USB replug captures. Repeatedly unplugging and replugging the device
  while logging traffic, trying to catch the moment it would start streaming. It never did on
  the iAP2 path.
- **`watchers/`** — the pyusb replug "watcher" scripts used to drive and record those captures
  (detect the device on plug-in, run a handshake attempt, log what came back).
- **`iap2-research/`** — the iAP2 investigation itself: detect-echo beats, link SYN/ACK, the
  609-byte Apple authentication certificate, identification, the `0xAE01` vendor "grant"
  message — plus **`frida_usee_hook.js`**, the first Frida attempt that hooked the *Java*
  `UsbDeviceConnection` API and **caught nothing**, because the app actually talks to USB
  through the native USBDEVFS `ioctl` interface. (The hook that *did* work,
  `frida_usbfs_hook.js`, is in [`../tools/`](../tools/).)

## Prior art these dead ends drew on

The legacy BB-AA / MJPEG path explored here was informed by community drivers — valuable early
signposts, even though the working WebUSB implementation does **not** use that path:

- [hbens/geek-szitman-supercamera](https://github.com/hbens/geek-szitman-supercamera)
- [MAkcanca/useeplus-linux-driver](https://github.com/MAkcanca/useeplus-linux-driver)
- [linux-media V4L2 driver patch](https://marc.info/?l=linux-media&m=175756642100535)

---

Full context: [`../docs/REVERSE_ENGINEERING.md`](../docs/REVERSE_ENGINEERING.md).
