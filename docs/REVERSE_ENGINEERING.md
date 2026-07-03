# How the Vendor Protocol Was Cracked

*An engineering war story about a $15 endoscope, an elaborate Apple-flavored dead end, and a real protocol so simple it was almost insulting.*

---

Most USB endoscopes are boring in the best possible way. They're standard **UVC** (USB Video Class) devices — the operating system sees them as a plain webcam, and the browser opens them with `getUserMedia`. No native app, no drama. That's the default path in this project, and it works for the majority of cheap endoscopes out there.

This document is about the one that *didn't*.

The **i4season / "Usee Plus"** family (USB `VID 0x2ce3` / `PID 0x3828`, sold as "Geek szitman useepluscam") is not a UVC device. It presents vendor-specific interfaces and ships with a proprietary Android app. If you want to see its picture in a browser, you have to speak its language directly over **WebUSB** — and nobody had written that language down.

Here's how we got there. It took eight steps, and roughly seven of them were wrong.

---

## Step 1 — Dump the descriptors, discover it's not UVC

The first honest question about any USB device is: *what does it say it is?* So we dumped its descriptors on macOS with [`tools/dump_descriptors.py`](../tools/dump_descriptors.py), capturing the raw result in [`tools/descriptors_mac_fresh_bcd0111.txt`](../tools/descriptors_mac_fresh_bcd0111.txt).

The answer was not encouraging:

- **Interface 0** — `"iAP Interface"`, class `255/240/0` (vendor-specific), bulk `EP 0x81 IN` / `0x01 OUT`.
- **Interface 1** — `"com.useeplus.protocol"`, class `255/240/1` (vendor-specific). Alt-setting 0 has **no endpoints**; alt-setting 1 exposes bulk `EP 0x82 IN` / `0x02 OUT`.

No `Video` interface class anywhere. Class 255 means "vendor-specific" — the USB spec's polite way of saying *you're on your own*. And that string, `"iAP Interface"`, would go on to cost us an enormous amount of time. (Foreshadowing.)

Conclusion: `getUserMedia` alone will never open this device. We'd have to drive it ourselves.

---

## Step 2 — The reference driver crashes on our device

Before writing anything, we tried the community reference: [`hbens/geek-szitman-supercamera`](https://github.com/hbens/geek-szitman-supercamera), a pip-installable driver for exactly this hardware family.

It crashed immediately:

```
ValueError: Invalid endpoint address 0x82
```

The reason is a subtle one, and it's worth understanding because it hints at the whole shape of the problem. The driver tries to drain `EP 0x82` **while interface 1 is still on alt-setting 0** — the alt-setting where that endpoint *doesn't exist yet*. It only catches `USBError`, not the `ValueError` pyusb raises for an unknown endpoint, so it dies. Its hard-coded endpoint constants only fit a slightly different device layout than ours.

Lesson filed away: **`EP 0x82` only appears after you `selectAlternateInterface(1, 1)`.** That detail turned out to be load-bearing.

---

## Step 3 — The "BB AA" bulk / MJPEG protocol (dead end #1)

The community drivers we could find — including [`MAkcanca/useeplus-linux-driver`](https://github.com/MAkcanca/useeplus-linux-driver) and a [linux-media V4L2 driver patch](https://marc.info/?l=linux-media&m=175756642100535) — all described a **legacy "BB AA" bulk protocol**: a 12-byte header, MJPEG payload, JPEG frames reassembled by scanning for `FFD8`…`FFD9` markers.

So we implemented it. Faithfully. Sent the magic bytes, waited for the stream.

The device stayed **completely silent.** Not an error, not a partial frame — nothing. Whatever firmware revision we had (`bcdDevice 0x0111`) either predated or postdated the "BB AA" era; either way, it didn't speak it.

**Dead end #1.** The prior art was real and well-intentioned, but it described a path our hardware simply didn't walk.

> An honest note on prior art: the drivers above were genuinely valuable *signposts* — they proved this device could be driven, and they narrowed the search. But every one of them documents the legacy BB-AA/MJPEG path, which is **not** what the working implementation ended up using.

---

## Step 4 — Down the iAP2 rabbit hole (dead end #2, the big one)

Remember that `"iAP Interface"` string from Step 1?

`iAP` is Apple's **iPod Accessory Protocol** — the framing used by MFi ("Made for iPhone") accessories. Combined with some Apple-certificate-shaped hints in the traffic, the descriptor string made a compelling case: *this is an iAP2 device, and we just need to complete the MFi handshake.*

So we went deep. Really deep. The raw captures and scripts from this dead end aren't published in this repo — one of them held the device's own Apple MFi authentication certificate, which has no place in a public project — but the investigation is worth recording. We implemented:

- iAP2 **detect / echo** beats to wake the link,
- the **link SYN/ACK** handshake,
- **authentication** using a 609-byte Apple certificate,
- **identification**,
- and a mysterious `0xAE01` vendor **"grant"** message we reconstructed from captures.

To pin down the handshake, we replugged the device **17 times**, logging all 17 sessions (those raw logs aren't published here).

And here's the maddening part: **the device ACKed the link handshake.** Every time. The SYN/ACK completed, the framing looked right, the state machine advanced. By every visible signal, we were talking to it correctly.

It just **never streamed a single frame of video.**

**Dead end #2 — and by far the most expensive.** We had built a plausible, internally-consistent, *acknowledged* protocol implementation against a device that was, in reality, never going to send us video that way. The handshake was a red herring wearing a very convincing costume.

This is the trap the whole story is really about: a protocol can *look* correct — ACKs and all — and still be completely wrong.

---

## Step 5 — Stop guessing. Watch the real app. (Frida, attempt #1)

At this point we stopped trying to *deduce* the protocol and decided to *observe* it. If the official Android app can get video out of this thing, then whatever the app sends over USB **is** the protocol, by definition. No more guessing.

The setup: a **rooted Pixel phone**, the real "Usee Plus" app (`com.i4season.useeplus`), and [Frida](https://frida.re/) to hook it live.

The first hook instrumented the Java `UsbDeviceConnection` API: `bulkTransfer`, `controlTransfer`, the obvious Android USB surface.

It caught **nothing.** No transfers, no bytes, silence.

That silence was actually the most useful result of the whole project, once we understood it: the app **wasn't using the Java USB API at all.** It was talking to the kernel directly through the native **USBDEVFS `ioctl`** interface — bypassing the Java layer we'd so carefully hooked. We'd been listening on the wrong floor of the building.

---

## Step 6 — Hook USBDEVFS ioctl — and there it is (Frida, attempt #2)

So we dropped down a level and hooked libc `ioctl` itself: [`tools/frida_usbfs_hook.js`](../tools/frida_usbfs_hook.js). This hook decodes raw **USBDEVFS URBs** — `SUBMITURB`, `REAPURB`, and the `CONTROL` / `BULK` transfer types — reconstructing every transfer the app makes to the kernel.

We plugged in the camera, opened the app, and watched the real init sequence scroll past for the first time. The full capture is in [`tools/app_capture_init_sequence.txt`](../tools/app_capture_init_sequence.txt). Here is what the app *actually* does, in its entirety:

1. `GET_CONFIGURATION` — `bmReqType=0x80 bReq=0x08` → returns `01`.
2. A **control-IN** (`bmReqType=0xa0`, i.e. class / device): `bRequest=0x00`, `wValue=0x0005`, `wIndex=0x0000`, length `512`.
   The device replies with an info string: **`i4season` / `su4p-002` / firmware `5.0.13` / `640x480`**.
3. A **control-OUT** (`bmReqType=0x20`, class / device): `bRequest=0x01`, `wValue=0x0005`, `wIndex=0x0000`, data = **64 bytes of `0x30`** (the ASCII character `'0'`, repeated 64 times). This is the **START** command.
4. **Bulk-IN reads on `EP 0x82`.** Raw **YUYV422** at 640×480 = **614,400 bytes per frame**. Between frames the device emits 511-byte header packets (they start `dd cc …`) which are simply skipped.

That's it. That's the whole protocol.

No iAP2. No Apple certificate. No `0xAE01` grant. No SYN/ACK. No MJPEG, no `FFD8` scanning, no "BB AA" bulk framing. **Two vendor control transfers and a firehose of raw YUYV.** The elaborate MFi handshake from Step 4 had been a red herring from the very beginning — the app never touched it.

There is a special kind of humbling in reverse-engineering: spending days on a 609-byte Apple certificate handshake, only to discover the real "authentication" is *the character zero, sixty-four times.*

---

## Step 7 — Verify with pyusb

Observation isn't proof. To confirm we'd read the capture correctly, we replayed the exact sequence on the Mac with pyusb in [`tools/test_vendor_protocol.py`](../tools/test_vendor_protocol.py):

1. Set configuration, claim interface 1, `selectAlternateInterface(1, 1)` — the move that finally activates `EP 0x82` (the very endpoint that crashed `supercamera` back in Step 2).
2. Control-IN for the info string.
3. Control-OUT of the 64 `'0'` bytes — START.
4. `transferIn(EP 0x82, 614400)`, decode YUYV → RGB.

It streamed **real video frames** on the first clean run. Here's an actual frame captured straight off the device by that script:

![Captured frame](../tools/vendor_frame.png)

After the iAP2 detour, watching a genuine image materialize from a plain bulk read was deeply satisfying.

---

## Step 8 — Port to WebUSB

The last step was almost anticlimactic, which is exactly how you want your last step to be. The whole sequence maps cleanly onto the WebUSB API, so it went straight into [`index.html`](../index.html):

- `controlTransferIn` / `controlTransferOut` for the two vendor control transfers,
- `transferIn(EP 0x82, 614400)` for each frame,
- and a small integer-math YUYV→RGB conversion painted onto a `<canvas>`:

```
R = Y + ((359 * (V - 128)) >> 8)
G = Y - (( 88 * (U - 128) + 183 * (V - 128)) >> 8)
B = Y + ((454 * (U - 128)) >> 8)
```

No dependencies, no build step, no network. The camera's image is decoded on the device and never leaves it.

**Working.**

---

## The actual protocol (summary box)

> **Device:** USB `VID 0x2ce3` / `PID 0x3828` · `iManufacturer` "Geek szitman" · `iProduct` "useepluscam" · `bcdDevice 0x0111`
>
> **Video interface:** Interface **1** (`"com.useeplus.protocol"`), **alt-setting 1** → bulk **`EP 0x82 IN`** (`0x02 OUT`). The IN endpoint only exists after `selectAlternateInterface(1, 1)`.
>
> **Init:**
> 1. Set configuration · claim interface 1 · `selectAlternateInterface(1, 1)`.
> 2. **Control-IN** — `bmReqType` class/device, `bRequest 0x00`, `wValue 0x0005`, `wIndex 0x0000`, len `512` → device info (`i4season` / `su4p-002` / FW `5.0.13` / `640x480`).
> 3. **Control-OUT** — `bmReqType` class/device, `bRequest 0x01`, `wValue 0x0005`, `wIndex 0x0000`, data = **64 × `0x30`** → **START**.
> 4. **Bulk-IN** `EP 0x82`: raw **YUYV422** 640×480 = **614,400 B/frame**. Skip 511-byte `dd cc …` header packets between frames.
>
> **No** iAP2, **no** Apple certificate, **no** MJPEG, **no** legacy "BB AA" framing anywhere in the working path.

For the complete, precise specification — every byte, every descriptor field, the exact framing of the header packets — see **[PROTOCOL_NOTES.md](../PROTOCOL_NOTES.md)**.

---

## Where everything lives

| Path | What it is |
|------|-----------|
| [`tools/dump_descriptors.py`](../tools/dump_descriptors.py) | Dumps the device's USB descriptors (Step 1). |
| [`tools/descriptors_mac_fresh_bcd0111.txt`](../tools/descriptors_mac_fresh_bcd0111.txt) | The real captured descriptors. |
| [`tools/frida_usbfs_hook.js`](../tools/frida_usbfs_hook.js) | **The** hook that cracked it — decodes USBDEVFS ioctl URBs (Step 6). |
| [`tools/app_capture_init_sequence.txt`](../tools/app_capture_init_sequence.txt) | The real init byte sequence, straight from the app. |
| [`tools/test_vendor_protocol.py`](../tools/test_vendor_protocol.py) | pyusb reference that streams real frames (Step 7). |
| [`tools/vendor_frame.png`](../tools/vendor_frame.png) | A real captured frame. |

The raw captures and scripts from the iAP2 dead end are **not** published in this repo — they included the device's own Apple MFi authentication certificate, which has no place in a public project. This write-up is the record of those dead ends, and of how much effort went into the *wrong* answers before the right one showed up.

---

## The lesson

Everything upstream of Step 5 was an attempt to **reason our way to the protocol** — from descriptor strings, from other people's drivers, from a very plausible reading of an Apple handshake. All of it was wrong, and one branch of it was wrong in the most dangerous way possible: it was *acknowledged by the device.*

The thing that actually worked was embarrassingly blunt: **hook the real app and write down what it does.** One correct capture from `ioctl` on USBDEVFS was worth more than every hour of protocol-guessing combined.

> **Descriptor strings and plausible-looking handshakes can send you down elaborate, self-consistent, even ACK-ed dead ends. Capturing what the real app actually does beats reverse-guessing the protocol — every single time.**
