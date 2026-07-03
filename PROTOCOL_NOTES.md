# useeplus vendor protocol — technical reference

This is the precise specification of the **working** vendor protocol used to stream
video from the i4season / "Usee Plus" family of USB endoscopes over WebUSB, without
the proprietary vendor app.

The protocol is intentionally simple: activate the video interface, do two vendor
control transfers, then read raw YUYV frames off a bulk endpoint. It has **nothing**
to do with iAP2, MFi, the legacy "BB AA" bulk protocol, or MJPEG — those were earlier
dead ends (see [History](#history)).

- **WebUSB implementation:** [`index.html`](index.html) (`startUsbStream` → `runVendorSession` → `drawYUYV`)
- **pyusb reference:** [`tools/test_vendor_protocol.py`](tools/test_vendor_protocol.py)
- **Captured init bytes:** [`tools/app_capture_init_sequence.txt`](tools/app_capture_init_sequence.txt)
- **Device descriptors:** [`tools/descriptors_mac_fresh_bcd0111.txt`](tools/descriptors_mac_fresh_bcd0111.txt)
- **A real captured frame:** [`tools/vendor_frame.png`](tools/vendor_frame.png)

## Device identity

| Field          | Value                                                    |
| -------------- | -------------------------------------------------------- |
| USB VID / PID  | `0x2ce3` / `0x3828`                                      |
| iManufacturer  | `Geek szitman`                                           |
| iProduct       | `useepluscam`                                            |
| iSerial        | `202402062300000` (batch/date code, **not** per-unit)   |
| bcdDevice      | `0x0111`                                                 |
| Marketed as    | "Geek szitman useepluscam" / "Usee Plus"                 |

The device is **not** a standard UVC (USB Video Class) device — the OS does not expose
it as a webcam, so `getUserMedia` cannot open it. It presents vendor-specific class-255
interfaces and must be driven directly over WebUSB / libusb.

Device info returned by the control-IN (step 2 below), plain text:

| Field       | Value       |
| ----------- | ----------- |
| vendor      | `i4season`  |
| model       | `su4p-002`  |
| firmware    | `5.0.13`    |
| resolution  | `640x480`   |

## USB interface & endpoint layout

One configuration, two interfaces (all class `255` / subclass `240`):

| Interface | Alt | bInterfaceProtocol | iInterface               | Endpoints                                  |
| --------- | --- | ------------------ | ------------------------ | ------------------------------------------ |
| 0         | 0   | 0                  | `iAP Interface`          | `0x81` IN bulk (512), `0x01` OUT bulk (512) |
| 1         | 0   | 1                  | `com.useeplus.protocol`  | *(none)*                                    |
| 1         | 1   | 1                  | `com.useeplus.protocol`  | `0x82` IN bulk (512), `0x02` OUT bulk (512) |

**The video path uses interface 1 only.** Interface 0 ("iAP Interface") plays no part
in the working protocol. The bulk **IN endpoint `0x82`** — which exists *only* on
interface 1, alt-setting 1 — carries the video.

> **Do not identify endpoints by number across devices.** On some reference dumps the
> EP numbers are swapped between the interfaces. Always select the endpoint by
> **interface role** (`bInterfaceProtocol`: `0` = iAP, `1` = useeplus), not by its
> address. This app claims interface 1 and reads its IN endpoint.

## The working sequence

### 1. Activate the video interface

```
set configuration
claim interface 1
selectAlternateInterface(interface 1, alt 1)   // activates EP 0x82
```

Switching interface 1 to alt-setting 1 is what makes EP `0x82` (and `0x02`) exist.

### 2. Control-IN — device info

| Field       | Value                                    |
| ----------- | ---------------------------------------- |
| requestType | class                                    |
| recipient   | device                                   |
| bRequest    | `0x00`                                   |
| wValue      | `0x0005`                                 |
| wIndex      | `0x0000`                                 |
| length      | `512`                                    |

The device replies with the plain-text info block (`i4season` / `su4p-002` /
FW `5.0.13` / 640x480). This step is informational; it also confirms the device is
in the expected mode. (pyusb `bmRequestType` for this transfer is `0xa0`.)

### 3. Control-OUT — START

| Field       | Value                                    |
| ----------- | ---------------------------------------- |
| requestType | class                                    |
| recipient   | device                                   |
| bRequest    | `0x01`                                   |
| wValue      | `0x0005`                                 |
| wIndex      | `0x0000`                                 |
| data        | 64 bytes of `0x30` (`'0'` repeated 64×)  |

This is the START command. After it, the device begins streaming on EP `0x82`.
(pyusb `bmRequestType` for this transfer is `0x20`.)

### 4. Bulk-IN — read frames from EP `0x82`

Issue bulk-IN reads on endpoint `0x82` with a `614400`-byte request length.

- **A full frame is exactly `614400` bytes**: raw **YUYV422**, 640 × 480
  (`640 × 480 × 2 = 614400`). Draw it (step 5) and keep reading.
- **Between frames the device emits `511`-byte header/status packets** (they start
  with the magic bytes `dd cc …`). These are **not** video — **skip** any read whose
  length is not `614400`.

There is **no** MJPEG, **no** JPEG `FFD8`/`FFD9` reassembly, and **no** length/`AA BB`
header parsing in the working path. A full frame arrives as one contiguous read.

## YUYV422 → RGB conversion

Each 4-byte YUYV group `[Y0, U, Y1, V]` encodes two pixels that share one `U`/`V`
chroma pair. Convert to RGB with integer math (this is what `drawYUYV` does on the
canvas, per pixel, reusing one `ImageData` buffer per frame):

```
R = Y + ((359 * (V - 128))              >> 8)
G = Y - ((88  * (U - 128) + 183 * (V - 128)) >> 8)
B = Y + ((454 * (U - 128))              >> 8)
```

Clamp each channel to `0..255`. Apply `Y = Y0` for the first pixel of the group and
`Y = Y1` for the second, using the same `U`/`V` for both.

## History

The protocol above is the result of capturing what the real "Usee Plus" Android app
(`com.i4season.useeplus`) actually sends over USB — hooking libc `ioctl` on the
USBDEVFS interface with Frida ([`tools/frida_usbfs_hook.js`](tools/frida_usbfs_hook.js)),
then verifying end-to-end with pyusb.

Earlier attempts went down two elaborate dead ends before that:

- a legacy **"BB AA" bulk / MJPEG** protocol (12-byte header, `FF D8`/`FF D9`
  reassembly) — the device stayed silent; and
- a deep **iAP2 / Apple MFi** investigation (detect-echo, link SYN/ACK, a 609-byte
  Apple certificate, a `0xAE01` vendor "grant") — the link handshake was ACKed across
  17 replug captures but the device **never** streamed video.

Both dead ends are described in
[`docs/REVERSE_ENGINEERING.md`](docs/REVERSE_ENGINEERING.md). The lesson: descriptor
strings and plausible handshakes can send you down long dead ends; capturing what the
real app actually does was worth more than all the protocol reverse-guessing combined.

---

## Deutsch

Dies ist die präzise Spezifikation des **funktionierenden** Vendor-Protokolls, mit dem
die USB-Endoskope der i4season- / „Usee Plus"-Familie per WebUSB Video streamen — ohne
die proprietäre Vendor-App.

Das Protokoll ist bewusst einfach: Video-Interface aktivieren, zwei Vendor-Control-
Transfers, dann rohe YUYV-Frames von einem Bulk-Endpunkt lesen. Es hat **nichts** mit
iAP2, MFi, dem alten „BB AA"-Bulk-Protokoll oder MJPEG zu tun — das waren frühere
Sackgassen (siehe [Historie](#historie)).

- **WebUSB-Implementierung:** [`index.html`](index.html) (`startUsbStream` → `runVendorSession` → `drawYUYV`)
- **pyusb-Referenz:** [`tools/test_vendor_protocol.py`](tools/test_vendor_protocol.py)
- **Mitgeschnittene Init-Bytes:** [`tools/app_capture_init_sequence.txt`](tools/app_capture_init_sequence.txt)
- **Geräte-Deskriptoren:** [`tools/descriptors_mac_fresh_bcd0111.txt`](tools/descriptors_mac_fresh_bcd0111.txt)
- **Ein echtes Frame:** [`tools/vendor_frame.png`](tools/vendor_frame.png)

### Geräte-Identität

| Feld           | Wert                                                        |
| -------------- | ---------------------------------------------------------- |
| USB VID / PID  | `0x2ce3` / `0x3828`                                        |
| iManufacturer  | `Geek szitman`                                             |
| iProduct       | `useepluscam`                                             |
| iSerial        | `202402062300000` (Batch-/Datumscode, **nicht** pro Gerät) |
| bcdDevice      | `0x0111`                                                   |
| Vermarktet als | „Geek szitman useepluscam" / „Usee Plus"                   |

Das Gerät ist **kein** Standard-UVC-Gerät (USB Video Class) — das Betriebssystem zeigt
es nicht als Webcam, also kann `getUserMedia` es nicht öffnen. Es präsentiert
vendor-spezifische Klasse-255-Interfaces und muss direkt über WebUSB / libusb
angesteuert werden.

Geräte-Info aus dem Control-IN (Schritt 2 unten), Klartext:

| Feld        | Wert        |
| ----------- | ----------- |
| Hersteller  | `i4season`  |
| Modell      | `su4p-002`  |
| Firmware    | `5.0.13`    |
| Auflösung   | `640x480`   |

### USB-Interface- & Endpunkt-Layout

Eine Konfiguration, zwei Interfaces (alle Klasse `255` / Subklasse `240`):

| Interface | Alt | bInterfaceProtocol | iInterface               | Endpunkte                                   |
| --------- | --- | ------------------ | ------------------------ | ------------------------------------------- |
| 0         | 0   | 0                  | `iAP Interface`          | `0x81` IN bulk (512), `0x01` OUT bulk (512) |
| 1         | 0   | 1                  | `com.useeplus.protocol`  | *(keine)*                                   |
| 1         | 1   | 1                  | `com.useeplus.protocol`  | `0x82` IN bulk (512), `0x02` OUT bulk (512) |

**Der Videopfad nutzt ausschließlich Interface 1.** Interface 0 („iAP Interface")
spielt im funktionierenden Protokoll keine Rolle. Der Bulk-**IN-Endpunkt `0x82`** — der
**nur** auf Interface 1, Alt-Setting 1 existiert — trägt das Video.

> **Endpunkte niemals über die Nummer geräteübergreifend zuordnen.** In manchen
> Referenzdumps sind die EP-Nummern zwischen den Interfaces vertauscht. Endpunkte immer
> über die **Interface-Rolle** wählen (`bInterfaceProtocol`: `0` = iAP, `1` = useeplus),
> nicht über die Adresse. Diese App claimt Interface 1 und liest dessen IN-Endpunkt.

### Die funktionierende Sequenz

#### 1. Video-Interface aktivieren

```
Konfiguration setzen
Interface 1 claimen
selectAlternateInterface(Interface 1, Alt 1)   // aktiviert EP 0x82
```

Der Wechsel von Interface 1 auf Alt-Setting 1 lässt EP `0x82` (und `0x02`) erst
entstehen.

#### 2. Control-IN — Geräte-Info

| Feld        | Wert                                     |
| ----------- | ---------------------------------------- |
| requestType | class                                    |
| recipient   | device                                   |
| bRequest    | `0x00`                                   |
| wValue      | `0x0005`                                 |
| wIndex      | `0x0000`                                 |
| Länge       | `512`                                    |

Das Gerät antwortet mit dem Klartext-Infoblock (`i4season` / `su4p-002` /
FW `5.0.13` / 640x480). Dieser Schritt ist informativ und bestätigt zugleich, dass
sich das Gerät im erwarteten Modus befindet. (pyusb-`bmRequestType`: `0xa0`.)

#### 3. Control-OUT — START

| Feld        | Wert                                        |
| ----------- | ------------------------------------------- |
| requestType | class                                       |
| recipient   | device                                      |
| bRequest    | `0x01`                                      |
| wValue      | `0x0005`                                    |
| wIndex      | `0x0000`                                    |
| Daten       | 64 Bytes `0x30` (`'0'`, 64× wiederholt)     |

Das ist das START-Kommando. Danach beginnt das Gerät, auf EP `0x82` zu streamen.
(pyusb-`bmRequestType`: `0x20`.)

#### 4. Bulk-IN — Frames von EP `0x82` lesen

Bulk-IN-Reads auf Endpunkt `0x82` mit Anforderungslänge `614400` Byte absetzen.

- **Ein volles Frame ist exakt `614400` Byte**: rohes **YUYV422**, 640 × 480
  (`640 × 480 × 2 = 614400`). Frame zeichnen (Schritt 5) und weiterlesen.
- **Zwischen den Frames sendet das Gerät `511`-Byte-Header-/Status-Pakete** (Beginn mit
  den Magic-Bytes `dd cc …`). Das ist **kein** Video — jeden Read, dessen Länge nicht
  `614400` ist, **überspringen**.

Es gibt **kein** MJPEG, **keine** JPEG-`FFD8`/`FFD9`-Reassemblierung und **keine**
Längen-/`AA BB`-Header-Verarbeitung im funktionierenden Pfad. Ein volles Frame kommt als
ein zusammenhängender Read an.

### YUYV422 → RGB-Umwandlung

Jede 4-Byte-YUYV-Gruppe `[Y0, U, Y1, V]` kodiert zwei Pixel, die sich ein `U`/`V`-
Chroma-Paar teilen. Umwandlung per Ganzzahl-Arithmetik (genau das macht `drawYUYV` pro
Pixel auf dem Canvas, mit einem pro Frame wiederverwendeten `ImageData`-Puffer):

```
R = Y + ((359 * (V - 128))                   >> 8)
G = Y - ((88  * (U - 128) + 183 * (V - 128)) >> 8)
B = Y + ((454 * (U - 128))                   >> 8)
```

Jeden Kanal auf `0..255` begrenzen. Für das erste Pixel der Gruppe `Y = Y0`, für das
zweite `Y = Y1` verwenden — bei beiden mit denselben `U`/`V`-Werten.

### Historie

Das obige Protokoll ist das Ergebnis eines Mitschnitts dessen, was die echte „Usee
Plus"-Android-App (`com.i4season.useeplus`) tatsächlich über USB sendet — mitgeschnitten
per Frida-Hook auf libc-`ioctl` an der USBDEVFS-Schnittstelle
([`tools/frida_usbfs_hook.js`](tools/frida_usbfs_hook.js)), dann per pyusb
Ende-zu-Ende verifiziert.

Frühere Versuche liefen davor in zwei aufwendige Sackgassen:

- ein altes **„BB AA"-Bulk-/MJPEG**-Protokoll (12-Byte-Header,
  `FF D8`/`FF D9`-Reassemblierung) — das Gerät blieb stumm; und
- eine tiefe **iAP2- / Apple-MFi**-Untersuchung (Detect-Echo, Link-SYN/ACK, ein
  609-Byte-Apple-Zertifikat, ein `0xAE01`-Vendor-„Grant") — der Link-Handshake wurde
  über 17 Replug-Captures hinweg ge-ackt, das Gerät hat aber **nie** Video gestreamt.

Beide Sackgassen sind in
[`docs/REVERSE_ENGINEERING.md`](docs/REVERSE_ENGINEERING.md) beschrieben. Die Lehre:
Deskriptor-Strings und plausibel wirkende Handshakes können in lange Sackgassen führen;
mitzuschneiden, was die echte App tatsächlich tut, war mehr wert als das gesamte
Protokoll-Herumraten zusammen.
