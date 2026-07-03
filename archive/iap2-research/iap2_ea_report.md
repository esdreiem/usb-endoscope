I now have comprehensive, verified material. Here is the complete answer.

---

# iAP2 External Accessory transport — byte-level analysis for VID 0x2ce3 / PID 0x3828

## Executive summary of the three answers

1. **(b) is correct for the standard spec, but with a crucial caveat you're hitting.** EA data does NOT re-negotiate the SYN, and it does NOT ride the Control session as vendor messages. In standard iAP2, EA data rides its **own session id** (session type **0x02 = External Accessory**) that must already be declared in the Link SYN. Your SYN declares only session 0x0A / type 0x00 (Control) and **no type-0x02 session at all** — so per the standard spec this accessory has *no* conformant channel for EA bytes. That is exactly why the vendor invented a dialect that stuffs everything (0xEA02 / 0xAE01 / 0xAE00) into the one Control session as vendor-defined control messages. So for *this device* the practical answer is (b)-by-vendor-hack, layered on top of a spec that would normally require the session to exist in the SYN.

2. **Yes — 0xEA02 is an accessory-initiated "please open a session for protocol X" request, and 0xAE01 is your grant.** The byte-swapped IDs (EA→AE) are deliberate: the vendor mirrored Apple's device→accessory `StartExternalAccessoryProtocolSession` (0xEA00) into an accessory→device flavor (0xEA02), and your grant must carry a **host-assigned session identifier** (a 2-byte value you choose), most plausibly *plus* the protocol identifier so the device knows which of its protocols you're binding. Your 7-shot 0xAE01 attempt failed because none of the variants carried a session id in the shape the device's parser wants, and — separately — **you skipped the auth challenge**, which very likely gates the whole EA path.

3. **The mismatch is the key: `com.useeplus.istorage` (stored files) is a *different* EA protocol from the advertised `com.useeplus.protocol` (live video).** The device is telling you "I want to open the *istorage* session first." You almost certainly must open/accept the istorage session before (or as a precondition to) the video protocol. The video path is a second EA protocol, likely started by a *second* 0xEA02 (or by you sending an 0xAE01 that names/selects `com.useeplus.protocol` after istorage is up).

---

## 1. How EA data physically moves (spec vs. this device)

### Standard iAP2 (Accessory Interface Specification R2 §25.4, §26.7; Table 25-1)

- The **Link Synchronization payload** enumerates *every* session up front: for each session it carries `session identifier (1 byte)`, `session type (1 byte)`, `session version (1 byte)`. Session types:
  - **0x00 = Control**
  - **0x01 = File Transfer**
  - **0x02 = External Accessory**
- **Sessions are NOT dynamically created after the SYN.** The set of sessions and their ids is fixed at link-establishment time. (The one legitimate way to change the session table is to tear the link down and send a *new* SYN — see below.)
- EA payload is **not** a control message and **not** re-SYN'd. After `StartExternalAccessoryProtocolSession`, the raw EA bytes travel as the **session payload of the EA session id** (the id whose type is 0x02 in the SYN). This is exactly what the Infineon/AIROC reference stack exposes: you send with `IAP2_EA_SESSION_ID`, and *"the first 2 octets of p_data must be the [EA-session] handle ... in big-endian."* Multiple EA protocols are **multiplexed over the single iAP2 link**, coordinated by Control-session messages, but each EA data stream flows on the EA session id, tagged by the 2-byte EA-session-identifier that `StartExternalAccessoryProtocolSession` assigned.

So your three options map to:
- **(a) Re-negotiated SYN** — this *is* how the session table can legitimately change, but it is triggered by a **full link reset** (link teardown → new SYN/ACK), not by "a session starting." iAP2 does not add sessions mid-link. In normal operation the EA session is present in the *first* SYN; you never see a second SYN just to add EA. **Not what happens here.**
- **(b) Rides an existing session** — correct in spirit. Standard: rides the pre-declared **EA session id**. This device: has no EA session id, so it rides the **Control session as vendor messages** (0xEA02/0xAE01/0xAE00). **This is your device's mechanism.**
- **(c) Separate USB bulk interface** — no. Everything stays on the one iAP bulk pair (EP 0x81 IN / 0x01 OUT). The dead "BB AA 05 00 00" raw path from older firmware was exactly such a side-channel; it's gone on iAP2 firmware. **Not applicable.**

### What this means concretely for you

Because the SYN gives you only Control (0x0A/0x00), **do not** expect to send EA data on a numeric EA session id — there isn't one. The vendor's design keeps *all* of it inside Control-session control messages:
- Framing stays exactly what you already have working: `FF 5A <len16> 40 <seq> <ack> 0A <hdrcksum>` then `40 40 <len16> <msgid16> <params...> <cksum>`.
- The "EA data" (0xAE00) will arrive as a **Control-session control message on session 0x0A**, with the JPEG/camera payload inside a parameter, not as bare session payload. That's consistent with the device having declared 0xAE00 in "Messages Sent by Accessory."

---

## 2. Decoding the 0xEA02 / 0xAE01 / 0xAE00 dialect

### The ID mirroring is the Rosetta Stone

Apple's standard EA control messages (spec §26.7):

| Msg ID | Name | Direction | Key params |
|--------|------|-----------|------------|
| **0xEA00** | StartExternalAccessoryProtocolSession | **Apple device → accessory** | ExternalAccessoryProtocolIdentifier (param **0x0000**, 1 byte) + ExternalAccessoryProtocolSessionIdentifier (param **0x0001**, 2 bytes) |
| **0xEA01** | StopExternalAccessoryProtocolSession | Apple device → accessory | ExternalAccessoryProtocolSessionIdentifier (0x0001, 2 bytes) |
| **0xEA02** | StatusExternalAccessoryProtocolSession | accessory → Apple device | session id + status (standard) |

Your device's advertised set:
- **Sent by accessory:** 0xEA02, 0xAE00, 0xAE02
- **Received by accessory:** 0xAE01

The vendor did a byte-swap rename (EA↔AE) to build an **accessory-initiated** mirror of the Apple flow:

| Vendor ID | Best interpretation | Direction | Analogous to |
|-----------|--------------------|-----------|--------------|
| **0xEA02** | "I want a session for protocol \<name\>" (accessory *requests* open) | accessory → host | inverse of 0xEA00 |
| **0xAE01** | "Session granted — here is the session id" (host *opens/grants*) | host → accessory | the actual 0xEA00 role |
| **0xAE00** | EA data stream (video/file bytes) | accessory → host | EA session payload |
| **0xAE02** | EA session status / stop / error | accessory → host | 0xEA02 (standard status) |

So **yes**: 0xEA02 is the accessory asking you to open a session (accessory-initiated), and 0xAE01 is your grant that must carry a session id.

### Why your 0xAE01 was silently ignored — and what it most plausibly needs

The device declared 0xEA02 carries **param 0x0000 = protocol NAME string** (`"com.useeplus.istorage\0"`), not the standard 1-byte protocol *identifier*. That is a strong hint that this dialect is **name-keyed, not id-keyed**. Given that, the most plausible 0xAE01 grant payload — in decreasing likelihood — is:

**Most likely (echo-the-name + assign a session id):**
```
40 40 <len16> AE 01
  <len16=..> 00 00  "com.useeplus.istorage" 00      ; param 0x0000 = protocol NAME echoed back
  00 05  00 01  00 01                                 ; param 0x0001 = host-assigned session id = 0x0001 (2 bytes BE)
<cksum>
```
Rationale: the device keyed its *request* on the name, so its parser almost certainly matches the *grant* on the same name (param 0x0000), and needs a 2-byte session id (param 0x0001) to stamp into subsequent 0xAE00 frames. This mirrors 0xEA00 exactly except protocol is identified by name instead of the 1-byte id.

**Second most likely (protocol id + session id, standard shape):**
```
40 40 <len16> AE 01
  00 04  00 00  01                                    ; param 0x0000 = protocol identifier = 0x01 (1 byte)
  00 05  00 01  00 01                                 ; param 0x0001 = session id = 0x0001 (2 bytes BE)
<cksum>
```

**What almost certainly is NOT enough (and matches your failures):** a bare `p0=01`, `p0=05 00 00`, `p0=0x1000`, or the name alone with **no distinct session-identifier parameter**. Your seven variants each supplied *one* value; the grant almost certainly needs **two** parameters — a protocol selector (name or id) *and* a 2-byte session id — because the device must know both *which* protocol you accepted and *what tag* to put on its 0xAE00 data. Sending only one is why it parsed as inert rather than rejected.

Concrete next experiments (one variable at a time), on the live Control session 0x0A:
1. 0xAE01 with **param 0x0000 = the exact name echoed** + **param 0x0001 = 2-byte session id 0x0001**. (highest priority)
2. If silent, swap param 0x0000 to the **1-byte protocol id 0x01** + param 0x0001 = 0x0001.
3. If silent, try session id **0x0A** (reuse the control id) or **0x0000** in param 0x0001 — some vendor stacks use 0 as "default/first."
4. Watch for the device to emit **0xEA02 again** (status) or start **0xAE00** — that is your success signal.

### The auth-skip is a likely hard blocker — fix it first

You jumped from 0xAA01 straight to 0xAA05, skipping `RequestAuthenticationChallengeResponse (0xAA02)` / `AuthenticationResponse (0xAA03)`. Multiple sources confirm iOS (and MFi-conformant accessory firmware) treat **successful challenge/response as a precondition** for the EA path: EA sessions are only established *after* auth + identification complete. A well-behaved accessory that received `AuthenticationSucceeded` without ever having produced a signature may:
- accept identification (which it did) but
- **refuse to arm the EA state machine**, so 0xAE01 is parsed-but-dropped because the accessory considers itself not-yet-authenticated for data.

This is the single most likely reason 0xAE01 is *inert rather than rejected*: the message is well-formed enough to parse, but the EA gate is closed. **Do the real challenge:** send 0xAA02 carrying the auth IC's challenge, read 0xAA03 (the signature the device's Apple auth coprocessor produces over your challenge), *then* 0xAA05. Since the device already handed you a genuine 609-byte Apple cert from 0xAA01, its auth IC is live and will answer 0xAA02.

---

## 3. `com.useeplus.protocol` vs `com.useeplus.istorage` — two protocols, order matters

The identification advertised exactly one EA protocol in the Supported-EA-Protocol group: **protocol id 1 = `com.useeplus.protocol`**. But the very first thing the device does after `IdentificationAccepted` is push **0xEA02 naming `com.useeplus.istorage`** — a name that was *not* in the advertised EA group.

Interpretation:
- **`com.useeplus.protocol` (id 1)** = the advertised, "primary" EA protocol. Given the app's purpose and the old-firmware MJPEG path, this is almost certainly the **live-video / control** protocol.
- **`com.useeplus.istorage`** = a **second, storage-oriented** protocol (browse/pull stored files/recordings). The device unsolicited-requests *this one first*, which strongly implies the firmware boots into a "storage/handshake" session and expects the host to bind it before anything else flows.
- The fact that istorage isn't in the advertised group is normal for vendor dialects: the advertised group is the "official" EAP string an iOS app would match on; the istorage name is an internal/second protocol the vendor opens out-of-band via its 0xEA02 request.

**Sequencing you should assume:**
1. Complete real auth (0xAA02/0xAA03) → 0xAA05 → identification (already works).
2. Device sends **0xEA02(istorage)** → you must reply **0xAE01 granting istorage** with a session id. Accept this first.
3. Once istorage is up, expect the device to either (a) send another **0xEA02 naming `com.useeplus.protocol`** for video, which you likewise grant with a *different* session id, or (b) begin 0xAE00 on istorage and only expose video after a storage/nav command. Either way, **you cannot skip istorage** — the device is gating on it by requesting it first.
4. Video (0xAE00 with the old 7-byte cam header + JPEG, `AA BB | cid 07/0B | ...`) will then arrive as 0xAE00 control-session messages tagged with the video protocol's session id — the same MJPEG structure as old firmware, just wrapped in iAP2 0xAE00 instead of the dead `BB AA` bulk path.

So: **istorage first, then video.** Track two session ids (one per protocol) and demux incoming 0xAE00 by the 2-byte session id you assigned in each 0xAE01 grant.

---

## Sources

- [Exploring Apple's MFi protocol iAP2 (wiomoc.de)](https://wiomoc.de/misc/posts/mfi_iap.html) — three session types (Control/File Transfer/External Accessory); EA protocols advertised in identification; multiple EA connections multiplexed over one link, coordinated by control-session messages.
- [Infineon AIROC CYW20721 iAP2 Library API](https://infineon.github.io/btsdk-docs/BT-SDK/20721-B2_Bluetooth/API/group__wiced__bt__iap2__api__functions.html) and [CYW20719](https://infineon.github.io/btsdk-docs/BT-SDK/20719-B2_Bluetooth/API/group__wiced__bt__iap2__api__functions.html) — `IAP2_EA_SESSION_ID`; the 2-octet big-endian session handle prefix on EA data; *"application on the device is responsible to start External Accessory Session."*
- [Oligo Security — Pwn My Ride / CarPlay iAP2 attack surface (CVE-2025-24132)](https://www.oligo.security/blog/pwn-my-ride-exploring-the-carplay-attack-surface) — packet magic `FF 5A`, len16, control byte, SYN-only-at-init; payload magic `40 40` + len16; session id roles (0 control/auth, 1 data/file transfer, 2 External Accessory).
- [MFi Accessory Interface Specification R2 (idoc.pub mirror)](https://idoc.pub/documents/mfi-accessory-interface-specification-for-apple-devices-r2-en5kmeo3epno) and [kupdf mirror](https://kupdf.net/download/mfi-accessory-interface-specification-for-apple-devices-r2_5a0f99e8e2b6f51a276f25d2_pdf) — §24.2 SYN payload (session id/type/version, 1 byte each); Table 25-1 session types; §25.4 External Accessory session / ExternalAccessoryTransfer datagram; §26.7.1 StartExternalAccessoryProtocolSession, §26.7.2 StopExternalAccessoryProtocolSession, params ExternalAccessoryProtocolIdentifier / ExternalAccessoryProtocolSessionIdentifier; §26.3.1 RequestAppLaunch; identification is device-initiated (§5.2).
- [Accessory Interface Specification R29 (scribd)](https://www.scribd.com/document/788716769/Accessory-Interface-Specification-R29) — StartExternalAccessoryProtocolSession control-message example, ExternalAccessoryProtocolIdentifier / ExternalAccessoryProtocolSessionIdentifier parameter structures.
- [Apple Developer Forums — External Accessory tag](https://developer.apple.com/forums/tags/externalaccessory) and [EA session transfer thread 98089](https://developer.apple.com/forums/thread/98089) — iOS sends `StartExternalAccessoryProtocolSession` only after auth challenge/response + identification complete; accessory cannot unilaterally start the EA session (app must open it); `RequestAppLaunch` must be listed in MessagesSentByAccessory.
- [CSDN — CarPlay iAP2 附件协议](https://blog.csdn.net/zoosenpin/article/details/87439254) — iAP2 message-id families including the 0xEA00/0xEA01 External Accessory control messages.

**Files:** the Troopers24 CarPlay PDF was fetched during research but is image-only (no text layer; needs OCR/poppler to mine further).

**One-line recommendation:** do the real MFi challenge (0xAA02/0xAA03) before 0xAA05, then answer the device's 0xEA02(istorage) with an **0xAE01 carrying two params — the protocol name echoed (param 0x0000) + a host-assigned 2-byte session id (param 0x0001)** — accept istorage first, and expect video (`com.useeplus.protocol`) as a second 0xEA02→0xAE01 exchange whose 0xAE00 frames carry the legacy MJPEG `AA BB` structure.