I now have complete, authoritative primary-source data from Apple's own HomeKitADK, the SzAllen/Iap2 accessory implementation, the wiomoc RE writeup, and the leaked iAP2 spec. I have everything needed to answer all three questions with concrete byte structures. Let me write the final answer.

---

# iAP2 / MFi Authentication: precise answer with byte structures

## Sources (primary, load-bearing)

- **Apple HomeKitADK** (Apple's own open-source MFi/HAP code) — the coprocessor register map, exact challenge/signature sizes, and cert-length constants: `HAP/HAPMFiHWAuth+Types.h`, `HAP/HAPMFiHWAuth.c` — https://github.com/apple/HomeKitADK/blob/master/HAP/HAPMFiHWAuth.c
- **SzAllen/Iap2** (a real accessory-side iAP2 stack) — the exact 0xAA0x message-ID constants, the control-message/param wire framing, and the accessory's request→response state machine: `Src/Iap2CtrlSession.c/.h` — https://github.com/SzAllen/Iap2/blob/master/Src/Iap2CtrlSession.c
- **wiomoc "Exploring Apple's MFi protocol iAP2"** — RE writeup of the flow and I2C register usage — https://wiomoc.de/misc/posts/mfi_iap.html
- **MFi Accessory Interface Spec R2 / AIS** dumps (idoc.pub / scribd) — the "Challenge/Response are Blobs" statement and message ordering.
- **Infineon AIROC iAP2 library docs** — EA-session gating on completed negotiation — https://infineon.github.io/btsdk-docs/BT-SDK/20721-B2_Bluetooth/API/group__wiced__bt__iap2__api__functions.html

A key caveat up front: the message-ID and parameter constants (0xAA00–0xAA05) are hard-confirmed from open code. The exact **numeric parameter IDs inside AA02/AA03** are NOT reproduced verbatim in any non-NDA source I could find — they are behind the MFi NDA. Everything I state about parameter numbering I flag as confirmed-vs-inferred below.

---

## 1. Exact wire format of the AA0x messages

### Message-ID constants (confirmed, `Iap2CtrlSession.h` lines 24–30)

```
IAP2_REQ_AUTH               0xAA00   RequestAuthenticationCertificate      (device -> accessory)
IAP2_RSP_AUTH               0xAA01   AuthenticationCertificate             (accessory -> device)
IAP2_REQ_AUTH_CHA_RSP       0xAA02   RequestAuthenticationChallengeResponse(device -> accessory)
IAP2_RSP_AUTH_CHA_RSP       0xAA03   AuthenticationResponse                (accessory -> device)
IAP2_RSP_AUTH_RESULT_FAILED 0xAA04   AuthenticationFailed                  (device -> accessory)
IAP2_RSP_AUTH_RESULT_SUCCESS 0xAA05  AuthenticationSucceeded               (device -> accessory)
```

Note the response for a request `msgId` is always `msgId+1` in this stack (`Iap2CtrlSessionMsg_Init(pRsp, msgId + 1)`), which matches the AA00→AA01 and AA02→AA03 pairing you already observed.

### Control-message + parameter framing (confirmed, matches what you have)

Inside the control session, each message is `40 40 <len16> <msgid16> {params} <cksum>`, and each parameter is laid out MSB-first as (this is `Iap2CtrlSessionMsg_AddParam`, verbatim):

```
pByte[i++] = U16_MSB(len);      // Parameter Length MSB   <- length INCLUDES the 4-byte param header
pByte[i++] = U16_LSB(len);      // Parameter Length LSB
pByte[i++] = U16_MSB(paramId);  // Parameter ID MSB
pByte[i++] = U16_LSB(paramId);  // Parameter ID LSB
memcpy(&pByte[i], pData, len);  // Parameter Data
```

So every param is `<len16><paramid16><data>` exactly as you framed it. (In AIS the length field is the total including the 4-byte header; double-check your own framing uses total-including-header, since one common bug is off-by-4.)

### AA02 — RequestAuthenticationChallengeResponse (device → accessory)

- **One parameter, id `0x0000`, type Blob**, carrying the **challenge**.
  - The AIS/R2 spec text states plainly: *"Challenge and Challenge Response's are sent via Blobs."* The certificate/challenge/response messages in this family all use a single blob parameter with **param id 0** (in this stack every generated response uses `Iap2CtrlSessionMsg_AddParam(pRsp, 0, ...)` — param id 0 — for the certificate/response blob; confirmed line 275). So param id 0 for the challenge blob in AA02 is the strongly-consistent inference; it is *not* independently spelled out in a non-NDA source.
- **What the challenge data is:** it is the raw bytes the host wants signed. The host is the one that chooses them; on a genuine iPhone these are effectively **random/nonce bytes** the phone generates so a replayed signature is useless. The coprocessor does **not** verify or interpret the challenge in any way — it blindly signs whatever it is handed.
- **Challenge size — this is the crucial byte fact, from Apple's own code** (`HAPMFiHWAuth+Types.h`):
  - `ChallengeData` register `0x21`, **Length: 32 bytes / 128 bytes (2.0C)**.
  - `ChallengeDataLength` register `0x20`, 2 bytes.
  - In `HAPMFiHWAuthCreateSignature`, for a **2.0C (protocol major 2 → RSA)** part, HomeKit writes `ChallengeDataLength = SHA1_BYTES` (0x14 = **20 bytes**) and writes 20 bytes of challenge data. HomeKit happens to SHA-1-hash its own challenge down to 20 bytes first, but that hashing is a HomeKit convention, not a coprocessor requirement — the coprocessor signs whatever `ChallengeData`/`ChallengeDataLength` you load (up to 128 bytes on 2.0C). **In iAP2 the accessory takes the AA02 challenge blob and loads it directly into registers 0x20/0x21 unhashed.**
  - Practical upshot: the AA02 challenge blob for a 2.0C accessory is a **small (≤128-byte, typically ~20-byte-range) opaque nonce**. The accessory doesn't care about its content or exact length as long as it fits register 0x21.

### The coprocessor signing step (confirmed, `HAPMFiHWAuth.c` + wiomoc)

The accessory, on receiving AA02, does this over I2C to the Apple Authentication Coprocessor (register addresses verbatim from `HAPMFiHWAuth+Types.h`):

```
0x20  ChallengeDataLength           write, 2 bytes  (big-endian length of challenge)
0x21  ChallengeData                 write, <=128B   (the challenge blob from AA02)
0x11  ChallengeResponseDataLength   write 0x0080    (2.0C: preset to 0x80 before signing)
0x10  AuthenticationControlAndStatus write 0x01     (PROC_CONTROL = start signing)
0x10  read back; success when bits 6|5|4 == 0b001  (HomeKit tests: bytes[0] == (1<<4) == 0x10)
0x11  ChallengeResponseDataLength   read, 2 bytes   (2.0C => 0x80 == 128; 3.0 => 64 (ECDSA))
0x12  ChallengeResponseData         read, that many bytes  (the signature)
```

- **Signature size / algorithm (confirmed):** 2.0C = **RSA-1024 + SHA-1 → 128-byte signature** (register 0x12 length 0x80). (3.0 = ECDSA P-256 → 64 bytes.) HomeKit's validity check: `protocolVersionMajor==2 && challengeResponseDataLength > 0x80` is rejected; for 2.0C it is exactly 0x80.
- This is exactly the same 128-byte-page I2C pattern the `SzAllen/Iap2` accessory uses to read its 607–609-byte cert (`IicDrv_Read(0x30, …2)` for length, then `0x31…` pages of 128 bytes). Your device returned a **609-byte** cert, which is right in Apple's own asserted range `607…609` for protocol v3-style / `<=1280` for v2 (`HAPMFiHWAuthCopyCertificate` bounds).

### AA03 — AuthenticationResponse (accessory → device)

- **One parameter, id `0x0000`, type Blob** = the **128-byte RSA signature** read from coprocessor register 0x12, verbatim, no wrapping. (Same "response is a Blob, param 0" basis as above.)
- Message framing: `40 40 <len16> AA03 <00xx 0000 {128 sig bytes}> <cksum>`, i.e. param len = 128+4 = 0x0084, param id 0x0000, then the 128 signature bytes.

The genuine phone then verifies: SHA-1(challenge) is RSA-verified against the public key in the AA01 certificate, and the cert chains to Apple's "Apple Accessories Certification Authority" (exactly the issuer string you saw). Only a real coprocessor holds the matching private key.

---

## 2. Can a FAKE host complete the exchange well enough to satisfy the accessory?

**Short answer: yes, trivially — and you don't even need to run AA02 at all.** The accessory is a pure responder here; it never checks that you verified anything.

Concrete evidence from the accessory-side code (`Iap2CtrlSession.c`), which is the behavior your device almost certainly mirrors:

- The accessory's request handler (`Iap2CtrlSession_ReqProc`) simply switches on the incoming msgId:
  - `AA00` → read cert from coprocessor, reply `AA01`.
  - `AA02` → sign challenge, reply `AA03`.
  - `AA05` (AuthenticationSucceeded) → **`//No Response`** — it just records `pSession->m_MsgId = 0xAA05` and moves on.
  - `1D00` → reply identification; `1D02` (IdentificationAccepted) → **`//No Response`**, proceed.
- There is **no state check anywhere** that "AA02 happened" or "the signature was correct." The accessory cannot know whether the host verified the signature — verification is entirely host-side. From the accessory's point of view AA05 is an unconditional "you're blessed, continue" token.
- Crucially, the accessory's own success signal is just **receiving AA05**: in `Iap2CtrlSession_EventProc`, after handling `AA00`, `AA02`, or `AA05` it calls `SessionMgr_RxReq` (keep receiving control), and only after `1D02` does it `SessionMgr_TxReq` (start pushing its own traffic). Nothing gates that transition on the challenge having occurred.

So a fake host that (a) answers AA00 with nothing (just consumes AA01), (b) **optionally** sends AA02 with any well-formed blob and ignores the AA03 it gets back, then (c) sends AA05 and proceeds to identification — fully satisfies the accessory. The accessory does **not** cryptographically gate anything; the entire challenge is a check the *phone* runs on the *accessory*, not vice-versa. **Skipping AA02 entirely and going straight AA00 → AA05 is spec-legal from the accessory's side and, per this reference stack, handled identically.** That is consistent with what you already observed: your AA05-without-challenge path let identification and the unsolicited `0xEA02` proceed.

**Therefore the challenge is almost certainly NOT the cause of your AE01 problem.** The accessory does not withhold EA/vendor-message handling because "the challenge didn't happen." If it were gating on auth, it would have refused *identification* too (it didn't) and would not have volunteered `0xEA02`.

---

## 3. Is skipping AA02 a known cause of an accessory refusing app/EA traffic while still allowing identification?

**No — there is no evidence for that, and the architecture argues against it.**

- **Ordering rule that does exist:** the spec ordering is Link → Authentication → Identification → (host app opens) EA session. Multiple sources state authentication and identification "must complete before meaningful iAP2 commands / EA sessions flow" (Infineon AIROC docs; MFi library overviews). But that rule is expressed from the *phone's* stack: *the iOS side* won't surface the accessory to apps until it has authenticated it. It is **not** a gate the accessory enforces on inbound EA traffic. A genuine phone always does the challenge, so the accessory has simply never been designed to police it.
- The reference accessory stack (above) proves the accessory takes AA05 at face value and does not condition later behavior on AA02. The AIS "authenticate before identify" text is about the *sequence the phone drives*, not an accessory-side EA gate.
- The one nearby real-world data point (Apple Developer Forums thread 673159) is the *opposite* failure: the **device** goes silent and only ACKs after the accessory sends its cert — a sequencing/retransmit issue (fixed by re-sending with an incremented seq), nothing about the accessory blocking EA because the host skipped the challenge.

### What is actually blocking your `0xAE01`

Your symptom — identification works, unsolicited `0xEA02` fires, link stays up, but `0xAE01` is silently inert while an *undeclared* msg (`0xEA00`) actively kills the link — is a **payload/format or session-plumbing problem in the vendor EA layer**, not an authentication gate. Things to check, in order:

1. **Session / message routing.** `0xAE0x` and `0xEA0x` are **vendor-defined control-session messages** (this device declares them in Identification p6/p7), not the generic ExternalAccessory *data* session. The device declared exactly one session (id 0x0A, Control) and no EA data session, so `com.useeplus.protocol` traffic is tunneled as these AE/EA control messages. `0xAE01` being silently ignored (vs `0xEA00` killing the link) means AE01 *is* in the accepted set but your **parameters are malformed for what it expects**, so its handler no-ops. Undeclared IDs hit a reject path that stalls the FIFO; declared-but-malformed hit a parse path that just drops.
2. **Parameter IDs and types.** You sent seven single-param `0xAE01` messages with param id `0x0000` and various raw values. The vendor handler likely expects **specific param id(s) and a specific type** (e.g. the protocol-identifier param that names `com.useeplus.protocol`, plus a command param), not param 0 with a bare integer. Since you don't have the vendor's param map, capture what a genuine app/host sends, or brute-force param ids with correctly-typed payloads. The fact that `0xEA02`'s payload was `param id 0x0000 = "com.useeplus.istorage\0"` (a NUL-terminated UTF-8 string) strongly suggests these vendor messages use **string-typed params**, so `0xAE01` probably wants a matching string/handshake echo, not `01`/`05 00 00`/`0x1000`.
3. **You likely must answer `0xEA02` first.** The device *unsolicited* sent `0xEA02 {com.useeplus.istorage}` immediately after `1D02`. That is a vendor handshake/announcement. `0xEA02` is in the accessory's *"Messages Sent by Accessory"* set and `0xAE01` is the sole *"received"* message — so the intended dialog is almost certainly **accessory sends `0xEA02` → host replies `0xAE01` echoing/acking `com.useeplus.istorage`** to open the stream. Your `0xAE01` variant that carried the string `"com.useeplus.istorage"` is the most promising; try it with the **exact byte-for-byte payload the device sent in EA02** (including the trailing NUL and the exact param id EA02 used), rather than assorted control bytes.

Net: complete or skip the MFi challenge freely — it will not change the AE01 behavior. Focus on the vendor `0xEA02`/`0xAE01` handshake payload format.

---

## Files/artifacts you can pull directly

- Apple coprocessor register map + exact sizes: `HAP/HAPMFiHWAuth+Types.h`, `HAP/HAPMFiHWAuth.c` in https://github.com/apple/HomeKitADK — registers 0x10 status, 0x11/0x12 response-len/data (128B RSA sig on 2.0C), 0x20/0x21 challenge-len/data (≤128B), 0x30/0x31.. cert-len/data pages.
- Accessory-side iAP2 message IDs + framing + state machine: `Src/Iap2CtrlSession.c` / `Src/Iap2CtrlSession.h` in https://github.com/SzAllen/Iap2 — confirms AA00–AA05 IDs, `msgId+1` response pairing, param blob at id 0, and that AA05/1D02 are `//No Response` pass-through with no auth gate.