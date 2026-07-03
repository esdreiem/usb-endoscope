#!/usr/bin/env python3
"""Replug capture #13: real MFi challenge + TWO-param 0xAE01 EA-session grant.

Two research reports converge (tools/research/*.md):
 - 0xAE01 is the host's grant that mirrors iAP2 StartExternalAccessoryProtocol
   Session (0xEA00): it needs TWO params — a protocol SELECTOR (param 0x0000,
   name string or 1-byte id) AND a host-assigned 2-byte SESSION ID (param
   0x0001). All 7 payloads in #12 had only ONE param → parsed-but-inert.
 - The device unsolicited-requests com.useeplus.istorage via 0xEA02 right after
   IdentificationAccepted; answer it immediately by GRANTING that exact name.
   Video is a second protocol (com.useeplus.protocol, id 1).
 - Challenge is probably not a hard gate, but do the REAL 0xAA02/0xAA03 anyway
   (the device's Apple auth IC is live — it gave us a 609-B cert).

This run: handshake WITH real challenge → grant the requested istorage session
→ grant com.useeplus.protocol (video) → listen for 0xAE00 (MJPEG). Logs empty
link ACKs so we can tell whether the device acks our grants. Dumps 0xAE00/0xAE02
raw for offline analysis.
"""
import os
import time
import threading
import usb.core
import usb.util

DETECT = bytes([0xFF, 0x55, 0x02, 0x00, 0xEE, 0x10])
CTRL_SESS = 0x0A

t0 = time.monotonic()
def log(m): print(f"[{time.monotonic()-t0:7.2f}] {m}", flush=True)
def cks(bs): return (0x100 - (sum(bs) & 0xFF)) & 0xFF

def iap2_packet(ctrl, seq, ack, session, payload=b""):
    hdr = bytes([0xFF, 0x5A]) + (9 + len(payload) + (1 if payload else 0)).to_bytes(2, "big") \
        + bytes([ctrl, seq, ack, session])
    hdr += bytes([cks(hdr)])
    if payload: payload = payload + bytes([cks(payload)])
    return hdr + payload

def parse_iap2(data):
    if len(data) < 9 or data[0] != 0xFF or data[1] != 0x5A: return None
    return {"ctrl": data[4], "seq": data[5], "ack": data[6], "sess": data[7],
            "payload": bytes(data[9:-1]) if len(data) > 9 else b""}

def param(pid, data): return (len(data) + 4).to_bytes(2, "big") + pid.to_bytes(2, "big") + data
def ctrl_msg(mid, params=b""): return bytes([0x40, 0x40]) + (6 + len(params)).to_bytes(2, "big") + mid.to_bytes(2, "big") + params
def parse_ctrl(pl):
    if len(pl) < 6 or pl[0] != 0x40 or pl[1] != 0x40: return None, []
    mid = int.from_bytes(pl[4:6], "big")
    params, i = [], 6
    while i + 4 <= len(pl):
        plen = int.from_bytes(pl[i:i+2], "big"); pid = int.from_bytes(pl[i+2:i+4], "big")
        if plen < 4: break
        params.append((pid, bytes(pl[i+4:i+plen]))); i += plen
    return mid, params

MSG = {0xAA01: "AuthCert", 0xAA03: "AuthResponse", 0x1D01: "IdentInfo",
       0xEA02: "EA02(req)", 0xAE00: "AE00(data)", 0xAE02: "AE02(status)"}

def find_dev(): return usb.core.find(idVendor=0x2CE3, idProduct=0x3828)

_dump = {"f": open("tools/replug13_ae_dump.bin", "wb"), "n": 0}
_dump_lock = threading.Lock()
frames = {"n": 0}
_fr = {"buf": bytearray(), "in": False}
_fr_lock = threading.Lock()
def feed_jpeg(chunk, src):
    with _fr_lock:
        payload = chunk[12:] if len(chunk) >= 12 and chunk[0] == 0xAA and chunk[1] == 0xBB else chunk
        i = 0
        while i < len(payload):
            if not _fr["in"]:
                q = payload.find(b"\xff\xd8", i)
                if q < 0: break
                _fr["in"] = True; _fr["buf"] = bytearray(b"\xff\xd8"); i = q + 2
            else:
                q = payload.find(b"\xff\xd9", i)
                if q < 0: _fr["buf"].extend(payload[i:]); break
                _fr["buf"].extend(payload[i:q+2]); i = q + 2
                frames["n"] += 1
                if frames["n"] <= 6:
                    fn = f"tools/replug13_frame_{frames['n']}.jpg"
                    open(fn, "wb").write(bytes(_fr["buf"]))
                    log(f"** FRAME {frames['n']} ({src}): {len(_fr['buf'])}B -> {fn}")
                _fr["in"] = False; _fr["buf"] = bytearray()

log("warte auf ABSTECKEN ...")
while find_dev() is not None: time.sleep(0.3)
log("abgesteckt. warte auf ANSTECKEN ...")
while True:
    dev = find_dev()
    if dev is not None: break
    time.sleep(0.15)
log("angesteckt! claim If0")
dev.set_configuration(); usb.util.claim_interface(dev, 0)

wlock = threading.Lock()
def wr(data, tag, ep=0x01):
    try:
        with wlock: dev.write(ep, data, timeout=800)
        if tag: log(f">> {tag}: {data[:40].hex(' ')}{' ...' if len(data) > 40 else ''}")
        return True
    except usb.core.USBError as e:
        if tag: log(f">> {tag}: FEHLER {e}")
        return False

link = {"my_seq": 0x0B, "their_seq": 0x00, "up": False, "gone": False, "stop": False,
        "msgs": set(), "ea02_names": [], "acks": 0}

def reader():
    last_ka = time.monotonic()
    while not link["stop"]:
        try:
            data = bytes(dev.read(0x81, 8192, timeout=250))
        except usb.core.USBError as e:
            if "No such device" in str(e): link["gone"] = True; log("!! iAP-in weg"); return
            if link["up"] and time.monotonic() - last_ka > 1.0:
                wr(iap2_packet(0x40, link["my_seq"], link["their_seq"], 0x00), None); last_ka = time.monotonic()
            continue
        last_ka = time.monotonic()
        if data == DETECT: wr(DETECT, "DETECT-ECHO"); continue
        p = parse_iap2(data)
        if p is None:
            log(f"<< non-iAP2 ({len(data)}B): {data[:32].hex(' ')}"); feed_jpeg(data, "EP81-raw"); continue
        if p["ctrl"] & 0x80 and not link["up"]:
            link["their_seq"] = p["seq"]; wr(iap2_packet(0xC0, link["my_seq"], p["seq"], 0x00, p["payload"]), "SYN/ACK")
        elif p["ctrl"] == 0x40 and not p["payload"]:
            if not link["up"] and p["ack"] == link["my_seq"]:
                link["up"] = True; log("*** LINK UP ***")
            else:
                # leeres Link-ACK des Geräts (Diagnose: ackt es unsere Grants?)
                link["acks"] += 1
                if link["acks"] <= 40:
                    log(f"<< ACK (ack={p['ack']:#04x})")
        elif p["payload"]:
            link["their_seq"] = p["seq"]
            wr(iap2_packet(0x40, link["my_seq"], p["seq"], 0x00), None)  # ACK
            mid, params = parse_ctrl(p["payload"])
            if mid is not None:
                link["msgs"].add(mid)
                log(f"<< CTRL {MSG.get(mid, hex(mid))} (sess {p['sess']:#04x}, {len(p['payload'])}B, {len(params)} params)")
                for pid, d in params:
                    if len(d) <= 28:
                        txt = d.rstrip(b'\x00'); pr = len(txt) > 0 and all(32 <= c < 127 for c in txt)
                        log(f"     p{pid}: {d.hex(' ')}" + (f'  = \"{txt.decode()}\"' if pr else ''))
                    else:
                        log(f"     p{pid}: {len(d)}B {d[:28].hex(' ')} ...")
                    feed_jpeg(d, f"{MSG.get(mid, hex(mid))}/p{pid}")
                if mid == 0xEA02:  # Gerät fordert eine Session an -> Namen merken
                    for pid, d in params:
                        if pid == 0x0000 and d: link["ea02_names"].append(d)
                if mid in (0xAE00, 0xAE02):
                    with _dump_lock:
                        _dump["f"].write(b"".join(d for _, d in params)); _dump["n"] += 1

threading.Thread(target=reader, daemon=True).start()
tw = time.monotonic()
while not link["up"] and time.monotonic() - tw < 15 and not link["gone"]: time.sleep(0.05)
if not link["up"]: log("kein Link-Up - ENDE"); raise SystemExit

def send_ctrl(mid, params=b"", tag=None):
    link["my_seq"] = (link["my_seq"] + 1) & 0xFF
    wr(iap2_packet(0x40, link["my_seq"], link["their_seq"], CTRL_SESS, ctrl_msg(mid, params)), tag or MSG.get(mid, hex(mid)))
def wait_for(mid, timeout):
    tw = time.monotonic()
    while time.monotonic() - tw < timeout:
        if mid in link["msgs"]: return True
        if link["gone"]: return False
        time.sleep(0.05)
    return False

# ---- Handshake MIT echter Challenge
send_ctrl(0xAA00, tag="RequestAuthenticationCertificate"); wait_for(0xAA01, 6)
challenge = os.urandom(20)  # Nonce; die Auth-IC signiert beliebige Daten
send_ctrl(0xAA02, param(0, challenge), tag="RequestAuthenticationChallengeResponse")
if wait_for(0xAA03, 6): log("Challenge-Response (0xAA03) erhalten ✅ — echte Auth")
else: log("kein 0xAA03 — fahre trotzdem fort")
send_ctrl(0xAA05, tag="AuthenticationSucceeded"); time.sleep(0.8)
send_ctrl(0x1D00, tag="StartIdentification")
if wait_for(0x1D01, 8):
    send_ctrl(0x1D02, tag="IdentificationAccepted")
else:
    log("keine IdentInfo")
# dem Gerät Zeit für sein spontanes 0xEA02
tw = time.monotonic()
while time.monotonic() - tw < 3 and 0xEA02 not in link["msgs"] and not link["gone"]: time.sleep(0.1)
log(f"Handshake fertig, msgs={[hex(m) for m in sorted(link['msgs'])]}, "
    f"EA02-Namen={[n.rstrip(chr(0).encode()).decode(errors='replace') for n in link['ea02_names']]}")

# ---- 0xAE01-GRANTS: zwei Parameter (Selector + 2-Byte Session-ID)
def grant(selector, sid): return param(0x0000, selector) + param(0x0001, sid.to_bytes(2, "big"))

ISTORAGE = b"com.useeplus.istorage\x00"
PROTOCOL = b"com.useeplus.protocol\x00"
# exakt den vom Gerät angefragten Namen zuerst spiegeln (falls empfangen)
requested = link["ea02_names"][0] if link["ea02_names"] else ISTORAGE

GRANTS = [
    (grant(requested, 0x0001),  f"GRANT name={requested.rstrip(bytes([0])).decode(errors='replace')} sid=0x0001"),
    (grant(PROTOCOL, 0x0002),   "GRANT name=com.useeplus.protocol sid=0x0002 (video)"),
    (grant(b"\x01", 0x0003),    "GRANT protoid=01 sid=0x0003 (video, id-keyed)"),
    (grant(PROTOCOL, 0x0000),   "GRANT name=com.useeplus.protocol sid=0x0000"),
    (grant(b"\x01", 0x000A),    "GRANT protoid=01 sid=0x000A"),
]

def has_video(): return frames["n"] > 0 or _dump["n"] > 0 or 0xAE00 in link["msgs"]

for params, tag in GRANTS:
    if has_video() or link["gone"]: break
    log(f"--- {tag} ---")
    send_ctrl(0xAE01, params, tag="0xAE01 " + tag)
    tw = time.monotonic()
    while time.monotonic() - tw < 6 and not has_video() and not link["gone"]:
        # falls das Gerät auf den Grant mit einem NEUEN 0xEA02 (Video-Protokoll)
        # antwortet, dieses gleich beim nächsten Schleifendurchlauf granten
        time.sleep(0.1)

# nachlauschen
tw = time.monotonic()
while time.monotonic() - tw < 10 and not link["gone"]: time.sleep(0.2)

link["stop"] = True
time.sleep(0.5)
_dump["f"].close()
log(f"ENDE: {frames['n']} Frames; AE00/AE02 gedumpt: {_dump['n']} (-> tools/replug13_ae_dump.bin); "
    f"Geräte-ACKs: {link['acks']}; link msgs={[hex(m) for m in sorted(link['msgs'])]}; gone={link['gone']}")
