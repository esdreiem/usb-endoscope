#!/usr/bin/env python3
"""Replug capture #16: grant + bulk (EP0x82) + broad 0xAE01 brute-force, one window.

Per user steer ("1 then 4"): first test whether video appears on the useeplus
BULK interface (EP 0x82) after an EA-session grant, and in the SAME live window
cycle a broad ranked set of 0xAE01 payloads while watching BOTH paths
(EP 0x81 for 0xAE00 control data, EP 0x82 for bulk). Needs a REAL replug for a
clean detect window (the self-reboot trick in #15 was too fragile).

Every 0xAE01 is a declared/accepted message that the device link-ACKs without
harming the link, so many payloads can be tried in one window. The bulk sniffer
runs the whole time so ANY grant that unlocks bulk is caught immediately.
"""
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
    hdr = bytes([0xFF, 0x5A]) + (9 + len(payload) + (1 if payload else 0)).to_bytes(2, "big") + bytes([ctrl, seq, ack, session])
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
    mid = int.from_bytes(pl[4:6], "big"); params, i = [], 6
    while i + 4 <= len(pl):
        plen = int.from_bytes(pl[i:i+2], "big"); pid = int.from_bytes(pl[i+2:i+4], "big")
        if plen < 4: break
        params.append((pid, bytes(pl[i+4:i+plen]))); i += plen
    return mid, params
MSG = {0xAA01: "AuthCert", 0x1D01: "IdentInfo", 0xEA02: "EA02(req)", 0xAE00: "AE00(data)", 0xAE02: "AE02(status)"}
def find_dev(): return usb.core.find(idVendor=0x2CE3, idProduct=0x3828)

_dump = {"f": open("tools/replug16_ae_dump.bin", "wb"), "n": 0}
_dl = threading.Lock()
frames = {"n": 0}
_fr = {"buf": bytearray(), "in": False}; _frl = threading.Lock()
def feed_jpeg(chunk, src):
    with _frl:
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
                fn = f"tools/replug16_frame_{frames['n']}.jpg"; open(fn, "wb").write(bytes(_fr["buf"]))
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
        if tag: log(f">> {tag}: {data[:36].hex(' ')}{' ...' if len(data) > 36 else ''}")
        return True
    except usb.core.USBError as e:
        if tag: log(f">> {tag}: FEHLER {e}")
        return False

link = {"my_seq": 0x0B, "their_seq": 0x00, "up": False, "gone": False, "stop": False, "msgs": set(), "ea02_names": []}
def reader():
    last_ka = time.monotonic()
    while not link["stop"]:
        try: data = bytes(dev.read(0x81, 8192, timeout=250))
        except usb.core.USBError as e:
            if "No such device" in str(e): link["gone"] = True; log("!! iAP-in weg"); return
            if link["up"] and time.monotonic() - last_ka > 1.0:
                wr(iap2_packet(0x40, link["my_seq"], link["their_seq"], 0x00), None); last_ka = time.monotonic()
            continue
        last_ka = time.monotonic()
        if data == DETECT: wr(DETECT, "DETECT-ECHO"); continue
        p = parse_iap2(data)
        if p is None: feed_jpeg(data, "EP81-raw"); continue
        if p["ctrl"] & 0x80 and not link["up"]:
            link["their_seq"] = p["seq"]; wr(iap2_packet(0xC0, link["my_seq"], p["seq"], 0x00, p["payload"]), "SYN/ACK")
        elif p["ctrl"] == 0x40 and not p["payload"]:
            if not link["up"] and p["ack"] == link["my_seq"]: link["up"] = True; log("*** LINK UP ***")
        elif p["payload"]:
            link["their_seq"] = p["seq"]; wr(iap2_packet(0x40, link["my_seq"], p["seq"], 0x00), None)
            mid, params = parse_ctrl(p["payload"])
            if mid is not None:
                link["msgs"].add(mid)
                log(f"<< CTRL {MSG.get(mid, hex(mid))} ({len(p['payload'])}B, {len(params)}p)")
                for pid, d in params:
                    if len(d) <= 28:
                        txt = d.rstrip(b'\x00'); pr = len(txt) and all(32 <= c < 127 for c in txt)
                        log(f"     p{pid}: {d.hex(' ')}" + (f'  = \"{txt.decode()}\"' if pr else ''))
                    else: log(f"     p{pid}: {len(d)}B {d[:28].hex(' ')} ...")
                    feed_jpeg(d, f"{MSG.get(mid, hex(mid))}/p{pid}")
                if mid == 0xEA02:
                    for pid, d in params:
                        if pid == 0 and d: link["ea02_names"].append(d)
                if mid in (0xAE00, 0xAE02):
                    with _dl: _dump["f"].write(b"".join(d for _, d in params)); _dump["n"] += 1
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

# ---- Handshake (Challenge übersprungen)
send_ctrl(0xAA00, tag="RequestAuthenticationCertificate"); wait_for(0xAA01, 6)
send_ctrl(0xAA05, tag="AuthenticationSucceeded"); time.sleep(0.8)
send_ctrl(0x1D00, tag="StartIdentification")
if wait_for(0x1D01, 8): send_ctrl(0x1D02, tag="IdentificationAccepted")
tw = time.monotonic()
while time.monotonic() - tw < 3 and 0xEA02 not in link["msgs"] and not link["gone"]: time.sleep(0.1)
IST = link["ea02_names"][0] if link["ea02_names"] else b"com.useeplus.istorage\x00"
PRO = b"com.useeplus.protocol\x00"
log(f"Handshake fertig; angefragt: {IST.rstrip(bytes([0])).decode(errors='replace')}")

# ---- Hypothese 1: Bulk EP0x82 nach Grant. Sniffer JETZT aktivieren.
bulk = {"rx": 0, "bytes": 0, "stop": False}
try:
    usb.util.claim_interface(dev, 1); dev.set_interface_altsetting(interface=1, alternate_setting=1)
    def bulk_sniffer():
        while not bulk["stop"]:
            try: data = bytes(dev.read(0x82, 65536, timeout=300))
            except usb.core.USBError: continue
            bulk["rx"] += 1; bulk["bytes"] += len(data)
            if bulk["rx"] <= 20: log(f"<< EP0x82: {len(data)}B: {data[:32].hex(' ')}")
            feed_jpeg(data, "EP82")
    threading.Thread(target=bulk_sniffer, daemon=True).start()
    log("If1->Alt1, EP0x82-Sniffer aktiv (Hypothese: Video über Bulk nach Grant)")
except usb.core.USBError as e:
    log(f"Bulk-Aktivierung: {e}")

def has_video(): return frames["n"] > 0 or _dump["n"] > 0 or bulk["rx"] > 0 or 0xAE00 in link["msgs"]
def g(sel, sid, extra=b""): return param(0, sel) + param(1, sid.to_bytes(2, "big")) + extra

# ---- Broad ranked 0xAE01 payload set (#4 brute-force). Each is link-safe.
CANDS = [
    # A) Session-Grants (Selector + 2-Byte SID), Antwort auf 0xEA02
    (g(IST, 0x0001),                         "grant istorage sid1"),
    (g(IST, 0x0001, param(2, b"\x01")),      "grant istorage sid1 +cmd01"),
    (g(PRO, 0x0002),                         "grant protocol sid2"),
    (g(PRO, 0x0002, param(2, b"\x01")),      "grant protocol sid2 +cmd01"),
    (g(b"\x01", 0x0002),                     "grant protoid1 sid2"),
    (g(b"\x01", 0x0002, param(2, b"\x01")),  "grant protoid1 sid2 +cmd01"),
    # B) Legacy-Kommando re-enkodiert (0xAE01 als Träger des alten BB-AA-Start)
    (param(0, b"\x05\x00\x00"),              "p0=05 00 00 (legacy start)"),
    (param(0, b"\x05\x00\x00\x07"),          "p0=05 00 00 07 (legacy+cam7)"),
    (param(0, b"\xbb\xaa\x05\x00\x00"),      "p0=BB AA 05 00 00 (legacy verbatim)"),
    (param(0, b"\xbb\xaa\x07\x00\x00"),      "p0=BB AA 07 00 00 (legacy cid07)"),
    # C) Einzel-Opcodes
    (param(0, b"\x01"),                      "p0=01"),
    (param(0, b"\x07"),                      "p0=07 (cam7)"),
    (param(0, b"\x0b"),                      "p0=0B (cam11)"),
    (param(0, b"\xff"),                      "p0=FF"),
    # D) Name-only (unmittelbares 0xEA02-Echo)
    (param(0, IST),                          "p0=name(istorage)"),
    (param(0, PRO),                          "p0=name(protocol)"),
    # E) Session-ID nur (0xEA00-artig, id-los)
    (param(1, (0x0001).to_bytes(2, "big")),  "p1=sid1 only"),
    (b"",                                    "no params"),
]
for params, tag in CANDS:
    if has_video() or link["gone"]: break
    log(f"--- {tag} ---")
    send_ctrl(0xAE01, params, tag="0xAE01 " + tag)
    tw = time.monotonic()
    while time.monotonic() - tw < 4 and not has_video() and not link["gone"]: time.sleep(0.1)

tw = time.monotonic()
while time.monotonic() - tw < 12 and not link["gone"] and not has_video(): time.sleep(0.2)
bulk["stop"] = True; link["stop"] = True; time.sleep(0.5); _dump["f"].close()
log(f"ENDE: {frames['n']} Frames; AE-dump {_dump['n']}; Bulk-RX {bulk['rx']} ({bulk['bytes']}B); "
    f"msgs={[hex(m) for m in sorted(link['msgs'])]}; gone={link['gone']}")
