#!/usr/bin/env python3
"""Replug capture #15: grant EA session, THEN watch BOTH iAP-in and useeplus bulk.

State after #14: two-param 0xAE01 grants are link-ACKed but no 0xAE00 comes on
EP 0x81, and the link stays healthy. Untested combinations that remain:
  A) After granting the session, does the video appear on the useeplus BULK
     interface (EP 0x82) instead of as 0xAE00 control messages? (#11 read EP0x82
     WITHOUT a grant and saw nothing; we never tried grant-then-bulk.)
  B) Does 0xAE01 need a third "start/command" param beyond selector+session id?

Self-reboot: if no detect beats are flowing (device idle after a prior link),
send 0xAA02 to crash-reboot this clone (Capture #13 showed 0xAA02 reliably
re-enumerates it), then use the fresh detect window. No physical replug needed.
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

_dump = {"f": open("tools/replug15_ae_dump.bin", "wb"), "n": 0}
_dump_lock = threading.Lock()
frames = {"n": 0}
_fr = {"buf": bytearray(), "in": False}; _fr_lock = threading.Lock()
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
                fn = f"tools/replug15_frame_{frames['n']}.jpg"; open(fn, "wb").write(bytes(_fr["buf"]))
                log(f"** FRAME {frames['n']} ({src}): {len(_fr['buf'])}B -> {fn}")
                _fr["in"] = False; _fr["buf"] = bytearray()

def beats_now(d):
    try:
        d.set_configuration(); usb.util.claim_interface(d, 0)
    except usb.core.USBError:
        return False
    got = False
    t = time.monotonic()
    while time.monotonic() - t < 3:
        try:
            if bytes(d.read(0x81, 512, timeout=400)) == DETECT: got = True; break
        except usb.core.USBError: pass
    return got

# --- fresh window sichern (self-reboot via 0xAA02 falls idle) ---
dev = find_dev()
if dev is None:
    log("kein Gerät — warte auf Anstecken ...");
    while dev is None: dev = find_dev(); time.sleep(0.15)
if not beats_now(dev):
    log("keine Beats -> Self-Reboot via 0xAA02 (Link kurz aufbauen, dann 0xAA02)")
    # Link aufbauen und 0xAA02 senden, um den Klon neu zu enumerieren
    try:
        seq = 0x0B
        # ein Detect-Echo, dann auf SYN warten
        try: dev.write(0x01, DETECT, timeout=500)
        except usb.core.USBError: pass
        their = 0x00; up = False; t = time.monotonic()
        while time.monotonic() - t < 6 and not up:
            try: raw = bytes(dev.read(0x81, 4096, timeout=400))
            except usb.core.USBError: continue
            p = parse_iap2(raw)
            if p and p["ctrl"] & 0x80:
                their = p["seq"]; dev.write(0x01, iap2_packet(0xC0, seq, their, 0x00, p["payload"]), timeout=500)
            elif p and p["ctrl"] == 0x40 and not p["payload"]: up = True
        # 0xAA00 dann 0xAA02 -> Reboot
        seq = (seq + 1) & 0xFF; dev.write(0x01, iap2_packet(0x40, seq, their, CTRL_SESS, ctrl_msg(0xAA00)), timeout=500)
        time.sleep(0.4)
        seq = (seq + 1) & 0xFF; dev.write(0x01, iap2_packet(0x40, seq, their, CTRL_SESS, ctrl_msg(0xAA02, param(0, b"\x00" * 20))), timeout=500)
        log("0xAA02 gesendet — warte auf Re-Enumeration")
    except usb.core.USBError as e:
        log(f"Reboot-Trigger: {e}")
    usb.util.dispose_resources(dev)
    t = time.monotonic()
    while find_dev() is not None and time.monotonic() - t < 8: time.sleep(0.2)
    while find_dev() is None and time.monotonic() - t < 15: time.sleep(0.2)
    dev = find_dev()
    if dev is None: log("Gerät nach Reboot nicht zurück — ENDE"); raise SystemExit
    log("Gerät nach Reboot zurück")
    time.sleep(1.0)
else:
    log("Beats vorhanden — Fenster offen")
    usb.util.dispose_resources(dev); dev = find_dev()

dev.set_configuration()
try: usb.util.claim_interface(dev, 0)
except usb.core.USBError as e: log(f"claim If0: {e}")

wlock = threading.Lock()
def wr(data, tag, ep=0x01):
    try:
        with wlock: dev.write(ep, data, timeout=800)
        if tag: log(f">> {tag}: {data[:36].hex(' ')}{' ...' if len(data) > 36 else ''}")
        return True
    except usb.core.USBError as e:
        if tag: log(f">> {tag}: FEHLER {e}");
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
                    with _dump_lock: _dump["f"].write(b"".join(d for _, d in params)); _dump["n"] += 1
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
name = link["ea02_names"][0] if link["ea02_names"] else b"com.useeplus.istorage\x00"
log(f"Handshake fertig; angefragt: {name.rstrip(bytes([0])).decode(errors='replace')}")

# ---- Bulk-Sniffer AKTIVIEREN (Hypothese A: Video kommt nach Grant über EP0x82)
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
    log("If1->Alt1, EP0x82-Sniffer aktiv")
except usb.core.USBError as e:
    log(f"Bulk-Aktivierung: {e}")

def has_video(): return frames["n"] > 0 or _dump["n"] > 0 or bulk["rx"] > 0 or 0xAE00 in link["msgs"]
def grant(sel, sid, extra=b""): return param(0, sel) + param(1, sid.to_bytes(2, "big")) + extra

# ---- Grants inkl. Hypothese B (3. "Start/Command"-Param 0x0002)
PROTO = b"com.useeplus.protocol\x00"
GRANTS = [
    (grant(name, 0x0001),                          f"grant istorage sid1"),
    (grant(name, 0x0001, param(2, b"\x01")),        f"grant istorage sid1 +cmd01"),
    (grant(PROTO, 0x0002),                          "grant protocol sid2"),
    (grant(PROTO, 0x0002, param(2, b"\x01")),       "grant protocol sid2 +cmd01"),
    (grant(b"\x01", 0x0002, param(2, b"\x01")),     "grant protoid1 sid2 +cmd01"),
]
for params, tag in GRANTS:
    if has_video() or link["gone"]: break
    log(f"--- {tag} ---"); send_ctrl(0xAE01, params, tag="0xAE01 " + tag)
    tw = time.monotonic()
    while time.monotonic() - tw < 6 and not has_video() and not link["gone"]: time.sleep(0.1)

tw = time.monotonic()
while time.monotonic() - tw < 12 and not link["gone"]: time.sleep(0.2)
bulk["stop"] = True; link["stop"] = True; time.sleep(0.5); _dump["f"].close()
log(f"ENDE: {frames['n']} Frames; AE-dump {_dump['n']}; Bulk-RX {bulk['rx']} ({bulk['bytes']}B); "
    f"msgs={[hex(m) for m in sorted(link['msgs'])]}; gone={link['gone']}")
