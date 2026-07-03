#!/usr/bin/env python3
"""Replug capture #11: DIAGNOSE nach der Identifizierung.

Capture #10: Auth + Identification laufen, aber Bulk-Aktivität (Alt1 + BB-AA)
killt das iAP-out-Draining. Das Gerät schickt nach IdentificationAccepted
UNAUFGEFORDERT 0xEA02(com.useeplus.istorage). Bevor wieder blind BB-AA
geschickt wird, drei Hypothesen in EINEM Anstecken testen:

  Phase 1: Handshake bis IdentificationAccepted, dann 20 s NUR ZUHÖREN
           (Link am Leben halten, alles auf EP0x81 mit vollem Payload
           dumpen). Treibt das Gerät den Stream selbst an?
  Phase 2: If1/Alt1 aktivieren, EP0x82 10 s lesen OHNE BB-AA
           (schaltet die Auth allein den Bulk-Stream frei?).
  Phase 3: BB-AA auf EP0x02, 10 s beobachten.

Dumps: volle IdentificationInformation-Parameter und die 0xEA02-Payload.
"""
import time
import threading
import usb.core
import usb.util

DETECT = bytes([0xFF, 0x55, 0x02, 0x00, 0xEE, 0x10])
CONNECT = bytes([0xBB, 0xAA, 0x05, 0x00, 0x00])
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

MSG = {0xAA01: "AuthCertificate", 0x1D01: "IdentInfo", 0xEA00: "StartEA", 0xEA01: "StopEA", 0xEA02: "EA02"}

def find_dev(): return usb.core.find(idVendor=0x2CE3, idProduct=0x3828)

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
        if tag: log(f">> {tag}: {data[:32].hex(' ')}{' ...' if len(data) > 32 else ''}")
        return True
    except usb.core.USBError as e:
        if tag: log(f">> {tag}: FEHLER {e}")
        return False

link = {"my_seq": 0x0B, "their_seq": 0x00, "up": False, "gone": False, "stop": False, "msgs": set()}

def reader():
    last_ka = time.monotonic()
    while not link["stop"]:
        try:
            data = bytes(dev.read(0x81, 8192, timeout=300))
        except usb.core.USBError as e:
            if "No such device" in str(e): link["gone"] = True; log("!! iAP-in weg"); return
            if link["up"] and time.monotonic() - last_ka > 1.0:
                wr(iap2_packet(0x40, link["my_seq"], link["their_seq"], 0x00), None); last_ka = time.monotonic()
            continue
        last_ka = time.monotonic()
        if data == DETECT: wr(DETECT, "DETECT-ECHO"); continue
        p = parse_iap2(data)
        if p is None: log(f"<< non-iAP2 ({len(data)}B): {data[:32].hex(' ')}"); continue
        if p["ctrl"] & 0x80 and not link["up"]:
            link["their_seq"] = p["seq"]; wr(iap2_packet(0xC0, link["my_seq"], p["seq"], 0x00, p["payload"]), "SYN/ACK")
        elif p["ctrl"] == 0x40 and not p["payload"] and not link["up"] and p["ack"] == link["my_seq"]:
            link["up"] = True; log("*** LINK UP ***")
        elif p["payload"]:
            link["their_seq"] = p["seq"]
            wr(iap2_packet(0x40, link["my_seq"], p["seq"], 0x00), None)  # ACK
            mid, params = parse_ctrl(p["payload"])
            if mid is not None:
                link["msgs"].add(mid)
                log(f"<< CTRL {MSG.get(mid, hex(mid))} (sess {p['sess']:#04x}, {len(p['payload'])}B)")
                for pid, d in params:
                    txt = d.rstrip(b'\x00')
                    printable = all(32 <= c < 127 for c in txt) and len(txt) > 0
                    log(f"     p{pid}: {d.hex(' ')}" + (f'  = \"{txt.decode()}\"' if printable else ''))
            else:
                log(f"<< EA/DATEN sess {p['sess']:#04x} ({len(p['payload'])}B): {p['payload'][:48].hex(' ')}")

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

# ---- Phase 1: Handshake, dann NUR zuhören
send_ctrl(0xAA00); wait_for(0xAA01, 6)
send_ctrl(0xAA05); time.sleep(1.0)
send_ctrl(0x1D00)
if wait_for(0x1D01, 8):
    send_ctrl(0x1D02, tag="IdentificationAccepted")
else:
    log("keine IdentInfo")
log("=== Phase 1: 20 s NUR ZUHÖREN (kein StartEA, kein Bulk) ===")
time.sleep(20)
log(f"Phase-1-Ende. Gesehene msgs: {[hex(m) for m in sorted(link['msgs'])]}")

# ---- Phase 2: Bulk lesen OHNE BB-AA
if link["gone"]: log("Link weg - Abbruch"); raise SystemExit
usb.util.claim_interface(dev, 1)
dev.set_interface_altsetting(interface=1, alternate_setting=1)
log("=== Phase 2: If1->Alt1, EP0x82 10 s lesen OHNE BB-AA ===")

st = {"stop": False, "rx": 0, "frames": 0, "bytes": 0}
def sniffer():
    buf, in_frame = bytearray(), False
    while not st["stop"]:
        try: data = bytes(dev.read(0x82, 65536, timeout=300))
        except usb.core.USBError: continue
        st["rx"] += 1; st["bytes"] += len(data)
        if st["rx"] <= 20: log(f"<< EP0x82: {len(data)}B: {data[:32].hex(' ')}")
        payload = data[12:] if len(data) >= 12 and data[0] == 0xAA and data[1] == 0xBB else data
        if not in_frame:
            q = payload.find(b"\xff\xd8")
            if q >= 0: in_frame, buf = True, bytearray(payload[q:])
        else: buf.extend(payload)
        if in_frame:
            q = buf.find(b"\xff\xd9")
            if q >= 0:
                st["frames"] += 1
                if st["frames"] <= 5:
                    fn = f"tools/replug11_frame_{st['frames']}.jpg"; open(fn, "wb").write(bytes(buf[:q+2]))
                    log(f"** FRAME {st['frames']}: {q+2}B -> {fn}")
                buf, in_frame = bytearray(), False
threading.Thread(target=sniffer, daemon=True).start()
time.sleep(10)
log(f"Phase-2-Ende: {st['rx']} Bulk-RX, {st['frames']} Frames (ohne BB-AA)")

# ---- Phase 3: BB-AA
log("=== Phase 3: BB-AA auf EP0x02, 10 s ===")
for i in range(3):
    if st["frames"] or st["rx"]: break
    wr(CONNECT, f"CONNECT #{i+1}", ep=0x02); time.sleep(3.3)
time.sleep(3)
st["stop"] = True; link["stop"] = True
time.sleep(0.5)
log(f"ENDE: {st['frames']} Frames, {st['rx']} Bulk-RX, {st['bytes']} B; msgs={[hex(m) for m in sorted(link['msgs'])]}")
