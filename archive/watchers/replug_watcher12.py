#!/usr/bin/env python3
"""Replug capture #12: send the one accepted host->accessory message 0xAE01
and listen for the stream on BOTH paths.

Capture #11 proved the device only accepts message 0xAE01 from the host
(IdentificationInformation p7). This run does the working handshake, keeps the
link healthy, sends 0xAE01 (payload candidates below), and reassembles MJPEG
from whichever path carries it:
  - iAP2 control messages 0xAE00/0xAE02 arriving on EP 0x81, and/or
  - raw bulk on EP 0x82 (12-byte AA BB header, then MJPEG).

The exact 0xAE01 payload + fallback order come from the research workflow;
AE01_CANDIDATES is filled in before the run.
"""
import time
import threading
import usb.core
import usb.util

DETECT = bytes([0xFF, 0x55, 0x02, 0x00, 0xEE, 0x10])
CTRL_SESS = 0x0A

# --- 0xAE01 payload candidates, ranked by the research synthesis (wf_6051de87).
# The device declared 0xAE01 is the ONLY host->accessory message it accepts, so
# every candidate reuses that msgid; a wrong payload costs a probe, not the link.
# Each entry: (params_bytes, tag). params_bytes is the raw param block that goes
# after "40 40 <len> AE 01"; b"" = no params.
def _p0(data):  # single param id 0x0000 with given data
    return (len(data) + 4).to_bytes(2, "big") + b"\x00\x00" + data
AE01_CANDIDATES = [
    (_p0(b"\x01"),                       "0xAE01 p0=01 (protocol id, PRIMARY)"),
    (b"",                                "0xAE01 (no params)"),
    (_p0(b"\x05\x00\x00"),               "0xAE01 p0=05 00 00 (legacy start body)"),
    (_p0((0x1000).to_bytes(2, "big")),   "0xAE01 p0=1000 (session handle)"),
    (_p0(b"\x07"),                       "0xAE01 p0=07 (camera id 7)"),
    (_p0(b"\x0b"),                       "0xAE01 p0=0B (camera id 11)"),
    (_p0(b"com.useeplus.istorage\x00"),  "0xAE01 p0=istorage (echo device 0xEA02)"),
]

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

MSG = {0xAA01: "AuthCert", 0x1D01: "IdentInfo", 0xEA02: "EA02", 0xAE00: "AE00", 0xAE02: "AE02"}

def find_dev(): return usb.core.find(idVendor=0x2CE3, idProduct=0x3828)

# --- Rohdump aller 0xAE00/0xAE02-Payloads (Offline-Analyse) ---
_dump = {"f": open("tools/replug12_ae_dump.bin", "wb"), "n": 0}
_dump_lock = threading.Lock()

# --- MJPEG reassembler shared by both paths ---
frames = {"n": 0}
_fr = {"buf": bytearray(), "in": False}
_fr_lock = threading.Lock()
def feed_jpeg(chunk, src):
    with _fr_lock:
        # strip a 12-byte AA BB ... header if present
        payload = chunk[12:] if len(chunk) >= 12 and chunk[0] == 0xAA and chunk[1] == 0xBB else chunk
        i = 0
        while i < len(payload):
            if not _fr["in"]:
                q = payload.find(b"\xff\xd8", i)
                if q < 0: break
                _fr["in"] = True; _fr["buf"] = bytearray(b"\xff\xd8"); i = q + 2
            else:
                q = payload.find(b"\xff\xd9", i)
                if q < 0:
                    _fr["buf"].extend(payload[i:]); break
                _fr["buf"].extend(payload[i:q+2]); i = q + 2
                frames["n"] += 1
                if frames["n"] <= 6:
                    fn = f"tools/replug12_frame_{frames['n']}.jpg"
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
            log(f"<< non-iAP2 ({len(data)}B): {data[:32].hex(' ')}")
            feed_jpeg(data, "EP81-raw"); continue
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
                total = sum(len(d) for _, d in params)
                log(f"<< CTRL {MSG.get(mid, hex(mid))} (sess {p['sess']:#04x}, {len(p['payload'])}B, {total}B params)")
                for pid, d in params:
                    if len(d) <= 24:
                        txt = d.rstrip(b'\x00')
                        pr = len(txt) > 0 and all(32 <= c < 127 for c in txt)
                        log(f"     p{pid}: {d.hex(' ')}" + (f'  = \"{txt.decode()}\"' if pr else ''))
                    else:
                        log(f"     p{pid}: {len(d)}B {d[:24].hex(' ')} ...")
                    feed_jpeg(d, f"{MSG.get(mid, hex(mid))}/p{pid}")
                # Rohdump der Video-Kandidaten (0xAE00/0xAE02): auch bei
                # unvollständiger Live-Reassemblierung offline auswertbar.
                if mid in (0xAE00, 0xAE02):
                    with _dump_lock:
                        _dump["f"].write(b"".join(d for _, d in params))
                        _dump["n"] += 1
            else:
                log(f"<< EA/DATEN sess {p['sess']:#04x} ({len(p['payload'])}B): {p['payload'][:32].hex(' ')}")
                feed_jpeg(p["payload"], "EP81-data")

threading.Thread(target=reader, daemon=True).start()

tw = time.monotonic()
while not link["up"] and time.monotonic() - tw < 15 and not link["gone"]: time.sleep(0.05)
if not link["up"]: log("kein Link-Up - ENDE"); raise SystemExit

def send_ctrl(mid, params=b"", tag=None):
    link["my_seq"] = (link["my_seq"] + 1) & 0xFF
    wr(iap2_packet(0x40, link["my_seq"], link["their_seq"], CTRL_SESS, ctrl_msg(mid, params)),
       tag or MSG.get(mid, hex(mid)))
def wait_for(mid, timeout):
    tw = time.monotonic()
    while time.monotonic() - tw < timeout:
        if mid in link["msgs"]: return True
        if link["gone"]: return False
        time.sleep(0.05)
    return False

# ---- working handshake (identical to #11)
send_ctrl(0xAA00, tag="RequestAuthenticationCertificate"); wait_for(0xAA01, 6)
send_ctrl(0xAA05, tag="AuthenticationSucceeded"); time.sleep(1.0)
send_ctrl(0x1D00, tag="StartIdentification")
if wait_for(0x1D01, 8):
    send_ctrl(0x1D02, tag="IdentificationAccepted")
    time.sleep(0.6)  # dem Gerät Zeit für sein spontanes 0xEA02
else:
    log("keine IdentInfo - trotzdem weiter")
log(f"Handshake fertig, msgs={[hex(m) for m in sorted(link['msgs'])]}")

# ---- Primär: 0xAE01-Kandidaten der Reihe nach auf EP 0x81 senden.
# Video wird laut Analyse als 0xAE00/0xAE02 auf iAP-in (EP 0x81) erwartet;
# das Bulk-Interface wird bewusst NICHT angefasst (Risiko-Hinweis der Analyse).
def had_ae():  # hat das Gerät begonnen, Video-Nachrichten zu senden?
    return frames["n"] > 0 or _dump["n"] > 0 or 0xAE00 in link["msgs"] or 0xAE02 in link["msgs"]

for params, tag in AE01_CANDIDATES:
    if had_ae() or link["gone"]: break
    log(f"--- Kandidat: {tag} ---")
    send_ctrl(0xAE01, params, tag=tag)
    t_w = time.monotonic()
    while time.monotonic() - t_w < 6 and not had_ae() and not link["gone"]:
        time.sleep(0.1)

# noch etwas nachlauschen (Frames können fragmentiert eintrudeln)
t_w = time.monotonic()
while time.monotonic() - t_w < 8 and not link["gone"]: time.sleep(0.2)

# ---- Last Resort: falls über EP 0x81 nichts kam UND der Link gesund ist,
# das useeplus-Bulk-Interface prüfen (Negativ-Kontrolle).
bulk = {"rx": 0, "bytes": 0, "stop": False}
if not had_ae() and not link["gone"]:
    log("=== Last Resort: If1->Alt1, EP 0x82 8 s prüfen ===")
    try:
        usb.util.claim_interface(dev, 1)
        dev.set_interface_altsetting(interface=1, alternate_setting=1)
        def bulk_sniffer():
            while not bulk["stop"]:
                try: data = bytes(dev.read(0x82, 65536, timeout=300))
                except usb.core.USBError: continue
                bulk["rx"] += 1; bulk["bytes"] += len(data)
                if bulk["rx"] <= 20: log(f"<< EP0x82: {len(data)}B: {data[:32].hex(' ')}")
                feed_jpeg(data, "EP82")
        threading.Thread(target=bulk_sniffer, daemon=True).start()
        time.sleep(8)
    except usb.core.USBError as e:
        log(f"Bulk-Prüfung fehlgeschlagen: {e}")

bulk["stop"] = True; link["stop"] = True
time.sleep(0.5)
_dump["f"].close()
log(f"ENDE: {frames['n']} Frames; AE00/AE02-Msgs gedumpt: {_dump['n']} "
    f"(-> tools/replug12_ae_dump.bin); Bulk-RX {bulk['rx']} ({bulk['bytes']}B); "
    f"link msgs={[hex(m) for m in sorted(link['msgs'])]}; gone={link['gone']}")
