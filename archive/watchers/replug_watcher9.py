#!/usr/bin/env python3
"""Replug capture #9: iAP2 Control-Session (Auth + Identification).

Capture #8: Link-Up klappt (Echo -> SYN -> SYN/ACK -> ACK), danach wartet das
Geraet - als Accessory erwartet es, dass das "Apple-Geraet" (wir) beginnt:
  1. RequestAuthenticationCertificate (0xAA00) -> AuthenticationCertificate
  2. (Challenge ueberspringen) AuthenticationSucceeded (0xAA05)
  3. StartIdentification (0x1D00) -> IdentificationInformation (0x1D01)
     -> enthaelt die ExternalAccessory-Protokolle (com.useeplus.protocol?)
  4. IdentificationAccepted (0x1D02)
  5. StartExternalAccessoryProtocolSession (0xEA00) fuer das erste Protokoll
Danach: lauschen (EA-Daten? neues SYN mit EA-Session? Re-Enumeration?) und
zum Schluss wieder BB-AA-Connect auf useeplus.

Wir verifizieren nichts kryptographisch - wir sind der Pruefer und sagen
einfach "bestanden".
"""
import time
import threading
import usb.core
import usb.util

DETECT = bytes([0xFF, 0x55, 0x02, 0x00, 0xEE, 0x10])
CONNECT = bytes([0xBB, 0xAA, 0x05, 0x00, 0x00])
CTRL_SESS = 0x0A

t0 = time.monotonic()
def log(m):
    print(f"[{time.monotonic()-t0:7.2f}] {m}", flush=True)

def cks(bs):
    return (0x100 - (sum(bs) & 0xFF)) & 0xFF

def iap2_packet(ctrl, seq, ack, session, payload=b""):
    hdr = bytes([0xFF, 0x5A]) + (9 + len(payload) + (1 if payload else 0)).to_bytes(2, "big") \
        + bytes([ctrl, seq, ack, session])
    hdr += bytes([cks(hdr)])
    if payload:
        payload = payload + bytes([cks(payload)])
    return hdr + payload

def parse_iap2(data):
    if len(data) < 9 or data[0] != 0xFF or data[1] != 0x5A:
        return None
    return {"ctrl": data[4], "seq": data[5], "ack": data[6], "sess": data[7],
            "payload": bytes(data[9:-1]) if len(data) > 9 else b""}

def param(pid, data):
    return (len(data) + 4).to_bytes(2, "big") + pid.to_bytes(2, "big") + data

def ctrl_msg(msgid, params=b""):
    return bytes([0x40, 0x40]) + (6 + len(params)).to_bytes(2, "big") + msgid.to_bytes(2, "big") + params

def parse_ctrl_msg(payload):
    if len(payload) < 6 or payload[0] != 0x40 or payload[1] != 0x40:
        return None
    msgid = int.from_bytes(payload[4:6], "big")
    params = []
    i = 6
    while i + 4 <= len(payload):
        plen = int.from_bytes(payload[i:i+2], "big")
        pid = int.from_bytes(payload[i+2:i+4], "big")
        params.append((pid, bytes(payload[i+4:i+plen])))
        i += max(plen, 4)
    return msgid, params

MSG_NAMES = {
    0xAA00: "RequestAuthenticationCertificate", 0xAA01: "AuthenticationCertificate",
    0xAA02: "RequestAuthenticationChallengeResponse", 0xAA03: "AuthenticationResponse",
    0xAA04: "AuthenticationFailed", 0xAA05: "AuthenticationSucceeded",
    0x1D00: "StartIdentification", 0x1D01: "IdentificationInformation",
    0x1D02: "IdentificationAccepted", 0x1D03: "IdentificationRejected",
    0xEA00: "StartExternalAccessoryProtocolSession", 0xEA01: "StopExternalAccessoryProtocolSession",
}

def find_dev():
    return usb.core.find(idVendor=0x2CE3, idProduct=0x3828)

log("warte auf ABSTECKEN ...")
while find_dev() is not None:
    time.sleep(0.3)
log("abgesteckt. warte auf ANSTECKEN ...")
while True:
    dev = find_dev()
    if dev is not None:
        break
    time.sleep(0.15)
log("angesteckt! claim If0 ONLY")
dev.set_configuration()
usb.util.claim_interface(dev, 0)

def wr(data, tag, ep=0x01):
    try:
        dev.write(ep, data, timeout=800)
        log(f">> {tag}: {data[:48].hex(' ')}{' ...' if len(data) > 48 else ''}")
        return True
    except usb.core.USBError as e:
        log(f">> {tag}: FEHLER {e}")
        return False

# ---- Link-Handshake
my_seq = 0x0B
their_seq = 0x00
link_up = False
t_s = time.monotonic()
while time.monotonic() - t_s < 20 and not link_up:
    try:
        data = bytes(dev.read(0x81, 4096, timeout=500))
    except usb.core.USBError:
        continue
    if data == DETECT:
        wr(DETECT, "DETECT-ECHO")
        continue
    p = parse_iap2(data)
    if p is None:
        log(f"<< non-iAP2: {data.hex(' ')}")
        continue
    if p["ctrl"] & 0x80:
        their_seq = p["seq"]
        wr(iap2_packet(0xC0, my_seq, their_seq, 0x00, p["payload"]), "SYN/ACK")
    elif p["ctrl"] == 0x40 and p["ack"] == my_seq:
        link_up = True
        log("*** LINK UP ***")
if not link_up:
    log("kein Link-Up - ENDE")
    raise SystemExit

# ---- Control-Session: Empfangs-Thread mit Reassemblierung + Auto-ACK
rx = {"msgs": [], "raw": [], "stop": False, "gone": False}
acc = bytearray()

def ctrl_reader():
    global their_seq, acc
    while not rx["stop"]:
        try:
            data = bytes(dev.read(0x81, 8192, timeout=400))
        except usb.core.USBError as e:
            if "No such device" in str(e):
                rx["gone"] = True
                log("!! GERAET WEG (Re-Enumeration?)")
                return
            continue
        p = parse_iap2(data)
        if p is None:
            log(f"<< non-iAP2 ({len(data)}B): {data[:32].hex(' ')}")
            continue
        log(f"<< iAP2 ctrl={p['ctrl']:#04x} seq={p['seq']:#04x} ack={p['ack']:#04x} sess={p['sess']:#04x} len(payload)={len(p['payload'])}")
        if p["payload"]:
            their_seq = p["seq"]
            wr(iap2_packet(0x40, my_seq, their_seq, 0x00), f"ACK seq {their_seq:#04x}")
            acc.extend(p["payload"])
            while len(acc) >= 6 and acc[0] == 0x40 and acc[1] == 0x40:
                mlen = int.from_bytes(acc[2:4], "big")
                if len(acc) < mlen:
                    break
                m = parse_ctrl_msg(bytes(acc[:mlen]))
                acc = acc[mlen:]
                if m:
                    msgid, params = m
                    name = MSG_NAMES.get(msgid, hex(msgid))
                    log(f"   MSG {name}: " + "; ".join(
                        f"p{pid}={d[:40].hex(' ')}{'...' if len(d) > 40 else ''}" for pid, d in params))
                    rx["msgs"].append((msgid, params))
            if acc and not (acc[0] == 0x40):
                log(f"   (Rest im Puffer, kein 4040: {bytes(acc[:16]).hex(' ')})")

threading.Thread(target=ctrl_reader, daemon=True).start()

def send_ctrl(msgid, params=b"", tag=None):
    global my_seq
    my_seq = (my_seq + 1) & 0xFF
    pkt = iap2_packet(0x40, my_seq, their_seq, CTRL_SESS, ctrl_msg(msgid, params))
    wr(pkt, tag or MSG_NAMES.get(msgid, hex(msgid)))

def wait_msg(msgid, timeout):
    t_w = time.monotonic()
    seen = len(rx["msgs"])
    while time.monotonic() - t_w < timeout:
        for m in rx["msgs"]:
            if m[0] == msgid:
                return m
        if rx["gone"]:
            return None
        time.sleep(0.1)
    return None

# 1) Zertifikat anfordern (beweist, dass die Control-Session funktioniert)
send_ctrl(0xAA00)
cert = wait_msg(0xAA01, 6)
log(f"Zertifikat: {'JA, ' + str(len(cert[1][0][1])) + ' B' if cert and cert[1] else 'keins'}")

# 2) Auth einfach fuer bestanden erklaeren
if not rx["gone"]:
    send_ctrl(0xAA05)
    time.sleep(1.5)

# 3) Identification
if not rx["gone"]:
    send_ctrl(0x1D00)
    ident = wait_msg(0x1D01, 8)
    proto_id = None
    if ident:
        for pid, d in ident[1]:
            if b"useeplus" in d or b"com." in d:
                log(f"   EA-Protokoll-Kandidat in Param {pid}: {d!r}")
        # ExternalAccessoryProtocol ist eine Parametergruppe; erste Sub-ID raten:
        for pid, d in ident[1]:
            if len(d) >= 5 and (b"com." in d):
                proto_id = d[4] if d[0:2] == b"\x00\x05" else 1
        send_ctrl(0x1D02)
    else:
        log("keine IdentificationInformation")

    # 4) EA-Session starten (Protokoll-ID 1, Session-ID 0x1000 raten)
    if not rx["gone"]:
        send_ctrl(0xEA00, param(0, bytes([proto_id if proto_id else 1]))
                  + param(1, (0x1000).to_bytes(2, "big")))
        time.sleep(4)

# ---- Beobachten, dann BB-AA-Connect
time.sleep(6)
log(f"Control-Phase fertig: {len(rx['msgs'])} Nachrichten, gone={rx['gone']}")

if rx["gone"]:
    t_w = time.monotonic()
    dev2 = None
    while time.monotonic() - t_w < 10:
        dev2 = find_dev()
        if dev2 is not None:
            break
        time.sleep(0.2)
    if dev2 is None:
        log("Geraet kommt nicht wieder - ENDE")
        raise SystemExit
    log(f"wieder da! bcdDevice={dev2.bcdDevice:#06x}")
    dev = dev2
    dev.set_configuration()
    usb.util.claim_interface(dev, 0)
rx["stop"] = True
time.sleep(0.5)

usb.util.claim_interface(dev, 1)
dev.set_interface_altsetting(interface=1, alternate_setting=1)
log("If1 -> Alt1")

state = {"stop": False, "rx": 0, "frames": 0, "bytes": 0}
def sniffer(ep, tag):
    buf, in_frame = bytearray(), False
    while not state["stop"]:
        try:
            data = bytes(dev.read(ep, 65536, timeout=300))
        except usb.core.USBError:
            continue
        state["rx"] += 1
        state["bytes"] += len(data)
        if state["rx"] <= 20:
            log(f"<< {tag}: {len(data)}B: {data[:32].hex(' ')}")
        payload = data[12:] if len(data) >= 12 and data[0] == 0xAA and data[1] == 0xBB else data
        if not in_frame:
            p = payload.find(b"\xff\xd8")
            if p >= 0:
                in_frame, buf = True, bytearray(payload[p:])
        else:
            buf.extend(payload)
        if in_frame:
            p = buf.find(b"\xff\xd9")
            if p >= 0:
                state["frames"] += 1
                if state["frames"] <= 5:
                    fn = f"tools/replug9_frame_{state['frames']}.jpg"
                    open(fn, "wb").write(bytes(buf[:p+2]))
                    log(f"** FRAME {state['frames']}: {p+2}B -> {fn}")
                buf, in_frame = bytearray(), False

for ep in (0x81, 0x82):
    threading.Thread(target=sniffer, args=(ep, f"EP{ep:#04x}"), daemon=True).start()
time.sleep(0.3)
wr(CONNECT, "CONNECT", ep=0x02)
time.sleep(15)
state["stop"] = True
time.sleep(0.5)
log(f"ENDE: {state['frames']} Frames, {state['rx']} RX-Events, {state['bytes']} B")
