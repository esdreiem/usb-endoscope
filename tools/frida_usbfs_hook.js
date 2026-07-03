// Frida-Hook für NATIVES USB-I/O über USBDEVFS-ioctl (/dev/bus/usb/...).
// Fängt Transfers, die NICHT über die Java-USB-API laufen (libusb intern, oder
// eigener nativer USB-Code) — z.B. bei com.i4season.useeplus, das die Java-API
// nicht nutzt. Dekodiert USBDEVFS_SUBMITURB (async OUT/IN), REAPURB(NDELAY)
// (fertige IN-Daten) und USBDEVFS_BULK (sync).
//
// Nutzung (an laufende App anhängen):
//   frida -H <ip>:27042 -n UseePlus -l tools/frida_usbfs_hook.js
// Wichtig: den STREAM-START abfangen -> beim laufenden Stream einmal das
// Endoskop ab-/anstecken oder in der App den Live-View neu öffnen, dann kommt
// der OUT-Startbefehl (0xAE01-Äquivalent) frisch.

'use strict';

var MAX_OUT = 600;  // ganze Vendor-Control-Payloads erfassen (512B + Setup)
var MAX_IN = 40;    // IN: nur Kopf zeigen (Video ist groß)
var ps = Process.pointerSize; // 8 = 64-bit-App, 4 = 32-bit-App

// URB-Struct-Offsets je Bitbreite
var OFF_EP = 1;
var OFF_BUF = (ps === 8) ? 16 : 12;
var OFF_BUFLEN = (ps === 8) ? 24 : 16;
var OFF_ACTLEN = (ps === 8) ? 28 : 20;
// usbdevfs_bulktransfer: ep(0) len(4) timeout(8) data(@16/@12)
var OFF_BULK_EP = 0, OFF_BULK_LEN = 4, OFF_BULK_DATA = (ps === 8) ? 16 : 12;

function epStr(addr) { return ((addr & 0x80) ? 'IN ' : 'OUT') + ' 0x' + (addr & 0xff).toString(16); }
function hexAt(ptr, n) {
  try {
    if (ptr.isNull() || n <= 0) return '';
    var bytes = new Uint8Array(ptr.readByteArray(n));
    var s = '';
    for (var i = 0; i < bytes.length; i++) { var v = bytes[i]; s += (v < 16 ? '0' : '') + v.toString(16) + ' '; }
    return s.trim();
  } catch (e) { return '(read-err ' + e + ')'; }
}

function findExport(name) {
  try { if (typeof Module.getGlobalExportByName === 'function') return Module.getGlobalExportByName(name); } catch (e) {}
  try { if (typeof Module.findExportByName === 'function') return Module.findExportByName(null, name); } catch (e) {}
  try { return Module.getExportByName(null, name); } catch (e) {}
  return null;
}

var submitted = {}; // urbPtr -> {ep, buf}

var ioctlPtr = findExport('ioctl');
if (!ioctlPtr) { console.log('[!] ioctl nicht gefunden'); }
else {
  Interceptor.attach(ioctlPtr, {
    onEnter: function (args) {
      this.cmd = args[1].toInt32() >>> 0;
      this.argp = args[2];
      var type = (this.cmd >> 8) & 0xff;   // 'U' = 0x55
      var nr = this.cmd & 0xff;
      this.nr = (type === 0x55) ? nr : -1;
      if (this.nr === 0) {                 // USBDEVFS_CONTROL (Setup/Vendor)
        try {
          var c = this.argp;
          var bmType = c.readU8();
          var bReq = c.add(1).readU8();
          var wVal = c.add(2).readU16();
          var wIdx = c.add(4).readU16();
          var wLen = c.add(6).readU16();
          var dp = c.add(ps === 8 ? 16 : 12).readPointer();
          this.ctl = { bmType: bmType, dp: dp, wLen: wLen, inDir: (bmType & 0x80) };
          var hx = (!(bmType & 0x80) && wLen) ? '  data=' + hexAt(dp, Math.min(wLen, MAX_OUT)) : '';
          console.log('[CTRL ' + ((bmType & 0x80) ? 'IN ' : 'OUT') + '] bmReqType=0x' + bmType.toString(16) +
            ' bReq=0x' + bReq.toString(16) + ' wValue=0x' + wVal.toString(16) +
            ' wIndex=0x' + wIdx.toString(16) + ' wLen=' + wLen + hx);
        } catch (e) {}
      } else if (this.nr === 4) {          // USBDEVFS_SETINTERFACE
        try { console.log('[SET_INTERFACE] iface=' + this.argp.readU32() + ' alt=' + this.argp.add(4).readU32()); } catch (e) {}
      } else if (this.nr === 5) {          // USBDEVFS_SETCONFIGURATION
        try { console.log('[SET_CONFIG] cfg=' + this.argp.readU32()); } catch (e) {}
      } else if (this.nr === 15) {         // USBDEVFS_CLAIMINTERFACE
        try { console.log('[CLAIM_INTERFACE] iface=' + this.argp.readU32()); } catch (e) {}
      } else if (this.nr === 10) {         // SUBMITURB
        try {
          var urb = this.argp;
          var utype = urb.readU8();        // 0=ISO 1=INT 2=CTRL 3=BULK
          var ep = urb.add(OFF_EP).readU8();
          var buf = urb.add(OFF_BUF).readPointer();
          var len = urb.add(OFF_BUFLEN).readInt();
          if (utype === 2 || ep === 0) {   // CONTROL-URB: Puffer = 8B Setup + Daten
            var bm = buf.readU8(), bReq = buf.add(1).readU8();
            var wVal = buf.add(2).readU16(), wIdx = buf.add(4).readU16(), wLen = buf.add(6).readU16();
            var inDir = (bm & 0x80);
            submitted[urb.toString()] = { ctrl: true, inDir: inDir, buf: buf };
            var hx = (!inDir && wLen) ? '  data=' + hexAt(buf.add(8), Math.min(wLen, MAX_OUT)) : '';
            console.log('[CTRL-URB ' + (inDir ? 'IN ' : 'OUT') + '] bmReqType=0x' + bm.toString(16) +
              ' bReq=0x' + bReq.toString(16) + ' wVal=0x' + wVal.toString(16) +
              ' wIdx=0x' + wIdx.toString(16) + ' wLen=' + wLen + hx);
          } else {
            submitted[urb.toString()] = { ep: ep, buf: buf };
            if (!(ep & 0x80)) console.log('[URB-OUT ' + epStr(ep) + '] len=' + len + '  ' + hexAt(buf, Math.min(len, MAX_OUT)));
          }
        } catch (e) {}
      } else if (this.nr === 2) {          // USBDEVFS_BULK (sync)
        try {
          this.bulkEp = this.argp.add(OFF_BULK_EP).readU32();
          this.bulkLen = this.argp.add(OFF_BULK_LEN).readU32();
          this.bulkData = this.argp.add(OFF_BULK_DATA).readPointer();
          if (!(this.bulkEp & 0x80)) {
            console.log('[BULK-OUT ' + epStr(this.bulkEp) + '] len=' + this.bulkLen + '  ' + hexAt(this.bulkData, Math.min(this.bulkLen, MAX_OUT)));
          }
        } catch (e) {}
      }
    },
    onLeave: function (ret) {
      if (this.nr === 0 && this.ctl && this.ctl.inDir) { // CONTROL-IN-Antwort
        try {
          var n = ret.toInt32();
          if (n > 0) console.log('[CTRL IN <-] len=' + n + '  ' + hexAt(this.ctl.dp, Math.min(n, MAX_OUT)));
        } catch (e) {}
      } else if (this.nr === 12 || this.nr === 13) { // REAPURB / REAPURBNDELAY
        try {
          if (ret.toInt32() !== 0) return;
          var urbPtr = this.argp.readPointer(); // *argp = fertige URB
          var rec = submitted[urbPtr.toString()];
          if (rec) {
            var actlen = urbPtr.add(OFF_ACTLEN).readInt();
            if (rec.ctrl && rec.inDir) { // Control-IN-Antwort (Daten ab Offset 8)
              console.log('[CTRL-URB IN <-] len=' + actlen + '  ' + hexAt(rec.buf.add(8), Math.min(actlen, MAX_OUT)));
            } else if (!rec.ctrl && (rec.ep & 0x80)) { // Bulk-IN
              console.log('[URB-IN  ' + epStr(rec.ep) + '] len=' + actlen + '  ' + hexAt(rec.buf, Math.min(actlen, MAX_IN)));
            }
            delete submitted[urbPtr.toString()];
          }
        } catch (e) {}
      } else if (this.nr === 2) {          // BULK-IN Ergebnis
        try {
          if (this.bulkEp & 0x80) {
            var n = ret.toInt32();
            if (n > 0) console.log('[BULK-IN  ' + epStr(this.bulkEp) + '] len=' + n + '  ' + hexAt(this.bulkData, Math.min(n, MAX_IN)));
          }
        } catch (e) {}
      }
    },
  });
  console.log('[+] ioctl/USBDEVFS-Hook aktiv (pointerSize=' + ps + ').');
}
