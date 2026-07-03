// Frida-Hook für die "Usee Plus"-App (oder jede App, die das Endoskop über die
// Android-USB-Host-API anspricht). Protokolliert jeden Bulk-/Control-Transfer
// samt Endpunkt, Richtung und Hex-Dump — damit sieht man die komplette iAP2-
// Sequenz und vor allem den 0xAE01-Payload, der den Videostream (0xAE00) auslöst.
//
// Nutzung (mit root + frida-server auf dem Pixel 8):
//   1) Paketnamen finden:   frida-ps -Uai | grep -i usee     (oder "cam"/"plus")
//   2) App gehookt starten:  frida -U -f <paket.name> -l tools/frida_usee_hook.js --no-pause
//      (bereits laufende App: frida -U -n "Usee Plus" -l tools/frida_usee_hook.js)
//   3) In der App den Livestream öffnen, dann die Konsole ansehen.
//
// Ohne root: APK mit frida-gadget patchen
//   objection patchapk -s UseePlus.apk    # neu signieren + installieren
// und dieses Skript per objection/frida-gadget laden.
//
// Der spannende Moment ist der erste OUT-Transfer auf dem iAP-OUT-Endpunkt mit
// einem 40 40 .. AE 01 .. Rumpf NACH IdentificationAccepted — das ist der
// gesuchte Start-Befehl. Gefolgt von 0xAE00-Nachrichten (IN) mit den MJPEG-Daten.

'use strict';

var MAX = 64; // Bytes pro Zeile hexen (erhöhen für volle Frames)

function hex(bytes, n) {
  n = Math.min(n === undefined ? bytes.length : n, bytes.length);
  var s = '';
  for (var i = 0; i < n; i++) {
    var v = bytes[i] & 0xff;
    s += (v < 16 ? '0' : '') + v.toString(16) + ' ';
  }
  if (n < bytes.length) s += '… (+' + (bytes.length - n) + ')';
  return s.trim();
}

// Endpunkt-Adresse lesbar: Bit 7 = Richtung (0x80 = IN)
function epStr(addr) {
  var dir = (addr & 0x80) ? 'IN ' : 'OUT';
  return dir + ' 0x' + (addr & 0xff).toString(16).padStart(2, '0');
}

Java.perform(function () {
  // async-Pfad: queue() merkt sich den Puffer je UsbRequest; die IN-Antwort ist
  // erst nach UsbDeviceConnection.requestWait() im Puffer -> dort auslesen.
  var pendingReq = {}; // hashCode(UsbRequest) -> {bb, addr}
  function bufBytes(bb) {
    try { var a = [], lim = bb.limit(); for (var i = 0; i < lim; i++) a.push(bb.get(i)); return a; }
    catch (e) { return []; }
  }

  // ---- java: UsbDeviceConnection.bulkTransfer / controlTransfer / requestWait ----
  try {
    var Conn = Java.use('android.hardware.usb.UsbDeviceConnection');

    // bulkTransfer(UsbEndpoint, byte[], int len, int timeout)
    Conn.bulkTransfer.overload(
      'android.hardware.usb.UsbEndpoint', '[B', 'int', 'int'
    ).implementation = function (ep, buf, len, to) {
      var r = this.bulkTransfer(ep, buf, len, to);
      dumpBulk(ep, buf, 0, r >= 0 ? r : len, r);
      return r;
    };

    // bulkTransfer(UsbEndpoint, byte[], int offset, int len, int timeout)
    Conn.bulkTransfer.overload(
      'android.hardware.usb.UsbEndpoint', '[B', 'int', 'int', 'int'
    ).implementation = function (ep, buf, off, len, to) {
      var r = this.bulkTransfer(ep, buf, off, len, to);
      dumpBulk(ep, buf, off, r >= 0 ? r : len, r);
      return r;
    };

    // controlTransfer(int reqType, int req, int value, int index, byte[], int len, int timeout)
    Conn.controlTransfer.overload(
      'int', 'int', 'int', 'int', '[B', 'int', 'int'
    ).implementation = function (rt, rq, val, idx, buf, len, to) {
      var r = this.controlTransfer(rt, rq, val, idx, buf, len, to);
      var b = buf ? Java.array('byte', buf) : [];
      console.log('[CTRL] rt=0x' + rt.toString(16) + ' req=0x' + rq.toString(16) +
        ' val=0x' + val.toString(16) + ' idx=' + idx + ' ret=' + r +
        (b.length ? '  ' + hex(b, MAX) : ''));
      return r;
    };

    function dumpBulk(ep, buf, off, n, ret) {
      try {
        var addr = ep.getAddress();
        var b = Java.array('byte', buf);
        var slice = [];
        for (var i = off; i < off + n && i < b.length; i++) slice.push(b[i]);
        console.log('[BULK ' + epStr(addr) + '] ret=' + ret + ' len=' + n +
          '  ' + hex(slice, MAX));
      } catch (e) { console.log('[BULK] dump-error ' + e); }
    }

    // requestWait() liefert den fertigen UsbRequest zurück; dessen Puffer (bei
    // IN jetzt gefüllt) über die queue()-Zuordnung dumpen.
    var hookedRW = 0;
    Conn.requestWait.overloads.forEach(function (ov) {
      try {
        ov.implementation = function () {
          var req = ov.apply(this, arguments);
          try {
            if (req) {
              var p = pendingReq[req.hashCode()];
              if (p && (p.addr & 0x80)) { // IN-Antwort
                var by = bufBytes(p.bb);
                console.log('[ASYNC ' + epStr(p.addr) + '] len=' + by.length + '  ' + hex(by, MAX));
              }
              if (p) delete pendingReq[req.hashCode()];
            }
          } catch (e) {}
          return req;
        };
        hookedRW++;
      } catch (e) {}
    });
    console.log('[+] UsbDeviceConnection-Hooks aktiv (requestWait=' + hookedRW + ').');
  } catch (e) {
    console.log('[!] UsbDeviceConnection nicht gehookt: ' + e);
  }

  // ---- java: UsbRequest.queue() — Puffer je Request merken; OUT-Kommandos
  // (z.B. 0xAE01) sofort dumpen, IN-Antworten kommen via requestWait() oben.
  try {
    var Req = Java.use('android.hardware.usb.UsbRequest');
    var hookedQ = 0;
    (Req.queue ? Req.queue.overloads : []).forEach(function (ov) {
      try {
        ov.implementation = function () {
          var bb = arguments[0];
          try {
            var ep = this.getEndpoint();
            var addr = ep ? ep.getAddress() : -1;
            pendingReq[this.hashCode()] = { bb: bb, addr: addr };
            if (!(addr & 0x80)) { // OUT: Daten stehen jetzt schon im Puffer
              var by = bufBytes(bb);
              console.log('[ASYNC ' + epStr(addr) + '] len=' + by.length + '  ' + hex(by, MAX));
            }
          } catch (e) {}
          return ov.apply(this, arguments);
        };
        hookedQ++;
      } catch (e) {}
    });
    console.log('[+] UsbRequest.queue-Hook aktiv (overloads=' + hookedQ + ').');
  } catch (e) {
    console.log('[!] UsbRequest nicht gehookt: ' + e);
  }
});

// ---- native Fallback: falls die App libusb statt der Java-API nutzt ----
// frida 17 hat die Module-API umgestellt — Export robust suchen.
function findNativeExport(name) {
  try { if (typeof Module.getGlobalExportByName === 'function') return Module.getGlobalExportByName(name); } catch (e) {}
  try { if (typeof Module.findGlobalExportByName === 'function') return Module.findGlobalExportByName(name); } catch (e) {}
  try { if (typeof Module.findExportByName === 'function') return Module.findExportByName(null, name); } catch (e) {}
  try { return Module.getExportByName(null, name); } catch (e) {}
  return null;
}
['libusb_bulk_transfer', 'libusb_interrupt_transfer'].forEach(function (name) {
  try {
    var p = findNativeExport(name);
    if (!p) return;
    Interceptor.attach(p, {
      onEnter: function (args) {
        this.ep = args[1].toInt32() & 0xff;
        this.data = args[2];
        this.len = args[3].toInt32();
      },
      onLeave: function () {
        try {
          var n = Math.min(this.len, MAX);
          console.log('[NATIVE ' + epStr(this.ep) + '] ' +
            hexdump(this.data, { length: n, header: false, ansi: false }).split('\n')[0]);
        } catch (e) {}
      },
    });
    console.log('[+] native ' + name + ' gehookt.');
  } catch (e) { /* native libusb nicht genutzt — Java-Hooks reichen */ }
});
