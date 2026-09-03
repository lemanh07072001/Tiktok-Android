'use strict';
// _spoof_fingerprint.js — spoof ĐỒNG BỘ device fingerprint metasec đọc.
// Profile-driven: đổi PROFILE bên dưới, mọi nguồn (/proc /sys + props) trả giá trị NHẤT QUÁN.
// Nguồn liệt kê trong DEVICE_INFO_SOURCES.md.
//
// Chạy: frida -H 127.0.0.1:47119 -f com.zhiliaoapp.musically -l _spoof_fingerprint.js
//   (cold spawn để hook trước khi metasec đọc lúc init)

// ===== PROFILE thiết bị giả (đổi ở đây) =====
// Mặc định: Samsung Galaxy S20 (SM-G981B, Exynos 990, 8 core: 2×M5 + 2×A76 + 4×A55)
var P = {
  props: {
    'ro.product.model': 'SM-G981B',
    'ro.product.device': 'x1s',
    'ro.product.name': 'x1sxxx',
    'ro.product.manufacturer': 'samsung',
    'ro.product.brand': 'samsung',
    'ro.product.board': 'exynos990',
    'ro.board.platform': 'exynos990',
    'ro.hardware': 'exynos990',
    'ro.product.cpu.abilist': 'arm64-v8a,armeabi-v7a,armeabi',
    'ro.product.cpu.abi': 'arm64-v8a',
    'ro.build.fingerprint': 'samsung/x1sxxx/x1s:12/SP1A.210812.016/G981BXXU5EUE1:user/release-keys',
    'ro.build.version.release': '12',
    'ro.build.version.sdk': '31',
    'ro.build.id': 'SP1A.210812.016',
    'ro.build.display.id': 'SP1A.210812.016.G981BXXU5EUE1',
    'ro.serialno': 'R58N40XXXXY'
  },
  cpu: {
    cores: 8,
    // per-core cpuinfo (Exynos 990: cpu0-3 A55, cpu4-5 A76, cpu6-7 M5)
    implementer: ['0x41','0x41','0x41','0x41','0x41','0x41','0x53','0x53'],
    part:        ['0xd05','0xd05','0xd05','0xd05','0xd0d','0xd0d','0x004','0x004'],
    variant:     ['0x1','0x1','0x1','0x1','0x1','0x1','0x1','0x1'],
    revision:    ['0','0','0','0','0','0','0','0'],
    features: 'fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp',
    arch: '8',
    max_freq: ['1950000','1950000','1950000','1950000','2314000','2314000','2730000','2730000'],
    min_freq: ['455000','455000','455000','455000','377000','377000','741000','741000'],
    cur_freq: ['1053000','1053000','1053000','1053000','864000','864000','741000','741000'],
    avail_freq: '455000 546000 650000 728000 819000 949000 1053000 1160000 1287000 1430000 1560000 1690000 1820000 1950000',
    present: '0-7', online: '0-7', possible: '0-7', kernel_max: '7'
  },
  mem_total_kb: 12000000  // 12 GB
};

// ===== engine =====
function buildCpuinfo() {
  var s = '';
  for (var i = 0; i < P.cpu.cores; i++) {
    s += 'processor\t: ' + i + '\n';
    s += 'BogoMIPS\t: 26.00\n';
    s += 'Features\t: ' + P.cpu.features + '\n';
    s += 'CPU implementer\t: ' + P.cpu.implementer[i] + '\n';
    s += 'CPU architecture: ' + P.cpu.arch + '\n';
    s += 'CPU variant\t: ' + P.cpu.variant[i] + '\n';
    s += 'CPU part\t: ' + P.cpu.part[i] + '\n';
    s += 'CPU revision\t: ' + P.cpu.revision[i] + '\n\n';
  }
  s += 'Hardware\t: Samsung EXYNOS990\n';
  return s;
}
// map: file path -> function returning spoofed content (or null = passthrough)
function spoofFor(path) {
  if (path === '/proc/cpuinfo') return buildCpuinfo();
  if (path === '/proc/meminfo') return 'MemTotal:       ' + P.mem_total_kb + ' kB\nMemFree:          500000 kB\nMemAvailable:    6000000 kB\n';
  var m;
  m = path.match(/cpu(\d+)\/cpufreq\/(\w+)/);
  if (m) {
    var idx = parseInt(m[1]), attr = m[2];
    if (attr === 'cpuinfo_max_freq') return P.cpu.max_freq[idx] + '\n';
    if (attr === 'cpuinfo_min_freq') return P.cpu.min_freq[idx] + '\n';
    if (attr === 'scaling_cur_freq') return P.cpu.cur_freq[idx] + '\n';
    if (attr === 'scaling_max_freq') return P.cpu.max_freq[idx] + '\n';
    if (attr === 'scaling_min_freq') return P.cpu.min_freq[idx] + '\n';
    if (attr === 'scaling_available_frequencies') return P.cpu.avail_freq + '\n';
  }
  if (path.indexOf('/cpu/present') >= 0) return P.cpu.present + '\n';
  if (path.indexOf('/cpu/online') >= 0) return P.cpu.online + '\n';
  if (path.indexOf('/cpu/possible') >= 0) return P.cpu.possible + '\n';
  if (path.indexOf('/cpu/kernel_max') >= 0) return P.cpu.kernel_max + '\n';
  return null;
}

// ===== gate: chỉ arm sau khi metasec load (tránh crash linker lúc spawn) =====
var armed = true; // live-attach: metasec already loaded
function checkArmed() { if (!armed && Process.findModuleByName('libmetasec_ov.so')) { armed = true; send({ t: 'info', msg: 'armed (metasec loaded)' }); } return armed; }
var dl = Module.findGlobalExportByName('android_dlopen_ext') || Module.findGlobalExportByName('dlopen');
if (dl) Interceptor.attach(dl, { onLeave: function () { checkArmed(); } });

// ===== hook openat/read: khi mở file target, thay nội dung ở lần read đầu =====
var fakeFds = {};  // fd -> {buf, pos}
var openat = Module.findGlobalExportByName('openat');
var openf  = Module.findGlobalExportByName('open');
function onOpen(path, retval) {
  if (!path || !armed) return;
  var content = spoofFor(path);
  if (content === null) return;
  var fd = retval.toInt32();
  if (fd < 0) return;
  fakeFds[fd] = { buf: content, pos: 0 };
}
if (openat) Interceptor.attach(openat, {
  onEnter: function (a) { try { this.path = a[1].readCString(); } catch (e) {} },
  onLeave: function (r) { onOpen(this.path, r); }
});
if (openf) Interceptor.attach(openf, {
  onEnter: function (a) { try { this.path = a[0].readCString(); } catch (e) {} },
  onLeave: function (r) { onOpen(this.path, r); }
});
function strToBytes(s) { var a = []; for (var i = 0; i < s.length; i++) a.push(s.charCodeAt(i) & 0xff); return a; }
var readf = Module.findGlobalExportByName('read');
if (readf) Interceptor.attach(readf, {
  onEnter: function (a) { if(!armed){this.fake=null;return;} this.fd = a[0].toInt32(); this.bufp = a[1]; this.cnt = a[2].toInt32(); this.fake = fakeFds[this.fd]; },
  onLeave: function (r) {
    var f = this.fake;
    if (!f) return;
    try {
      var remain = f.buf.length - f.pos;
      if (remain <= 0) { r.replace(ptr(0)); return; }
      var n = Math.min(remain, this.cnt);
      if (n <= 0) { r.replace(ptr(0)); return; }
      var bytes = strToBytes(f.buf.substr(f.pos, n));
      this.bufp.writeByteArray(bytes);   // exactly n bytes, no extra terminator
      f.pos += n;
      r.replace(ptr(n));
    } catch (e) { /* on any fault, leave original result untouched */ }
  }
});
var closef = Module.findGlobalExportByName('close');
if (closef) Interceptor.attach(closef, { onEnter: function (a) { delete fakeFds[a[0].toInt32()]; } });

// ===== hook system properties =====
var sp = Module.findGlobalExportByName('__system_property_get');
if (sp) Interceptor.attach(sp, {
  onEnter: function (a) { try { this.name = a[0].readCString(); this.out = a[1]; } catch (e) {} },
  onLeave: function (r) {
    if (this.name && P.props[this.name] && this.out) {
      try {
        var v = P.props[this.name];
        if (v.length > 90) v = v.substr(0, 90);   // PROP_VALUE_MAX = 92 incl NUL
        this.out.writeUtf8String(v);
        r.replace(ptr(v.length));
      } catch (e) {}
    }
  }
});

send({ t: 'info', msg: 'fingerprint spoof active: ' + P.props['ro.product.model'] });
