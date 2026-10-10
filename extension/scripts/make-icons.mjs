// Generates the Heimdall toolbar icons (16/32/48/128 px PNG) from scratch — no
// image libraries, no binary assets. Draws the brand shield (dark navy face,
// cyan edge, glowing core) into an RGBA buffer and encodes a valid PNG with the
// built-in zlib. Keeps the repo free of committed binaries and guarantees the
// icons match the dashboard's logo palette.

import { deflateSync } from 'node:zlib';
import { writeFileSync, mkdirSync } from 'node:fs';

// ---- tiny PNG encoder (RGBA, 8-bit) -------------------------------------
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const typeBuf = Buffer.from(type, 'ascii');
  const body = Buffer.concat([typeBuf, data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body), 0);
  return Buffer.concat([len, body, crc]);
}

function encodePng(width, height, rgba) {
  const sig = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // color type RGBA
  // 10,11,12 = compression/filter/interlace = 0
  // raw scanlines, each prefixed with filter byte 0
  const stride = width * 4;
  const raw = Buffer.alloc((stride + 1) * height);
  for (let y = 0; y < height; y++) {
    raw[y * (stride + 1)] = 0;
    rgba.copy(raw, y * (stride + 1) + 1, y * stride, y * stride + stride);
  }
  const idat = deflateSync(raw, { level: 9 });
  return Buffer.concat([sig, chunk('IHDR', ihdr), chunk('IDAT', idat), chunk('IEND', Buffer.alloc(0))]);
}

// ---- drawing -------------------------------------------------------------
function lerp(a, b, t) { return a + (b - a) * t; }
function mix(c1, c2, t) {
  return [lerp(c1[0], c2[0], t), lerp(c1[1], c2[1], t), lerp(c1[2], c2[2], t)];
}

// Shield polygon in unit space (y down), centroid ≈ (0.5, 0.5).
const SHIELD = [
  [0.5, 0.05], [0.9, 0.2], [0.9, 0.52], [0.5, 0.95], [0.1, 0.52], [0.1, 0.2],
];

function pointInPoly(px, py, poly) {
  let inside = false;
  for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
    const xi = poly[i][0], yi = poly[i][1];
    const xj = poly[j][0], yj = poly[j][1];
    const intersect = (yi > py) !== (yj > py) && px < ((xj - xi) * (py - yi)) / (yj - yi) + xi;
    if (intersect) inside = !inside;
  }
  return inside;
}

function scalePoly(poly, s, cx, cy) {
  return poly.map(([x, y]) => [cx + (x - cx) * s, cy + (y - cy) * s]);
}

function drawIcon(size) {
  const rgba = Buffer.alloc(size * size * 4); // transparent
  const cx = 0.5, cy = 0.52;
  const outer = SHIELD;
  const inner = scalePoly(SHIELD, 0.72, cx, cy);

  const NAVY_TOP = [12, 26, 46];
  const NAVY_BOT = [6, 17, 31];
  const CYAN = [56, 189, 248];
  const CYAN_LIGHT = [125, 211, 252];

  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const u = (x + 0.5) / size;
      const v = (y + 0.5) / size;
      const i = (y * size + x) * 4;
      const inOuter = pointInPoly(u, v, outer);
      if (!inOuter) continue;
      const inInner = pointInPoly(u, v, inner);
      let col;
      let a = 255;
      if (!inInner) {
        // cyan edge ring with a vertical sheen
        col = mix(CYAN, CYAN_LIGHT, Math.max(0, 1 - v));
      } else {
        // navy face, vertical gradient
        col = mix(NAVY_TOP, NAVY_BOT, v);
        // glowing core
        const dx = u - cx, dy = v - cy;
        const d = Math.sqrt(dx * dx + dy * dy);
        const glow = Math.max(0, 1 - d / 0.18);
        if (glow > 0) col = mix(col, CYAN_LIGHT, glow * 0.95);
      }
      rgba[i] = Math.round(col[0]);
      rgba[i + 1] = Math.round(col[1]);
      rgba[i + 2] = Math.round(col[2]);
      rgba[i + 3] = a;
    }
  }
  return encodePng(size, size, rgba);
}

mkdirSync('public/icons', { recursive: true });
for (const size of [16, 32, 48, 128]) {
  writeFileSync(`public/icons/icon-${size}.png`, drawIcon(size));
}
console.log('icons: wrote public/icons/icon-{16,32,48,128}.png');
