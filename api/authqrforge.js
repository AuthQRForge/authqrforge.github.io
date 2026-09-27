(function (root) {
  'use strict';

  const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

  function base32Decode(input) {
    const cleaned = String(input).toUpperCase().replace(/[^A-Z2-7]/g, '');
    let bits = 0, value = 0;
    const out = [];
    for (let i = 0; i < cleaned.length; i++) {
      const idx = BASE32_ALPHABET.indexOf(cleaned[i]);
      if (idx === -1) continue;
      value = (value << 5) | idx;
      bits += 5;
      if (bits >= 8) {
        out.push((value >>> (bits - 8)) & 0xFF);
        bits -= 8;
      }
    }
    return new Uint8Array(out);
  }

  function randomBase32(length) {
    const random = new Uint8Array(length);
    if (root.crypto && root.crypto.getRandomValues) {
      root.crypto.getRandomValues(random);
    } else {
      for (let i = 0; i < length; i++) random[i] = Math.floor(Math.random() * 256);
    }
    let out = '';
    for (let i = 0; i < length; i++) out += BASE32_ALPHABET[random[i] % 32];
    return out;
  }

  function rotl(n, b) { return ((n << b) | (n >>> (32 - b))) >>> 0; }

  function sha1(bytes) {
    const ml = bytes.length * 8;
    const withOne = new Uint8Array(((bytes.length + 8) >> 6 << 6) + 64);
    withOne.set(bytes);
    withOne[bytes.length] = 0x80;
    new DataView(withOne.buffer).setUint32(withOne.length - 4, ml, false);

    let h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;
    const w = new Uint32Array(80);

    for (let i = 0; i < withOne.length; i += 64) {
      for (let j = 0; j < 16; j++) {
        w[j] = (withOne[i + j*4] << 24) | (withOne[i + j*4 + 1] << 16) |
               (withOne[i + j*4 + 2] << 8) | withOne[i + j*4 + 3];
      }
      for (let j = 16; j < 80; j++) {
        w[j] = rotl(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1);
      }
      let a = h0, b = h1, c = h2, d = h3, e = h4;
      for (let j = 0; j < 80; j++) {
        let f, k;
        if (j < 20)      { f = (b & c) | ((~b) & d); k = 0x5A827999; }
        else if (j < 40) { f = b ^ c ^ d;             k = 0x6ED9EBA1; }
        else if (j < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else             { f = b ^ c ^ d;             k = 0xCA62C1D6; }
        const temp = (rotl(a, 5) + f + e + k + w[j]) >>> 0;
        e = d; d = c; c = rotl(b, 30); b = a; a = temp;
      }
      h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0;
      h3 = (h3 + d) >>> 0; h4 = (h4 + e) >>> 0;
    }

    const result = new Uint8Array(20);
    const rv = new DataView(result.buffer);
    rv.setUint32(0, h0, false); rv.setUint32(4, h1, false);
    rv.setUint32(8, h2, false); rv.setUint32(12, h3, false);
    rv.setUint32(16, h4, false);
    return result;
  }

  function hmacSha1(key, message) {
    const blockSize = 64;
    let k = key;
    if (k.length > blockSize) k = sha1(k);
    const paddedKey = new Uint8Array(blockSize);
    paddedKey.set(k);
    const oKeyPad = new Uint8Array(blockSize);
    const iKeyPad = new Uint8Array(blockSize);
    for (let i = 0; i < blockSize; i++) {
      oKeyPad[i] = paddedKey[i] ^ 0x5C;
      iKeyPad[i] = paddedKey[i] ^ 0x36;
    }
    const inner = new Uint8Array(blockSize + message.length);
    inner.set(iKeyPad);
    inner.set(message, blockSize);
    const innerHash = sha1(inner);
    const outer = new Uint8Array(blockSize + 20);
    outer.set(oKeyPad);
    outer.set(innerHash, blockSize);
    return sha1(outer);
  }

  function hotp(secretBytes, counter, digits) {
    const counterBytes = new Uint8Array(8);
    const view = new DataView(counterBytes.buffer);
    view.setUint32(0, Math.floor(counter / 0x100000000), false);
    view.setUint32(4, counter >>> 0, false);
    const hmac = hmacSha1(secretBytes, counterBytes);
    const offset = hmac[hmac.length - 1] & 0x0F;
    const binary = ((hmac[offset] & 0x7F) << 24) |
                   ((hmac[offset + 1] & 0xFF) << 16) |
                   ((hmac[offset + 2] & 0xFF) << 8) |
                   (hmac[offset + 3] & 0xFF);
    const otp = binary % Math.pow(10, digits);
    return otp.toString().padStart(digits, '0');
  }

  function getRSBlock(version) {
    const table = {
      1:  { blocks: 1, eccPerBlock: 7  },
      2:  { blocks: 1, eccPerBlock: 10 },
      3:  { blocks: 1, eccPerBlock: 15 },
      4:  { blocks: 1, eccPerBlock: 20 },
      5:  { blocks: 1, eccPerBlock: 26 },
      6:  { blocks: 2, eccPerBlock: 18 },
      7:  { blocks: 2, eccPerBlock: 20 },
      8:  { blocks: 2, eccPerBlock: 24 },
      9:  { blocks: 2, eccPerBlock: 30 },
      10: { blocks: 4, eccPerBlock: 18 }
    };
    return table[version] || table[1];
  }

  function getAlignmentPositions(version) {
    if (version === 1) return [];
    const pos = {
      2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34],
      7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50]
    };
    return pos[version] || [];
  }

  function rsEncode(data, eccLen) {
    const gfExp = new Uint8Array(512);
    const gfLog = new Uint8Array(256);
    let x = 1;
    for (let i = 0; i < 255; i++) {
      gfExp[i] = x;
      gfLog[x] = i;
      x <<= 1;
      if (x & 0x100) x ^= 0x11D;
    }
    for (let i = 255; i < 512; i++) gfExp[i] = gfExp[i - 255];

    const gfMul = (a, b) => (a === 0 || b === 0) ? 0 : gfExp[gfLog[a] + gfLog[b]];

    const genPoly = [1];
    for (let i = 0; i < eccLen; i++) {
      const newPoly = new Array(genPoly.length + 1).fill(0);
      for (let j = 0; j < genPoly.length; j++) {
        newPoly[j] ^= gfMul(genPoly[j], 1);
        newPoly[j + 1] ^= gfMul(genPoly[j], gfExp[i]);
      }
      genPoly.length = 0;
      genPoly.push(...newPoly);
    }

    const msg = data.concat(new Array(eccLen).fill(0));
    for (let i = 0; i < data.length; i++) {
      const coef = msg[i];
      if (coef !== 0) {
        for (let j = 0; j < genPoly.length; j++) msg[i + j] ^= gfMul(genPoly[j], coef);
      }
    }
    return msg.slice(data.length);
  }

  function qrEncode(text) {
    const bytes = [];
    for (let i = 0; i < text.length; i++) {
      const c = text.charCodeAt(i);
      if (c < 0x80) bytes.push(c);
      else if (c < 0x800) bytes.push(0xC0 | (c >> 6), 0x80 | (c & 0x3F));
      else bytes.push(0xE0 | (c >> 12), 0x80 | ((c >> 6) & 0x3F), 0x80 | (c & 0x3F));
    }
    const len = bytes.length;
    const capacity = [0, 17, 32, 53, 78, 106, 134, 154, 192, 230, 271];
    let version = 1;
    for (let v = 1; v <= 10; v++) {
      if (len <= capacity[v]) { version = v; break; }
    }
    if (version > 10) throw new Error('Data too long');

    const totalCodewords = [0, 26, 44, 70, 100, 134, 172, 196, 242, 292, 346][version];
    const dataCodewords = [0, 19, 34, 55, 80, 108, 136, 156, 194, 232, 274][version];

    const bits = [];
    const putBit = b => bits.push(b);
    const putBits = (value, length) => {
      for (let i = length - 1; i >= 0; i--) putBit((value >> i) & 1);
    };

    putBits(4, 4);
    putBits(len, version <= 9 ? 8 : 16);
    for (const b of bytes) putBits(b, 8);

    const totalDataBits = dataCodewords * 8;
    for (let i = 0; i < Math.min(4, totalDataBits - bits.length); i++) putBit(0);
    while (bits.length % 8 !== 0) putBit(0);

    const padBytes = [0xEC, 0x11];
    let padIndex = 0;
    while (bits.length < totalDataBits) {
      putBits(padBytes[padIndex % 2], 8);
      padIndex++;
    }

    const dataCw = [];
    for (let i = 0; i < bits.length; i += 8) {
      let val = 0;
      for (let j = 0; j < 8; j++) val = (val << 1) | (bits[i + j] || 0);
      dataCw.push(val);
    }

    const rsBlock = getRSBlock(version);
    const { blocks, eccPerBlock } = rsBlock;
    const dataPerBlock = Math.floor(dataCodewords / blocks);
    const extraData = dataCodewords % blocks;

    const dataBlocks = [];
    let dataIdx = 0;
    for (let b = 0; b < blocks; b++) {
      const blockSize = dataPerBlock + (b < extraData ? 1 : 0);
      dataBlocks.push(dataCw.slice(dataIdx, dataIdx + blockSize));
      dataIdx += blockSize;
    }

    const eccBlocks = dataBlocks.map(b => rsEncode(b, eccPerBlock));

    const finalCw = [];
    const maxDataLen = Math.max(...dataBlocks.map(b => b.length));
    for (let i = 0; i < maxDataLen; i++) {
      for (let b = 0; b < blocks; b++) {
        if (i < dataBlocks[b].length) finalCw.push(dataBlocks[b][i]);
      }
    }
    for (let i = 0; i < eccPerBlock; i++) {
      for (let b = 0; b < blocks; b++) finalCw.push(eccBlocks[b][i]);
    }
    if (finalCw.length !== totalCodewords) throw new Error('Codeword mismatch');

    const size = version * 4 + 17;
    const matrix = Array(size).fill().map(() => Array(size).fill(0));
    const reserved = Array(size).fill().map(() => Array(size).fill(false));

    const setFinder = (row, col) => {
      for (let r = -1; r <= 7; r++) {
        for (let c = -1; c <= 7; c++) {
          const rr = row + r, cc = col + c;
          if (rr < 0 || rr >= size || cc < 0 || cc >= size) continue;
          matrix[rr][cc] = (
            (r >= 0 && r <= 6 && (c === 0 || c === 6)) ||
            (c >= 0 && c <= 6 && (r === 0 || r === 6)) ||
            (r >= 2 && r <= 4 && c >= 2 && c <= 4)
          ) ? 1 : 0;
          reserved[rr][cc] = true;
        }
      }
    };
    setFinder(0, 0);
    setFinder(0, size - 7);
    setFinder(size - 7, 0);

    for (const r of getAlignmentPositions(version)) {
      for (const c of getAlignmentPositions(version)) {
        if ((r === 6 && c === 6) || (r === 6 && c === size - 7) || (r === size - 7 && c === 6)) continue;
        for (let dr = -2; dr <= 2; dr++) {
          for (let dc = -2; dc <= 2; dc++) {
            matrix[r + dr][c + dc] = (Math.abs(dr) === 2 || Math.abs(dc) === 2 || (dr === 0 && dc === 0)) ? 1 : 0;
            reserved[r + dr][c + dc] = true;
          }
        }
      }
    }

    for (let i = 8; i < size - 8; i++) {
      if (!reserved[6][i]) { matrix[6][i] = (i % 2 === 0) ? 1 : 0; reserved[6][i] = true; }
      if (!reserved[i][6]) { matrix[i][6] = (i % 2 === 0) ? 1 : 0; reserved[i][6] = true; }
    }

    for (let i = 0; i < 9; i++) {
      if (!reserved[8][i]) { reserved[8][i] = true; matrix[8][i] = 0; }
      if (!reserved[i][8]) { reserved[i][8] = true; matrix[i][8] = 0; }
    }
    for (let i = 0; i < 8; i++) {
      reserved[8][size - 1 - i] = true; matrix[8][size - 1 - i] = 0;
      reserved[size - 1 - i][8] = true; matrix[size - 1 - i][8] = 0;
    }
    reserved[8][size - 8] = true; matrix[8][size - 8] = 0;
    reserved[size - 8][8] = true; matrix[size - 8][8] = 1;

    let bitIdx = 0;
    const totalBits = finalCw.length * 8;
    const getBit = idx => {
      if (idx >= totalBits) return 0;
      return (finalCw[Math.floor(idx / 8)] >> (7 - (idx % 8))) & 1;
    };

    let dir = -1, row = size - 1, col = size - 1;
    while (col > 0) {
      if (col === 6) col--;
      while (row >= 0 && row < size) {
        for (let c = 0; c < 2; c++) {
          const cc = col - c;
          if (!reserved[row][cc]) matrix[row][cc] = getBit(bitIdx++);
        }
        row += dir;
      }
      row -= dir;
      dir = -dir;
      col -= 2;
    }

    for (let r = 0; r < size; r++) {
      for (let c = 0; c < size; c++) {
        if (!reserved[r][c] && (r + c) % 2 === 0) matrix[r][c] ^= 1;
      }
    }

    const fmt = [1,1,1,0,1,1,1,1,1,0,0,0,1,0,0];
    for (let i = 0; i < 6; i++) matrix[8][i] = fmt[i];
    matrix[8][7] = fmt[6];
    matrix[8][8] = fmt[7];
    matrix[7][8] = fmt[8];
    for (let i = 0; i < 6; i++) matrix[5 - i][8] = fmt[9 + i];
    for (let i = 0; i < 7; i++) matrix[size - 1 - i][8] = fmt[14 - i];
    for (let i = 0; i < 8; i++) matrix[8][size - 8 + i] = fmt[7 + i];
    matrix[size - 8][8] = 1;

    return { matrix, size };
  }

  // ---------- Public API ----------
  const AuthQRForge = {
    generateSecret(options) {
      const opts = options || {};
      return randomBase32(opts.length || 26);
    },

    buildUri(issuer, account, secret) {
      const encIssuer = encodeURIComponent(issuer);
      const encAccount = encodeURIComponent(account);
      return `otpauth://totp/${encIssuer}:${encAccount}?secret=${encodeURIComponent(secret)}&issuer=${encIssuer}`;
    },

    generate(issuer, account, options) {
      const opts = options || {};
      const iss = issuer || 'AuthQRForge';
      const acc = account || 'user';
      const secret = opts.secret || randomBase32(opts.length || 26);
      return { secret, uri: this.buildUri(iss, acc, secret), issuer: iss, account: acc };
    },

    getCode(secret, options) {
      const opts = options || {};
      const period = opts.period || 30;
      const digits = opts.digits || 6;
      const timestamp = opts.timestamp || Date.now();
      const counter = Math.floor(timestamp / 1000 / period);
      return hotp(base32Decode(secret), counter, digits);
    },

    verify(secret, code, options) {
      const opts = options || {};
      const window = opts.window !== undefined ? opts.window : 1;
      const period = opts.period || 30;
      const digits = opts.digits || 6;
      const cleaned = String(code).replace(/\D/g, '');

      if (cleaned.length !== digits) {
        return { valid: false, reason: 'invalid_format' };
      }
      if (!secret) {
        return { valid: false, reason: 'missing_secret' };
      }

      const counter = Math.floor((opts.timestamp || Date.now()) / 1000 / period);
      const secretBytes = base32Decode(secret);
      for (let i = -window; i <= window; i++) {
        if (hotp(secretBytes, counter + i, digits) === cleaned) {
          return { valid: true, reason: 'match' };
        }
      }
      return { valid: false, reason: 'no_match' };
    },

    drawQR(canvas, uri, options) {
      const opts = options || {};
      const ctx = canvas.getContext('2d');
      try {
        const { matrix, size } = qrEncode(uri);
        const scale = Math.floor(canvas.width / size);
        const offset = Math.floor((canvas.width - size * scale) / 2);
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = opts.background || '#ffffff';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = opts.foreground || '#000000';
        for (let r = 0; r < size; r++) {
          for (let c = 0; c < size; c++) {
            if (matrix[r][c]) ctx.fillRect(offset + c * scale, offset + r * scale, scale, scale);
          }
        }
        return true;
      } catch (e) {
        return false;
      }
    },

    downloadPng(canvas, options) {
      const opts = options || {};
      const link = document.createElement('a');
      link.download = opts.filename || 'qr.png';
      link.href = canvas.toDataURL('image/png');
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    }
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = AuthQRForge;
  } else {
    root.AuthQRForge = AuthQRForge;
  }
})(typeof window !== 'undefined' ? window : this);
